// Packet forwarding to a remote backend.
//
// Every received packet is appended to the durable spool before delivery and
// is POSTed individually with an Idempotency-Key. Failed deliveries are
// retried with exponential backoff and survive restarts because the spool is
// the source of truth. Delivery is at-least-once: duplicates are possible and
// are deduplicated by the backend using (node_id, event_id).
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultMinBackoff    = time.Second
	defaultMaxBackoff    = 60 * time.Second
	forwardUserAgent     = "direwolf-api/1.0"
	deadletterBodyLimit  = 512
	responseBodyLimit    = 1 << 20
	maxRetryAfter        = 5 * time.Minute
	housekeepingInterval = time.Second
)

// ForwardStats is exposed in /api/stats and rendered by the web UI.
type ForwardStats struct {
	Enabled      bool       `json:"enabled"`
	State        string     `json:"state"`
	NodeID       string     `json:"node_id,omitempty"`
	Pending      int64      `json:"pending"`
	SpoolBytes   int64      `json:"spool_bytes"`
	Sent         int64      `json:"sent"`
	Retries      int64      `json:"retries"`
	Deadlettered int64      `json:"deadlettered"`
	Dropped      int64      `json:"dropped"`
	LastSuccess  *time.Time `json:"last_success,omitempty"`
	LastAttempt  *time.Time `json:"last_attempt,omitempty"`
	LastError    string     `json:"last_error,omitempty"`
}

// DisabledForwardStats is the zero state returned when forwarding is off.
func DisabledForwardStats() ForwardStats {
	return ForwardStats{Enabled: false, State: "disabled"}
}

// forwardEnvelope is the JSON body sent to the backend for each packet.
type forwardEnvelope struct {
	SchemaVersion int     `json:"schema_version"`
	EventID       string  `json:"event_id"`
	Seq           int64   `json:"seq"`
	NodeID        string  `json:"node_id"`
	Packet        *Packet `json:"packet"`
}

type postResult int

const (
	postAck postResult = iota
	postDead
	postRetry
	postUnauthorized
)

// Forwarder delivers spooled packets to the backend.
type Forwarder struct {
	cfg   ForwardConfig
	token string
	mode  fsyncMode
	spool *Spool
	in    chan *Packet

	notify chan struct{}

	client *http.Client

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	closed    atomic.Bool
	closeOnce sync.Once
	closeErr  error

	enqueueMu sync.Mutex
	enqueueWG sync.WaitGroup

	minBackoff time.Duration
	maxBackoff time.Duration

	dlMu   sync.Mutex
	dlFile *os.File

	mu                  sync.Mutex
	consecutiveFailures int
	unauthorized        bool
	probeDown           bool
	probeAt             time.Time
	probeOKAt           time.Time
	lastSuccess         time.Time
	lastReachable       time.Time
	lastAttempt         time.Time
	lastError           string
	sent                int64
	retries             int64
	deadlettered        int64
	dropped             int64
}

// NewForwarder opens the spool and prepares the HTTP client. Call Start to
// begin delivery.
func NewForwarder(cfg ForwardConfig) (*Forwarder, error) {
	if cfg.URL == "" {
		return nil, errors.New("forward: url is empty")
	}
	if cfg.NodeID == "" {
		cfg.NodeID = defaultNodeID()
	}
	if cfg.Queue < 1 {
		cfg.Queue = 1024
	}
	if cfg.SpoolMaxBytes < 1 {
		cfg.SpoolMaxBytes = 256 << 20
	}
	if cfg.Timeout.Std() <= 0 {
		cfg.Timeout = Duration(10 * time.Second)
	}
	if cfg.EnqueueTimeout.Std() < 0 {
		cfg.EnqueueTimeout = 0
	}
	if cfg.HealthURL != "" && cfg.HealthInterval.Std() <= 0 {
		cfg.HealthInterval = Duration(30 * time.Second)
	}
	mode, err := parseFsyncMode(cfg.Fsync)
	if err != nil {
		return nil, err
	}
	spool, err := OpenSpool(cfg.SpoolDir, cfg.SpoolMaxBytes, mode)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	f := &Forwarder{
		cfg:        cfg,
		token:      cfg.Token,
		mode:       mode,
		spool:      spool,
		in:         make(chan *Packet, cfg.Queue),
		notify:     make(chan struct{}, 1),
		ctx:        ctx,
		cancel:     cancel,
		minBackoff: defaultMinBackoff,
		maxBackoff: defaultMaxBackoff,
		client: &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				MaxIdleConns:          4,
				MaxIdleConnsPerHost:   2,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: time.Second,
				TLSClientConfig:       &tls.Config{InsecureSkipVerify: cfg.Insecure}, //nolint:gosec // opt-in flag
			},
		},
	}
	return f, nil
}

// Start launches the writer, sender, health check and housekeeping goroutines.
func (f *Forwarder) Start(parent context.Context) {
	go func() {
		select {
		case <-parent.Done():
			f.cancel()
		case <-f.ctx.Done():
		}
	}()

	f.wg.Add(3)
	go func() { defer f.wg.Done(); f.writeLoop() }()
	go func() { defer f.wg.Done(); f.sendLoop() }()
	go func() { defer f.wg.Done(); f.housekeepingLoop() }()

	if f.cfg.HealthURL != "" {
		f.wg.Add(1)
		go func() { defer f.wg.Done(); f.probeLoop() }()
	}
}

// Enqueue hands a packet to the writer. It waits briefly when the channel is
// full and then drops the packet, so a stalled disk never blocks ingest.
func (f *Forwarder) Enqueue(pkt *Packet) {
	if pkt == nil {
		return
	}

	// Registration and the closed check share a mutex with Close. This lets
	// Close wait for in-flight calls before cancelling, so a packet can never
	// be queued after the writer's final drain.
	f.enqueueMu.Lock()
	if f.closed.Load() {
		f.enqueueMu.Unlock()
		f.countDrop()
		return
	}
	f.enqueueWG.Add(1)
	f.enqueueMu.Unlock()
	defer f.enqueueWG.Done()

	select {
	case f.in <- pkt:
		return
	default:
	}

	timer := time.NewTimer(f.cfg.EnqueueTimeout.Std())
	defer timer.Stop()
	select {
	case f.in <- pkt:
	case <-timer.C:
		f.countDrop()
		log.Printf("[FWD] queue full, dropping packet #%d", pkt.ID)
	case <-f.ctx.Done():
		f.countDrop()
	}
}

func (f *Forwarder) countDrop() {
	f.mu.Lock()
	f.dropped++
	f.mu.Unlock()
}

// Close stops the goroutines, drains the in-memory queue and closes the spool.
// Undelivered packets remain in the spool for the next start.
func (f *Forwarder) Close() error {
	f.closeOnce.Do(func() {
		f.enqueueMu.Lock()
		f.closed.Store(true)
		f.enqueueMu.Unlock()

		// Let in-flight Enqueue calls finish while the writer and sender are
		// still running. Cancelling first would let the writer drain and exit
		// while an Enqueue could still slip a packet into the channel.
		f.enqueueWG.Wait()

		f.cancel()
		f.wg.Wait()
		f.dlMu.Lock()
		if f.dlFile != nil {
			f.dlFile.Close()
			f.dlFile = nil
		}
		f.dlMu.Unlock()
		f.closeErr = f.spool.Close()
	})
	return f.closeErr
}

// Stats returns a consistent snapshot for the API and the UI.
func (f *Forwarder) Stats() ForwardStats {
	f.mu.Lock()
	st := ForwardStats{
		Enabled:      true,
		State:        f.stateLocked(),
		NodeID:       f.cfg.NodeID,
		Sent:         f.sent,
		Retries:      f.retries,
		Deadlettered: f.deadlettered,
		Dropped:      f.dropped,
		LastError:    f.lastError,
	}
	if !f.lastSuccess.IsZero() {
		t := f.lastSuccess
		st.LastSuccess = &t
	}
	if !f.lastAttempt.IsZero() {
		t := f.lastAttempt
		st.LastAttempt = &t
	}
	f.mu.Unlock()

	st.Pending = f.spool.Pending()
	st.SpoolBytes = f.spool.Size()
	st.Dropped += f.spool.Dropped()
	return st
}

// stateLocked derives the UI state from the most recent signals.
func (f *Forwarder) stateLocked() string {
	switch {
	case f.consecutiveFailures >= 3:
		if f.unauthorized {
			return "unauthorized"
		}
		return "disconnected"
	case f.consecutiveFailures > 0:
		return "degraded"
	case f.unauthorized:
		return "unauthorized"
	case f.probeDown:
		return "disconnected"
	case f.lastSuccess.IsZero() && f.lastReachable.IsZero() && f.probeOKAt.IsZero():
		return "starting"
	default:
		return "connected"
	}
}

// writeLoop moves packets from the in-memory queue into the durable spool.
func (f *Forwarder) writeLoop() {
	for {
		select {
		case pkt := <-f.in:
			f.appendPacket(pkt)
		case <-f.ctx.Done():
			// Drain whatever is already in the channel, then stop. Enqueue
			// refuses new packets once Close has set the closed flag.
			for {
				select {
				case pkt := <-f.in:
					f.appendPacket(pkt)
				default:
					return
				}
			}
		}
	}
}

func (f *Forwarder) appendPacket(pkt *Packet) {
	if _, _, err := f.spool.Append(pkt, f.cfg.NodeID); err != nil {
		f.countDrop()
		log.Printf("[FWD] spool append failed for packet #%d: %v", pkt.ID, err)
		return
	}
	select {
	case f.notify <- struct{}{}:
	default:
	}
}

// sendLoop delivers spooled packets in order, one request at a time.
func (f *Forwarder) sendLoop() {
	next := f.spool.FirstUnacked()
	backoff := f.minBackoff

	for {
		select {
		case <-f.ctx.Done():
			return
		default:
		}

		entry, ok, err := f.spool.Next(next)
		if err != nil {
			if f.ctx.Err() != nil {
				return
			}
			f.recordFailure(fmt.Sprintf("spool read: %v", err), false)
			if !f.sleep(f.minBackoff) {
				return
			}
			continue
		}
		if !ok {
			if err := f.spool.Compact(); err != nil {
				log.Printf("[FWD] spool compaction failed: %v", err)
			}
			next = f.spool.FirstUnacked()
			select {
			case <-f.ctx.Done():
				return
			case <-f.notify:
			case <-time.After(500 * time.Millisecond):
			}
			continue
		}

		// Retry this entry from memory. Calling Next again with the same
		// sequence would make the spool reset its reader and rescan the whole
		// acknowledged prefix on every attempt.
		for {
			result, retryAfter, detail := f.post(entry)
			if f.ctx.Err() != nil {
				return
			}

			if result == postAck {
				f.spool.Ack(entry.Seq)
				f.recordSuccess()
				backoff = f.minBackoff
				break
			}
			if result == postDead {
				f.writeDeadletter(entry, detail)
				f.spool.Ack(entry.Seq)
				f.recordDead(detail)
				backoff = f.minBackoff
				break
			}

			f.recordFailure(detail, result == postUnauthorized)
			if !f.sleepWithRetry(backoff, retryAfter) {
				return
			}
			backoff = f.nextBackoff(backoff)
		}

		next = entry.Seq + 1
	}
}

func (f *Forwarder) nextBackoff(d time.Duration) time.Duration {
	d *= 2
	if d > f.maxBackoff {
		return f.maxBackoff
	}
	if d < f.minBackoff {
		return f.minBackoff
	}
	return d
}

func (f *Forwarder) sleep(d time.Duration) bool {
	if d <= 0 {
		return f.ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-f.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (f *Forwarder) sleepWithRetry(backoff, retryAfter time.Duration) bool {
	d := backoff
	if retryAfter > 0 {
		d = retryAfter
		if d > maxRetryAfter {
			d = maxRetryAfter
		}
	} else {
		d = jitter(backoff)
	}
	return f.sleep(d)
}

func jitter(d time.Duration) time.Duration {
	if d <= 1 {
		return d
	}
	half := d / 2
	return half + time.Duration(rand.Int64N(int64(half)+1))
}

// post sends one packet and classifies the response.
func (f *Forwarder) post(entry *spoolEntry) (postResult, time.Duration, string) {
	body, err := json.Marshal(forwardEnvelope{
		SchemaVersion: 1,
		EventID:       entry.EventID,
		Seq:           entry.Seq,
		NodeID:        entry.NodeID,
		Packet:        entry.Packet,
	})
	if err != nil {
		return postDead, 0, fmt.Sprintf("marshal: %v", err)
	}

	ctx, cancel := context.WithTimeout(f.ctx, f.cfg.Timeout.Std())
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.cfg.URL, bytes.NewReader(body))
	if err != nil {
		// A malformed URL is a configuration problem, not a bad packet:
		// keep the entry in the spool so it is not lost.
		return postRetry, 0, fmt.Sprintf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", forwardUserAgent)
	req.Header.Set("Idempotency-Key", entry.NodeID+":"+entry.EventID)

	resp, err := f.client.Do(req)
	if err != nil {
		if f.ctx.Err() != nil {
			return postRetry, 0, "shutting down"
		}
		return postRetry, 0, err.Error()
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, responseBodyLimit))
	detail := strings.TrimSpace(string(data))
	if len(detail) > deadletterBodyLimit {
		detail = detail[:deadletterBodyLimit] + "..."
	}
	retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300, resp.StatusCode == http.StatusConflict:
		return postAck, 0, ""
	case resp.StatusCode == http.StatusBadRequest,
		resp.StatusCode == http.StatusRequestEntityTooLarge,
		resp.StatusCode == http.StatusUnprocessableEntity:
		return postDead, 0, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, detail)
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return postUnauthorized, retryAfter, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, detail)
	default:
		return postRetry, retryAfter, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, detail)
	}
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if secs, err := strconv.Atoi(value); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(value); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func (f *Forwarder) recordSuccess() {
	now := time.Now()
	f.mu.Lock()
	f.consecutiveFailures = 0
	f.unauthorized = false
	f.probeDown = false
	f.lastSuccess = now
	f.lastReachable = now
	f.lastAttempt = now
	f.lastError = ""
	f.sent++
	f.mu.Unlock()
}

func (f *Forwarder) recordDead(detail string) {
	now := time.Now()
	f.mu.Lock()
	f.consecutiveFailures = 0
	f.unauthorized = false
	f.probeDown = false
	f.lastReachable = now
	f.lastAttempt = now
	f.lastError = "dead-letter: " + detail
	f.deadlettered++
	f.mu.Unlock()
	log.Printf("[FWD] packet dead-lettered: %s", detail)
}

func (f *Forwarder) recordFailure(detail string, unauthorized bool) {
	now := time.Now()
	f.mu.Lock()
	f.consecutiveFailures++
	f.retries++
	if unauthorized {
		f.unauthorized = true
	}
	f.lastAttempt = now
	f.lastError = detail
	n := f.consecutiveFailures
	f.mu.Unlock()
	log.Printf("[FWD] delivery failed (%d consecutive): %s", n, detail)
}

func (f *Forwarder) writeDeadletter(entry *spoolEntry, reason string) {
	f.dlMu.Lock()
	defer f.dlMu.Unlock()
	if f.dlFile == nil {
		fh, err := os.OpenFile(f.spool.DeadletterPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Printf("[FWD] cannot open dead-letter file: %v", err)
			return
		}
		f.dlFile = fh
	}
	line, err := json.Marshal(map[string]any{"error": reason, "entry": entry})
	if err != nil {
		log.Printf("[FWD] dead-letter marshal failed: %v", err)
		return
	}
	line = append(line, '\n')
	if _, err := f.dlFile.Write(line); err != nil {
		log.Printf("[FWD] dead-letter write failed: %v", err)
		return
	}
	if err := f.dlFile.Sync(); err != nil {
		log.Printf("[FWD] dead-letter sync failed: %v", err)
	}
}

func (f *Forwarder) housekeepingLoop() {
	ticker := time.NewTicker(housekeepingInterval)
	defer ticker.Stop()
	var lastLog time.Time
	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			var err error
			if f.mode == fsyncPeriodic {
				err = f.spool.Sync()
			}
			if err == nil {
				err = f.spool.PersistAck()
			}
			if err != nil && time.Since(lastLog) > 30*time.Second {
				log.Printf("[FWD] spool housekeeping: %v", err)
				lastLog = time.Now()
			}
		}
	}
}

func (f *Forwarder) probeLoop() {
	f.probe()
	ticker := time.NewTicker(f.cfg.HealthInterval.Std())
	defer ticker.Stop()
	for {
		select {
		case <-f.ctx.Done():
			return
		case <-ticker.C:
			f.probe()
		}
	}
}

func (f *Forwarder) probe() {
	timeout := 5 * time.Second
	if t := f.cfg.Timeout.Std(); t > 0 && t < timeout {
		timeout = t
	}
	ctx, cancel := context.WithTimeout(f.ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.cfg.HealthURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("User-Agent", forwardUserAgent)

	resp, err := f.client.Do(req)
	now := time.Now()
	if err != nil {
		if f.ctx.Err() != nil {
			return
		}
		f.mu.Lock()
		f.probeAt = now
		f.probeDown = true
		f.mu.Unlock()
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))

	f.mu.Lock()
	f.probeAt = now
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		f.probeDown = false
		f.probeOKAt = now
		if f.consecutiveFailures == 0 {
			f.unauthorized = false
		}
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		f.probeDown = true
		if f.lastSuccess.IsZero() {
			f.unauthorized = true
		}
	default:
		f.probeDown = true
	}
	f.mu.Unlock()
}
