package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type receivedRequest struct {
	idempotency string
	auth        string
	body        forwardEnvelope
	err         error
}

func testForwardConfig(t *testing.T, url string) ForwardConfig {
	t.Helper()
	return ForwardConfig{
		URL:            url,
		NodeID:         "test-node",
		Token:          "secret",
		SpoolDir:       t.TempDir(),
		SpoolMaxBytes:  1 << 20,
		Fsync:          "never",
		Timeout:        Duration(2 * time.Second),
		Queue:          16,
		EnqueueTimeout: Duration(100 * time.Millisecond),
	}
}

func startTestForwarder(t *testing.T, cfg ForwardConfig) *Forwarder {
	t.Helper()
	f, err := NewForwarder(cfg)
	if err != nil {
		t.Fatalf("NewForwarder: %v", err)
	}
	f.minBackoff = 10 * time.Millisecond
	f.maxBackoff = 50 * time.Millisecond
	f.Start(context.Background())
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestForwarderDeliversEnvelope(t *testing.T) {
	var mu sync.Mutex
	var got []receivedRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env forwardEnvelope
		err := json.NewDecoder(r.Body).Decode(&env)
		mu.Lock()
		got = append(got, receivedRequest{
			idempotency: r.Header.Get("Idempotency-Key"),
			auth:        r.Header.Get("Authorization"),
			body:        env,
			err:         err,
		})
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)

	f := startTestForwarder(t, testForwardConfig(t, srv.URL))
	pkt := testPacket(1)
	f.Enqueue(pkt)

	waitFor(t, 2*time.Second, "delivery", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(got) == 1
	})

	mu.Lock()
	req := got[0]
	mu.Unlock()

	if req.err != nil {
		t.Fatalf("decode request: %v", req.err)
	}
	if req.auth != "Bearer secret" {
		t.Errorf("Authorization = %q", req.auth)
	}
	if req.body.SchemaVersion != 1 || req.body.NodeID != "test-node" {
		t.Errorf("envelope = %+v", req.body)
	}
	if req.body.Packet == nil || req.body.Packet.ID != 1 {
		t.Errorf("packet = %+v", req.body.Packet)
	}
	if req.idempotency != "test-node:"+req.body.EventID {
		t.Errorf("Idempotency-Key = %q, event ID = %q", req.idempotency, req.body.EventID)
	}

	waitFor(t, 2*time.Second, "ack", func() bool {
		st := f.Stats()
		return st.Pending == 0 && st.Sent == 1
	})
	if st := f.Stats(); st.Sent != 1 || st.Dropped != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestForwarderRetriesWithSameEventID(t *testing.T) {
	var mu sync.Mutex
	var keys []string
	var calls int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env forwardEnvelope
		_ = json.NewDecoder(r.Body).Decode(&env)
		n := atomic.AddInt32(&calls, 1)
		mu.Lock()
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		mu.Unlock()
		if n == 1 {
			http.Error(w, "temporary failure", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	f := startTestForwarder(t, testForwardConfig(t, srv.URL))
	f.Enqueue(testPacket(1))

	waitFor(t, 2*time.Second, "two attempts", func() bool { return atomic.LoadInt32(&calls) >= 2 })
	waitFor(t, 2*time.Second, "ack", func() bool { return f.Stats().Pending == 0 })

	mu.Lock()
	defer mu.Unlock()
	if len(keys) < 2 {
		t.Fatalf("got %d attempts", len(keys))
	}
	if keys[0] != keys[1] {
		t.Fatalf("event ID changed between retries: %q != %q", keys[0], keys[1])
	}
}

func TestForwarderDeadLettersPermanentError(t *testing.T) {
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			http.Error(w, "bad packet", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	f := startTestForwarder(t, testForwardConfig(t, srv.URL))
	f.Enqueue(testPacket(1))
	f.Enqueue(testPacket(2))

	waitFor(t, 2*time.Second, "dead letter and delivery", func() bool {
		st := f.Stats()
		return st.Deadlettered == 1 && st.Sent == 1
	})
	if got := f.Stats().Pending; got != 0 {
		t.Errorf("pending = %d", got)
	}

	data, err := os.ReadFile(f.spool.DeadletterPath())
	if err != nil {
		t.Fatalf("read dead letter: %v", err)
	}
	if !strings.Contains(string(data), "HTTP 400") {
		t.Errorf("dead letter content = %s", data)
	}
}

func TestForwarderUnauthorizedIsNotDropped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	t.Cleanup(srv.Close)

	f := startTestForwarder(t, testForwardConfig(t, srv.URL))
	f.Enqueue(testPacket(1))

	waitFor(t, 2*time.Second, "unauthorized state", func() bool {
		st := f.Stats()
		return st.Retries >= 1 && st.State == "unauthorized"
	})
	st := f.Stats()
	if st.Pending != 1 {
		t.Errorf("pending = %d, want 1 (packet kept in the spool)", st.Pending)
	}
	if st.Sent != 0 || st.Deadlettered != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestForwarderHealthStates(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)

	mux := http.NewServeMux()
	mux.HandleFunc("/packets", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if healthy.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	cfg := testForwardConfig(t, srv.URL+"/packets")
	cfg.HealthURL = srv.URL + "/health"
	cfg.HealthInterval = Duration(20 * time.Millisecond)
	f := startTestForwarder(t, cfg)

	waitFor(t, 2*time.Second, "connected", func() bool { return f.Stats().State == "connected" })

	healthy.Store(false)
	waitFor(t, 2*time.Second, "disconnected", func() bool { return f.Stats().State == "disconnected" })

	healthy.Store(true)
	waitFor(t, 2*time.Second, "connected again", func() bool { return f.Stats().State == "connected" })
}

func TestForwarderReplaysSpoolAfterRestart(t *testing.T) {
	dir := t.TempDir()

	var firstKey atomic.Value
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env forwardEnvelope
		_ = json.NewDecoder(r.Body).Decode(&env)
		firstKey.Store(env.EventID)
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(failing.Close)

	cfg1 := testForwardConfig(t, failing.URL)
	cfg1.SpoolDir = dir
	f1, err := NewForwarder(cfg1)
	if err != nil {
		t.Fatal(err)
	}
	f1.minBackoff = 10 * time.Millisecond
	f1.Start(context.Background())
	f1.Enqueue(testPacket(1))
	waitFor(t, 2*time.Second, "first attempt", func() bool { return firstKey.Load() != nil })
	if err := f1.Close(); err != nil {
		t.Fatal(err)
	}

	var secondKey atomic.Value
	working := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var env forwardEnvelope
		_ = json.NewDecoder(r.Body).Decode(&env)
		secondKey.Store(env.EventID)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(working.Close)

	cfg2 := testForwardConfig(t, working.URL)
	cfg2.SpoolDir = dir
	f2, err := NewForwarder(cfg2)
	if err != nil {
		t.Fatal(err)
	}
	f2.minBackoff = 10 * time.Millisecond
	f2.Start(context.Background())
	t.Cleanup(func() { _ = f2.Close() })

	waitFor(t, 2*time.Second, "replay", func() bool { return secondKey.Load() != nil })
	waitFor(t, 2*time.Second, "replay ack", func() bool { return f2.Stats().Pending == 0 })

	if firstKey.Load() != secondKey.Load() {
		t.Fatalf("replayed event ID changed: %v != %v", firstKey.Load(), secondKey.Load())
	}
}

func TestForwarderDropsAfterClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	f := startTestForwarder(t, testForwardConfig(t, srv.URL))
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	f.Enqueue(testPacket(1))
	if got := f.Stats().Dropped; got != 1 {
		t.Fatalf("dropped = %d, want 1", got)
	}
}

func TestBackendExamplePayloadMatchesTypes(t *testing.T) {
	data, err := os.ReadFile("backend-example-payload.json")
	if err != nil {
		t.Fatal(err)
	}
	var env forwardEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("example payload does not match the forwarded types: %v", err)
	}
	if env.SchemaVersion != 1 || env.EventID == "" || env.Seq != 42 || env.NodeID != "fr-paris-1" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
	if env.Packet == nil || env.Packet.Source != "N0CALL" || env.Packet.InfoRaw == "" {
		t.Fatalf("unexpected packet: %+v", env.Packet)
	}
	if env.Packet.APRS == nil || env.Packet.APRS.Type != TypePosition || env.Packet.APRS.Position == nil {
		t.Fatalf("unexpected APRS data: %+v", env.Packet.APRS)
	}
	if env.Packet.APRS.Position.Lat == 0 || env.Packet.APRS.Position.Lon == 0 {
		t.Fatalf("example position was not parsed: %+v", env.Packet.APRS.Position)
	}
}

func TestForwarderRetriesInMemory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("removing an open spool file is not supported on Windows")
	}

	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	cfg := testForwardConfig(t, srv.URL)
	f, err := NewForwarder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.minBackoff = 200 * time.Millisecond
	f.maxBackoff = 200 * time.Millisecond
	f.Start(context.Background())
	t.Cleanup(func() { _ = f.Close() })

	f.Enqueue(testPacket(1))
	waitFor(t, 2*time.Second, "first attempt", func() bool { return atomic.LoadInt32(&calls) >= 1 })

	// Remove the spool file: a sender that re-reads the spool on retries would
	// fail to reopen it, while an in-memory retry keeps delivering.
	if err := os.Remove(filepath.Join(cfg.SpoolDir, spoolFileName)); err != nil {
		t.Fatal(err)
	}
	before := atomic.LoadInt32(&calls)
	waitFor(t, 2*time.Second, "retry from memory", func() bool {
		return atomic.LoadInt32(&calls) >= before+1
	})
}

func TestForwarderCloseDrainsQueue(t *testing.T) {
	// The handler blocks until the request is cancelled, so the sender can
	// never acknowledge a packet and everything must stay in the spool.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	cfg := testForwardConfig(t, srv.URL)
	cfg.Queue = 256
	f, err := NewForwarder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.minBackoff = 10 * time.Millisecond
	f.Start(context.Background())
	t.Cleanup(func() { _ = f.Close() })

	const n = 64
	for i := 1; i <= n; i++ {
		f.Enqueue(testPacket(i))
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := OpenSpool(cfg.SpoolDir, cfg.SpoolMaxBytes, fsyncNever)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := s.Pending(); got != n {
		t.Fatalf("pending after close = %d, want %d", got, n)
	}
}

func TestParseRetryAfter(t *testing.T) {
	if got := parseRetryAfter("2"); got != 2*time.Second {
		t.Errorf("seconds: %s", got)
	}
	if got := parseRetryAfter(""); got != 0 {
		t.Errorf("empty: %s", got)
	}
	if got := parseRetryAfter("not-a-date"); got != 0 {
		t.Errorf("invalid: %s", got)
	}
	date := time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)
	if got := parseRetryAfter(date); got <= 0 || got > 4*time.Second {
		t.Errorf("date: %s", got)
	}
}
