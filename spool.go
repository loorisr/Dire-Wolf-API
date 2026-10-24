// Durable on-disk spool for outgoing packets.
//
// Packets are appended as newline-delimited JSON to current.ndjson before they
// are sent to the backend. The last acknowledged sequence number is stored in
// the acked file, which is replaced atomically. On startup every entry after
// the acknowledged offset is replayed, so a crash at any point can only cause
// duplicates (deduplicated by the backend), never a silent gap.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

const (
	spoolFileName  = "current.ndjson"
	spoolAckName   = "acked"
	spoolLockName  = ".lock"
	deadletterName = "deadletter.ndjson"

	defaultCompactThreshold = 1 << 20 // 1 MiB
)

type fsyncMode int

const (
	fsyncAlways fsyncMode = iota
	fsyncPeriodic
	fsyncNever
)

func parseFsyncMode(s string) (fsyncMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "always":
		return fsyncAlways, nil
	case "periodic":
		return fsyncPeriodic, nil
	case "never":
		return fsyncNever, nil
	default:
		return 0, fmt.Errorf("invalid fsync mode %q (want always, periodic or never)", s)
	}
}

// spoolEntry is one line of the spool file.
type spoolEntry struct {
	Seq     int64   `json:"seq"`
	EventID string  `json:"event_id"`
	NodeID  string  `json:"node_id"`
	Packet  *Packet `json:"packet"`
}

// Spool is a crash-safe FIFO of packets waiting for delivery.
type Spool struct {
	dir      string
	maxBytes int64
	fsync    fsyncMode

	mu           sync.Mutex
	file         *os.File // append handle
	readFile     *os.File // read handle for the sender
	reader       *bufio.Reader
	readOffset   int64
	readSeq      int64
	size         int64
	lastSeq      int64
	ackedSeq     int64
	persistedAck int64
	dropped      int64
	closed       bool

	lock       *os.File
	compactMin int64
}

// OpenSpool opens (or creates) the spool directory and recovers its state.
func OpenSpool(dir string, maxBytes int64, mode fsyncMode) (*Spool, error) {
	if dir == "" {
		return nil, errors.New("spool: directory is empty")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("spool: create %s: %w", dir, err)
	}

	s := &Spool{
		dir:        dir,
		maxBytes:   maxBytes,
		fsync:      mode,
		compactMin: defaultCompactThreshold,
	}

	// One process per spool directory. A stale .lock after a hard crash must
	// be removed by the operator; silently sharing the directory would corrupt
	// the sequence.
	lock, err := os.OpenFile(filepath.Join(dir, spoolLockName), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("spool: %s is locked by another process (remove %s if it is stale)",
				dir, filepath.Join(dir, spoolLockName))
		}
		return nil, fmt.Errorf("spool: lock %s: %w", dir, err)
	}
	fmt.Fprintf(lock, "%d\n", os.Getpid())
	s.lock = lock

	f, err := os.OpenFile(s.currentPath(), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		s.releaseLock()
		return nil, fmt.Errorf("spool: open %s: %w", s.currentPath(), err)
	}
	s.file = f

	if err := s.recover(); err != nil {
		if s.readFile != nil {
			s.readFile.Close()
			s.readFile = nil
		}
		f.Close()
		s.releaseLock()
		return nil, err
	}
	return s, nil
}

func (s *Spool) currentPath() string    { return filepath.Join(s.dir, spoolFileName) }
func (s *Spool) ackPath() string        { return filepath.Join(s.dir, spoolAckName) }
func (s *Spool) DeadletterPath() string { return filepath.Join(s.dir, deadletterName) }

func (s *Spool) releaseLock() {
	if s.lock != nil {
		name := s.lock.Name()
		s.lock.Close()
		os.Remove(name)
		s.lock = nil
	}
}

// recover reads the acknowledged offset, validates the tail of the spool file
// and prepares the read cursor. It must be called before any concurrent use.
func (s *Spool) recover() error {
	acked, err := readAcked(s.ackPath())
	if err != nil {
		log.Printf("[SPOOL] ignoring unreadable ack file: %v", err)
		acked = 0
		s.persistedAck = -1
	} else {
		s.persistedAck = acked
	}
	s.ackedSeq = acked

	stat, err := s.file.Stat()
	if err != nil {
		return fmt.Errorf("spool: stat: %w", err)
	}

	readFile, err := os.Open(s.currentPath())
	if err != nil {
		return fmt.Errorf("spool: open for reading: %w", err)
	}
	defer readFile.Close()

	reader := bufio.NewReaderSize(readFile, 64*1024)
	var (
		offset       int64
		validSize    int64
		lastSeq      int64
		firstOffset  int64 = -1
		firstReadSeq int64
	)
	for {
		line, rerr := reader.ReadString('\n')
		if len(line) > 0 {
			if !strings.HasSuffix(line, "\n") {
				// Partial last line (crash during write): drop it.
				break
			}
			validSize = offset + int64(len(line))
			var e spoolEntry
			if jerr := json.Unmarshal([]byte(line[:len(line)-1]), &e); jerr != nil {
				log.Printf("[SPOOL] skipping corrupt entry at offset %d: %v", offset, jerr)
			} else {
				if e.Seq > lastSeq {
					lastSeq = e.Seq
				}
				if firstOffset < 0 && e.Seq > s.ackedSeq {
					firstOffset = offset
					firstReadSeq = e.Seq
				}
			}
			offset = validSize
		}
		if rerr != nil {
			if rerr != io.EOF {
				return fmt.Errorf("spool: scan: %w", rerr)
			}
			break
		}
	}

	if validSize < stat.Size() {
		log.Printf("[SPOOL] truncating %d partial byte(s) at the end of the spool", stat.Size()-validSize)
		if err := s.file.Truncate(validSize); err != nil {
			return fmt.Errorf("spool: truncate partial line: %w", err)
		}
	}
	s.size = validSize
	s.lastSeq = lastSeq

	if s.ackedSeq > s.lastSeq {
		if s.lastSeq == 0 && s.size == 0 {
			log.Printf("[SPOOL] spool was compacted (acked=%d), starting a new sequence", s.ackedSeq)
		} else {
			log.Printf("[SPOOL] acked sequence %d is past the end of the spool (%d), resetting",
				s.ackedSeq, s.lastSeq)
		}
		s.ackedSeq = 0
		s.persistedAck = -1 // force the reset to be persisted
	}
	if firstOffset < 0 {
		firstOffset = validSize
		firstReadSeq = s.lastSeq + 1
	}
	if err := s.resetReaderLocked(firstOffset, firstReadSeq); err != nil {
		return err
	}
	if s.persistedAck < 0 {
		if err := s.persistAckLocked(); err != nil {
			return err
		}
	}

	if pending := s.pendingLocked(); pending > 0 {
		log.Printf("[SPOOL] %d packet(s) awaiting delivery from %s", pending, s.dir)
	}
	return nil
}

func readAcked(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid ack value: %w", err)
	}
	if v < 0 {
		return 0, fmt.Errorf("negative ack value %d", v)
	}
	return v, nil
}

func (s *Spool) resetReaderLocked(offset, seq int64) error {
	if s.readFile != nil {
		s.readFile.Close()
		s.readFile = nil
	}
	f, err := os.Open(s.currentPath())
	if err != nil {
		return fmt.Errorf("spool: open reader: %w", err)
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return fmt.Errorf("spool: seek reader: %w", err)
	}
	s.readFile = f
	s.reader = bufio.NewReaderSize(f, 64*1024)
	s.readOffset = offset
	s.readSeq = seq
	return nil
}

// Append durably writes a packet and returns its sequence number and event ID.
func (s *Spool) Append(pkt *Packet, nodeID string) (int64, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, "", errors.New("spool: closed")
	}
	if s.file == nil {
		return 0, "", errors.New("spool: file is not open")
	}

	eventID, err := newEventID()
	if err != nil {
		return 0, "", fmt.Errorf("spool: generate event id: %w", err)
	}
	entry := spoolEntry{
		Seq:     s.lastSeq + 1,
		EventID: eventID,
		NodeID:  nodeID,
		Packet:  pkt,
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return 0, "", fmt.Errorf("spool: marshal: %w", err)
	}
	line = append(line, '\n')

	if s.maxBytes > 0 && int64(len(line)) > s.maxBytes {
		log.Printf("[SPOOL] warning: a single entry (%d bytes) exceeds the spool cap (%d bytes)", len(line), s.maxBytes)
	}
	if s.maxBytes > 0 && s.size+int64(len(line)) > s.maxBytes && int64(len(line)) <= s.maxBytes {
		if err := s.makeRoomLocked(int64(len(line))); err != nil {
			return 0, "", err
		}
	}

	before := s.size
	n, err := s.file.Write(line)
	if err != nil {
		if n > 0 {
			if terr := s.file.Truncate(before); terr != nil {
				log.Printf("[SPOOL] truncate after short write: %v", terr)
			}
		}
		return 0, "", fmt.Errorf("spool: write: %w", err)
	}
	s.size += int64(n)
	s.lastSeq = entry.Seq

	if s.fsync == fsyncAlways {
		if err := s.file.Sync(); err != nil {
			return 0, "", fmt.Errorf("spool: fsync: %w", err)
		}
	}
	return entry.Seq, eventID, nil
}

// FirstUnacked returns the next sequence number to try. It may point past the
// end of the file when everything has been acknowledged.
func (s *Spool) FirstUnacked() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ackedSeq + 1
}

// Next returns the first entry with seq >= seq. The entry's Seq may be greater
// than the requested value when older entries were dropped by the size cap.
func (s *Spool) Next(seq int64) (*spoolEntry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false, errors.New("spool: closed")
	}
	if s.reader == nil {
		if err := s.resetReaderLocked(0, 1); err != nil {
			return nil, false, err
		}
	}
	if seq < s.readSeq {
		if err := s.resetReaderLocked(0, 1); err != nil {
			return nil, false, err
		}
	}

	for {
		line, err := s.reader.ReadString('\n')
		if len(line) > 0 {
			if !strings.HasSuffix(line, "\n") {
				// A writer is in the middle of appending; rewind and retry later.
				if _, serr := s.readFile.Seek(s.readOffset, io.SeekStart); serr != nil {
					return nil, false, serr
				}
				s.reader.Reset(s.readFile)
				return nil, false, nil
			}
			var e spoolEntry
			if jerr := json.Unmarshal([]byte(line[:len(line)-1]), &e); jerr != nil {
				log.Printf("[SPOOL] skipping corrupt entry at offset %d: %v", s.readOffset, jerr)
				s.readOffset += int64(len(line))
				continue
			}
			s.readOffset += int64(len(line))
			s.readSeq = e.Seq + 1
			if e.Seq >= seq {
				return &e, true, nil
			}
			continue
		}
		if err == io.EOF {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
	}
}

// Ack marks seq (and everything before it) as delivered. Acks never regress.
func (s *Spool) Ack(seq int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq > s.lastSeq {
		seq = s.lastSeq
	}
	if seq > s.ackedSeq {
		s.ackedSeq = seq
	}
}

// PersistAck atomically stores the acknowledged sequence number.
func (s *Spool) PersistAck() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.persistAckLocked()
}

func (s *Spool) persistAckLocked() error {
	if s.ackedSeq == s.persistedAck {
		return nil
	}
	tmp := s.ackPath() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("spool: write ack: %w", err)
	}
	if _, err := fmt.Fprintf(f, "%d\n", s.ackedSeq); err != nil {
		f.Close()
		return fmt.Errorf("spool: write ack: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("spool: sync ack: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("spool: close ack: %w", err)
	}
	if err := os.Rename(tmp, s.ackPath()); err != nil {
		return fmt.Errorf("spool: replace ack: %w", err)
	}
	syncDir(s.dir)
	s.persistedAck = s.ackedSeq
	return nil
}

// syncDir makes a rename durable on Unix. It is a no-op elsewhere.
func syncDir(dir string) {
	if runtime.GOOS == "windows" {
		return
	}
	d, err := os.Open(dir)
	if err != nil {
		return
	}
	_ = d.Sync()
	_ = d.Close()
}

// Compact truncates the spool when every entry has been acknowledged.
func (s *Spool) Compact() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.ackedSeq != s.lastSeq || s.size == 0 || s.size < s.compactMin {
		return nil
	}
	if s.file == nil {
		return errors.New("spool: file is not open")
	}

	// Persist acked=lastSeq before truncating: a crash in between replays
	// packets (duplicates) instead of losing them.
	s.ackedSeq = s.lastSeq
	if err := s.persistAckLocked(); err != nil {
		return err
	}
	if err := s.file.Truncate(0); err != nil {
		return fmt.Errorf("spool: truncate: %w", err)
	}
	s.size = 0
	// Keep lastSeq monotonic: the sender may still hold a sequence cursor and
	// sequence numbers must never be reused within a process.
	if err := s.resetReaderLocked(0, s.lastSeq+1); err != nil {
		return err
	}
	log.Printf("[SPOOL] compacted spool %s", s.dir)
	return nil
}

// makeRoomLocked drops the oldest entries until the new line fits under the
// cap. It always drops the acknowledged prefix first, for free.
func (s *Spool) makeRoomLocked(need int64) error {
	target := s.maxBytes * 8 / 10
	if target < need {
		target = need
	}
	allowed := target - need

	reader, err := os.Open(s.currentPath())
	if err != nil {
		return fmt.Errorf("spool: open for compaction: %w", err)
	}
	defer reader.Close()

	br := bufio.NewReaderSize(reader, 64*1024)
	var (
		offset     int64
		keepOffset int64 = s.size
		remaining        = s.size
		newAcked         = s.ackedSeq
		dropped    int64
	)
	for {
		line, rerr := br.ReadString('\n')
		if len(line) > 0 && strings.HasSuffix(line, "\n") {
			if remaining <= allowed {
				keepOffset = offset
				break
			}
			var e spoolEntry
			if jerr := json.Unmarshal([]byte(line[:len(line)-1]), &e); jerr == nil {
				if e.Seq > newAcked {
					newAcked = e.Seq
					dropped++
				}
			}
			remaining -= int64(len(line))
			offset += int64(len(line))
		}
		if rerr != nil {
			break
		}
	}
	if keepOffset < 0 {
		keepOffset = 0
	}

	tmp := s.currentPath() + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("spool: create temp: %w", err)
	}
	if keepOffset < s.size {
		if _, err := reader.Seek(keepOffset, io.SeekStart); err != nil {
			out.Close()
			os.Remove(tmp)
			return fmt.Errorf("spool: seek compaction: %w", err)
		}
		if _, err := io.Copy(out, reader); err != nil {
			out.Close()
			os.Remove(tmp)
			return fmt.Errorf("spool: copy into temp: %w", err)
		}
	}
	if err := out.Sync(); err != nil {
		out.Close()
		os.Remove(tmp)
		return fmt.Errorf("spool: sync temp: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("spool: close temp: %w", err)
	}

	// Close every handle before renaming: Windows refuses to replace a file
	// that is still open.
	reader.Close()
	if s.readFile != nil {
		s.readFile.Close()
		s.readFile = nil
	}
	s.reader = nil
	if s.file != nil {
		s.file.Close()
		s.file = nil
	}

	if err := os.Rename(tmp, s.currentPath()); err != nil {
		os.Remove(tmp)
		// Best effort: reopen the original file so the spool stays usable.
		if f, oerr := os.OpenFile(s.currentPath(), os.O_RDWR|os.O_APPEND, 0o600); oerr == nil {
			s.file = f
		}
		if rerr := s.resetReaderLocked(0, 1); rerr != nil {
			log.Printf("[SPOOL] reopen reader after failed compaction: %v", rerr)
		}
		return fmt.Errorf("spool: replace spool: %w", err)
	}

	f, err := os.OpenFile(s.currentPath(), os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("spool: reopen: %w", err)
	}
	s.file = f
	s.size = remaining
	if s.size < 0 {
		s.size = 0
	}
	s.ackedSeq = newAcked
	s.dropped += dropped
	if err := s.resetReaderLocked(0, 1); err != nil {
		return err
	}
	if err := s.persistAckLocked(); err != nil {
		return err
	}
	if dropped > 0 {
		log.Printf("[SPOOL] spool full: dropped %d oldest unacknowledged packet(s)", dropped)
	} else {
		log.Printf("[SPOOL] removed acknowledged prefix")
	}
	return nil
}

// Sync flushes the spool file to disk (used in periodic mode).
func (s *Spool) Sync() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.file == nil {
		return nil
	}
	return s.file.Sync()
}

// Pending returns the number of entries not yet acknowledged.
func (s *Spool) Pending() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pendingLocked()
}

func (s *Spool) pendingLocked() int64 {
	if s.lastSeq <= s.ackedSeq {
		return 0
	}
	return s.lastSeq - s.ackedSeq
}

// Size returns the current spool file size in bytes.
func (s *Spool) Size() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.size
}

// LastSeq returns the highest sequence number written in this process.
func (s *Spool) LastSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastSeq
}

// Dropped returns the number of unacknowledged packets discarded by the size cap.
func (s *Spool) Dropped() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Close flushes state and releases the directory lock.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true

	var firstErr error
	if err := s.persistAckLocked(); err != nil && firstErr == nil {
		firstErr = err
	}
	if s.file != nil {
		if err := s.file.Sync(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := s.file.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if s.readFile != nil {
		s.readFile.Close()
		s.readFile = nil
	}
	s.releaseLock()
	return firstErr
}

// newEventID returns a random RFC 4122 version 4 UUID.
func newEventID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
