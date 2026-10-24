package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPacket(id int) *Packet {
	return &Packet{
		ID:        int64(id),
		Timestamp: time.Unix(int64(id), 0).UTC(),
		Port:      0,
		RawHex:    "8288",
		Source:    "N0CALL",
		Dest:      "APRS",
		Path:      "N0CALL>APRS",
		InfoRaw:   fmt.Sprintf("packet-%d", id),
	}
}

func openTestSpool(t *testing.T, dir string, maxBytes int64) *Spool {
	t.Helper()
	s, err := OpenSpool(dir, maxBytes, fsyncNever)
	if err != nil {
		t.Fatalf("OpenSpool: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSpoolAppendNextAck(t *testing.T) {
	s := openTestSpool(t, t.TempDir(), 1<<20)

	seq, eventID, err := s.Append(testPacket(1), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 || eventID == "" {
		t.Fatalf("seq=%d eventID=%q", seq, eventID)
	}
	if s.Pending() != 1 {
		t.Errorf("pending = %d", s.Pending())
	}

	entry, ok, err := s.Next(s.FirstUnacked())
	if err != nil || !ok {
		t.Fatalf("Next: ok=%v err=%v", ok, err)
	}
	if entry.Seq != 1 || entry.NodeID != "node-a" || entry.Packet.ID != 1 {
		t.Errorf("unexpected entry: %+v", entry)
	}
	if entry.EventID != eventID {
		t.Errorf("event ID changed: %q != %q", entry.EventID, eventID)
	}

	s.Ack(entry.Seq)
	if s.Pending() != 0 {
		t.Errorf("pending after ack = %d", s.Pending())
	}
	if got := s.FirstUnacked(); got != 2 {
		t.Errorf("FirstUnacked = %d", got)
	}
}

func TestSpoolReplayAfterReopen(t *testing.T) {
	dir := t.TempDir()
	s := openTestSpool(t, dir, 1<<20)

	for i := 1; i <= 3; i++ {
		if _, _, err := s.Append(testPacket(i), "node"); err != nil {
			t.Fatal(err)
		}
	}
	s.Ack(1)
	if err := s.PersistAck(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	s2 := openTestSpool(t, dir, 1<<20)
	if got := s2.FirstUnacked(); got != 2 {
		t.Fatalf("FirstUnacked after reopen = %d, want 2", got)
	}
	if got := s2.LastSeq(); got != 3 {
		t.Fatalf("LastSeq = %d, want 3", got)
	}
	if got := s2.Pending(); got != 2 {
		t.Fatalf("Pending = %d, want 2", got)
	}

	entry, ok, err := s2.Next(2)
	if err != nil || !ok {
		t.Fatalf("Next(2): ok=%v err=%v", ok, err)
	}
	if entry.Seq != 2 {
		t.Fatalf("replayed seq = %d", entry.Seq)
	}
	s2.Ack(3)
	if err := s2.PersistAck(); err != nil {
		t.Fatal(err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}

	s3 := openTestSpool(t, dir, 1<<20)
	if got := s3.FirstUnacked(); got != 4 {
		t.Fatalf("FirstUnacked after full ack = %d, want 4", got)
	}
	if s3.Pending() != 0 {
		t.Fatalf("Pending = %d", s3.Pending())
	}
}

func TestSpoolTruncatesPartialTail(t *testing.T) {
	dir := t.TempDir()
	s := openTestSpool(t, dir, 1<<20)
	if _, _, err := s.Append(testPacket(1), "node"); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	f, err := os.OpenFile(filepath.Join(dir, spoolFileName), os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"seq":2,"event_id":"partial`); err != nil {
		t.Fatal(err)
	}
	f.Close()

	s2 := openTestSpool(t, dir, 1<<20)
	if got := s2.LastSeq(); got != 1 {
		t.Fatalf("LastSeq = %d, want 1", got)
	}
	if _, ok, err := s2.Next(2); err != nil || ok {
		t.Fatalf("partial entry was parsed: ok=%v err=%v", ok, err)
	}

	seq, _, err := s2.Append(testPacket(2), "node")
	if err != nil {
		t.Fatal(err)
	}
	if seq != 2 {
		t.Fatalf("seq after truncation = %d, want 2", seq)
	}
	data, err := os.ReadFile(filepath.Join(dir, spoolFileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "partial") {
		t.Fatal("partial line was not removed")
	}
}

func TestSpoolLock(t *testing.T) {
	dir := t.TempDir()
	s := openTestSpool(t, dir, 1<<20)

	if _, err := OpenSpool(dir, 1<<20, fsyncNever); err == nil {
		t.Fatal("expected the second open to fail while locked")
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := OpenSpool(dir, 1<<20, fsyncNever)
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	s2.Close()
}

func TestSpoolCompactWithoutFile(t *testing.T) {
	s := openTestSpool(t, t.TempDir(), 1<<20)
	s.compactMin = 1

	if _, _, err := s.Append(testPacket(1), "node"); err != nil {
		t.Fatal(err)
	}
	s.Ack(1)

	// Simulate a failed reopen after a compaction rewrite.
	s.mu.Lock()
	s.file.Close()
	s.file = nil
	s.mu.Unlock()

	if err := s.Compact(); err == nil {
		t.Fatal("Compact should fail when the spool file is not open")
	}
}

func TestSpoolCompaction(t *testing.T) {
	s := openTestSpool(t, t.TempDir(), 1<<20)
	s.compactMin = 1

	if _, _, err := s.Append(testPacket(1), "node"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Append(testPacket(2), "node"); err != nil {
		t.Fatal(err)
	}
	s.Ack(2)
	if err := s.PersistAck(); err != nil {
		t.Fatal(err)
	}
	if err := s.Compact(); err != nil {
		t.Fatal(err)
	}
	if s.Size() != 0 {
		t.Fatalf("size after compaction = %d", s.Size())
	}
	// Sequence numbers stay monotonic within the process.
	if got := s.LastSeq(); got != 2 {
		t.Fatalf("LastSeq = %d", got)
	}
	if got := s.FirstUnacked(); got != 3 {
		t.Fatalf("FirstUnacked = %d", got)
	}

	seq, _, err := s.Append(testPacket(3), "node")
	if err != nil {
		t.Fatal(err)
	}
	if seq != 3 {
		t.Fatalf("seq after compaction = %d, want 3", seq)
	}
	entry, ok, err := s.Next(3)
	if err != nil || !ok || entry.Seq != 3 {
		t.Fatalf("Next(3): entry=%+v ok=%v err=%v", entry, ok, err)
	}
}

func TestSpoolSizeCapDropsOldest(t *testing.T) {
	dir := t.TempDir()
	const maxBytes = int64(1200)
	s := openTestSpool(t, dir, maxBytes)

	pkt := testPacket(1)
	pkt.InfoRaw = strings.Repeat("i", 300)
	pkt.RawHex = strings.Repeat("ab", 100)

	for i := 0; i < 20; i++ {
		pkt.ID = int64(i + 1)
		if _, _, err := s.Append(pkt, "node"); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
	if got := s.Size(); got > maxBytes {
		t.Fatalf("size = %d, cap = %d", got, maxBytes)
	}
	if s.Dropped() == 0 {
		t.Fatal("expected the cap to drop entries")
	}
	if s.Pending() >= 20 {
		t.Fatalf("pending = %d, expected drops", s.Pending())
	}

	entry, ok, err := s.Next(1)
	if err != nil || !ok {
		t.Fatalf("Next(1): ok=%v err=%v", ok, err)
	}
	if entry.Seq <= 1 {
		t.Fatalf("expected to skip dropped entries, got seq %d", entry.Seq)
	}
	s.Ack(entry.Seq)
	if err := s.PersistAck(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Recovery keeps the remaining entry and the advanced ack.
	s2 := openTestSpool(t, dir, maxBytes)
	if got := s2.LastSeq(); got != 20 {
		t.Fatalf("LastSeq after reopen = %d, want 20", got)
	}
	if got := s2.Pending(); got != 0 {
		t.Fatalf("Pending after reopen = %d", got)
	}
}

func TestSpoolAckedBeyondEndResets(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	line, err := json.Marshal(spoolEntry{Seq: 1, EventID: "e1", NodeID: "n", Packet: testPacket(1)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, spoolFileName), append(line, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, spoolAckName), []byte("99\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := openTestSpool(t, dir, 1<<20)
	if got := s.FirstUnacked(); got != 1 {
		t.Fatalf("FirstUnacked = %d, want 1 after reset", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, spoolAckName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "0" {
		t.Fatalf("acked file = %q, want 0", data)
	}
}
