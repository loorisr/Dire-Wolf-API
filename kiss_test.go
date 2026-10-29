package main

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestParseKISSSourceTCP(t *testing.T) {
	tests := []string{
		"localhost:8001",
		"tcp://localhost:8001",
		":8001",
		"tcp://[::1]:8001",
	}
	for _, spec := range tests {
		src, err := parseKISSSource(spec)
		if err != nil {
			t.Fatalf("parseKISSSource(%q): %v", spec, err)
		}
		if src.Kind != SourceTCP {
			t.Fatalf("parseKISSSource(%q).Kind = %v, want SourceTCP", spec, src.Kind)
		}
		if src.Addr == "" {
			t.Fatalf("parseKISSSource(%q).Addr is empty", spec)
		}
	}
}

func TestParseKISSSourceSerial(t *testing.T) {
	tests := []struct {
		spec   string
		device string
		baud   int
	}{
		{"serial:COM5", "COM5", defaultSerialBaud},
		{"serial://COM7?baud=38400", "COM7", 38400},
		{"serial:/dev/rfcomm0", "/dev/rfcomm0", defaultSerialBaud},
		{"serial:///dev/rfcomm0?baud=9600", "/dev/rfcomm0", 9600},
	}
	for _, tt := range tests {
		src, err := parseKISSSource(tt.spec)
		if err != nil {
			t.Fatalf("parseKISSSource(%q): %v", tt.spec, err)
		}
		if src.Kind != SourceSerial {
			t.Errorf("parseKISSSource(%q).Kind = %v, want SourceSerial", tt.spec, src.Kind)
		}
		if src.Device != tt.device {
			t.Errorf("parseKISSSource(%q).Device = %q, want %q", tt.spec, src.Device, tt.device)
		}
		if src.Baud != tt.baud {
			t.Errorf("parseKISSSource(%q).Baud = %d, want %d", tt.spec, src.Baud, tt.baud)
		}
	}
}

func TestParseKISSSourceRFCOMM(t *testing.T) {
	if !rfcommSupported() {
		t.Skip("native RFCOMM is only available on Linux")
	}

	tests := []struct {
		spec    string
		mac     string
		channel uint8
		auto    bool
	}{
		{"rfcomm://38:D2:00:AA:BB:CC", "38:d2:00:aa:bb:cc", 0, false},
		{"rfcomm://38:D2:00:AA:BB:CC?channel=5", "38:d2:00:aa:bb:cc", 5, false},
		{"rfcomm://38:D2:00:AA:BB:CC?channel=auto", "38:d2:00:aa:bb:cc", 0, false},
		{"rfcomm://38-D2-00-AA-BB-CC/7", "38:d2:00:aa:bb:cc", 7, false},
		{"rfcomm://auto", "", 0, true},
		{"rfcomm://AUTO?channel=3", "", 3, true},
		{"rfcomm://auto?channel=auto", "", 0, true},
		{"rfcomm://auto/2", "", 2, true},
	}
	for _, tt := range tests {
		src, err := parseKISSSource(tt.spec)
		if err != nil {
			t.Fatalf("parseKISSSource(%q): %v", tt.spec, err)
		}
		if src.Kind != SourceRFCOMM {
			t.Errorf("parseKISSSource(%q).Kind = %v, want SourceRFCOMM", tt.spec, src.Kind)
		}
		if src.Auto != tt.auto {
			t.Errorf("parseKISSSource(%q).Auto = %v, want %v", tt.spec, src.Auto, tt.auto)
		}
		if src.BDAddr != tt.mac {
			t.Errorf("parseKISSSource(%q).BDAddr = %q, want %q", tt.spec, src.BDAddr, tt.mac)
		}
		if src.Channel != tt.channel {
			t.Errorf("parseKISSSource(%q).Channel = %d, want %d", tt.spec, src.Channel, tt.channel)
		}
	}
}

func TestParseKISSSourceInvalid(t *testing.T) {
	tests := []string{
		"",
		"localhost",
		"udp://localhost:8001",
		"tcp://",
		"serial:",
		"serial:COM5?baud=0",
		"serial:COM5?baud=abc",
		"serial:COM5?foo=1",
	}
	if rfcommSupported() {
		tests = append(tests,
			"rfcomm://not-a-mac",
			"rfcomm://38:D2:00:AA:BB:CC?channel=0",
			"rfcomm://38:D2:00:AA:BB:CC?channel=31",
			"rfcomm://38:D2:00:AA:BB:CC/abc",
			"rfcomm://38:D2:00:AA:BB:CC?foo=1",
		)
	}
	for _, spec := range tests {
		if _, err := parseKISSSource(spec); err == nil {
			t.Errorf("parseKISSSource(%q) succeeded, want an error", spec)
		}
	}
}

func TestReadKISSFrames(t *testing.T) {
	client := testClient(t)
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.read(ctx, pr)

	// Include every special byte to exercise escaping and pass-through.
	payload := []byte{fend, fesc, tfend, tfesc, 0x82, 0xA0}
	wire := []byte{fend, 0x00}
	for _, b := range payload {
		switch b {
		case fend:
			wire = append(wire, fesc, tfend)
		case fesc:
			wire = append(wire, fesc, tfesc)
		default:
			wire = append(wire, b)
		}
	}
	wire = append(wire, fend)

	if _, err := pw.Write(wire); err != nil {
		t.Fatalf("write: %v", err)
	}

	frame := nextFrame(t, client.Frames())
	if frame.Port != 0 {
		t.Errorf("Port = %d, want 0", frame.Port)
	}
	if !bytes.Equal(frame.Data, payload) {
		t.Errorf("Data = %x, want %x", frame.Data, payload)
	}
}

func TestReadKISSIgnoresNonDataFrames(t *testing.T) {
	client := testClient(t)
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.read(ctx, pr)

	// 0x03 is a management frame and must be ignored; 0x10 is a data frame on
	// port 1.
	wire := []byte{fend, 0x03, 0x01, fend, fend, 0x10, 0xAA, fend}
	if _, err := pw.Write(wire); err != nil {
		t.Fatalf("write: %v", err)
	}

	frame := nextFrame(t, client.Frames())
	if frame.Port != 1 {
		t.Errorf("Port = %d, want 1", frame.Port)
	}
	if !bytes.Equal(frame.Data, []byte{0xAA}) {
		t.Errorf("Data = %x, want aa", frame.Data)
	}

	select {
	case extra := <-client.Frames():
		t.Errorf("unexpected extra frame: %+v", extra)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestReadKISSSplitAndMultipleFrames(t *testing.T) {
	client := testClient(t)
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.read(ctx, pr)

	// A frame split across two writes, then a complete second frame.
	if _, err := pw.Write([]byte{fend, 0x00, 0x41}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := pw.Write([]byte{0x42, fend, fend, 0x00, 0x43, fend}); err != nil {
		t.Fatalf("write: %v", err)
	}

	first := nextFrame(t, client.Frames())
	if !bytes.Equal(first.Data, []byte{0x41, 0x42}) {
		t.Errorf("first Data = %x, want 4142", first.Data)
	}
	second := nextFrame(t, client.Frames())
	if !bytes.Equal(second.Data, []byte{0x43}) {
		t.Errorf("second Data = %x, want 43", second.Data)
	}
}

func testClient(t *testing.T) *Client {
	t.Helper()
	client, err := NewClient("tcp://localhost:1")
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

func nextFrame(t *testing.T, frames <-chan KISSFrame) KISSFrame {
	t.Helper()
	select {
	case frame := <-frames:
		return frame
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for a KISS frame")
		return KISSFrame{}
	}
}
