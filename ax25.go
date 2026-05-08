// AX.25 frame decoder. AX.25 (Amateur X.25) is the data link layer protocol
// used in amateur radio packet networks. This package decodes raw frame bytes
// into structured Address and Frame types.
package main

import (
	"fmt"
	"strings"
)

// Address represents a 7-byte AX.25 address field (6-char callsign + SSID + flags).
type Address struct {
	Callsign string // up to 6 uppercase alphanumeric characters
	SSID     int    // secondary station identifier (0-15)
	HBIT     bool   // has-been-repeated flag (set by digipeaters after forwarding)
}

// String returns the human-readable address: "CALLSIGN" or "CALLSIGN-N".
func (a Address) String() string {
	if a.SSID == 0 {
		return a.Callsign
	}
	return fmt.Sprintf("%s-%d", a.Callsign, a.SSID)
}

// AX25Frame is a fully decoded AX.25 link-layer frame.
type AX25Frame struct {
	Destination Address   // destination address
	Source      Address   // source address
	Repeaters   []Address // digipeater path (may be empty)
	Control     byte      // control field byte
	PID         byte      // protocol identifier (0xF0 = no layer 3 / APRS)
	Info        []byte    // information field payload
	Type        string    // frame type: "I", "S", "UI", or "U"
}

// Via returns the digipeater path as a comma-separated string.
// Repeaters that have already forwarded the frame are marked with "*".
func (f *AX25Frame) Via() string {
	parts := make([]string, len(f.Repeaters))
	for i, r := range f.Repeaters {
		s := r.String()
		if r.HBIT {
			s += "*"
		}
		parts[i] = s
	}
	return strings.Join(parts, ",")
}

// Path returns the TNC2-style path string "SRC>DST[,REPEATER1*,REPEATER2,...]".
func (f *AX25Frame) Path() string {
	s := fmt.Sprintf("%s>%s", f.Source, f.Destination)
	if via := f.Via(); via != "" {
		s += "," + via
	}
	return s
}

// decodeAddr decodes a 7-byte AX.25 address field. The first 6 bytes hold
// an ASCII character left-shifted by 1. The 7th byte holds the SSID in bits
// 4-1 and the H-bit (has-been-repeated) in bit 7.
func decodeAddr(b []byte) Address {
	cs := make([]byte, 6)
	for i := 0; i < 6; i++ {
		cs[i] = b[i] >> 1
	}
	ssid := int((b[6] >> 1) & 0x0F)
	hbit := (b[6] & 0x80) != 0
	return Address{
		Callsign: strings.TrimRight(string(cs), " "),
		SSID:     ssid,
		HBIT:     hbit,
	}
}

// DecodeAX25 decodes a raw AX.25 frame from bytes. It returns an error if the
// frame is too short (<15 bytes) or truncated after address fields.
func DecodeAX25(data []byte) (*AX25Frame, error) {
	if len(data) < 15 {
		return nil, fmt.Errorf("frame too short: %d bytes", len(data))
	}

	f := &AX25Frame{}
	// First 14 bytes: destination (0-6) and source (7-13).
	f.Destination = decodeAddr(data[0:7])
	f.Source = decodeAddr(data[7:14])

	// Iterate repeater addresses until the "end of address" flag is found
	// (bit 0 of the 7th byte set to 1).
	offset := 14
	for (data[offset-1]&0x01) == 0 {
		if offset+7 > len(data) {
			break
		}
		rep := decodeAddr(data[offset : offset+7])
		f.Repeaters = append(f.Repeaters, rep)
		offset += 7
	}

	if offset >= len(data) {
		return nil, fmt.Errorf("frame truncated after address fields")
	}

	// Parse control field and classify frame type.
	ctrl := data[offset]
	f.Control = ctrl
	offset++

	switch {
	case ctrl == 0x03 || ctrl == 0x13:
		f.Type = "UI" // unnumbered information (P/F=0 or 1)
	case ctrl&0x01 == 0:
		f.Type = "I" // information
	case ctrl&0x03 == 0x01:
		f.Type = "S" // supervisory
	default:
		f.Type = "U" // other unnumbered
	}

	// I and UI frames carry a PID byte followed by an information field.
	if (f.Type == "I" || f.Type == "UI") && offset < len(data) {
		f.PID = data[offset]
		offset++
	}

	if offset < len(data) {
		f.Info = data[offset:]
	}

	return f, nil
}
