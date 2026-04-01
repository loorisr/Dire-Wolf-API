// Package ax25 decodes AX.25 frames from raw bytes.
package ax25

import (
	"fmt"
	"strings"
)

// Address represents a 7-byte AX.25 address (6-char callsign + SSID).
type Address struct {
	Callsign string
	SSID     int
	// HBIT is the "has-been-repeated" bit (set by a digipeater after forwarding).
	HBIT bool
}

func (a Address) String() string {
	if a.SSID == 0 {
		return a.Callsign
	}
	return fmt.Sprintf("%s-%d", a.Callsign, a.SSID)
}

// Frame is a decoded AX.25 frame.
type Frame struct {
	Destination Address
	Source      Address
	Repeaters   []Address
	Control     byte
	PID         byte
	Info        []byte
	// Type is one of "I", "S", "UI", "U".
	Type string
}

// Via returns the repeater path as a comma-separated string.
// An asterisk (*) is appended to a repeater that has already forwarded the frame.
func (f *Frame) Via() string {
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

// Path returns the APRS-style path string "SRC>DST[,via]".
func (f *Frame) Path() string {
	s := fmt.Sprintf("%s>%s", f.Source, f.Destination)
	if via := f.Via(); via != "" {
		s += "," + via
	}
	return s
}

// decodeAddr decodes a 7-byte AX.25 address field.
// Each of the first 6 bytes holds an ASCII character left-shifted by 1.
// The 7th byte holds the SSID (bits 4-1) and flags.
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

// Decode decodes an AX.25 frame from raw bytes.
func Decode(data []byte) (*Frame, error) {
	// Minimum: 2 addresses (14 bytes) + control (1) + PID (1) = 16 bytes
	if len(data) < 15 {
		return nil, fmt.Errorf("frame too short: %d bytes", len(data))
	}

	f := &Frame{}
	f.Destination = decodeAddr(data[0:7])
	f.Source = decodeAddr(data[7:14])

	// Bit 0 of the 7th byte of each address is the "end of address" flag.
	// A 0 means "more addresses follow".
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

	ctrl := data[offset]
	f.Control = ctrl
	offset++

	// Classify the frame by the control field bits.
	switch {
	case ctrl == 0x03 || ctrl == 0x13:
		// UI frame: unnumbered, control = 0x03 (P/F=0) or 0x13 (P/F=1)
		f.Type = "UI"
	case ctrl&0x01 == 0:
		f.Type = "I"
	case ctrl&0x03 == 0x01:
		f.Type = "S"
	default:
		f.Type = "U"
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
