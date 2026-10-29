// KISS source parsing. The -kiss flag accepts a TCP address, a serial port
// (including Windows Bluetooth COM ports) or a native Linux RFCOMM address.
package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// KISSSourceKind identifies the transport used to reach a KISS TNC.
type KISSSourceKind int

const (
	SourceTCP KISSSourceKind = iota
	SourceSerial
	SourceRFCOMM
)

// KISSSource is a parsed KISS source specification.
type KISSSource struct {
	Kind    KISSSourceKind
	Addr    string // TCP host:port
	Device  string // serial device, e.g. COM5 or /dev/rfcomm0
	Baud    int    // serial bitrate
	BDAddr  string // Bluetooth address for RFCOMM
	Channel uint8  // RFCOMM channel; 0 = discover via SDP
	Auto    bool   // RFCOMM: select the only paired device exposing SPP
}

// defaultSerialBaud matches the VR-N76 documentation. The radio itself
// auto-adjusts, but other serial TNCs need a sensible default.
const defaultSerialBaud = 19200

// String returns a normalized description used in logs and /api/status.
func (s KISSSource) String() string {
	switch s.Kind {
	case SourceTCP:
		return s.Addr
	case SourceSerial:
		return fmt.Sprintf("serial:%s?baud=%d", s.Device, s.Baud)
	case SourceRFCOMM:
		channel := "auto"
		if s.Channel != 0 {
			channel = strconv.Itoa(int(s.Channel))
		}
		if s.Auto {
			return fmt.Sprintf("rfcomm://auto?channel=%s", channel)
		}
		return fmt.Sprintf("rfcomm://%s?channel=%s", s.BDAddr, channel)
	default:
		return ""
	}
}

// parseKISSSource parses a -kiss value.
//
// Accepted forms:
//
//	localhost:8001                          TCP (backward compatible)
//	tcp://localhost:8001                    TCP
//	serial:COM5                             serial, 19200 baud (Windows)
//	serial:/dev/rfcomm0                     serial, 19200 baud (Linux)
//	serial:COM5?baud=9600                   serial with an explicit bitrate
//	rfcomm://AA:BB:CC:DD:EE:FF?channel=1    native RFCOMM (Linux only)
//	rfcomm://auto?channel=auto              pick the only paired SPP device (Linux)
func parseKISSSource(raw string) (KISSSource, error) {
	spec := strings.TrimSpace(raw)
	if spec == "" {
		return KISSSource{}, errors.New("kiss source must not be empty")
	}

	lower := strings.ToLower(spec)
	switch {
	case strings.HasPrefix(lower, "tcp://"):
		return parseTCPSource(spec[len("tcp://"):])
	case strings.HasPrefix(lower, "serial:"):
		return parseSerialSource(spec[len("serial:"):])
	case strings.HasPrefix(lower, "rfcomm://"):
		return parseRFCOMMSource(spec[len("rfcomm://"):])
	case strings.Contains(spec, "://"):
		return KISSSource{}, fmt.Errorf("kiss source %q uses an unsupported transport (use tcp://, serial: or rfcomm://)", spec)
	default:
		return parseTCPSource(spec)
	}
}

func parseTCPSource(addr string) (KISSSource, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return KISSSource{}, errors.New("kiss TCP address must not be empty")
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return KISSSource{}, fmt.Errorf("kiss TCP address %q is invalid: %w", addr, err)
	}
	return KISSSource{Kind: SourceTCP, Addr: addr}, nil
}

func parseSerialSource(rest string) (KISSSource, error) {
	// Accept serial:/dev/rfcomm0, serial:///dev/rfcomm0 and serial://COM5.
	rest = strings.TrimPrefix(rest, "//")
	devicePart, query, _ := strings.Cut(rest, "?")
	device := strings.TrimSpace(devicePart)
	if device == "" {
		return KISSSource{}, errors.New("kiss serial device must not be empty")
	}

	baud, err := parseSerialBaud(query)
	if err != nil {
		return KISSSource{}, err
	}
	return KISSSource{Kind: SourceSerial, Device: device, Baud: baud}, nil
}

func parseSerialBaud(query string) (int, error) {
	baud := defaultSerialBaud
	if query == "" {
		return baud, nil
	}

	values, err := url.ParseQuery(query)
	if err != nil {
		return 0, fmt.Errorf("kiss serial options are invalid: %w", err)
	}
	for key := range values {
		if key != "baud" {
			return 0, fmt.Errorf("kiss serial option %q is not supported", key)
		}
	}
	if raw := values.Get("baud"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("kiss serial baud rate %q is invalid", raw)
		}
		baud = n
	}
	return baud, nil
}

func parseRFCOMMSource(rest string) (KISSSource, error) {
	if !rfcommSupported() {
		return KISSSource{}, errors.New("kiss native RFCOMM is only supported on Linux; " +
			"on Windows create an outgoing Bluetooth COM port and use serial:COMx")
	}

	hostPart, query, _ := strings.Cut(rest, "?")
	hostPart = strings.TrimSuffix(hostPart, "/")

	mac := hostPart
	channel := uint8(0) // 0 = auto (discover via SDP)
	channelSet := false

	// Also accept rfcomm://MAC/1 or rfcomm://MAC/auto.
	if i := strings.LastIndexByte(hostPart, '/'); i >= 0 {
		mac = hostPart[:i]
		raw := hostPart[i+1:]
		if strings.EqualFold(raw, "auto") {
			channel = 0
		} else {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 30 {
				return KISSSource{}, fmt.Errorf("kiss RFCOMM channel %q is invalid (expected 1-30 or auto)", raw)
			}
			channel = uint8(n)
		}
		channelSet = true
	}

	if query != "" {
		values, err := url.ParseQuery(query)
		if err != nil {
			return KISSSource{}, fmt.Errorf("kiss RFCOMM options are invalid: %w", err)
		}
		for key := range values {
			if key != "channel" {
				return KISSSource{}, fmt.Errorf("kiss RFCOMM option %q is not supported", key)
			}
		}
		if raw := values.Get("channel"); raw != "" {
			var n uint8
			if strings.EqualFold(raw, "auto") {
				n = 0
			} else {
				parsed, err := strconv.Atoi(raw)
				if err != nil || parsed < 1 || parsed > 30 {
					return KISSSource{}, fmt.Errorf("kiss RFCOMM channel %q is invalid (expected 1-30 or auto)", raw)
				}
				n = uint8(parsed)
			}
			if channelSet && n != channel {
				return KISSSource{}, errors.New("kiss RFCOMM channel is specified twice")
			}
			channel = n
			channelSet = true
		}
	}

	if strings.EqualFold(mac, "auto") {
		return KISSSource{Kind: SourceRFCOMM, Auto: true, Channel: channel}, nil
	}

	hw, err := net.ParseMAC(mac)
	if err != nil {
		return KISSSource{}, fmt.Errorf("kiss Bluetooth address %q is invalid: %w", mac, err)
	}
	if len(hw) != 6 {
		return KISSSource{}, fmt.Errorf("kiss Bluetooth address %q must have 6 bytes", mac)
	}

	return KISSSource{Kind: SourceRFCOMM, BDAddr: hw.String(), Channel: channel}, nil
}
