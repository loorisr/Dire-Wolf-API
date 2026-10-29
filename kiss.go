// KISS client that reads from a TCP, serial or Bluetooth RFCOMM source and
// reconnects automatically with exponential backoff.
//
// KISS (Keep It Simple, Stupid) is the protocol Dire Wolf and many hardware
// TNCs use to exchange AX.25 frames. Dire Wolf exposes it over TCP (default
// port 8001); hardware TNCs expose it over a serial port (USB or Windows
// Bluetooth SPP) or a native Bluetooth RFCOMM channel.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"go.bug.st/serial"
)

// KISS escape bytes.
const (
	fend  = 0xC0 // Frame End
	fesc  = 0xDB // Frame Escape
	tfend = 0xDC // Transposed FEND (escaped FEND)
	tfesc = 0xDD // Transposed FESC (escaped FESC)
)

const (
	// Maximum exponential backoff ceiling for reconnection attempts.
	maxBackoff = 32 * time.Second
	// Timeout for TCP and RFCOMM connection attempts.
	dialTimeout = 10 * time.Second
	// Read timeout used to notice context cancellation. Serial ports return
	// (0, nil) after this delay; TCP and RFCOMM use a read deadline.
	readPollInterval = 5 * time.Second
)

// KISSFrame holds a decoded KISS data frame with its source TNC port.
type KISSFrame struct {
	Port byte   // TNC logical port (0-15), extracted from the command byte
	Data []byte // Raw AX.25 frame payload (command byte already stripped)
}

// KISSState tracks the connection lifecycle.
type KISSState int

const (
	StateDisconnected KISSState = iota
	StateConnecting
	StateConnected
)

// kissConn is the subset of io.ReadCloser the KISS reader needs.
type kissConn interface {
	io.ReadCloser
}

// readDeadliner is implemented by net.Conn and *os.File.
type readDeadliner interface {
	SetReadDeadline(time.Time) error
}

// Client maintains a connection to a KISS source, reconnecting automatically
// on failure with exponential backoff.
type Client struct {
	source KISSSource
	addr   string

	mu    sync.RWMutex
	state KISSState

	frames chan KISSFrame // buffered output channel (capacity 256)
}

// NewClient parses spec and creates a KISS client for it.
func NewClient(spec string) (*Client, error) {
	source, err := parseKISSSource(spec)
	if err != nil {
		return nil, err
	}
	return &Client{
		source: source,
		addr:   source.String(),
		state:  StateDisconnected,
		frames: make(chan KISSFrame, 256),
	}, nil
}

// Start launches the reconnection loop in a background goroutine.
func (c *Client) Start(ctx context.Context) {
	go c.loop(ctx)
}

// Frames returns a read-only channel of decoded KISS frames.
// The channel is buffered (capacity 256); when full, new frames are dropped.
func (c *Client) Frames() <-chan KISSFrame {
	return c.frames
}

// State returns the current connection state.
func (c *Client) State() KISSState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// Addr returns the normalized KISS source description.
func (c *Client) Addr() string {
	return c.addr
}

func (c *Client) setState(s KISSState) {
	c.mu.Lock()
	c.state = s
	c.mu.Unlock()
}

// loop runs the connect/reconnect cycle with exponential backoff.
// Retry backoff starts at 1 s and doubles each attempt up to maxBackoff.
// On successful connection the backoff resets to 1 s.
func (c *Client) loop(ctx context.Context) {
	backoff := time.Second
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		c.setState(StateConnecting)
		log.Printf("[KISS] Connecting to %s ...", c.addr)

		conn, err := c.dial(ctx)
		if err != nil {
			log.Printf("[KISS] Connection failed: %v – retry in %s", err, backoff)
			c.setState(StateDisconnected)
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			if backoff < maxBackoff {
				backoff *= 2
			}
			continue
		}

		// Reset backoff on successful connection.
		backoff = time.Second
		c.setState(StateConnected)
		log.Printf("[KISS] Connected to %s", c.addr)

		// Close the connection when the context is cancelled so a blocking
		// read cannot keep the shutdown waiting.
		readDone := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				conn.Close()
			case <-readDone:
			}
		}()

		// read blocks until the connection breaks or ctx is cancelled.
		c.read(ctx, conn)
		close(readDone)

		c.setState(StateDisconnected)
		select {
		case <-ctx.Done():
			return
		default:
			log.Printf("[KISS] Disconnected – reconnecting ...")
		}
	}
}

// dial opens the configured transport.
func (c *Client) dial(ctx context.Context) (kissConn, error) {
	switch c.source.Kind {
	case SourceTCP:
		d := net.Dialer{Timeout: dialTimeout}
		return d.DialContext(ctx, "tcp", c.source.Addr)
	case SourceSerial:
		return dialSerial(c.source)
	case SourceRFCOMM:
		mac := c.source.BDAddr
		if c.source.Auto {
			resolved, label, err := resolveAutoRFCOMM()
			if err != nil {
				return nil, err
			}
			if label != "" {
				log.Printf("[KISS] auto-selected %s (%s)", resolved, label)
			} else {
				log.Printf("[KISS] auto-selected %s", resolved)
			}
			mac = resolved
		}

		channel := c.source.Channel
		if channel == 0 {
			discovered, err := discoverSPPChannel(mac)
			if err != nil {
				log.Printf("[KISS] SPP channel discovery failed: %v – using channel 1", err)
				channel = 1
			} else {
				log.Printf("[KISS] SPP channel %d", discovered)
				channel = discovered
			}
		}
		return dialRFCOMM(mac, channel, dialTimeout)
	default:
		return nil, fmt.Errorf("unsupported KISS source %q", c.addr)
	}
}

// dialSerial opens a serial port. On Windows this is normally the outgoing
// Bluetooth COM port created by the SPP profile; on Linux it can be a USB
// serial TNC or /dev/rfcomm0.
func dialSerial(source KISSSource) (kissConn, error) {
	mode := &serial.Mode{
		BaudRate: source.Baud,
		DataBits: 8,
		Parity:   serial.NoParity,
		StopBits: serial.OneStopBit,
	}
	port, err := serial.Open(source.Device, mode)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", source.Device, err)
	}
	if err := port.SetReadTimeout(readPollInterval); err != nil {
		port.Close()
		return nil, fmt.Errorf("configure %s: %w", source.Device, err)
	}
	return port, nil
}

// read processes bytes from the KISS connection and emits complete frames
// after unescaping. It checks the context every readPollInterval so shutdown
// stays responsive even when no data is arriving.
func (c *Client) read(ctx context.Context, conn kissConn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	var frame []byte // accumulating frame buffer
	inFrame := false // true between FEND markers
	escaped := false // true after receiving FESC

	if d, ok := conn.(readDeadliner); ok {
		_ = d.SetReadDeadline(time.Now().Add(readPollInterval))
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := conn.Read(buf)
		if err != nil {
			if isTimeout(err) {
				if d, ok := conn.(readDeadliner); ok {
					_ = d.SetReadDeadline(time.Now().Add(readPollInterval))
				}
				continue
			}
			if ctx.Err() != nil {
				return
			}
			log.Printf("[KISS] Read error: %v", err)
			return
		}
		if n == 0 {
			// Serial ports return (0, nil) on their read timeout.
			if d, ok := conn.(readDeadliner); ok {
				_ = d.SetReadDeadline(time.Now().Add(readPollInterval))
			}
			continue
		}

		for _, b := range buf[:n] {
			switch {
			case b == fend:
				// FEND: dispatch accumulated frame, start new one.
				if inFrame && len(frame) > 0 {
					c.dispatch(frame)
				}
				frame = frame[:0]
				inFrame = true
				escaped = false

			case !inFrame:
				// Discard bytes outside frame boundaries.

			case escaped:
				// Previous byte was FESC: unescape this byte.
				escaped = false
				switch b {
				case tfend:
					frame = append(frame, fend)
				case tfesc:
					frame = append(frame, fesc)
				default:
					log.Printf("[KISS] protocol violation: unexpected escaped byte 0x%02X", b)
					frame = append(frame, b)
				}

			case b == fesc:
				escaped = true

			default:
				frame = append(frame, b)
			}
		}

		if d, ok := conn.(readDeadliner); ok {
			_ = d.SetReadDeadline(time.Now().Add(readPollInterval))
		}
	}
}

// isTimeout reports whether err is a read deadline / timeout error.
func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// dispatch extracts the port from the KISS command byte and sends the raw
// AX.25 data onto the output channel. Only data frames (command nibble == 0)
// are forwarded. If the channel buffer is full the frame is dropped.
func (c *Client) dispatch(data []byte) {
	if len(data) < 2 {
		return
	}
	cmd := data[0]
	// Data frames have command nibble == 0.
	if cmd&0x0F != 0x00 {
		return
	}
	port := (cmd >> 4) & 0x0F
	select {
	case c.frames <- KISSFrame{Port: port, Data: append([]byte(nil), data[1:]...)}:
	default:
		log.Println("[KISS] Frame buffer full – dropping frame")
	}
}
