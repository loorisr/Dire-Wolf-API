// KISS-over-TCP client that handles reconnection with exponential backoff.
// KISS (Keep It Simple, Stupid) is the protocol Dire Wolf uses to exchange
// AX.25 frames over TCP (default port 8001).
package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

// KISS escape bytes.
const (
	fend  = 0xC0 // Frame End
	fesc  = 0xDB // Frame Escape
	tfend = 0xDC // Transposed FEND (escaped FEND)
	tfesc = 0xDD // Transposed FESC (escaped FESC)
)

// Maximum exponential backoff ceiling for reconnection attempts.
const maxBackoff = 32 * time.Second

// KISSFrame holds a decoded KISS data frame with its source TNC port.
type KISSFrame struct {
	Port byte   // TNC logical port (0-15), extracted from the command byte
	Data []byte // Raw AX.25 frame payload (command byte already stripped)
}

// KISSState tracks the TCP connection lifecycle.
type KISSState int

const (
	StateDisconnected KISSState = iota
	StateConnecting
	StateConnected
)

// Client maintains a KISS TCP connection to Dire Wolf, reconnecting
// automatically on failure with exponential backoff.
type Client struct {
	addr string

	mu    sync.RWMutex
	state KISSState

	frames chan KISSFrame // buffered output channel (capacity 256)
}

// NewClient creates a KISS client targeting the given address (host:port).
func NewClient(addr string) *Client {
	return &Client{
		addr:   addr,
		state:  StateDisconnected,
		frames: make(chan KISSFrame, 256),
	}
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

// Addr returns the configured remote KISS TCP address.
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

		conn, err := net.DialTimeout("tcp", c.addr, 10*time.Second)
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

		// read blocks until the connection breaks or ctx is cancelled.
		c.read(ctx, conn)

		c.setState(StateDisconnected)
		log.Printf("[KISS] Disconnected – reconnecting ...")
	}
}

// read processes bytes from the TCP connection and emits complete KISS frames
// after unescaping. A 5 s read deadline is set so context cancellation can
// interrupt blocking reads.
func (c *Client) read(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	var frame []byte // accumulating frame buffer
	inFrame := false // true between FEND markers
	escaped := false // true after receiving FESC

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			log.Printf("[KISS] Read error: %v", err)
			return
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
	}
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
