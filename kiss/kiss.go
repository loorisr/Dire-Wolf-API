// Package kiss implements a KISS-over-TCP client with automatic reconnection.
// KISS (Keep It Simple, Stupid) is the protocol used by Direwolf to exchange
// AX.25 frames over a TCP connection (default port 8001).
package kiss

import (
	"context"
	"log"
	"net"
	"sync"
	"time"
)

const (
	fend  = 0xC0 // Frame End
	fesc  = 0xDB // Frame Escape
	tfend = 0xDC // Transposed FEND
	tfesc = 0xDD // Transposed FESC
)

// Frame holds a decoded KISS data frame.
type Frame struct {
	Port byte   // TNC port (0-15)
	Data []byte // Raw AX.25 frame bytes
}

// State represents the TCP connection state.
type State int

const (
	StateDisconnected State = iota
	StateConnecting
	StateConnected
)

// Client is a KISS TCP client that reconnects automatically on disconnect.
type Client struct {
	addr string

	mu    sync.RWMutex
	state State
	conn  net.Conn

	frames chan Frame
}

// NewClient creates a new KISS client targeting the given address (host:port).
func NewClient(addr string) *Client {
	return &Client{
		addr:   addr,
		state:  StateDisconnected,
		frames: make(chan Frame, 256),
	}
}

// Start launches the connect-loop in a goroutine. It returns immediately.
func (c *Client) Start(ctx context.Context) {
	go c.loop(ctx)
}

// Frames returns the read-only channel of decoded frames.
func (c *Client) Frames() <-chan Frame {
	return c.frames
}

// State returns the current connection state.
func (c *Client) State() State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// Addr returns the configured remote address.
func (c *Client) Addr() string {
	return c.addr
}

func (c *Client) setState(s State) {
	c.mu.Lock()
	c.state = s
	c.mu.Unlock()
}

// loop keeps trying to connect and read frames until ctx is cancelled.
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
			if backoff < 60*time.Second {
				backoff *= 2
			}
			continue
		}

		backoff = time.Second
		c.mu.Lock()
		c.conn = conn
		c.state = StateConnected
		c.mu.Unlock()
		log.Printf("[KISS] Connected to %s", c.addr)

		c.read(ctx, conn)

		c.mu.Lock()
		c.conn = nil
		c.state = StateDisconnected
		c.mu.Unlock()
		log.Printf("[KISS] Disconnected – reconnecting ...")
	}
}

// read processes bytes from the TCP connection and emits KISS frames.
func (c *Client) read(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 4096)
	var frame []byte
	inFrame := false
	escaped := false

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
				if inFrame && len(frame) > 0 {
					c.dispatch(frame)
				}
				frame = frame[:0]
				inFrame = true
				escaped = false

			case !inFrame:
				// ignore bytes outside frames

			case escaped:
				escaped = false
				switch b {
				case tfend:
					frame = append(frame, fend)
				case tfesc:
					frame = append(frame, fesc)
				default:
					// protocol violation – keep byte as-is
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

// dispatch parses the command byte and sends data frames to the channel.
func (c *Client) dispatch(data []byte) {
	if len(data) < 2 {
		return
	}
	cmd := data[0]
	if cmd&0x0F != 0x00 { // only handle data frames (command nibble == 0)
		return
	}
	port := (cmd >> 4) & 0x0F
	select {
	case c.frames <- Frame{Port: port, Data: append([]byte(nil), data[1:]...)}:
	default:
		log.Println("[KISS] Frame buffer full – dropping frame")
	}
}
