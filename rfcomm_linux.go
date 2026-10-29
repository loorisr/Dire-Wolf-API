//go:build linux

// Native Bluetooth RFCOMM transport. Unlike the rfcomm(8) TTY helper this does
// not require root or a /dev/rfcommN device: it opens an AF_BLUETOOTH socket
// directly to the TNC's SPP channel.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

func rfcommSupported() bool { return true }

// sppChannelRE matches the RFCOMM channel line inside an SDP service record.
var sppChannelRE = regexp.MustCompile(`(?m)^\s*Channel:\s*(\d+)\s*$`)

// discoverSPPChannel asks BlueZ for the RFCOMM channel of the Serial Port
// service. The VR-N76 can expose SPP Dev on channel 1 or 4; sdptool records
// gives the authoritative value.
func discoverSPPChannel(mac string) (uint8, error) {
	// "sdptool search" is much faster than "records" on the VR-N76
	// (milliseconds versus more than ten seconds) and returns the same SPP
	// record. Fall back to "records" for older sdptool versions.
	if ch, err := runSDP(10*time.Second, "search", "--bdaddr", mac, "SP"); err == nil {
		return ch, nil
	}
	return runSDP(20*time.Second, "records", mac)
}

func runSDP(timeout time.Duration, args ...string) (uint8, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	out, err := exec.CommandContext(ctx, "sdptool", args...).Output()
	if err != nil {
		return 0, fmt.Errorf("sdptool %s: %w", strings.Join(args, " "), err)
	}
	return parseSPPChannel(string(out))
}

// parseSPPChannel extracts the RFCOMM channel from sdptool records output.
// It looks for the Serial Port service (UUID 0x1101) and ignores the other
// services (BS AOC, Voice Gateway, ...).
func parseSPPChannel(output string) (uint8, error) {
	output = strings.ReplaceAll(output, "\r\n", "\n")

	for _, block := range strings.Split(output, "\n\n") {
		lower := strings.ToLower(block)
		if !strings.Contains(lower, "serial port") &&
			!strings.Contains(lower, "0x1101") &&
			!strings.Contains(lower, sppServiceUUID) {
			continue
		}
		match := sppChannelRE.FindStringSubmatch(block)
		if match == nil {
			continue
		}
		n, err := strconv.Atoi(match[1])
		if err != nil || n < 1 || n > 30 {
			continue
		}
		return uint8(n), nil
	}

	return 0, errors.New("SPP Dev channel not found in SDP records")
}

func dialRFCOMM(mac string, channel uint8, timeout time.Duration) (kissConn, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return nil, fmt.Errorf("invalid Bluetooth address %q: %w", mac, err)
	}
	if len(hw) != 6 {
		return nil, fmt.Errorf("Bluetooth address %q must have 6 bytes", mac)
	}

	// SockaddrRFCOMM expects the Bluetooth address in little-endian order.
	var addr [6]uint8
	for i := 0; i < 6; i++ {
		addr[i] = hw[5-i]
	}

	fd, err := unix.Socket(
		unix.AF_BLUETOOTH,
		unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK,
		unix.BTPROTO_RFCOMM,
	)
	if err != nil {
		return nil, fmt.Errorf("rfcomm socket: %w", err)
	}
	closeFD := true
	defer func() {
		if closeFD {
			unix.Close(fd)
		}
	}()

	sa := &unix.SockaddrRFCOMM{Addr: addr, Channel: channel}
	if err := unix.Connect(fd, sa); err != nil {
		switch err {
		case unix.EINPROGRESS, unix.EALREADY, unix.EISCONN:
			// Wait for the non-blocking connect to complete below.
		default:
			return nil, rfcommConnectError(mac, channel, err)
		}
	}

	deadline := time.Now().Add(timeout)
	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("rfcomm connect to %s channel %d: timeout after %s", mac, channel, timeout)
		}
		ms := int(remaining / time.Millisecond)
		if ms < 1 {
			ms = 1
		}

		pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		n, err := unix.Poll(pfd, ms)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, fmt.Errorf("rfcomm poll: %w", err)
		}
		if n == 0 {
			continue
		}
		if pfd[0].Revents&unix.POLLNVAL != 0 {
			return nil, fmt.Errorf("rfcomm connect to %s channel %d: invalid socket", mac, channel)
		}

		sockErr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
		if err != nil {
			return nil, fmt.Errorf("rfcomm getsockopt: %w", err)
		}
		if sockErr != 0 {
			return nil, rfcommConnectError(mac, channel, unix.Errno(sockErr))
		}
		break
	}

	f := os.NewFile(uintptr(fd), fmt.Sprintf("rfcomm:%s:%d", mac, channel))
	if f == nil {
		return nil, fmt.Errorf("rfcomm connect to %s channel %d: invalid file descriptor", mac, channel)
	}
	closeFD = false
	return f, nil
}

// rfcommConnectError adds actionable hints to the most common Bluetooth errors.
func rfcommConnectError(mac string, channel uint8, err error) error {
	switch {
	case errors.Is(err, unix.ECONNREFUSED):
		return fmt.Errorf("rfcomm connect to %s channel %d: %w "+
			"(check that the radio is in KISS TNC mode and that the channel is correct)", mac, channel, err)
	case errors.Is(err, unix.EHOSTDOWN), errors.Is(err, unix.EHOSTUNREACH), errors.Is(err, unix.ETIMEDOUT):
		return fmt.Errorf("rfcomm connect to %s channel %d: %w "+
			"(is the radio powered on, awake and in range?)", mac, channel, err)
	default:
		return fmt.Errorf("rfcomm connect to %s channel %d: %w", mac, channel, err)
	}
}

// sppServiceUUID is the Bluetooth Serial Port Profile service class.
const sppServiceUUID = "00001101-0000-1000-8000-00805f9b34fb"

// bluezDevice is the subset of org.bluez.Device1 used for auto-selection.
type bluezDevice struct {
	Address   string
	Alias     string
	Name      string
	Paired    bool
	Connected bool
	UUIDs     []string
}

// resolveAutoRFCOMM asks BlueZ for the only paired/connected device exposing
// the Serial Port service.
func resolveAutoRFCOMM() (string, string, error) {
	conn, err := dbus.SystemBus()
	if err != nil {
		return "", "", fmt.Errorf("Bluetooth D-Bus unavailable: %w (is BlueZ running?)", err)
	}
	defer conn.Close()

	obj := conn.Object("org.bluez", dbus.ObjectPath("/"))
	var managed map[dbus.ObjectPath]map[string]map[string]dbus.Variant
	if err := obj.Call("org.freedesktop.DBus.ObjectManager.GetManagedObjects", 0).Store(&managed); err != nil {
		return "", "", fmt.Errorf("query BlueZ managed objects: %w", err)
	}

	devices := make([]bluezDevice, 0, len(managed))
	for _, interfaces := range managed {
		props, ok := interfaces["org.bluez.Device1"]
		if !ok {
			continue
		}
		devices = append(devices, bluezDevice{
			Address:   variantString(props["Address"]),
			Alias:     variantString(props["Alias"]),
			Name:      variantString(props["Name"]),
			Paired:    variantBool(props["Paired"]),
			Connected: variantBool(props["Connected"]),
			UUIDs:     variantStrings(props["UUIDs"]),
		})
	}
	return pickAutoBluetoothDevice(devices)
}

// pickAutoBluetoothDevice selects the single paired/connected SPP device.
// Multiple matches are rejected so auto can never pick the wrong radio.
func pickAutoBluetoothDevice(devices []bluezDevice) (string, string, error) {
	candidates := make([]bluezDevice, 0, len(devices))
	for _, d := range devices {
		if d.Address == "" {
			continue
		}
		if !d.Paired && !d.Connected {
			continue
		}
		if !hasSPPUUID(d.UUIDs) {
			continue
		}
		candidates = append(candidates, d)
	}

	switch len(candidates) {
	case 0:
		return "", "", errors.New("no paired Bluetooth Serial Port (SPP) device found; " +
			"pair the radio first or use its MAC address")
	case 1:
		d := candidates[0]
		label := d.Alias
		if label == "" {
			label = d.Name
		}
		return d.Address, label, nil
	default:
		labels := make([]string, 0, len(candidates))
		for _, d := range candidates {
			label := d.Alias
			if label == "" {
				label = d.Name
			}
			if label != "" {
				labels = append(labels, fmt.Sprintf("%s (%s)", label, d.Address))
			} else {
				labels = append(labels, d.Address)
			}
		}
		return "", "", fmt.Errorf("multiple Bluetooth SPP devices found: %s; "+
			"use a MAC address instead of auto", strings.Join(labels, ", "))
	}
}

func hasSPPUUID(uuids []string) bool {
	for _, uuid := range uuids {
		if strings.EqualFold(uuid, sppServiceUUID) {
			return true
		}
	}
	return false
}

func variantString(v dbus.Variant) string {
	s, _ := v.Value().(string)
	return s
}

func variantBool(v dbus.Variant) bool {
	b, _ := v.Value().(bool)
	return b
}

func variantStrings(v dbus.Variant) []string {
	s, _ := v.Value().([]string)
	return s
}
