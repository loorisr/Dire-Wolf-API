//go:build !linux

package main

import (
	"errors"
	"time"
)

func rfcommSupported() bool { return false }

func dialRFCOMM(string, uint8, time.Duration) (kissConn, error) {
	return nil, errors.New("native RFCOMM is only supported on Linux; " +
		"on Windows create an outgoing Bluetooth COM port and use serial:COMx")
}

func resolveAutoRFCOMM() (string, string, error) {
	return "", "", errors.New("native RFCOMM auto-selection is only supported on Linux; " +
		"on Windows create an outgoing Bluetooth COM port and use serial:COMx")
}

func discoverSPPChannel(string) (uint8, error) {
	return 0, errors.New("SPP channel discovery is only supported on Linux")
}
