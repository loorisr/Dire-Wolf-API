//go:build linux

package main

import (
	"strings"
	"testing"
)

func TestParseSPPChannel(t *testing.T) {
	records := `Service Name: BS AOC
Service RecHandle: 0x10000
Service Class ID List:
  UUID 128: 39144315-32fa-40db-85ed-fbfeba2d86e6
Protocol Descriptor List:
  "L2CAP" (0x0100)
  "RFCOMM" (0x0003)
    Channel: 2

Service Name: Voice Gateway
Service RecHandle: 0x10001
Service Class ID List:
  "Handsfree Audio Gateway" (0x111f)
Protocol Descriptor List:
  "L2CAP" (0x0100)
  "RFCOMM" (0x0003)
    Channel: 3

Service Name: SPP Dev
Service RecHandle: 0x10009
Service Class ID List:
  "Serial Port" (0x1101)
Protocol Descriptor List:
  "L2CAP" (0x0100)
  "RFCOMM" (0x0003)
    Channel: 4
`
	ch, err := parseSPPChannel(records)
	if err != nil {
		t.Fatalf("parseSPPChannel: %v", err)
	}
	if ch != 4 {
		t.Fatalf("channel = %d, want 4", ch)
	}

	if _, err := parseSPPChannel(records[:strings.Index(records, "Service Name: SPP Dev")]); err == nil {
		t.Fatal("expected an error when the SPP service is absent")
	}

	searchOutput := "Searching for SP on 38:D2:00:AA:BB:CC ...\n" +
		records[strings.Index(records, "Service Name: SPP Dev"):]
	ch, err = parseSPPChannel(searchOutput)
	if err != nil {
		t.Fatalf("parseSPPChannel(search output): %v", err)
	}
	if ch != 4 {
		t.Fatalf("search channel = %d, want 4", ch)
	}
}

func TestPickAutoBluetoothDevice(t *testing.T) {
	const mac = "38:D2:00:AA:BB:CC"

	tests := []struct {
		name      string
		devices   []bluezDevice
		wantMAC   string
		wantLabel string
		wantErr   string
	}{
		{
			name: "single paired SPP device",
			devices: []bluezDevice{{
				Address: mac,
				Alias:   "VR-N76",
				Paired:  true,
				UUIDs:   []string{sppServiceUUID},
			}},
			wantMAC:   mac,
			wantLabel: "VR-N76",
		},
		{
			name: "single connected device falls back to name",
			devices: []bluezDevice{{
				Address:   mac,
				Name:      "VR-N76",
				Connected: true,
				UUIDs:     []string{strings.ToUpper(sppServiceUUID)},
			}},
			wantMAC:   mac,
			wantLabel: "VR-N76",
		},
		{
			name: "unpaired device is ignored",
			devices: []bluezDevice{{
				Address: mac,
				Alias:   "VR-N76",
				UUIDs:   []string{sppServiceUUID},
			}},
			wantErr: "no paired",
		},
		{
			name: "device without SPP is ignored",
			devices: []bluezDevice{{
				Address: mac,
				Alias:   "Headset",
				Paired:  true,
				UUIDs:   []string{"0000110b-0000-1000-8000-00805f9b34fb"},
			}},
			wantErr: "no paired",
		},
		{
			name: "multiple SPP devices are rejected",
			devices: []bluezDevice{
				{Address: mac, Alias: "VR-N76", Paired: true, UUIDs: []string{sppServiceUUID}},
				{Address: "AA:BB:CC:DD:EE:FF", Alias: "Other", Paired: true, UUIDs: []string{sppServiceUUID}},
			},
			wantErr: "multiple Bluetooth SPP devices",
		},
		{
			name: "empty address is ignored",
			devices: []bluezDevice{{
				Alias:  "VR-N76",
				Paired: true,
				UUIDs:  []string{sppServiceUUID},
			}},
			wantErr: "no paired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mac, label, err := pickAutoBluetoothDevice(tt.devices)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want an error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mac != tt.wantMAC {
				t.Errorf("mac = %q, want %q", mac, tt.wantMAC)
			}
			if label != tt.wantLabel {
				t.Errorf("label = %q, want %q", label, tt.wantLabel)
			}
		})
	}
}
