// APRS (Automatic Packet Reporting System) information field decoder.
// Uses go-aprs-fap to parse position reports, weather data, messages,
// telemetry, status, objects, items, and NMEA sentences from APRS packets.
package main

import (
	"fmt"
	"math"
	"strings"
	"time"

	fap "github.com/hessu/go-aprs-fap"
)

// APRSType identifies the APRS packet type.
type APRSType string

const (
	TypePosition  APRSType = "position"
	TypeMessage   APRSType = "message"
	TypeStatus    APRSType = "status"
	TypeObject    APRSType = "object"
	TypeItem      APRSType = "item"
	TypeWeather   APRSType = "weather"
	TypeTelemetry APRSType = "telemetry"
	TypeNMEA      APRSType = "nmea"
	TypeMicE      APRSType = "mic-e"
	TypeUnknown   APRSType = "unknown"
)

// APRSPosition holds geographic coordinates and navigation data.
type APRSPosition struct {
	Lat      float64  `json:"lat"`
	Lon      float64  `json:"lon"`
	Symbol   string   `json:"symbol"`
	Speed    *float64 `json:"speed,omitempty"`    // km/h
	Course   *int     `json:"course,omitempty"`   // degrees (0-360)
	Altitude *float64 `json:"altitude,omitempty"` // metres
	Comment  string   `json:"comment,omitempty"`
}

// APRSMessage holds an APRS text message, acknowledgement, or reject.
type APRSMessage struct {
	Addressee string `json:"addressee"`
	Text      string `json:"text,omitempty"`
	MsgID     string `json:"msg_id,omitempty"`
	IsAck     bool   `json:"is_ack,omitempty"`
	IsRej     bool   `json:"is_rej,omitempty"`
}

// APRSWeather holds weather observation data.
type APRSWeather struct {
	WindDir   *int     `json:"wind_dir,omitempty"`   // degrees (0-360)
	WindSpeed *float64 `json:"wind_speed,omitempty"` // km/h
	WindGust  *float64 `json:"wind_gust,omitempty"`  // km/h
	Temp      *float64 `json:"temp,omitempty"`       // degrees Celsius
	RainHour  *float64 `json:"rain_hour,omitempty"`  // mm
	RainDay   *float64 `json:"rain_day,omitempty"`   // mm
	Humidity  *int     `json:"humidity,omitempty"`   // percent
	Pressure  *float64 `json:"pressure,omitempty"`   // hPa
}

// APRSPacket is a fully decoded APRS information field.
type APRSPacket struct {
	Type      APRSType      `json:"type"`
	Timestamp *time.Time    `json:"timestamp,omitempty"`
	Position  *APRSPosition `json:"position,omitempty"`
	Message   *APRSMessage  `json:"message,omitempty"`
	Weather   *APRSWeather  `json:"weather,omitempty"`
	Status    string        `json:"status,omitempty"`
	Telemetry string        `json:"telemetry,omitempty"`
	Comment   string        `json:"comment,omitempty"`
	Raw       string        `json:"raw"`
}

// DecodeAPRS decodes an APRS information field using the go-aprs-fap library.
// srcCallsign and dstCallsign are used for Mic-E position decoding.
// Returns a Packet with type TypeUnknown on parse failure.
func DecodeAPRS(info []byte, srcCallsign, dstCallsign string) *APRSPacket {
	if len(info) == 0 {
		return &APRSPacket{Type: TypeUnknown, Raw: ""}
	}
	raw := string(info)

	// Reconstruct a TNC2-format string for the fap parser.
	tnc2 := srcCallsign + ">" + dstCallsign + ":" + raw
	fp, err := fap.Parse(tnc2, fap.WithAcceptBrokenMicE())
	if err != nil {
		return &APRSPacket{Type: TypeUnknown, Raw: raw, Comment: raw}
	}

	return convertAPRS(fp, raw)
}

// convertAPRS maps the fap library's Packet type to our APRSPacket.
func convertAPRS(fp *fap.Packet, raw string) *APRSPacket {
	p := &APRSPacket{
		Raw:       raw,
		Timestamp: cloneTimePtr(fp.Timestamp),
	}

	p.Type = mapAPRSType(fp)

	// Extract position if latitude or longitude is present.
	if fp.Latitude != nil || fp.Longitude != nil {
		p.Position = &APRSPosition{
			Lat:     derefFloat64(fp.Latitude),
			Lon:     derefFloat64(fp.Longitude),
			Symbol:  symbolString(fp.SymbolTable, fp.SymbolCode),
			Comment: fp.Comment,
		}
		if fp.Speed != nil {
			p.Position.Speed = cloneFloat64Ptr(fp.Speed)
		}
		if fp.Course != nil {
			p.Position.Course = cloneIntPtr(fp.Course)
		}
		if fp.Altitude != nil {
			p.Position.Altitude = cloneFloat64Ptr(fp.Altitude)
		}
	}

	// Extract message fields.
	if fp.Message != nil {
		m := &APRSMessage{
			Addressee: fp.Message.Destination,
			Text:      fp.Message.Text,
		}
		if fp.Message.AckID != "" {
			m.IsAck = true
			m.MsgID = fp.Message.AckID
		} else if fp.Message.RejID != "" {
			m.IsRej = true
			m.MsgID = fp.Message.RejID
		} else {
			m.MsgID = fp.Message.ID
		}
		p.Message = m
	}

	// Extract weather observations (wind speed converted from m/s to km/h).
	if fp.Wx != nil {
		p.Weather = convertAPRSWeather(fp.Wx)
	}

	if fp.Status != "" {
		p.Status = fp.Status
	}

	// Format telemetry as "seq=N bits=... v1=X v2=Y ...".
	if fp.TelemetryData != nil {
		p.Telemetry = formatAPRSTelemetry(fp.TelemetryData)
	}

	// Object and item names are stored in the comment field.
	if fp.ObjectName != "" {
		status := "killed"
		if fp.Alive != nil && *fp.Alive {
			status = "live"
		}
		p.Comment = fmt.Sprintf("%s [%s]", fp.ObjectName, status)
	}

	if fp.ItemName != "" {
		p.Comment = fp.ItemName
	}

	if fp.Comment != "" && p.Comment == "" {
		p.Comment = fp.Comment
	}

	return p
}

// mapAPRSType converts the fap library packet type to our APRSType enum.
func mapAPRSType(fp *fap.Packet) APRSType {
	switch fp.Type {
	case fap.PacketTypeLocation:
		switch fp.Format {
		case fap.FormatMicE:
			return TypeMicE
		case fap.FormatNMEA:
			return TypeNMEA
		default:
			return TypePosition
		}
	case fap.PacketTypeObject:
		return TypeObject
	case fap.PacketTypeItem:
		return TypeItem
	case fap.PacketTypeMessage:
		return TypeMessage
	case fap.PacketTypeWx:
		return TypeWeather
	case fap.PacketTypeTelemetry, fap.PacketTypeTelemetryMessage:
		return TypeTelemetry
	case fap.PacketTypeStatus, fap.PacketTypeCapabilities:
		return TypeStatus
	default:
		return TypeUnknown
	}
}

// convertAPRSWeather maps the fap Weather struct to our APRSWeather struct.
// Wind speeds are converted from m/s to km/h.
func convertAPRSWeather(fw *fap.Weather) *APRSWeather {
	w := &APRSWeather{}
	if fw.WindDirection != nil {
		dir := int(math.Round(*fw.WindDirection))
		w.WindDir = &dir
	}
	if fw.WindSpeed != nil {
		kph := *fw.WindSpeed * 3.6
		w.WindSpeed = &kph
	}
	if fw.WindGust != nil {
		kph := *fw.WindGust * 3.6
		w.WindGust = &kph
	}
	if fw.Temp != nil {
		w.Temp = cloneFloat64Ptr(fw.Temp)
	}
	if fw.Humidity != nil {
		w.Humidity = cloneIntPtr(fw.Humidity)
	}
	if fw.Pressure != nil {
		w.Pressure = cloneFloat64Ptr(fw.Pressure)
	}
	if fw.Rain1h != nil {
		w.RainHour = cloneFloat64Ptr(fw.Rain1h)
	}
	if fw.Rain24h != nil {
		w.RainDay = cloneFloat64Ptr(fw.Rain24h)
	}
	return w
}

// formatAPRSTelemetry converts the fap Telemetry struct to a human-readable
// string: "seq=N bits=BBBBBBBBBBB v1=... v2=... ...".
func formatAPRSTelemetry(td *fap.Telemetry) string {
	if td == nil {
		return ""
	}
	var parts []string
	parts = append(parts, fmt.Sprintf("seq=%d", td.Seq))
	if td.Bits != "" {
		parts = append(parts, fmt.Sprintf("bits=%s", td.Bits))
	}
	for i, v := range td.Vals {
		if v != nil {
			parts = append(parts, fmt.Sprintf("v%d=%.3f", i+1, *v))
		} else {
			parts = append(parts, fmt.Sprintf("v%d=-", i+1))
		}
	}
	return strings.Join(parts, " ")
}

// symbolString returns the 2-character APRS symbol (table + code byte).
// An empty string is returned when both bytes are zero (no symbol).
func symbolString(table, code byte) string {
	if table == 0 && code == 0 {
		return ""
	}
	return string([]byte{table, code})
}

// derefFloat64 returns the dereferenced value or 0 if nil.
func derefFloat64(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}

// cloneFloat64Ptr returns a copy of the float64 pointer, or nil.
func cloneFloat64Ptr(v *float64) *float64 {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

// cloneIntPtr returns a copy of the int pointer, or nil.
func cloneIntPtr(v *int) *int {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

// cloneTimePtr returns a copy of the time pointer, or nil.
func cloneTimePtr(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}
