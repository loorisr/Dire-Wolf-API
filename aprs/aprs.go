// Package aprs decodes APRS (Automatic Packet Reporting System) information fields.
// It uses the go-aprs-fap library for packet parsing.
package aprs

import (
	"fmt"
	"math"
	"strings"
	"time"

	fap "github.com/hessu/go-aprs-fap"
)

// Type identifies the APRS packet type.
type Type string

const (
	TypePosition  Type = "position"
	TypeMessage   Type = "message"
	TypeStatus    Type = "status"
	TypeObject    Type = "object"
	TypeItem      Type = "item"
	TypeWeather   Type = "weather"
	TypeTelemetry Type = "telemetry"
	TypeNMEA      Type = "nmea"
	TypeMicE      Type = "mic-e"
	TypeUnknown   Type = "unknown"
)

// Position holds geographic information.
type Position struct {
	Lat      float64  `json:"lat"`
	Lon      float64  `json:"lon"`
	Symbol   string   `json:"symbol"`
	Speed    *float64 `json:"speed,omitempty"`
	Course   *int     `json:"course,omitempty"`
	Altitude *float64 `json:"altitude,omitempty"`
	Comment  string   `json:"comment,omitempty"`
}

// Message holds an APRS text message.
type Message struct {
	Addressee string `json:"addressee"`
	Text      string `json:"text,omitempty"`
	MsgID     string `json:"msg_id,omitempty"`
	IsAck     bool   `json:"is_ack,omitempty"`
	IsRej     bool   `json:"is_rej,omitempty"`
}

// Weather holds weather observation data.
type Weather struct {
	WindDir   *int     `json:"wind_dir,omitempty"`
	WindSpeed *float64 `json:"wind_speed,omitempty"`
	WindGust  *float64 `json:"wind_gust,omitempty"`
	Temp      *float64 `json:"temp,omitempty"`
	RainHour  *float64 `json:"rain_hour,omitempty"`
	RainDay   *float64 `json:"rain_day,omitempty"`
	Humidity  *int     `json:"humidity,omitempty"`
	Pressure  *float64 `json:"pressure,omitempty"`
}

// Packet is a fully decoded APRS packet.
type Packet struct {
	Type      Type       `json:"type"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
	Position  *Position  `json:"position,omitempty"`
	Message   *Message   `json:"message,omitempty"`
	Weather   *Weather   `json:"weather,omitempty"`
	Status    string     `json:"status,omitempty"`
	Telemetry string     `json:"telemetry,omitempty"`
	Comment   string     `json:"comment,omitempty"`
	Raw       string     `json:"raw"`
}

// Decode decodes an APRS information field.
// srcCallsign and dstCallsign are used for Mic-E decoding.
func Decode(info []byte, srcCallsign, dstCallsign string) *Packet {
	if len(info) == 0 {
		return &Packet{Type: TypeUnknown, Raw: ""}
	}
	raw := string(info)

	tnc2 := srcCallsign + ">" + dstCallsign + ":" + raw
	fp, err := fap.Parse(tnc2, fap.WithAcceptBrokenMicE())
	if err != nil {
		return &Packet{Type: TypeUnknown, Raw: raw, Comment: raw}
	}

	return convert(fp, raw)
}

func convert(fp *fap.Packet, raw string) *Packet {
	p := &Packet{
		Raw:       raw,
		Timestamp: cloneTimePtr(fp.Timestamp),
	}

	p.Type = mapType(fp)

	if fp.Latitude != nil || fp.Longitude != nil {
		p.Position = &Position{
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

	if fp.Message != nil {
		m := &Message{
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

	if fp.Wx != nil {
		p.Weather = convertWeather(fp.Wx)
	}

	if fp.Status != "" {
		p.Status = fp.Status
	}

	if fp.TelemetryData != nil {
		p.Telemetry = formatTelemetry(fp.TelemetryData)
	}

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

func mapType(fp *fap.Packet) Type {
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

func convertWeather(fw *fap.Weather) *Weather {
	w := &Weather{}
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

func formatTelemetry(td *fap.Telemetry) string {
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

func symbolString(table, code byte) string {
	if table == 0 && code == 0 {
		return ""
	}
	return string([]byte{table, code})
}

func derefFloat64(v *float64) float64 {
	if v == nil {
		return 0
	}
	return *v
}

func cloneFloat64Ptr(v *float64) *float64 {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

func cloneIntPtr(v *int) *int {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}

func cloneTimePtr(v *time.Time) *time.Time {
	if v == nil {
		return nil
	}
	c := *v
	return &c
}
