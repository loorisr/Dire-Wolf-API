// Package aprs decodes APRS (Automatic Packet Reporting System) information fields.
// It supports the most common packet types: position, message, status, object,
// weather, telemetry, Mic-E and NMEA.
package aprs

import (
	"fmt"
	"strconv"
	"strings"
	"time"
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
	Symbol   string   `json:"symbol"`             // 2-char: table + code
	Speed    *float64 `json:"speed,omitempty"`    // km/h
	Course   *int     `json:"course,omitempty"`   // degrees 0-360
	Altitude *float64 `json:"altitude,omitempty"` // metres
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

// Weather holds weather observation data (all values in SI units).
type Weather struct {
	WindDir   *int     `json:"wind_dir,omitempty"`   // degrees
	WindSpeed *float64 `json:"wind_speed,omitempty"` // km/h
	WindGust  *float64 `json:"wind_gust,omitempty"`  // km/h
	Temp      *float64 `json:"temp,omitempty"`       // °C
	RainHour  *float64 `json:"rain_hour,omitempty"`  // mm
	RainDay   *float64 `json:"rain_day,omitempty"`   // mm
	Humidity  *int     `json:"humidity,omitempty"`   // %
	Pressure  *float64 `json:"pressure,omitempty"`   // hPa
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
	p := &Packet{Raw: raw}

	switch info[0] {
	case '!', '=':
		// Position without timestamp (= means messaging capable)
		p.Type = TypePosition
		p.Position = decodePositionNoTS(info[1:])
	case '/', '@':
		// Position with timestamp
		p.Type = TypePosition
		decodePositionWithTS(p, info)
	case ':':
		p.Type = TypeMessage
		p.Message = decodeMessage(info[1:])
	case '>':
		p.Type = TypeStatus
		p.Status = strings.TrimSpace(string(info[1:]))
	case ';':
		p.Type = TypeObject
		decodeObject(p, info[1:])
	case ')':
		p.Type = TypeItem
		p.Comment = string(info[1:])
	case '_':
		// Weather report without position
		p.Type = TypeWeather
		w := &Weather{}
		parseWeatherFields(w, string(info[1:]))
		p.Weather = w
	case 'T':
		p.Type = TypeTelemetry
		p.Telemetry = raw
	case '$':
		p.Type = TypeNMEA
		p.Comment = raw
	case '`', '\'':
		p.Type = TypeMicE
		decodeMicE(p, info, dstCallsign)
	default:
		p.Type = TypeUnknown
		p.Comment = raw
	}
	return p
}

// ─── Position helpers ────────────────────────────────────────────────────────

func decodePositionNoTS(data []byte) *Position {
	if len(data) == 0 {
		return nil
	}
	if isCompressedPosition(data) {
		return decodeCompressedPos(data)
	}
	return decodeUncompressedPos(data)
}

func decodePositionWithTS(p *Packet, data []byte) {
	// data[0] is '/' or '@', data[1..7] is timestamp, data[7] is format char
	if len(data) < 8 {
		return
	}
	ts := string(data[1:8])
	now := time.Now().UTC()

	var t time.Time
	var err error
	switch data[7] {
	case 'z', 'Z':
		t, err = parseDHMZ(ts[:6], now)
	case '/':
		t, err = parseDHMZ(ts[:6], now) // local treated as UTC
	case 'h', 'H':
		t, err = parseHMS(ts[:6], now)
	}
	if err == nil {
		p.Timestamp = &t
	}

	rest := data[8:]
	if len(rest) == 0 {
		return
	}
	if isCompressedPosition(rest) {
		p.Position = decodeCompressedPos(rest)
	} else {
		p.Position = decodeUncompressedPos(rest)
	}
}

func parseDHMZ(s string, now time.Time) (time.Time, error) {
	if len(s) < 6 {
		return time.Time{}, fmt.Errorf("too short")
	}
	day, _ := strconv.Atoi(s[0:2])
	hour, _ := strconv.Atoi(s[2:4])
	min, _ := strconv.Atoi(s[4:6])
	t := time.Date(now.Year(), now.Month(), day, hour, min, 0, 0, time.UTC)
	// If the result is more than 12 h in the future, roll back one month
	if t.After(now.Add(12 * time.Hour)) {
		t = t.AddDate(0, -1, 0)
	}
	return t, nil
}

func parseHMS(s string, now time.Time) (time.Time, error) {
	if len(s) < 6 {
		return time.Time{}, fmt.Errorf("too short")
	}
	hour, _ := strconv.Atoi(s[0:2])
	min, _ := strconv.Atoi(s[2:4])
	sec, _ := strconv.Atoi(s[4:6])
	return time.Date(now.Year(), now.Month(), now.Day(), hour, min, sec, 0, time.UTC), nil
}

// decodeUncompressedPos parses DDmm.mm[NS]xDDDmm.mm[EW]y[ext][comment]
// where x is the symbol table char and y is the symbol code char.
func decodeUncompressedPos(data []byte) *Position {
	// Minimum: 7 (lat) + 1 (N/S) + 1 (sym tbl) + 8 (lon) + 1 (E/W) + 1 (sym code) = 19
	if len(data) < 19 {
		return nil
	}
	s := string(data)
	if !looksLikeUncompressedPosition(s) {
		return nil
	}

	latStr := s[0:7]
	latHem := s[7]
	symTable := s[8]
	lonStr := s[9:17]
	lonHem := s[17]
	symCode := s[18]

	lat, err := parseDM(latStr)
	if err != nil {
		return nil
	}
	if latHem == 'S' || latHem == 's' {
		lat = -lat
	}
	lon, err := parseDM(lonStr)
	if err != nil {
		return nil
	}
	if lonHem == 'W' || lonHem == 'w' {
		lon = -lon
	}

	pos := &Position{
		Lat:    lat,
		Lon:    lon,
		Symbol: string([]byte{symTable, symCode}),
	}
	if len(s) > 19 {
		pos.Comment, pos.Course, pos.Speed, pos.Altitude = parseExtComment(s[19:])
	}
	return pos
}

// parseDM parses a DDmm.mm or DDDmm.mm string to decimal degrees.
func parseDM(s string) (float64, error) {
	dot := strings.IndexByte(s, '.')
	if dot < 3 {
		return 0, fmt.Errorf("bad DM: %q", s)
	}
	deg, err := strconv.ParseFloat(s[:dot-2], 64)
	if err != nil {
		return 0, err
	}
	min, err := strconv.ParseFloat(s[dot-2:], 64)
	if err != nil {
		return 0, err
	}
	return deg + min/60.0, nil
}

func isBase91(b byte) bool { return b >= '!' && b <= '{' }

func looksLikeUncompressedPosition(s string) bool {
	if len(s) < 19 {
		return false
	}
	if s[4] != '.' || s[14] != '.' {
		return false
	}
	if (s[7] != 'N' && s[7] != 'n' && s[7] != 'S' && s[7] != 's') || (s[17] != 'E' && s[17] != 'e' && s[17] != 'W' && s[17] != 'w') {
		return false
	}
	for _, idx := range []int{0, 1, 2, 3, 5, 6, 9, 10, 11, 12, 13, 15, 16} {
		if s[idx] < '0' || s[idx] > '9' {
			return false
		}
	}
	return true
}

func isCompressedPosition(data []byte) bool {
	if len(data) < 11 {
		return false
	}
	// If this clearly matches an uncompressed position, do not treat it as compressed.
	if len(data) >= 19 && looksLikeUncompressedPosition(string(data[:19])) {
		return false
	}
	return isBase91(data[0]) && isBase91(data[1]) && isBase91(data[2]) && isBase91(data[3]) && isBase91(data[4]) && isBase91(data[5]) && isBase91(data[6]) && isBase91(data[7]) && isBase91(data[8]) && isBase91(data[9])
}

// decodeCompressedPos decodes a compressed APRS position (base-91 encoding).
func decodeCompressedPos(data []byte) *Position {
	// Format: [sym_table][lat4][lon4][sym_code][cs][t][comment]
	if len(data) < 11 {
		return nil
	}
	symTable := data[0]

	lv := int(data[1]-33)*91*91*91 + int(data[2]-33)*91*91 + int(data[3]-33)*91 + int(data[4]-33)
	lat := 90.0 - float64(lv)/380926.0

	lo := int(data[5]-33)*91*91*91 + int(data[6]-33)*91*91 + int(data[7]-33)*91 + int(data[8]-33)
	lon := -180.0 + float64(lo)/190463.0

	symCode := data[9]
	pos := &Position{
		Lat:    lat,
		Lon:    lon,
		Symbol: string([]byte{symTable, symCode}),
	}
	if len(data) > 13 {
		pos.Comment = string(data[13:])
	}
	return pos
}

// parseExtComment extracts course/speed, altitude and comment from the tail
// of a position packet information field.
func parseExtComment(s string) (comment string, course *int, speed *float64, alt *float64) {
	// Course/speed extension: CSE/SPD (3 digits / 3 digits, knots)
	if len(s) >= 7 && s[3] == '/' {
		c, err1 := strconv.Atoi(s[0:3])
		sp, err2 := strconv.Atoi(s[4:7])
		if err1 == nil && err2 == nil && c >= 0 && c <= 360 {
			course = &c
			kph := float64(sp) * 1.852
			speed = &kph
			s = s[7:]
		}
	}

	// Altitude: /A=XXXXXX (feet)
	if idx := strings.Index(s, "/A="); idx >= 0 && idx+9 <= len(s) {
		ft, err := strconv.Atoi(s[idx+3 : idx+9])
		if err == nil {
			m := float64(ft) * 0.3048
			alt = &m
			s = s[:idx] + s[idx+9:]
		}
	}

	comment = strings.TrimSpace(s)
	return
}

// ─── Message ─────────────────────────────────────────────────────────────────

func decodeMessage(data []byte) *Message {
	// Format: :AAAAAAAAA:text{id  (addressee is 9 chars padded with spaces)
	if len(data) < 10 || data[9] != ':' {
		return &Message{Text: string(data)}
	}
	addressee := strings.TrimRight(string(data[0:9]), " ")
	rest := string(data[10:])
	msg := &Message{Addressee: addressee}

	switch {
	case strings.HasPrefix(rest, "ack"):
		msg.IsAck = true
		msg.MsgID = strings.TrimSpace(rest[3:])
	case strings.HasPrefix(rest, "rej"):
		msg.IsRej = true
		msg.MsgID = strings.TrimSpace(rest[3:])
	default:
		if idx := strings.LastIndexByte(rest, '{'); idx >= 0 {
			msg.Text = rest[:idx]
			msg.MsgID = rest[idx+1:]
		} else {
			msg.Text = rest
		}
	}
	return msg
}

// ─── Object ──────────────────────────────────────────────────────────────────

func decodeObject(p *Packet, data []byte) {
	// Format: NNNNNNNNN*time/pos...
	// Name is 9 chars, then '*' (live) or '_' (killed)
	if len(data) < 10 {
		p.Comment = string(data)
		return
	}
	name := strings.TrimRight(string(data[0:9]), " ")
	live := data[9] == '*'

	var pos *Position
	if len(data) > 17 {
		// After name+status there is a time+position field same as '@' packets
		rest := append([]byte{'@'}, data[10:]...)
		tmp := &Packet{}
		decodePositionWithTS(tmp, rest)
		pos = tmp.Position
		if tmp.Timestamp != nil {
			p.Timestamp = tmp.Timestamp
		}
	}

	status := "killed"
	if live {
		status = "live"
	}
	p.Comment = fmt.Sprintf("%s [%s]", name, status)
	p.Position = pos
}

// ─── Weather ─────────────────────────────────────────────────────────────────

// parseWeatherFields parses weather data fields found in the tail of a
// weather packet or after a position symbol.
func parseWeatherFields(w *Weather, s string) {
	// Wind direction/speed: DDD/SSS (degrees / mph)
	if len(s) >= 7 && s[3] == '/' {
		if s[0:3] != "..." {
			if dir, err := strconv.Atoi(s[0:3]); err == nil {
				w.WindDir = &dir
			}
		}
		if s[4:7] != "..." {
			if sp, err := strconv.Atoi(s[4:7]); err == nil {
				kph := float64(sp) * 1.60934
				w.WindSpeed = &kph
			}
		}
		s = s[7:]
	}

	// Remaining fields are single-char prefixed
	i := 0
	for i < len(s) {
		if i+4 > len(s) {
			break
		}
		tag := s[i]
		val3 := s[i+1 : i+4]
		switch tag {
		case 'g': // gust mph
			if v, err := strconv.Atoi(val3); err == nil {
				kph := float64(v) * 1.60934
				w.WindGust = &kph
			}
		case 't', 'T': // temperature °F
			if v, err := strconv.Atoi(val3); err == nil {
				c := (float64(v) - 32) * 5 / 9
				w.Temp = &c
			}
		case 'r': // rain last hour (1/100 inch)
			if v, err := strconv.Atoi(val3); err == nil {
				mm := float64(v) * 0.254
				w.RainHour = &mm
			}
		case 'p', 'P': // rain last 24 h
			if v, err := strconv.Atoi(val3); err == nil {
				mm := float64(v) * 0.254
				w.RainDay = &mm
			}
		case 'h': // humidity %  (2 digits, "00" = 100%)
			if i+3 <= len(s) {
				if v, err := strconv.Atoi(s[i+1 : i+3]); err == nil {
					if v == 0 {
						v = 100
					}
					w.Humidity = &v
				}
			}
		case 'b': // barometric pressure (1/10 mbar)
			if i+6 <= len(s) {
				if v, err := strconv.Atoi(s[i+1 : i+6]); err == nil {
					hpa := float64(v) / 10.0
					w.Pressure = &hpa
				}
			}
		}
		i++
	}
}

// ─── Mic-E ───────────────────────────────────────────────────────────────────
func decodeMicE(p *Packet, info []byte, dest string) {
	// Mic-E minimum (without comment): type + 3 lon + 3 spd/crs + 2 symbol chars.
	if len(info) < 9 {
		p.Comment = string(info)
		return
	}

	dest6 := normalizeMicEDestination(dest)
	lat, north, okLat := decodeMicELatitude(dest6)

	lon, speedKPH, course, okLon := decodeMicELongitudeSpeedCourse(info[1:7], dest6)
	if okLon && isMicEWest(dest6[5]) {
		lon = -lon
	}
	if okLat && !north {
		lat = -lat
	}

	if okLat && okLon {
		p.Position = &Position{
			Lat:    lat,
			Lon:    lon,
			Symbol: string([]byte{info[8], info[7]}), // table + code
			Speed:  speedKPH,
			Course: course,
		}
	}

	// Mic-E status/comment starts after symbol code + symbol table.
	if len(info) > 9 {
		tail := strings.TrimSpace(string(info[9:]))
		if tail != "" {
			p.Status = tail
			p.Comment = tail
		}
	}
}

func normalizeMicEDestination(dest string) string {
	base := strings.ToUpper(dest)
	if i := strings.IndexByte(base, '-'); i >= 0 {
		base = base[:i]
	}
	if len(base) < 6 {
		base += strings.Repeat(" ", 6-len(base))
	}
	if len(base) > 6 {
		base = base[:6]
	}
	return base
}

func decodeMicELatitude(dest6 string) (float64, bool, bool) {
	if len(dest6) < 6 {
		return 0, false, false
	}

	d := make([]int, 6)
	for i := 0; i < 6; i++ {
		v, ok := micELatDigit(dest6[i])
		if !ok {
			return 0, false, false
		}
		d[i] = v
	}

	deg := d[0]*10 + d[1]
	min := d[2]*10 + d[3]
	hundredths := d[4]*10 + d[5]
	lat := float64(deg) + (float64(min)+float64(hundredths)/100.0)/60.0

	// 4th destination character encodes N/S.
	north := isMicENorth(dest6[3])
	return lat, north, true
}

func decodeMicELongitudeSpeedCourse(data []byte, dest6 string) (float64, *float64, *int, bool) {
	if len(data) < 6 || len(dest6) < 6 {
		return 0, nil, nil, false
	}

	lonDeg := int(data[0]) - 28
	if isMicELonOffset(dest6[4]) {
		lonDeg += 100
	}
	switch {
	case lonDeg >= 180 && lonDeg <= 189:
		lonDeg -= 80
	case lonDeg >= 190 && lonDeg <= 199:
		lonDeg -= 190
	}

	lonMin := int(data[1]) - 28
	if lonMin >= 60 {
		lonMin -= 60
	}
	lonHun := int(data[2]) - 28
	if lonHun >= 100 {
		lonHun -= 100
	}

	if lonDeg < 0 || lonDeg > 179 || lonMin < 0 || lonMin > 59 || lonHun < 0 || lonHun > 99 {
		return 0, nil, nil, false
	}
	lon := float64(lonDeg) + (float64(lonMin)+float64(lonHun)/100.0)/60.0

	sp := int(data[3]) - 28
	dc := int(data[4]) - 28
	se := int(data[5]) - 28

	speedKnots := sp*10 + dc/10
	if speedKnots >= 800 {
		speedKnots -= 800
	}
	if speedKnots < 0 {
		speedKnots = 0
	}
	sv := float64(speedKnots) * 1.852
	speedKPH := &sv

	c := (dc%10)*100 + se
	if c >= 400 {
		c -= 400
	}
	if c < 0 {
		c = 0
	}
	course := &c

	return lon, speedKPH, course, true
}

func micELatDigit(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'A' && c <= 'J':
		return int(c - 'A'), true
	case c >= 'P' && c <= 'Y':
		return int(c - 'P'), true
	case c == 'K' || c == 'L' || c == 'Z':
		// Position ambiguity digit, use midpoint.
		return 5, true
	default:
		return 0, false
	}
}

func isMicENorth(c byte) bool { return c >= 'P' && c <= 'Z' }

func isMicELonOffset(c byte) bool { return c >= 'P' && c <= 'Z' }

func isMicEWest(c byte) bool { return c >= 'P' && c <= 'Z' }
