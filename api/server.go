// Package api provides the HTTP REST + WebSocket API server.
package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"direwolf_api/aprs"
	"direwolf_api/ax25"
	"direwolf_api/kiss"
)

// ─── Data types ──────────────────────────────────────────────────────────────

// Packet is the enriched data structure stored and served by the API.
type Packet struct {
	ID        int64        `json:"id"`
	Timestamp time.Time    `json:"timestamp"`
	Port      byte         `json:"port"`
	RawHex    string       `json:"raw_hex"`
	Source    string       `json:"source,omitempty"`
	Dest      string       `json:"dest,omitempty"`
	Via       string       `json:"via,omitempty"`
	Path      string       `json:"path,omitempty"`
	PID       byte         `json:"pid,omitempty"`
	InfoRaw   string       `json:"info_raw,omitempty"`
	APRS      *aprs.Packet `json:"aprs,omitempty"`
	Error     string       `json:"error,omitempty"`
}

// Stats holds aggregate statistics about received packets.
type Stats struct {
	TotalPackets int64     `json:"total_packets"`
	TotalErrors  int64     `json:"total_errors"`
	StartTime    time.Time `json:"start_time"`
	Uptime       string    `json:"uptime"`
}

// ─── Server ───────────────────────────────────────────────────────────────────

// Server is the combined HTTP REST + WebSocket server.
type Server struct {
	addr       string
	tlsAddr    string
	certFile   string
	keyFile    string
	maxPackets int
	kiss       *kiss.Client

	mu      sync.RWMutex
	packets []*Packet
	pktByID map[int64]*Packet

	counter int64 // auto-increment packet ID
	total   int64
	errors  int64

	startTime time.Time

	wsMu      sync.Mutex
	wsClients map[*websocket.Conn]bool

	upgrader websocket.Upgrader
}

// NewServer creates a new Server.
func NewServer(addr, tlsAddr, certFile, keyFile string, maxPackets int, kissClient *kiss.Client) *Server {
	return &Server{
		addr:       addr,
		tlsAddr:    tlsAddr,
		certFile:   certFile,
		keyFile:    keyFile,
		maxPackets: maxPackets,
		kiss:       kissClient,
		wsClients:  make(map[*websocket.Conn]bool),
		pktByID:   make(map[int64]*Packet),
		startTime:  time.Now(),
		upgrader: websocket.Upgrader{
			// Accept all origins (add your own check in production)
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

// Start begins processing frames and listening for HTTP connections.
// It blocks until the context is cancelled.
func (s *Server) Start(ctx context.Context) error {
	go s.processFrames(ctx)

	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/packets", s.handlePackets)
	mux.HandleFunc("/api/packets/", s.handlePacket)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/ws", s.handleWS)

	srv := &http.Server{
		Addr:         s.addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()

	if s.tlsAddr != "" {
		tlsSrv := &http.Server{
			Addr:         s.tlsAddr,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  120 * time.Second,
		}
		go func() {
			var tlsCfg *tls.Config
			if s.certFile != "" && s.keyFile != "" {
				cert, err := tls.LoadX509KeyPair(s.certFile, s.keyFile)
				if err != nil {
					log.Printf("[TLS] failed to load cert/key: %v", err)
					return
				}
				tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
			} else {
				var err error
				tlsCfg, err = selfSignedTLS()
				if err != nil {
					log.Printf("[TLS] failed to generate self-signed cert: %v", err)
					return
				}
				log.Printf("[TLS] self-signed certificate generated")
				log.Printf("[TLS] *** Open https://localhost%s in your browser and accept the security exception before connecting ***", s.tlsAddr)
			}
			tlsSrv.ErrorLog = log.New(&tlsHandshakeFilter{log.Writer()}, "", log.LstdFlags)
			ln, err := tls.Listen("tcp", s.tlsAddr, tlsCfg)
			if err != nil {
				log.Printf("[TLS] listen error: %v", err)
				return
			}
			go func() {
				<-ctx.Done()
				tlsSrv.Close()
			}()
			log.Printf("WSS/HTTPS : https://localhost%s", s.tlsAddr)
			if err := tlsSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Printf("[TLS] error: %v", err)
			}
		}()
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// ─── Frame processing ─────────────────────────────────────────────────────────

func (s *Server) processFrames(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case frame, ok := <-s.kiss.Frames():
			if !ok {
				return
			}
			s.ingest(frame)
		}
	}
}

func (s *Server) ingest(frame kiss.Frame) {
	id := atomic.AddInt64(&s.counter, 1)
	pkt := &Packet{
		ID:        id,
		Timestamp: time.Now(),
		Port:      frame.Port,
		RawHex:    hex.EncodeToString(frame.Data),
	}

	ax25Frame, err := ax25.Decode(frame.Data)
	if err != nil {
		pkt.Error = fmt.Sprintf("AX.25: %v", err)
		atomic.AddInt64(&s.errors, 1)
	} else {
		pkt.Source = ax25Frame.Source.String()
		pkt.Dest = ax25Frame.Destination.String()
		pkt.Via = ax25Frame.Via()
		pkt.Path = ax25Frame.Path()
		pkt.PID = ax25Frame.PID
		pkt.InfoRaw = string(ax25Frame.Info)

		// APRS uses UI frames with PID 0xF0 (no layer 3)
		if ax25Frame.Type == "UI" && ax25Frame.PID == 0xF0 {
			pkt.APRS = aprs.Decode(ax25Frame.Info, pkt.Source, pkt.Dest)
		}
	}

	atomic.AddInt64(&s.total, 1)
	log.Printf("[PKT #%d] %-9s  %s  %s", pkt.ID, pkt.Source, pkt.Path, pkt.InfoRaw)

	s.mu.Lock()
	s.packets = append(s.packets, pkt)
	s.pktByID[pkt.ID] = pkt
	if len(s.packets) > s.maxPackets {
		removed := s.packets[:len(s.packets)-s.maxPackets]
		for _, old := range removed {
			delete(s.pktByID, old.ID)
		}
		s.packets = s.packets[len(s.packets)-s.maxPackets:]
	}
	s.mu.Unlock()

	s.broadcast(pkt)
}

// ─── WebSocket broadcast ──────────────────────────────────────────────────────

func (s *Server) broadcast(pkt *Packet) {
	data, err := json.Marshal(pkt)
	if err != nil {
		log.Printf("[WS] marshal error: %v", err)
		return
	}
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	for conn := range s.wsClients {
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			conn.Close()
			delete(s.wsClients, conn)
		}
	}
}

// ─── TLS helpers ─────────────────────────────────────────────────────────────

// tlsHandshakeFilter is an io.Writer that drops TLS handshake error lines
// (expected noise when a browser hasn't yet accepted a self-signed cert).
type tlsHandshakeFilter struct{ w interface{ Write([]byte) (int, error) } }

func (f tlsHandshakeFilter) Write(p []byte) (int, error) {
	if bytes.Contains(p, []byte("TLS handshake error")) {
		return len(p), nil
	}
	return f.w.Write(p)
}

// selfSignedTLS generates an in-memory self-signed ECDSA certificate valid for
// localhost / 127.0.0.1 for one year.
func selfSignedTLS() (*tls.Config, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"direwolf_api"}},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  priv,
		}},
	}, nil
}

// ─── HTTP handlers ────────────────────────────────────────────────────────────

func jsonHeader(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

// GET /api/packets?limit=N&offset=N
func (s *Server) handlePackets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 100
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(q.Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	s.mu.RLock()
	all := s.packets
	s.mu.RUnlock()

	// Return newest-first
	result := make([]*Packet, 0, limit)
	for i := len(all) - 1 - offset; i >= 0 && len(result) < limit; i-- {
		result = append(result, all[i])
	}

	jsonHeader(w)
	json.NewEncoder(w).Encode(map[string]any{
		"packets": result,
		"total":   len(all),
		"limit":   limit,
		"offset":  offset,
	})
}

// GET /api/packets/{id}
func (s *Server) handlePacket(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Path[len("/api/packets/"):]
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	s.mu.RLock()
	found := s.pktByID[id]
	s.mu.RUnlock()
	if found == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	jsonHeader(w)
	json.NewEncoder(w).Encode(found)
}

// GET /api/stats
func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(s.startTime)
	jsonHeader(w)
	json.NewEncoder(w).Encode(Stats{
		TotalPackets: atomic.LoadInt64(&s.total),
		TotalErrors:  atomic.LoadInt64(&s.errors),
		StartTime:    s.startTime,
		Uptime:       uptime.Round(time.Second).String(),
	})
}

// GET /api/status
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	state := s.kiss.State()
	stateStr := []string{"disconnected", "connecting", "connected"}[state]
	jsonHeader(w)
	json.NewEncoder(w).Encode(map[string]any{
		"status": stateStr,
		"addr":   s.kiss.Addr(),
	})
}

// GET /ws – WebSocket endpoint
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[WS] upgrade error: %v", err)
		return
	}

	s.wsMu.Lock()
	s.wsClients[conn] = true
	s.wsMu.Unlock()
	log.Printf("[WS] client connected: %s", conn.RemoteAddr())

	// Replay last 50 packets so the UI is populated immediately
	s.mu.RLock()
	replay := s.packets
	if len(replay) > 50 {
		replay = replay[len(replay)-50:]
	}
	s.mu.RUnlock()
	for _, pkt := range replay {
		data, err := json.Marshal(pkt)
		if err != nil {
			log.Printf("[WS] replay marshal error: %v", err)
			continue
		}
		conn.WriteMessage(websocket.TextMessage, data)
	}

	// Keep reading to detect disconnection
	for {
		if _, _, err := conn.ReadMessage(); err != nil {
			break
		}
	}

	s.wsMu.Lock()
	delete(s.wsClients, conn)
	s.wsMu.Unlock()
	conn.Close()
	log.Printf("[WS] client disconnected: %s", conn.RemoteAddr())
}

// GET / – Web UI
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, indexHTML)
}

// ─── Embedded Web UI ─────────────────────────────────────────────────────────

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Direwolf API</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Courier New',monospace;background:#0d1117;color:#c9d1d9;height:100vh;display:flex;flex-direction:column}
header{background:#161b22;border-bottom:1px solid #30363d;padding:10px 16px;display:flex;align-items:center;gap:12px;flex-shrink:0}
header h1{font-size:1.1em;color:#58a6ff}
#badge{padding:3px 10px;border-radius:12px;font-size:.78em;font-weight:700}
.connected{background:#1a4731;color:#3fb950}
.connecting{background:#3d2f00;color:#d29922}
.disconnected{background:#3d0000;color:#f85149}
.hdr-stats{display:flex;gap:16px;font-size:.8em;color:#8b949e;margin-left:auto}
.hdr-stats b{color:#c9d1d9}
main{display:flex;flex:1;min-height:0;--right-w:360px;--list-h:55%}
#map-pane{flex:1;min-width:200px;background:#1a1a2e;position:relative;overflow:hidden}
#map{width:100%;height:100%}
#split-v{cursor:col-resize;width:4px;background:#30363d;flex-shrink:0;transition:background .15s}
#split-v:hover,#split-v.active{background:#58a6ff}
#right-pane{width:var(--right-w);min-width:200px;display:flex;flex-direction:column;flex-shrink:0}
#list-pane{overflow-y:auto;height:var(--list-h);min-height:80px}
#split-h{cursor:row-resize;height:4px;background:#30363d;flex-shrink:0;transition:background .15s}
#split-h:hover,#split-h.active{background:#58a6ff}
#detail{padding:14px;overflow-y:auto;background:#0d1117;font-size:.82em;flex:1;min-height:60px}
#no-sel{color:#8b949e;text-align:center;padding-top:20px}
.sec{margin-bottom:14px}
.sec-title{font-size:.72em;color:#8b949e;text-transform:uppercase;letter-spacing:.05em;border-bottom:1px solid #21262d;padding-bottom:3px;margin-bottom:7px}
.kv{display:flex;gap:6px;margin-bottom:3px}
.k{color:#8b949e;min-width:96px;flex-shrink:0}
.v{color:#c9d1d9;word-break:break-all}
#hex{font-size:.73em;color:#8b949e;word-break:break-all;background:#161b22;padding:8px;border-radius:4px;line-height:1.6;white-space:pre-wrap}
</style>
</head>
<body>
<header>
  <h1>&#x1F43A; Direwolf API</h1>
  <span id="badge" class="disconnected">Disconnected</span>
  <div class="hdr-stats">
    <span>Packets: <b id="s-total">0</b></span>
    <span>Errors: <b id="s-err">0</b></span>
    <span>Uptime: <b id="s-up">-</b></span>
  </div>
</header>
<main>
  <div id="map-pane"><div id="map"></div></div>
  <div id="split-v"></div>
  <div id="right-pane">
    <div id="list-pane">
      <table>
        <thead><tr>
          <th class="c-id">#</th>
          <th class="c-time">Time</th>
          <th class="c-src">Source</th>
          <th class="c-dst">Dest</th>
          <th class="c-type">Type</th>
          <th class="c-info">Info</th>
        </tr></thead>
        <tbody id="tbody"></tbody>
      </table>
    </div>
    <div id="split-h"></div>
    <div id="detail"><div id="no-sel">Select a packet to inspect it</div><div id="dc" style="display:none"></div></div>
  </div>
</main>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const MAX=300;
let db={};
let selId=null;
const badge=document.getElementById('badge');
const tbody=document.getElementById('tbody');
const dc=document.getElementById('dc');

const map=L.map('map',{zoomControl:true}).setView([48.8,2.3],5);
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{
  attribution:'&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a>',
  maxZoom:19
}).addTo(map);
(function initSplits(){
  const main=document.querySelector('main');
  function drag(el, vertical, cb){
    let active=false;
    el.addEventListener('mousedown',e=>{e.preventDefault();active=true;el.classList.add('active');});
    document.addEventListener('mousemove',e=>{if(!active)return;cb(e,vertical);});
    document.addEventListener('mouseup',()=>{active=false;el.classList.remove('active');map.invalidateSize();});
  }
  drag(document.getElementById('split-v'),true,(e)=>{
    const rect=main.getBoundingClientRect();
    const x=Math.max(200,Math.min(e.clientX-rect.left,rect.width-200));
    main.style.setProperty('--right-w',(rect.width-x)+'px');
  });
  drag(document.getElementById('split-h'),false,(e)=>{
    const rp=document.getElementById('right-pane');
    const rect=rp.getBoundingClientRect();
    const y=Math.max(80,Math.min(e.clientY-rect.top,rect.height-60));
    rp.style.setProperty('--list-h',((y/rect.height)*100)+'%');
  });
})();
const markers={};
const MARKER_COLORS={
  'position':'#3fb950','mic-e':'#ff79c6','weather':'#bc8cff',
  'object':'#d29922','item':'#d29922','status':'#58a6ff',
  'message':'#8b949e','telemetry':'#8b949e','nmea':'#8b949e'
};
function markerColor(typ){return MARKER_COLORS[typ]||'#8b949e';}
function addMarker(p){
  if(!p.aprs||!p.aprs.position)return;
  const lat=p.aprs.position.lat,lon=p.aprs.position.lon;
  if(isNaN(lat)||isNaN(lon))return;
  if(markers[p.id]){markers[p.id].setLatLng([lat,lon]);return;}
  const color=markerColor(p.aprs.type);
  const m=L.circleMarker([lat,lon],{radius:6,color:'#fff',weight:1.5,fillColor:color,fillOpacity:.85}).addTo(map);
  m.bindPopup('<b>'+esc(p.source||'?')+'</b><br>'+esc(p.aprs.type)+'<br>'+lat.toFixed(4)+' '+lon.toFixed(4));
  m.on('click',()=>inspect(p.id));
  markers[p.id]=m;
  const ids=Object.keys(markers).map(Number);
  if(ids.length>MAX){
    ids.sort((a,b)=>a-b);
    for(let i=0;i<ids.length-MAX;i++){map.removeLayer(markers[ids[i]]);delete markers[ids[i]];}
  }
}
function fitMap(){
  const pts=[];
  for(const k in markers)pts.push(markers[k].getLatLng());
  if(pts.length>0){
    const bounds=L.latLngBounds(pts);
    if(pts.length===1)map.setView(bounds.getCenter(),13);
    else map.fitBounds(bounds.pad(.1));
  }
}
let fitTmr=null;
function debounceFit(){
  clearTimeout(fitTmr);
  fitTmr=setTimeout(fitMap,500);
}

function connect(){
  const proto=location.protocol==='https:'?'wss:':'ws:';
  const ws=new WebSocket(proto+'//'+location.host+'/ws');
  ws.onopen=()=>setBadge('connected','Connected');
  ws.onclose=()=>{setBadge('disconnected','Disconnected');setTimeout(connect,3000);};
  ws.onmessage=e=>{addPkt(JSON.parse(e.data));refreshStats();};
}

function setBadge(cls,txt){badge.className=cls;badge.textContent=txt;}

function addPkt(p){
  db[p.id]=p;
  let row=document.getElementById('r'+p.id);
  if(!row){
    row=document.createElement('tr');
    row.id='r'+p.id;
    row.className='row new';
    row.onclick=()=>inspect(p.id);
    tbody.insertBefore(row,tbody.firstChild);
    while(tbody.children.length>MAX)tbody.removeChild(tbody.lastChild);
  }
  const t=new Date(p.timestamp).toLocaleTimeString();
  const typ=p.aprs?p.aprs.type:(p.error?'error':'raw');
  row.innerHTML=
    '<td class="c-id">'+p.id+'</td>'+
    '<td class="c-time">'+t+'</td>'+
    '<td class="c-src">'+esc(p.source||'?')+'</td>'+
    '<td class="c-dst">'+esc(p.dest||'?')+'</td>'+
    '<td class="c-type"><span class="badge '+typ+'">'+esc(typ)+'</span></td>'+
    '<td class="c-info">'+esc(summary(p))+'</td>';
  if(selId===p.id)inspect(p.id);
  addMarker(p);
  debounceFit();
}

function summary(p){
  if(p.error)return'['+p.error+']';
  if(!p.aprs)return p.info_raw||'';
  const a=p.aprs;
  if(a.position){let s='lat='+a.position.lat.toFixed(4)+' lon='+a.position.lon.toFixed(4);if(a.position.comment)s+=' '+a.position.comment;return s;}
  if(a.message)return'To:'+a.message.addressee+' "'+a.message.text+'"';
  if(a.status)return a.status;
  if(a.comment)return a.comment;
  return a.raw||'';
}

function inspect(id){
  selId=id;
  document.querySelectorAll('tr.row').forEach(r=>r.classList.remove('sel'));
  const row=document.getElementById('r'+id);
  if(row)row.classList.add('sel');
  const p=db[id];if(!p)return;
  document.getElementById('no-sel').style.display='none';
  dc.style.display='block';

  let h='<div class="sec"><div class="sec-title">AX.25 Frame</div>';
  h+=kv('#',p.id)+kv('Time',new Date(p.timestamp).toLocaleString());
  h+=kv('Port',p.port)+kv('Source',p.source||'-')+kv('Dest',p.dest||'-');
  if(p.via)h+=kv('Via',p.via);
  if(p.path)h+=kv('Path',p.path);
  if(p.pid!=null)h+=kv('PID','0x'+p.pid.toString(16).toUpperCase().padStart(2,'0'));
  if(p.error)h+=kv('Error','<span style="color:#f85149">'+esc(p.error)+'</span>');
  h+='</div>';

  if(p.info_raw){
    h+='<div class="sec"><div class="sec-title">Info Field</div>';
    h+='<div class="v" style="word-break:break-all">'+esc(p.info_raw)+'</div></div>';
  }

  if(p.aprs){
    const a=p.aprs;
    h+='<div class="sec"><div class="sec-title">APRS &mdash; '+a.type+'</div>';
    if(a.timestamp)h+=kv('Timestamp',new Date(a.timestamp).toLocaleString());
    if(a.position){
      const pos=a.position;
      h+=kv('Latitude',pos.lat.toFixed(6)+'&deg;');
      h+=kv('Longitude',pos.lon.toFixed(6)+'&deg;');
      h+=kv('Symbol',esc(pos.symbol));
      if(pos.speed!=null)h+=kv('Speed',pos.speed.toFixed(1)+' km/h');
      if(pos.course!=null)h+=kv('Course',pos.course+'&deg;');
      if(pos.altitude!=null)h+=kv('Altitude',pos.altitude.toFixed(0)+' m');
      if(pos.comment)h+=kv('Comment',esc(pos.comment));
    }
    if(a.message){
      h+=kv('Addressee',esc(a.message.addressee));
      if(a.message.is_ack)h+=kv('Type','ACK');
      else if(a.message.is_rej)h+=kv('Type','REJ');
      else h+=kv('Text',esc(a.message.text));
      if(a.message.msg_id)h+=kv('Msg ID',esc(a.message.msg_id));
    }
    if(a.status)h+=kv('Status',esc(a.status));
    if(a.weather){
      const w=a.weather;
      if(w.temp!=null)h+=kv('Temperature',w.temp.toFixed(1)+' &deg;C');
      if(w.wind_speed!=null)h+=kv('Wind',w.wind_speed.toFixed(1)+' km/h');
      if(w.wind_dir!=null)h+=kv('Wind Dir',w.wind_dir+'&deg;');
      if(w.wind_gust!=null)h+=kv('Gust',w.wind_gust.toFixed(1)+' km/h');
      if(w.humidity!=null)h+=kv('Humidity',w.humidity+'%');
      if(w.pressure!=null)h+=kv('Pressure',w.pressure.toFixed(1)+' hPa');
      if(w.rain_hour!=null)h+=kv('Rain/h',w.rain_hour.toFixed(2)+' mm');
    }
    if(a.telemetry)h+=kv('Telemetry',esc(a.telemetry));
    if(a.comment)h+=kv('Comment',esc(a.comment));
    h+='</div>';
  }

  h+='<div class="sec"><div class="sec-title">Raw Frame (hex)</div>';
  h+='<div id="hex">'+fmtHex(p.raw_hex)+'</div></div>';
  dc.innerHTML=h;
  for(const k in markers)markers[k].setStyle({radius:6,weight:1.5});
  if(markers[id]){markers[id].setStyle({radius:10,weight:3});map.panTo(markers[id].getLatLng());}
}

function fmtHex(h){
  let r='',i=0;
  for(;i<h.length;i+=2){
    if(i>0&&i%32===0)r+='\n';
    else if(i>0)r+=' ';
    r+=h[i]+h[i+1];
  }
  return r;
}

function kv(k,v){return'<div class="kv"><span class="k">'+esc(k)+'</span><span class="v">'+v+'</span></div>';}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}

function refreshStats(){
  fetch('/api/stats').then(r=>r.json()).then(s=>{
    document.getElementById('s-total').textContent=s.total_packets;
    document.getElementById('s-err').textContent=s.total_errors;
    document.getElementById('s-up').textContent=s.uptime;
  });
}

connect();
setInterval(refreshStats,5000);
</script>
</body>
</html>`
