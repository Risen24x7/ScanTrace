// Package collector — UDP syslog listener.
//
// Binds a UDP socket on :514 (or configurable port) and pipes every received
// line through the AsusAdapter in real-time. This is the transport layer that
// bridges the router's syslog output to the ScanTrace event pipeline.
//
// The router must be configured to forward syslog to this host:
//   Administration → System → Syslog → Enable: Yes, Server IP: <this host>
//
// Received lines are written to the adapter exactly as TailFile does for
// file-based ingestion — same path, same dedup, same DB writes.
package collector

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/Risen24x7/scantrace/internal/db"
)

const (
	// DefaultSyslogPort is the standard syslog UDP port.
	DefaultSyslogPort = 514

	// maxSyslogPacket is the maximum UDP datagram we accept.
	// RFC 5424 recommends at least 480 bytes; 64KB covers iptables verbose output.
	maxSyslogPacket = 65536
)

// privateRanges holds RFC1918 + loopback + link-local prefixes.
// isExternal returns false for any IP that falls within these.
var privateRanges []*net.IPNet

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateRanges = append(privateRanges, block)
	}
}

// isExternal reports whether ip is a publicly routable address.
// Returns false for RFC1918, loopback, and link-local addresses.
func isExternal(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, block := range privateRanges {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

// SyslogServer listens on UDP and feeds received lines to an Adapter.
type SyslogServer struct {
	port    int
	store   *db.DB
	adapter Adapter
	done    chan struct{}
	conn    *net.UDPConn

	// Metrics — exported for /scantrace mcp status and Slack /status command.
	LinesReceived int64
	LinesParsed   int64
	LinesSkipped  int64
	Errors        int64
	StartedAt     time.Time
}

// NewSyslogServer creates a SyslogServer. Call Listen() to start receiving.
func NewSyslogServer(port int, store *db.DB, adapter Adapter) *SyslogServer {
	if port == 0 {
		port = DefaultSyslogPort
	}
	return &SyslogServer{
		port:      port,
		store:     store,
		adapter:   adapter,
		done:      make(chan struct{}),
		StartedAt: time.Now().UTC(),
	}
}

// Listen binds the UDP socket and starts the receive loop. Blocks until
// Close() is called or a fatal error occurs. Run in a goroutine.
func (s *SyslogServer) Listen() error {
	addr := &net.UDPAddr{Port: s.port, IP: net.ParseIP("0.0.0.0")}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		if s.port < 1024 {
			return fmt.Errorf(
				"syslog_server: cannot bind :%d (requires root or CAP_NET_BIND_SERVICE). "+
					"Either run as root, or use port 5140 and forward on the router: %w",
				s.port, err,
			)
		}
		return fmt.Errorf("syslog_server: bind :%d: %w", s.port, err)
	}
	s.conn = conn
	log.Printf("[syslog_server] listening on UDP :%d", s.port)

	buf := make([]byte, maxSyslogPacket)
	for {
		select {
		case <-s.done:
			return nil
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.done:
				return nil
			default:
				log.Printf("[syslog_server] read error from %s: %v", remote, err)
				s.Errors++
				continue
			}
		}

		raw := strings.TrimSpace(string(buf[:n]))
		if raw == "" {
			continue
		}
		s.LinesReceived++

		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			s.processLine(line, remote.IP.String())
		}
	}
}

func (s *SyslogServer) processLine(line, remoteIP string) {
	evt, err := s.adapter.Parse(line)
	if err != nil {
		s.LinesSkipped++
		return
	}
	if evt == nil {
		s.LinesSkipped++
		return
	}

	if evt.SrcIP == "" {
		evt.SrcIP = remoteIP
	}

	if err := s.store.InsertEvent(evt); err != nil {
		log.Printf("[syslog_server] db insert error: %v", err)
		s.Errors++
		return
	}
	s.LinesParsed++

	if evt.Direction == "inbound" && isExternal(evt.SrcIP) {
		log.Printf("[syslog_server] INBOUND %s src=%s dst=%s dport=%d proto=%s",
			evt.EventType, evt.SrcIP, evt.DstIP, evt.DstPort, evt.Protocol)
	}
}

// Close signals the receive loop to stop.
func (s *SyslogServer) Close() {
	close(s.done)
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

// Stats returns a human-readable status string for the /scantrace mcp command.
func (s *SyslogServer) Stats() string {
	uptime := time.Since(s.StartedAt).Round(time.Second)
	return fmt.Sprintf(
		"UDP syslog :%d | uptime=%s received=%d parsed=%d skipped=%d errors=%d",
		s.port, uptime, s.LinesReceived, s.LinesParsed, s.LinesSkipped, s.Errors,
	)
}
