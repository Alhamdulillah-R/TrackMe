package server

import (
	"log"
	"strings"
	"sync"
	"time"

	"github.com/pagpeter/trackme/pkg/parquet"
	"github.com/pagpeter/trackme/pkg/types"
)

const (
	maxTCPSynFingerprints = 10_000
	tcpSynFingerprintTTL  = 10 * time.Second
)

// State holds all the global state previously scattered across the application
type State struct {
	Config             *types.Config
	TCPFingerprints    sync.Map
	TCPSynFingerprints sync.Map
	tcpSynSlots        chan struct{}
	tcpSynTTL          time.Duration
	Local              bool
	Parquet            *parquet.Logger
}

type storedTCPSyn struct {
	details    types.TCPSynDetails
	p0f        string
	capturedAt time.Time
	expiresAt  time.Time
}

// Server provides access to shared state and functionality
type Server struct {
	State *State
}

// NewServer creates a new server instance with initialized state
func NewServer() *Server {
	return newServerWithTCPSynLimits(maxTCPSynFingerprints, tcpSynFingerprintTTL)
}

func newServerWithTCPSynLimits(limit int, ttl time.Duration) *Server {
	return &Server{
		State: &State{
			Config:             &types.Config{},
			TCPFingerprints:    sync.Map{},
			TCPSynFingerprints: sync.Map{},
			tcpSynSlots:        make(chan struct{}, limit),
			tcpSynTTL:          ttl,
		},
	}
}

// GetConfig returns the loaded configuration
func (s *Server) GetConfig() *types.Config {
	return s.State.Config
}

// InitParquet starts the Parquet logger if enabled in the config. It must be
// called after the config has been loaded.
func (s *Server) InitParquet() {
	if !s.State.Config.LogToParquet {
		return
	}
	l, err := parquet.New(s.State.Config.ParquetDir, s.State.Config.ParquetLogIPs)
	if err != nil {
		log.Println("Failed to start parquet logger:", err)
		return
	}
	s.State.Parquet = l
	log.Println("Logging captured fingerprints to parquet dir:", s.State.Config.ParquetDir)
}

// LogParquet persists a captured response if the Parquet logger is enabled.
func (s *Server) LogParquet(res types.Response) {
	s.State.Parquet.Log(res)
}

// CloseParquet flushes and stops the Parquet logger.
func (s *Server) CloseParquet() {
	s.State.Parquet.Close()
}

// GetTCPFingerprints returns the TCP fingerprints map
func (s *Server) GetTCPFingerprints() *sync.Map {
	return &s.State.TCPFingerprints
}

// StoreTCPSyn records an inbound SYN under the same remote-address string that
// net.Conn.RemoteAddr returns, allowing the HTTP handler to claim it later.
func (s *Server) StoreTCPSyn(remoteAddr string, details types.TCPSynDetails, p0f string) {
	select {
	case s.State.tcpSynSlots <- struct{}{}:
	default:
		return
	}

	now := time.Now()
	stored := &storedTCPSyn{
		details:    details,
		p0f:        p0f,
		capturedAt: now,
		expiresAt:  now.Add(s.State.tcpSynTTL),
	}

	// Preserve the first SYN when the client retransmits the same connection.
	if _, loaded := s.State.TCPSynFingerprints.LoadOrStore(remoteAddr, stored); loaded {
		s.releaseTCPSynSlot()
		return
	}

	time.AfterFunc(s.State.tcpSynTTL, func() {
		if s.State.TCPSynFingerprints.CompareAndDelete(remoteAddr, stored) {
			s.releaseTCPSynSlot()
		}
	})
}

// TakeTCPSyn returns and removes the SYN for one accepted connection.
func (s *Server) TakeTCPSyn(remoteAddr string) (types.TCPSynDetails, string, bool) {
	v, ok := s.State.TCPSynFingerprints.LoadAndDelete(remoteAddr)
	if !ok {
		return types.TCPSynDetails{}, "", false
	}
	s.releaseTCPSynSlot()
	stored, ok := v.(*storedTCPSyn)
	if !ok || time.Now().After(stored.expiresAt) {
		return types.TCPSynDetails{}, "", false
	}
	return stored.details, stored.p0f, true
}

// PruneTCPSyn removes SYNs that never reached the HTTP handler (failed TLS
// handshakes, scans, and abandoned connections).
func (s *Server) PruneTCPSyn(before time.Time) {
	s.State.TCPSynFingerprints.Range(func(key, value any) bool {
		stored, ok := value.(*storedTCPSyn)
		if !ok || stored.capturedAt.Before(before) {
			if s.State.TCPSynFingerprints.CompareAndDelete(key, value) {
				s.releaseTCPSynSlot()
			}
		}
		return true
	})
}

func (s *Server) releaseTCPSynSlot() {
	select {
	case <-s.State.tcpSynSlots:
	default:
	}
}

// GetAdmin returns the CORS key configuration
func (s *Server) GetAdmin() (string, bool) {
	return s.State.Config.CorsKey, s.State.Config.CorsKey != ""
}

// GetUserAgent extracts the user agent from a response
func GetUserAgent(res types.Response) string {
	var headers []string
	var ua string

	if res.HTTPVersion == "h2" {
		return res.UserAgent
	} else {
		if res.Http1 == nil {
			return ""
		}
		headers = res.Http1.Headers
	}

	for _, header := range headers {
		lower := strings.ToLower(header)
		if strings.HasPrefix(lower, "user-agent: ") {
			ua = strings.Split(header, ": ")[1]
		}
	}

	return ua
}

// SetLocal sets the local development flag
func (s *Server) SetLocal(local bool) {
	s.State.Local = local
}

// IsLocal returns whether we're running in local development mode
func (s *Server) IsLocal() bool {
	return s.State.Local
}
