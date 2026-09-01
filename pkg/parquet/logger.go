// Package parquet persists captured request fingerprints to Parquet files.
package parquet

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pagpeter/trackme/pkg/types"
	pq "github.com/parquet-go/parquet-go"
)

// Row is the schema written to Parquet. It captures the useful fingerprints
// rather than the full nested Response (whose TLS extension list does not map
// cleanly onto a columnar schema).
type Row struct {
	Timestamp   int64  `parquet:"timestamp"`
	IP          string `parquet:"ip"`
	HTTPVersion string `parquet:"http_version"`
	Method      string `parquet:"method"`
	Path        string `parquet:"path"`
	JA3         string `parquet:"ja3"`
	JA4         string `parquet:"ja4"`
	JA4R        string `parquet:"ja4_r"`
	PeetPrint   string `parquet:"peetprint"`
	Akamai      string `parquet:"akamai"`
	// Headers holds the request headers in wire order, each as "name: value".
	Headers []string `parquet:"headers"`
	// TCPIP holds the full TCP/IP fingerprint, when one was captured for the IP.
	TCPIP TCPIP `parquet:"tcpip"`
}

// TCPIP mirrors types.TCPIPDetails with Parquet-friendly column names.
type TCPIP struct {
	CapLen    int32   `parquet:"cap_length"`
	DstPort   int32   `parquet:"dst_port"`
	SrcPort   int32   `parquet:"src_port"`
	HeaderLen int32   `parquet:"header_length"`
	TS        []int64 `parquet:"ts"`
	IP        IP      `parquet:"ip"`
	TCP       TCP     `parquet:"tcp"`
	P0F       string  `parquet:"p0f"`
}

// IP mirrors types.IPDetails.
type IP struct {
	DF          int32  `parquet:"df"`
	HDRLength   int32  `parquet:"hdr_length"`
	ID          int32  `parquet:"id"`
	MF          int32  `parquet:"mf"`
	NXT         int32  `parquet:"nxt"`
	OFF         int32  `parquet:"off"`
	PLEN        int32  `parquet:"plen"`
	Protocol    int32  `parquet:"protocol"`
	RF          int32  `parquet:"rf"`
	TOS         int32  `parquet:"tos"`
	TotalLength int32  `parquet:"total_length"`
	TTL         int32  `parquet:"ttl"`
	IPVersion   int32  `parquet:"ip_version"`
	DstIp       string `parquet:"dst_ip"`
	SrcIP       string `parquet:"src_ip"`
}

// TCP mirrors types.TCPDetails.
type TCP struct {
	Ack                int64  `parquet:"ack"`
	Checksum           int64  `parquet:"checksum"`
	Flags              int64  `parquet:"flags"`
	HeaderLength       int64  `parquet:"header_length"`
	MSS                int64  `parquet:"mss"`
	OFF                int64  `parquet:"off"`
	Options            string `parquet:"options"`
	OptionsOrder       string `parquet:"options_order"`
	Seq                int64  `parquet:"seq"`
	Timestamp          int64  `parquet:"timestamp"`
	TimestampEchoReply int64  `parquet:"timestamp_echo_reply"`
	URP                int64  `parquet:"urp"`
	Window             int64  `parquet:"window"`
}

const (
	// channelBuffer is how many rows can queue before logging starts dropping
	// them. Dropping (rather than blocking) keeps request handling fast even if
	// disk writes stall.
	channelBuffer = 4096
	// batchSize triggers a row-group flush once this many rows have accumulated.
	batchSize = 500
	// flushInterval forces a row-group flush even when batchSize is not reached,
	// so low-traffic data lands on disk without waiting for shutdown.
	flushInterval = 3 * time.Minute
)

// Logger persists Rows to a single Parquet file per run. Row groups are
// flushed periodically so data reaches disk without waiting for shutdown, but
// the file footer (needed for readers) is only written on Close.
type Logger struct {
	dir    string
	logIPs bool

	ch   chan Row
	done chan struct{}
	wg   sync.WaitGroup
}

// New creates and starts a Logger writing to dir. The directory is created if it
// does not exist.
func New(dir string, logIPs bool) (*Logger, error) {
	if dir == "" {
		dir = "data"
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create parquet dir %q: %w", dir, err)
	}

	l := &Logger{
		dir:    dir,
		logIPs: logIPs,
		ch:     make(chan Row, channelBuffer),
		done:   make(chan struct{}),
	}
	l.wg.Add(1)
	go l.run()
	return l, nil
}

// Log enqueues a captured Response. It never blocks: if the buffer is full the
// row is dropped and a warning is logged.
func (l *Logger) Log(res types.Response) {
	if l == nil {
		return
	}
	row := rowFromResponse(res, l.logIPs)
	select {
	case l.ch <- row:
	default:
		log.Println("parquet: buffer full, dropping row")
	}
}

// Close flushes any buffered rows and stops the background goroutine.
func (l *Logger) Close() {
	if l == nil {
		return
	}
	close(l.done)
	l.wg.Wait()
}

func rowFromResponse(res types.Response, logIPs bool) Row {
	row := Row{
		Timestamp:   time.Now().UnixNano(),
		HTTPVersion: res.HTTPVersion,
		Method:      res.Method,
		Path:        res.Path,
	}
	if logIPs {
		row.IP = res.IP
	}
	if res.TLS != nil {
		row.JA3 = res.TLS.JA3
		row.JA4 = res.TLS.JA4
		row.JA4R = res.TLS.JA4_r
		row.PeetPrint = res.TLS.PeetPrint
	}
	if res.HTTPVersion == "h2" && res.Http2 != nil {
		row.Akamai = res.Http2.AkamaiFingerprint
	} else if res.HTTPVersion == "h3" && res.Http3 != nil {
		row.Akamai = res.Http3.AkamaiFingerprint
	}
	row.Headers = orderedHeaders(res)
	row.TCPIP = tcpipFromResponse(res.TCPIP, logIPs)
	return row
}

// orderedHeaders returns the request headers in the order they were sent, as
// "name: value" strings, regardless of the protocol version.
func orderedHeaders(res types.Response) []string {
	switch res.HTTPVersion {
	case "h2":
		if res.Http2 != nil {
			for _, f := range res.Http2.SendFrames {
				if f.Type == "HEADERS" && len(f.Headers) > 0 {
					return f.Headers
				}
			}
		}
	case "h3":
		if res.Http3 != nil {
			return res.Http3.Headers
		}
	default:
		if res.Http1 != nil {
			return res.Http1.Headers
		}
	}
	return nil
}

func tcpipFromResponse(d types.TCPIPDetails, logIPs bool) TCPIP {
	ts := make([]int64, len(d.TS))
	for i, v := range d.TS {
		ts[i] = int64(v)
	}
	result := TCPIP{
		CapLen:    int32(d.CapLen),
		DstPort:   int32(d.DstPort),
		SrcPort:   int32(d.SrcPort),
		HeaderLen: int32(d.HeaderLen),
		TS:        ts,
		P0F:       d.P0F,
		IP: IP{
			DF:          int32(d.IP.DF),
			HDRLength:   int32(d.IP.HDRLength),
			ID:          int32(d.IP.ID),
			MF:          int32(d.IP.MF),
			NXT:         int32(d.IP.NXT),
			OFF:         int32(d.IP.OFF),
			PLEN:        int32(d.IP.PLEN),
			Protocol:    int32(d.IP.Protocol),
			RF:          int32(d.IP.RF),
			TOS:         int32(d.IP.TOS),
			TotalLength: int32(d.IP.TotalLength),
			TTL:         int32(d.IP.TTL),
			IPVersion:   int32(d.IP.IPVersion),
		},
		TCP: TCP{
			Ack:                int64(d.TCP.Ack),
			Checksum:           int64(d.TCP.Checksum),
			Flags:              int64(d.TCP.Flags),
			HeaderLength:       int64(d.TCP.HeaderLength),
			MSS:                int64(d.TCP.MSS),
			OFF:                int64(d.TCP.OFF),
			Options:            d.TCP.Options,
			OptionsOrder:       d.TCP.OptionsOrder,
			Seq:                int64(d.TCP.Seq),
			Timestamp:          int64(d.TCP.Timestamp),
			TimestampEchoReply: int64(d.TCP.TimestampEchoReply),
			URP:                int64(d.TCP.URP),
			Window:             int64(d.TCP.Window),
		},
	}
	if logIPs {
		result.IP.DstIp = d.IP.DstIp
		result.IP.SrcIP = d.IP.SrcIP
	}
	return result
}

func (l *Logger) run() {
	defer l.wg.Done()

	ticker := time.NewTicker(flushInterval)
	defer ticker.Stop()

	buf := make([]Row, 0, batchSize)

	// Open a single file for this run; close it on exit.
	name := fmt.Sprintf("trackme-%d.parquet", time.Now().UnixNano())
	path := filepath.Join(l.dir, name)
	f, err := os.Create(path)
	if err != nil {
		log.Println("parquet: failed to create file:", err)
		return
	}
	w := pq.NewGenericWriter[Row](f, pq.Compression(&pq.Snappy))

	closeWriter := func() {
		if err := w.Close(); err != nil {
			log.Println("parquet: failed to close writer:", err)
		}
		if err := f.Close(); err != nil {
			log.Println("parquet: failed to close file:", err)
		}
	}
	defer closeWriter()

	// flushRowGroup writes buffered rows as a row group and clears the buffer.
	// The file footer is not written until closeWriter, so the file is not yet
	// readable by external tools — but the row-group bytes are on disk.
	flushRowGroup := func() {
		if len(buf) == 0 {
			return
		}
		if _, err := w.Write(buf); err != nil {
			log.Println("parquet: failed to write rows:", err)
		} else if err := w.Flush(); err != nil {
			log.Println("parquet: failed to flush row group:", err)
		}
		buf = buf[:0]
	}

	for {
		select {
		case row := <-l.ch:
			buf = append(buf, row)
			if len(buf) >= batchSize {
				flushRowGroup()
			}
		case <-ticker.C:
			flushRowGroup()
		case <-l.done:
			for {
				select {
				case row := <-l.ch:
					buf = append(buf, row)
				default:
					flushRowGroup()
					return
				}
			}
		}
	}
}
