package parquet

import (
	"path/filepath"
	"strconv"
	"testing"

	"github.com/pagpeter/trackme/pkg/types"
	pq "github.com/parquet-go/parquet-go"
)

func TestRowFromResponseRedactsIPs(t *testing.T) {
	res := types.Response{
		IP: "192.0.2.10:54321",
		TCPIP: types.TCPIPDetails{
			IP: types.IPDetails{
				SrcIP: "192.0.2.10",
				DstIp: "198.51.100.20",
			},
		},
	}

	row := rowFromResponse(res, false)
	if row.IP != "" || row.TCPIP.IP.SrcIP != "" || row.TCPIP.IP.DstIp != "" {
		t.Fatalf("IP logging disabled, got top-level=%q src=%q dst=%q", row.IP, row.TCPIP.IP.SrcIP, row.TCPIP.IP.DstIp)
	}
}

func TestRowFromResponsePreservesP0FAndTCPValues(t *testing.T) {
	if strconv.IntSize < 64 {
		t.Skip("TCP uint32 values require a 64-bit Go int")
	}

	high := int(uint32(0xf1234567))
	res := types.Response{
		TCPIP: types.TCPIPDetails{
			P0F: "4:47+?:0:1460:64240,8:mss,sok,ts,nop,ws:df,id+:0",
			TS:  []int{high},
			TCP: types.TCPDetails{
				Ack:                high,
				Seq:                high,
				Timestamp:          high,
				TimestampEchoReply: high,
			},
		},
	}

	row := rowFromResponse(res, false)
	if row.TCPIP.P0F != res.TCPIP.P0F {
		t.Fatalf("p0f=%q, want %q", row.TCPIP.P0F, res.TCPIP.P0F)
	}
	if row.TCPIP.TCP.Ack != int64(high) || row.TCPIP.TCP.Seq != int64(high) ||
		row.TCPIP.TCP.Timestamp != int64(high) || row.TCPIP.TCP.TimestampEchoReply != int64(high) {
		t.Fatalf("TCP values were not preserved: %+v", row.TCPIP.TCP)
	}
	if len(row.TCPIP.TS) != 1 || row.TCPIP.TS[0] != int64(high) {
		t.Fatalf("TS=%v, want [%d]", row.TCPIP.TS, high)
	}
}

func TestLoggerRoundTrip(t *testing.T) {
	dir := t.TempDir()
	l, err := New(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(types.Response{TCPIP: types.TCPIPDetails{P0F: "raw-p0f"}})
	l.Close()

	files, err := filepath.Glob(filepath.Join(dir, "*.parquet"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("got %d parquet files, want 1", len(files))
	}
	rows, err := pq.ReadFile[Row](files[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].TCPIP.P0F != "raw-p0f" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}
