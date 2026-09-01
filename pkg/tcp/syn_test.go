package tcp

import (
	"net"
	"reflect"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func TestParseTCPSynIPv4(t *testing.T) {
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      47,
		Id:       12345,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.IPv4(192, 0, 2, 10),
		DstIP:    net.IPv4(198, 51, 100, 20),
	}
	tcp := &layers.TCP{
		SrcPort: 54321,
		DstPort: 443,
		Seq:     123456,
		SYN:     true,
		Window:  64240,
		Options: []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindSACKPermitted},
			{OptionType: layers.TCPOptionKindTimestamps, OptionData: []byte{1, 2, 3, 4, 0, 0, 0, 0}},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindWindowScale, OptionData: []byte{8}},
		},
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, ip, tcp); err != nil {
		t.Fatal(err)
	}

	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	decodedTCP, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		t.Fatal("serialized packet did not decode as TCP")
	}

	details, fingerprint, ok := parseTCPSyn(packet, decodedTCP)
	if !ok {
		t.Fatal("SYN was not parsed")
	}

	if want := "4:47+?:0:1460:64240,8:mss,sok,ts,nop,ws:df,id+:0"; fingerprint != want {
		t.Fatalf("fingerprint = %q, want %q", fingerprint, want)
	}
	if details.IPVersion != 4 || details.SrcIP != "192.0.2.10" || details.DstIP != "198.51.100.20" {
		t.Fatalf("unexpected IP details: %+v", details)
	}
	if details.SrcPort != 54321 || details.DstPort != 443 || details.TTL != 47 || details.IPID == nil || *details.IPID != 12345 {
		t.Fatalf("unexpected address/header details: %+v", details)
	}
	if details.DF == nil || !*details.DF || details.ECN || details.Window != 64240 || details.MSS != 1460 {
		t.Fatalf("unexpected fingerprint fields: %+v", details)
	}
	if details.WindowScale == nil || *details.WindowScale != 8 {
		t.Fatalf("window_scale = %v, want 8", details.WindowScale)
	}
	if !details.SACKPermitted || !details.Timestamps {
		t.Fatalf("expected SACK and timestamps: %+v", details)
	}
	wantOptions := []string{"mss", "sackOK", "timestamp", "nop", "wscale"}
	if !reflect.DeepEqual(details.Options, wantOptions) {
		t.Fatalf("options = %#v, want %#v", details.Options, wantOptions)
	}
	if want := "020405b40402080a010203040000000001030308"; details.OptionsRaw != want {
		t.Fatalf("options_raw = %q, want %q", details.OptionsRaw, want)
	}
	if details.OptionOrder != "mss,sackOK,timestamp,nop,wscale" {
		t.Fatalf("option_order = %q", details.OptionOrder)
	}
	if details.PayloadLen != 0 || details.PacketLen != 60 {
		t.Fatalf("unexpected packet lengths: %+v", details)
	}
}

func TestParseTCPSynIPv6OmitsIPv4OnlyFields(t *testing.T) {
	ip := &layers.IPv6{
		Version:      6,
		TrafficClass: 2,
		FlowLabel:    123,
		NextHeader:   layers.IPProtocolTCP,
		HopLimit:     55,
		SrcIP:        net.ParseIP("2001:db8::10"),
		DstIP:        net.ParseIP("2001:db8::20"),
	}
	tcp := &layers.TCP{
		SrcPort: 54321,
		DstPort: 443,
		Seq:     123456,
		SYN:     true,
		Window:  65535,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		t.Fatal(err)
	}

	buffer := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}, ip, tcp); err != nil {
		t.Fatal(err)
	}
	packet := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv6, gopacket.Default)
	decodedTCP, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		t.Fatal("serialized packet did not decode as TCP")
	}

	details, fingerprint, ok := parseTCPSyn(packet, decodedTCP)
	if !ok {
		t.Fatal("SYN was not parsed")
	}
	if want := "6:55+?:0:0:65535,0::ecn,flow:0"; fingerprint != want {
		t.Fatalf("fingerprint = %q, want %q", fingerprint, want)
	}
	if details.IPID != nil || details.DF != nil {
		t.Fatalf("IPv4-only fields should be absent: %+v", details)
	}
	if !details.ECN || details.PacketLen != 60 {
		t.Fatalf("unexpected IPv6 fields: %+v", details)
	}
}

func TestParseSYNOptionsPreservesP0FQuirks(t *testing.T) {
	parsed := parseSYNOptions([]byte{
		8, 10, 0, 0, 0, 0, 0, 0, 0, 1,
		3, 3, 15,
		0, 0, 1,
	})

	if !parsed.zeroTimestamp || !parsed.nonzeroTimestamp2 {
		t.Fatalf("timestamp quirks not retained: %+v", parsed)
	}
	if !parsed.excessiveWScale || !parsed.nonzeroEOLPadding {
		t.Fatalf("option quirks not retained: %+v", parsed)
	}
	wantLayout := []string{"ts", "ws", "eol+2"}
	if !reflect.DeepEqual(parsed.p0fLayout, wantLayout) {
		t.Fatalf("p0f layout = %#v, want %#v", parsed.p0fLayout, wantLayout)
	}
}

func TestParseSYNOptionsMarksMalformedOption(t *testing.T) {
	parsed := parseSYNOptions([]byte{2, 4, 0x05})
	if !parsed.bad {
		t.Fatal("truncated MSS option was not marked bad")
	}
	if want := []string{"mss"}; !reflect.DeepEqual(parsed.p0fLayout, want) {
		t.Fatalf("p0f layout = %#v, want %#v", parsed.p0fLayout, want)
	}
}
