package tcp

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/pagpeter/trackme/pkg/server"
	"github.com/pagpeter/trackme/pkg/types"
)

// TCP packet capture variables
var (
	snapshot_len int32         = 1024
	promiscuous  bool          = false
	timeout      time.Duration = 1 * time.Millisecond
	handle       *pcap.Handle
)

func parseIP(packet gopacket.Packet) *types.IPDetails {
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer == nil {
		if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer == nil {
			return nil
		} else {
			// IPv6
			ip := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
			return &types.IPDetails{
				DstIp:     ip.DstIP.String(),
				SrcIP:     ip.SrcIP.String(),
				TTL:       int(ip.HopLimit),
				IPVersion: 6,
			}
		}
	} else {
		// IPv4
		ip := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		return &types.IPDetails{
			DstIp:     ip.DstIP.String(),
			SrcIP:     ip.SrcIP.String(),
			ID:        int(ip.Id),
			TOS:       int(ip.TOS),
			TTL:       int(ip.TTL),
			IPVersion: 4,
		}
	}
}

func SniffTCP(device string, tlsPort int, srv *server.Server) {
	handle, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	if err := handle.SetBPFFilter(fmt.Sprintf("tcp and dst port %d", tlsPort)); err != nil {
		log.Printf("failed to install TCP capture filter: %v", err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for packet := range packets {
		if packet == nil {
			continue
		}

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			ip := parseIP(packet)
			tcp := tcpLayer.(*layers.TCP)
			if int(tcp.DstPort) != tlsPort || ip == nil || ip.IPVersion == 0 {
				continue
			}

			src := net.JoinHostPort(ip.SrcIP, strconv.Itoa(int(tcp.SrcPort)))
			if tcp.SYN && !tcp.ACK {
				if syn, p0f, ok := parseTCPSyn(packet, tcp); ok {
					srv.StoreTCPSyn(src, syn, p0f)
				}
				continue
			}
			if !tcp.ACK {
				continue
			}

			pack := types.TCPIPDetails{
				CapLen:  packet.Metadata().CaptureLength,
				DstPort: int(tcp.DstPort),
				SrcPort: int(tcp.SrcPort),
				IP:      *ip,
				TCP: types.TCPDetails{
					Ack:          int(tcp.Ack),
					Checksum:     int(tcp.Checksum),
					Options:      parseTCPOptions(tcp.Options),
					OptionsOrder: parseTCPOptionsOrder(tcp.Options),
					Seq:          int(tcp.Seq),
					Window:       int(tcp.Window),
				},
			}
			srv.GetTCPFingerprints().Store(src, pack)
		}
	}
}

func parseTCPOptions(_ []layers.TCPOption) string {
	return ""
}

func parseTCPOptionsOrder(_ []layers.TCPOption) string {
	return ""
}
