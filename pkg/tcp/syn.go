package tcp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pagpeter/trackme/pkg/types"
)

const maxP0FTCPOptions = 24

type synIPMetadata struct {
	version      int
	srcIP        string
	dstIP        string
	ttl          int
	id           int
	df           bool
	ecn          bool
	reserved     bool
	flow         bool
	optionLength int
	packetLength int
}

type parsedSYNOptions struct {
	names              []string
	p0fLayout          []string
	mss                int
	windowScale        int
	windowScalePresent bool
	sackPermitted      bool
	timestamps         bool
	timestampValue     uint32
	zeroTimestamp      bool
	nonzeroTimestamp2  bool
	nonzeroEOLPadding  bool
	excessiveWScale    bool
	bad                bool
}

// parseTCPSyn extracts the wire values from an inbound SYN and renders the
// p0f v3 TCP signature shape. The TTL is deliberately emitted as observed+?
// and the window remains literal: this API reports observations, not guesses.
func parseTCPSyn(packet gopacket.Packet, tcp *layers.TCP) (types.TCPSynDetails, string, bool) {
	if !tcp.SYN || tcp.ACK || tcp.FIN || tcp.RST {
		return types.TCPSynDetails{}, "", false
	}
	ip, ok := parseSYNIPMetadata(packet)
	if !ok || len(tcp.Contents) < 20 {
		return types.TCPSynDetails{}, "", false
	}

	rawOptions := tcp.Contents[20:]
	options := parseSYNOptions(rawOptions)
	ecn := ip.ecn || tcp.ECE || tcp.CWR || tcp.NS

	details := types.TCPSynDetails{
		IPVersion:     ip.version,
		SrcIP:         ip.srcIP,
		DstIP:         ip.dstIP,
		SrcPort:       int(tcp.SrcPort),
		DstPort:       int(tcp.DstPort),
		TTL:           ip.ttl,
		ECN:           ecn,
		Window:        int(tcp.Window),
		MSS:           options.mss,
		SACKPermitted: options.sackPermitted,
		Timestamps:    options.timestamps,
		Options:       options.names,
		OptionsRaw:    hex.EncodeToString(rawOptions),
		OptionOrder:   strings.Join(options.names, ","),
		PayloadLen:    len(tcp.Payload),
		PacketLen:     ip.packetLength,
	}
	if ip.version == 4 {
		ipID := ip.id
		df := ip.df
		details.IPID = &ipID
		details.DF = &df
	}
	if options.windowScalePresent {
		windowScale := options.windowScale
		details.WindowScale = &windowScale
	}

	quirks := p0fQuirks(ip, tcp, options, ecn)
	payloadClass := "0"
	if details.PayloadLen > 0 {
		payloadClass = "+"
	}

	p0f := fmt.Sprintf(
		"%d:%d+?:%d:%d:%d,%d:%s:%s:%s",
		ip.version,
		ip.ttl,
		ip.optionLength,
		options.mss,
		details.Window,
		options.windowScale,
		strings.Join(options.p0fLayout, ","),
		strings.Join(quirks, ","),
		payloadClass,
	)

	return details, p0f, true
}

func parseSYNIPMetadata(packet gopacket.Packet) (synIPMetadata, bool) {
	if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
		ip := layer.(*layers.IPv4)
		// p0f does not fingerprint fragmented TCP packets.
		if ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0 {
			return synIPMetadata{}, false
		}
		headerLength := int(ip.IHL) * 4
		if headerLength < 20 {
			return synIPMetadata{}, false
		}
		return synIPMetadata{
			version:      4,
			srcIP:        ip.SrcIP.String(),
			dstIP:        ip.DstIP.String(),
			ttl:          int(ip.TTL),
			id:           int(ip.Id),
			df:           ip.Flags&layers.IPv4DontFragment != 0,
			ecn:          ip.TOS&0x03 != 0,
			reserved:     ip.Flags&layers.IPv4EvilBit != 0,
			optionLength: headerLength - 20,
			packetLength: int(ip.Length),
		}, true
	}

	if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
		ip := layer.(*layers.IPv6)
		// This mirrors p0f v3: IPv6 extension headers are not skipped.
		if ip.NextHeader != layers.IPProtocolTCP {
			return synIPMetadata{}, false
		}
		return synIPMetadata{
			version:      6,
			srcIP:        ip.SrcIP.String(),
			dstIP:        ip.DstIP.String(),
			ttl:          int(ip.HopLimit),
			ecn:          ip.TrafficClass&0x03 != 0,
			flow:         ip.FlowLabel != 0,
			optionLength: 0,
			packetLength: 40 + int(ip.Length),
		}, true
	}

	return synIPMetadata{}, false
}

func parseSYNOptions(raw []byte) parsedSYNOptions {
	parsed := parsedSYNOptions{}
	offset := 0

	for offset < len(raw) && len(parsed.p0fLayout) < maxP0FTCPOptions {
		kind := raw[offset]
		offset++

		switch layers.TCPOptionKind(kind) {
		case layers.TCPOptionKindEndList:
			padding := raw[offset:]
			parsed.names = append(parsed.names, "eol")
			parsed.p0fLayout = append(parsed.p0fLayout, fmt.Sprintf("eol+%d", len(padding)))
			for _, value := range padding {
				if value != 0 {
					parsed.nonzeroEOLPadding = true
					break
				}
			}
			offset = len(raw)

		case layers.TCPOptionKindNop:
			parsed.names = append(parsed.names, "nop")
			parsed.p0fLayout = append(parsed.p0fLayout, "nop")

		case layers.TCPOptionKindMSS:
			parsed.names = append(parsed.names, "mss")
			parsed.p0fLayout = append(parsed.p0fLayout, "mss")
			if offset+3 > len(raw) {
				parsed.bad = true
				return parsed
			}
			if raw[offset] != 4 {
				parsed.bad = true
			}
			parsed.mss = int(binary.BigEndian.Uint16(raw[offset+1 : offset+3]))
			offset += 3

		case layers.TCPOptionKindWindowScale:
			parsed.names = append(parsed.names, "wscale")
			parsed.p0fLayout = append(parsed.p0fLayout, "ws")
			if offset+2 > len(raw) {
				parsed.bad = true
				return parsed
			}
			if raw[offset] != 3 {
				parsed.bad = true
			}
			parsed.windowScalePresent = true
			parsed.windowScale = int(raw[offset+1])
			parsed.excessiveWScale = parsed.windowScale > 14
			offset += 2

		case layers.TCPOptionKindSACKPermitted:
			parsed.names = append(parsed.names, "sackOK")
			parsed.p0fLayout = append(parsed.p0fLayout, "sok")
			parsed.sackPermitted = true
			if offset+1 > len(raw) {
				parsed.bad = true
				return parsed
			}
			if raw[offset] != 2 {
				parsed.bad = true
			}
			offset++

		case layers.TCPOptionKindSACK:
			parsed.names = append(parsed.names, "sack")
			parsed.p0fLayout = append(parsed.p0fLayout, "sack")
			if offset >= len(raw) {
				parsed.bad = true
				return parsed
			}
			length := int(raw[offset])
			if length < 10 || length > 34 || offset-1+length > len(raw) {
				parsed.bad = true
				return parsed
			}
			offset += length - 1

		case layers.TCPOptionKindTimestamps:
			parsed.names = append(parsed.names, "timestamp")
			parsed.p0fLayout = append(parsed.p0fLayout, "ts")
			parsed.timestamps = true
			if offset+9 > len(raw) {
				parsed.bad = true
				return parsed
			}
			if raw[offset] != 10 {
				parsed.bad = true
			}
			parsed.timestampValue = binary.BigEndian.Uint32(raw[offset+1 : offset+5])
			parsed.zeroTimestamp = parsed.timestampValue == 0
			parsed.nonzeroTimestamp2 = binary.BigEndian.Uint32(raw[offset+5:offset+9]) != 0
			offset += 9

		default:
			parsed.names = append(parsed.names, fmt.Sprintf("unknown-%d", kind))
			parsed.p0fLayout = append(parsed.p0fLayout, fmt.Sprintf("?%d", kind))
			if offset >= len(raw) {
				parsed.bad = true
				return parsed
			}
			length := int(raw[offset])
			if length < 2 || length > 40 || offset-1+length > len(raw) {
				parsed.bad = true
				return parsed
			}
			offset += length - 1
		}
	}

	if offset != len(raw) {
		// p0f processes at most 24 options and marks any remainder as bad.
		parsed.bad = true
	}

	return parsed
}

func p0fQuirks(ip synIPMetadata, tcp *layers.TCP, options parsedSYNOptions, ecn bool) []string {
	quirks := make([]string, 0, 8)
	if ip.df {
		quirks = append(quirks, "df")
		if ip.id != 0 {
			quirks = append(quirks, "id+")
		}
	} else if ip.version == 4 && ip.id == 0 {
		quirks = append(quirks, "id-")
	}
	if ecn {
		quirks = append(quirks, "ecn")
	}
	if ip.reserved {
		quirks = append(quirks, "0+")
	}
	if ip.flow {
		quirks = append(quirks, "flow")
	}
	if tcp.Seq == 0 {
		quirks = append(quirks, "seq-")
	}
	if !tcp.ACK && tcp.Ack != 0 && !tcp.RST {
		quirks = append(quirks, "ack+")
	}
	if tcp.ACK && tcp.Ack == 0 {
		quirks = append(quirks, "ack-")
	}
	if !tcp.URG && tcp.Urgent != 0 {
		quirks = append(quirks, "uptr+")
	}
	if tcp.URG {
		quirks = append(quirks, "urgf+")
	}
	if tcp.PSH {
		quirks = append(quirks, "pushf+")
	}
	if options.zeroTimestamp {
		quirks = append(quirks, "ts1-")
	}
	if options.nonzeroTimestamp2 {
		quirks = append(quirks, "ts2+")
	}
	if options.nonzeroEOLPadding {
		quirks = append(quirks, "opt+")
	}
	if options.excessiveWScale {
		quirks = append(quirks, "exws")
	}
	if options.bad {
		quirks = append(quirks, "bad")
	}
	return quirks
}
