package tracert

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func encodeUDPPacket(localIP, remoteIP net.IP, localPort, remotePort uint16, tos uint8, payload []byte) ([]byte, error) {
	ip := &layers.IPv4{
		Version:  4,
		TTL:      128,
		SrcIP:    localIP,
		DstIP:    remoteIP,
		TOS:      tos,
		Protocol: layers.IPProtocolUDP,
	}
	// Our TCP header
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(localPort),
		DstPort: layers.UDPPort(remotePort),
	}
	udp.SetNetworkLayerForChecksum(ip)

	// Serialize.  Note:  we only serialize the TCP layer, because the
	// socket we get with net.ListenPacket wraps our data in IPv4 packets
	// already.  We do still need the IP layer to compute checksums
	// correctly, though.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	err := gopacket.SerializeLayers(buf, opts, udp, gopacket.Payload(payload))

	return buf.Bytes(), err
}
