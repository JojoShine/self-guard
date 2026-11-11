package main

import (
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"net"
	"testing"
)

func TestCaptureOnlySendsApprovedEndpointToDecoder(t *testing.T) {
	c := CaptureConfiguration{Address: "127.0.0.1", Port: 18080}
	for _, test := range []struct {
		port uint16
		ip   string
		want bool
	}{{18080, "127.0.0.1", true}, {22, "127.0.0.1", false}, {18080, "127.0.0.2", false}} {
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{1, 2, 3, 4, 5, 6}, DstMAC: net.HardwareAddr{6, 5, 4, 3, 2, 1}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.IPv4(10, 0, 0, 1), DstIP: net.ParseIP(test.ip)}
		tcp := &layers.TCP{SrcPort: 40000, DstPort: layers.TCPPort(test.port)}
		tcp.SetNetworkLayerForChecksum(ip)
		buffer := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload("synthetic")); err != nil {
			t.Fatal(err)
		}
		if selectedPacket(buffer.Bytes(), c) != test.want {
			t.Fatal("endpoint scope mismatch", test)
		}
	}
}
