package scanner

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type SYN struct{}

func (s *SYN) Name() string { return "SYN Stealth" }

func (b *Scaner) SYN() *Scaner {
	b.strategy = &SYN{}
	return b
}

func (s *SYN) Scan(req *ScanRequest) ([]ScanResult, error) {

	if req.Target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	dstIP, err := net.ResolveIPAddr("ip4", req.Target)
	if err != nil {
		return nil, err
	}

	device, srcIP, err := getActiveInterface(req.Target)
	if err != nil {
		return nil, err
	}

	handle, err := pcap.OpenLive(device, 65535, true, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	// ONE filter for entire scan
	filter := fmt.Sprintf("tcp and src host %s", dstIP.IP.String())
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, err
	}

	results := make(map[int]string)
	var mu sync.Mutex

	// Start receiver
	go listenForResponses(handle, results, &mu)

	// Send SYN packets fast
	for _, port := range req.Ports {
		sendSYNPacket(handle, srcIP, dstIP.IP, port)
	}

	// Wait for responses
	time.Sleep(req.Timeout)

	// Convert results
	var scanResults []ScanResult
	for port, state := range results {
		if state == "open" {
			scanResults = append(scanResults, ScanResult{
				Port:    port,
				State:   state,
				Service: getServiceName(port),
			})
		}
	}

	return scanResults, nil
}

func sendSYNPacket(handle *pcap.Handle, srcIP, dstIP net.IP, port int) {

	ipLayer := &layers.IPv4{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(54321),
		DstPort: layers.TCPPort(port),
		SYN:     true,
		Seq:     1105024978,
		Window:  14600,
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	gopacket.SerializeLayers(buffer, opts, ipLayer, tcpLayer)
	handle.WritePacketData(buffer.Bytes())
}

func listenForResponses(handle *pcap.Handle, results map[int]string, mu *sync.Mutex) {

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {

		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

			tcp := tcpLayer.(*layers.TCP)
			port := int(tcp.SrcPort)

			mu.Lock()
			defer mu.Unlock()

			if tcp.SYN && tcp.ACK {
				results[port] = "open"
			} else if tcp.RST {
				results[port] = "closed"
			}
		}
	}
}

func getActiveInterface(target string) (string, net.IP, error) {
	conn, err := net.Dial("udp", target+":80")
	if err != nil {
		return "", nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	localIP := localAddr.IP

	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", nil, err
	}

	for _, dev := range devs {
		for _, addr := range dev.Addresses {
			if addr.IP.Equal(localIP) {
				return dev.Name, localIP, nil
			}
		}
	}

	return "", nil, fmt.Errorf("no matching interface found")
}
