package capture

import (
	"fmt"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type PacketInfo struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
	Data    []byte
}

type PacketCapture struct {
	handle     *pcap.Handle
	deviceName string
	onPacket   func(PacketInfo)
}

func NewPacketCapture(deviceName string) (*PacketCapture, error) {
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open device %s: %v", deviceName, err)
	}
	err = handle.SetBPFFilter("udp")
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter: %v", err)
	}
	return &PacketCapture{
		handle:     handle,
		deviceName: deviceName,
	}, nil
}

func AutoDetectDevice() (string, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	for _, device := range devices {
		for _, addr := range device.Addresses {
			if addr.IP.IsLoopback() || addr.IP.IsPrivate() {
				continue
			}
			return device.Name, nil
		}
	}
	return "", fmt.Errorf("no suitable device found")
}

func (pc *PacketCapture) Start() {
	packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())
	for packet := range packetSource.Packets() {
		// fmt.Println(pc.extractPacketInfo(packet))
		info := pc.extractPacketInfo(packet)
		if info != nil && pc.onPacket != nil {
			pc.onPacket(*info)
		}
	}
	// packetSource := gopacket.NewPacketSource(pc.handle, pc.handle.LinkType())
	// for packet := range packetSource.Packets() {
	// 	// Обработка пакета
	// }
}

func (pc *PacketCapture) extractPacketInfo(packet gopacket.Packet) *PacketInfo {
	ipLayer := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ipLayer == nil {
		return nil
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if udpLayer == nil {
		return nil
	}
	// fmt.Println(ipLayer.DstIP, ipLayer.SrcIP)
	// fmt.Println(udpLayer.SrcPort, udpLayer.DstPort, udpLayer.Payload)
	return &PacketInfo{
		SrcIP:   ipLayer.SrcIP.String(),
		DstIP:   ipLayer.DstIP.String(),
		SrcPort: uint16(udpLayer.SrcPort),
		DstPort: uint16(udpLayer.DstPort),
		Data:    udpLayer.Payload,
	}
}

func (pc *PacketCapture) OnPacket(pi func(PacketInfo)) {
	pc.onPacket = pi
}

func (pc *PacketCapture) Close() {
	pc.handle.Close()
}

func ListDevices() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}
