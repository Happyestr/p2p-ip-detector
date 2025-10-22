package capture

import (
	"fmt"
	"strings"

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
	handle, err := pcap.OpenLive(deviceName, 65536, true, pcap.BlockForever)
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
	var ethernetDevices []string
	var wifiDevices []string
	var otherDevices []string
	for _, device := range devices {
		if len(device.Addresses) == 0 || device.Addresses[0].IP == nil || device.Addresses[0].IP.IsLoopback() {
			continue
		}
		desc := strings.ToLower(device.Description)
		if strings.Contains(desc, "vmware") ||
			strings.Contains(desc, "bluetooth") ||
			strings.Contains(desc, "virtualbox") {
			continue
		}
		// Ethernet
		if strings.Contains(desc, "ethernet") ||
			strings.Contains(desc, "realtek") ||
			strings.Contains(desc, "intel") && strings.Contains(desc, "connection") ||
			strings.Contains(desc, "gigabit") ||
			strings.Contains(desc, "controller") && !strings.Contains(desc, "wi-fi") {
			if !strings.Contains(desc, "virtual") {
				ethernetDevices = append(ethernetDevices, device.Name)
				continue
			}
		}
		// Wi-Fi
		if strings.Contains(desc, "wi-fi") ||
			strings.Contains(desc, "wifi") ||
			strings.Contains(desc, "wireless") ||
			strings.Contains(desc, "802.11") {
			// пропуск виртуальных
			if !strings.Contains(desc, "virtual") &&
				!strings.Contains(desc, "microsoft wi-fi direct") {
				wifiDevices = append(wifiDevices, device.Name)
				continue
			}
		}
		otherDevices = append(otherDevices, device.Name)
	}
	if len(ethernetDevices) > 0 {
		return ethernetDevices[0], nil
	}
	if len(wifiDevices) > 0 {
		return wifiDevices[0], nil
	}
	if len(otherDevices) > 0 {
		return otherDevices[0], nil
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
	// Этот кусок кода мог выдать панику, если в пакете не было IPv4 слоя
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return nil
	}
	ip, ok := ipLayer.(*layers.IPv4)
	if !ok {
		return nil
	}
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		return nil
	}
	udp, ok := udpLayer.(*layers.UDP)
	if !ok {
		return nil
	}
	// fmt.Println(ipLayer.DstIP, ipLayer.SrcIP)
	// fmt.Println(udpLayer.SrcPort, udpLayer.DstPort, udpLayer.Payload)
	return &PacketInfo{
		SrcIP:   ip.SrcIP.String(),
		DstIP:   ip.DstIP.String(),
		SrcPort: uint16(udp.SrcPort),
		DstPort: uint16(udp.DstPort),
		Data:    udp.Payload,
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
