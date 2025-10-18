package capture

import (
	"fmt"

	"github.com/google/gopacket/pcap"
)

type PacketInfo struct {
	SrcIP   string
	SrcPort uint16
	DstIP   string
	DstPort uint16
}

func PacketCapture(deviceName string) (*pcap.Handle, error) {
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		return nil, fmt.Errorf("failed to open device %s: %v", deviceName, err)
	}
	err = handle.SetBPFFilter("udp or tcp")
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("failed to set BPF filter: %v", err)
	}
	return handle, nil
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
