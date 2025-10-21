package analyzer

import (
	"sync"
)

type P2PConnection struct {
	PeerIP      string
	PeerPort    uint16
	LocalIP     string
	LocalPort   uint16
	PacketCount int
}

type P2PAnalyzer struct {
	connections map[string]*P2PConnection
	mu          sync.RWMutex
	localIPs    map[string]bool
	onDetected  func(P2PConnection)
}

func NewP2PAnalyzer(localIPs []string) *P2PAnalyzer {
	localIPMap := make(map[string]bool)
	for _, ip := range localIPs {
		localIPMap[ip] = true
	}

	return &P2PAnalyzer{
		connections: make(map[string]*P2PConnection),
		localIPs:    localIPMap,
	}
}

// func (a *P2PAnalyzer) AnalyzePacket(pkt capture.PacketInfo) {

// }

// Magic Cookie (0x2112A442)
func IsStunPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	return data[4] == 0x21 && data[5] == 0x12 &&
		data[6] == 0xA4 && data[7] == 0x42
}
