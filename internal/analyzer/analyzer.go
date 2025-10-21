package analyzer

import (
	"sync"
)

type P2PConnection struct {
	PeerIP      string `json:"PeerIP"`
	PeerPort    uint16 `json:"PeerPort"`
	LocalIP     string `json:"LocalIP"`
	LocalPort   uint16 `json:"LocalPort"`
	PacketCount int    `json:"PacketCount"`
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
