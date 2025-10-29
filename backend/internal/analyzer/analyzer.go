package analyzer

import (
	"backend/internal/capture"
	"fmt"
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

func New(localIPs []string) *P2PAnalyzer {
	localIPMap := make(map[string]bool)
	for _, ip := range localIPs {
		localIPMap[ip] = true
	}

	return &P2PAnalyzer{
		connections: make(map[string]*P2PConnection),
		localIPs:    localIPMap,
	}
}

//Устройство STUN пакета:
// байты 0-1: тип сообщения
// байты 2-3: длина сообщения
// байты 4-7: магическое число (0x2112A442)
// байты 8-19: идентификатор транзакции
// Далее идут атрибуты (20+ байты):
// каждый атрибут имеет структуру:
// байты 0-1: тип атрибута
// байты 2-3: длина атрибута
// байты 4+: значение атрибута

func (a *P2PAnalyzer) AnalyzePacket(pkt capture.PacketInfo) {
	if !isStunPacket(pkt.Data) { // проверка стан пакет ли (если нет то не относится)
		return
	}
	if a.localIPs[pkt.SrcIP] || !a.localIPs[pkt.DstIP] { // проверка что пакет направлен на локальный IP
		return
	}
	if isStunServerPacket(pkt.Data) { // фильтрация пакетов от стан серверов по содержимому
		fmt.Println("Stun server", pkt.SrcIP, pkt.SrcPort)
		return
	}
	if isStunServerPort(pkt.DstPort) || isStunServerPort(pkt.SrcPort) { //фильтрация стан серверов по порту
		return
	}
	// fmt.Println(pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort)
	key := fmt.Sprintf("%s:%d", pkt.DstIP, pkt.DstPort)
	a.mu.Lock()
	defer a.mu.Unlock()
	conn, exists := a.connections[key]
	if !exists {
		conn = &P2PConnection{
			PeerIP:      pkt.SrcIP,
			PeerPort:    pkt.SrcPort,
			LocalIP:     pkt.DstIP,
			LocalPort:   pkt.DstPort,
			PacketCount: 0,
		}
		a.connections[key] = conn
		if a.onDetected != nil {
			a.onDetected(*conn)
		}
		fmt.Printf("P2P stun: %s:%d → %s:%d\n",
			pkt.SrcIP, pkt.SrcPort,
			pkt.DstIP, pkt.DstPort)
	}
	conn.PacketCount++
}

func isStunServerPort(port uint16) bool {
	return port == 443 || // STUN over HTTPS
		port == 3478 || // Стандартный STUN UDP
		port == 5349 || // STUN over TLS
		port == 80 || // HTTP
		port < 1024 // Все привилегированные порты
}

// Magic Cookie (0x2112A442) (4-7 байты)
func isStunPacket(data []byte) bool {
	if len(data) < 20 {
		return false
	}
	return data[4] == 0x21 && data[5] == 0x12 &&
		data[6] == 0xA4 && data[7] == 0x42
}

// Пакет будет от сервера есть есть атрибуты MAPPED-ADDRESS (0x0001) или XOR-MAPPED-ADDRESS (0x0020)
func isStunServerPacket(data []byte) bool {
	if !isStunPacket(data) {
		return false
	}
	return hasAttribute(data, 0x0001) || hasAttribute(data, 0x0020)
}

func hasAttribute(data []byte, attrType uint16) bool {
	if len(data) < 20 { // заголовок 20 байт
		return false
	}
	pos := 20
	msgLen := int((uint16(data[2]) << 8) | uint16(data[3])) // байты 2 и 3 - длина сообщения
	for pos < 20+msgLen && pos+4 <= len(data) {             //идем по атрибутам
		currentAttrType := (uint16(data[pos]) << 8) | uint16(data[pos+1]) // чмитаем тип - 2байта
		if currentAttrType == attrType {
			return true
		}
		attrLen := int((uint16(data[pos+2]) << 8) | uint16(data[pos+3])) //длина атрибута 2 байта
		pos += 4 + ((attrLen + 3) & ^3)                                  // следующий атрибут (выравнивание до 4 байт)
	}
	return false
}

func (a *P2PAnalyzer) OnP2PDetected(callback func(P2PConnection)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.onDetected = callback
}

func (a *P2PAnalyzer) GetConnections() []P2PConnection {
	a.mu.RLock()
	defer a.mu.RUnlock()

	conns := make([]P2PConnection, 0, len(a.connections))
	for _, conn := range a.connections {
		conns = append(conns, *conn)
	}
	return conns
}
