package analyzer

import (
	"fmt"
	"p2p-detector/internal/capture"
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

type STUNMessageType uint16

const (
	STUNBindingRequest    STUNMessageType = 0x0001 // Запрос (от пира)
	STUNBindingResponse   STUNMessageType = 0x0101 // Ответ (от сервера или пира)
	STUNBindingErrorResp  STUNMessageType = 0x0111 // Ошибка
	STUNBindingIndication STUNMessageType = 0x0011 // Индикация (keep-alive)
)

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
	if !isStunPacket(pkt.Data) {
		fmt.Println("Не STUN пакет")
		return
	}
	if isStunServerPacket(pkt.Data) {
		fmt.Printf("STUN сервер: %s\n", pkt.SrcIP)
		return
	}
	fmt.Println("STUN клиентский пакет", pkt)
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

// Первые 2 байта
func getStunType(data []byte) STUNMessageType {
	if len(data) < 2 {
		return 0
	}
	return STUNMessageType((uint16(data[0]) << 8) | uint16(data[1])) // первые 2 байта - тип
}
