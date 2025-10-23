package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"

	"backend/internal/analyzer"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
)

type Server struct {
	analyzer *analyzer.P2PAnalyzer
	clients  map[*websocket.Conn]bool
	mu       sync.RWMutex
	upgrader websocket.Upgrader
}

func New(analyzer *analyzer.P2PAnalyzer) *Server {
	s := &Server{
		analyzer: analyzer,
		clients:  make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}
	analyzer.OnP2PDetected(s.broadcastP2PConnection)
	return s
}

// старт веб-сервера
func (s *Server) Start(addr string) error {
	r := mux.NewRouter()
	r.HandleFunc("/", s.handleIndex)
	r.HandleFunc("/ws", s.handleWebSocket)
	r.HandleFunc("/api/connections", s.handleGetConnections)

	log.Printf("Start webserver %s\n", addr)
	return http.ListenAndServe(addr, r)
}

// обработка главной страницы
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "../frontend/web/index.html")
}

// обработка соединений
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade error:", err)
		return
	}
	s.mu.Lock()
	s.clients[conn] = true
	s.mu.Unlock()
	log.Println("New client")

	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()
		conn.Close()
		log.Println("Client disconnected")
	}()
	connections := s.analyzer.GetConnections()
	for _, connection := range connections {
		s.sendToClient(conn, connection)
	}
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

// получаем все соединения
func (s *Server) handleGetConnections(w http.ResponseWriter, r *http.Request) {
	connections := s.analyzer.GetConnections()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(connections)
}

// броадкаст нового соединения всем клиентам
func (s *Server) broadcastP2PConnection(conn analyzer.P2PConnection) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, _ := json.Marshal(conn)
	log.Println("Broadcast")
	for client := range s.clients {
		err := client.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			log.Println("WebSocket send error:", err)
		}
	}
}

// отправляем данные новому клиенту
func (s *Server) sendToClient(client *websocket.Conn, conn analyzer.P2PConnection) {
	data, _ := json.Marshal(conn)
	client.WriteMessage(websocket.TextMessage, data)
}
