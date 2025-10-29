package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"backend/internal/analyzer"
	"backend/internal/api"
	"backend/internal/capture"
)

func main() {
	deviceName := os.Getenv("DEVICE")
	listDevices := os.Getenv("LIST_DEVICES") == "true"
	webAddr := os.Getenv("WEB")
	if listDevices {
		printDevices()
	}
	if deviceName == "" {
		device, err := capture.AutoDetectDevice()
		if err != nil {
			log.Fatal(err)
		}
		deviceName = device
		log.Println("Auto-detected device:", device)
	}
	if deviceName == "" {
		log.Fatal("No device specified")
	}

	localIPs, err := getLocalIPsFromDevices()
	localIPs = append(localIPs, "10.10.10.2") // Добавляем локальный IP (WireGuard)
	if err != nil {
		log.Fatal("Error getting local IPs:", err)
	}
	fmt.Println(localIPs)
	analyzer := analyzer.New(localIPs)
	webServer := api.New(analyzer)
	go func() {
		if err := webServer.Start(webAddr); err != nil {
			log.Fatal("Server start error:", err)
		}
	}()
	packetCapture, err := capture.New(deviceName)
	if err != nil {
		log.Fatal("Error starting packet capture:", err)
	}
	defer packetCapture.Close()
	packetCapture.OnPacket(func(pkt capture.PacketInfo) {
		// fmt.Println(pkt.SrcIP, pkt.DstIP)
		analyzer.AnalyzePacket(pkt)
	})
	go packetCapture.Start()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan
}

func getLocalIPsFromDevices() ([]string, error) {
	devices, err := capture.ListDevices()
	if err != nil {
		return nil, fmt.Errorf("failed to list devices: %v", err)
	}
	localIPs := make([]string, 0, 10)
	seenIPs := make(map[string]bool, 10)
	for _, device := range devices {
		for _, addr := range device.Addresses {
			if addr.IP == nil || addr.IP.IsLoopback() {
				continue
			}
			if ipv4 := addr.IP.To4(); ipv4 != nil {
				ipStr := ipv4.String()
				if !seenIPs[ipStr] {
					seenIPs[ipStr] = true
					localIPs = append(localIPs, ipStr)
				}
			}
		}
	}
	return localIPs, nil
}

func printDevices() {
	devices, err := capture.ListDevices()
	if err != nil {
		log.Fatal("Error listing devices:", err)
	}
	for _, device := range devices {
		if len(device.Addresses) != 0 && device.Addresses[0].IP != nil && !device.Addresses[0].IP.IsLoopback() {
			fmt.Println(device.Name)
			fmt.Printf("\t%s\n\t%s\n", device.Description, device.Addresses)
		}
	}
}
