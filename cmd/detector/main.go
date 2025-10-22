package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"p2p-detector/internal/analyzer"
	"p2p-detector/internal/api"
	"p2p-detector/internal/capture"
)

func main() {
	deviceName := flag.String("device", "", "Network device to capture packets")
	listDevices := flag.Bool("list-devices", false, "List available network devices")
	autoDetect := flag.Bool("auto", false, "Automatically detect network device")
	debug := flag.Bool("debug", false, "Enable debug mode with packet logging")
	flag.Parse()
	if *listDevices {
		printDevices()
		return
	}
	if *autoDetect {
		device, err := capture.AutoDetectDevice()
		if err != nil {
			log.Fatal(err)
		}
		*deviceName = device
		log.Println("Auto-detected device:", device)
	}
	if *deviceName == "" {
		log.Fatal("No device specified")
	}
	if *debug {
		log.Println("Debug mode enabled")
	}

	localIPs, err := getLocalIPsFromDevices()
	if err != nil {
		log.Fatal("Error getting local IPs:", err)
	}
	// fmt.Println(localIPs)
	// analyzer := analyzer.NewP2PAnalyzer(localIPs)

	// fmt.Println(analyzer)
	// go packetCapture.Start()
	analyzer := analyzer.NewP2PAnalyzer(localIPs)
	webServer := api.NewServer(analyzer)
	go func() {
		if err := webServer.Start("localhost:8080"); err != nil {
			log.Fatal("Server start error:", err)
		}
	}()
	packetCapture, err := capture.NewPacketCapture(*deviceName)
	if err != nil {
		log.Fatal("Error starting packet capture:", err)
	}
	defer packetCapture.Close()
	packetCapture.OnPacket(func(pkt capture.PacketInfo) {
		// fmt.Printf("%s %d \t %s %d          %d\n", pkt.SrcIP, pkt.SrcPort, pkt.DstIP, pkt.DstPort, len(pkt.Data))
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
	// fmt.Println(devices)
	for _, device := range devices {
		if len(device.Addresses) != 0 && device.Addresses[0].IP != nil && !device.Addresses[0].IP.IsLoopback() {
			fmt.Println(device.Name)
			fmt.Printf("\t%s\n\t%s\n", device.Description, device.Addresses)
		}
	}
}
