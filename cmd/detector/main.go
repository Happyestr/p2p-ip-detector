package main

import (
	"flag"
	"fmt"
	"log"

	"p2p-detector/internal/capture"

	"github.com/google/gopacket"
)

func main() {
	deviceName := flag.String("device", "", "Network device to capture packets")
	autoDetect := flag.Bool("auto", false, "Automatically detect network device")
	debug := flag.Bool("debug", false, "Enable debug mode with packet logging")
	flag.Parse()

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
	handle, err := capture.PacketCapture(*deviceName)
	if err != nil {
		log.Fatal("Error starting packet capture:", err)
	}
	defer handle.Close()
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet)
	}
}
