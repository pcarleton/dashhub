package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tswaugh/go.wemo"
	"log"
	"net"
  "time"
)

// Based off arpscan.go from gopacket examples

func main() {
	iface, err := net.InterfaceByName("en0")

	if err != nil {
		panic(err)
	}

	err = scan(iface)
	if err != nil {
		log.Printf("interface %v: %v", iface.Name, err)
	}
}

func scan(iface *net.Interface) error {
	// We just look for IPv4 addresses, so try to find if the interface has one.
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask[len(ipnet.Mask)-4:],
					}
					break
				}
			}
		}
	}
	// Sanity-check that the interface has a good address.
	if addr == nil {
		return fmt.Errorf("no good IP network found")
	} else if addr.IP[0] == 127 {
		return fmt.Errorf("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return fmt.Errorf("mask means network is too large")
	}
	log.Printf("Using network range %v for interface %v", addr, iface.Name)

	// Open up a pcap handle for packet reads/writes.
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Start up a goroutine to read in packet data.
	stop := make(chan struct{})
	go readARP(handle, iface, stop)
	defer close(stop)
	select {}
}

// readARP watches a handle for incoming ARP responses we might care about, and prints them.
//
// readARP loops until 'stop' is closed.
func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()

	api, _ := wemo.NewByInterface("en0")
	devices, _ := api.DiscoverAll(3*time.Second)
	for _, device := range devices {
		fmt.Printf("Found %+v\n", device)
	}

	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				//log.Printf("No arp layer")
				continue
			}
			arp := arpLayer.(*layers.ARP)
			if (arp.Operation == layers.ARPRequest) {
				var macAddr = net.HardwareAddr(arp.SourceHwAddress)
				if macAddr.String() == "74:c2:46:21:c9:42" {
					log.Printf("Pushed Bounty!")

					for _ ,device := range devices {
						device.Toggle()
					}
				}
				continue
			}
		}
	}
}
