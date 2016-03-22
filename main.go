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
"flag"
)

// Based off arpscan.go from gopacket examples
var netInterface string
var buttonMac string
var timeout int64
func init() {
	flag.StringVar(&netInterface, "interface", "en0", "help message for flagname")
	flag.StringVar(&buttonMac, "mac", "NOPE", "Mac address for dash button")
	flag.Int64Var(&timeout, "timeout", 10, "Mac address for dash button")
}

func main() {
	flag.Parse()
	iface, err := net.InterfaceByName(netInterface)

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

	api, _ := wemo.NewByInterface(netInterface)
	fmt.Printf("Scanning for WeMo devices")
	devices, _ := api.DiscoverAll(time.Duration(timeout)*time.Second)
	for _, device := range devices {
		fmt.Printf("Found %+v\n", device)
	}
	if len(devices) == 0 {
		fmt.Printf("Didn't find any devices.")
	}

	var waiter = time.After(time.Second*1);

	var pause = false;
	for {
		var packet gopacket.Packet
		select {
		case <-waiter:
			log.Printf("Tick!")
			pause = false;
			continue
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				//log.Printf("No arp layer")
				continue
			}
			arp := arpLayer.(*layers.ARP)
			var macAddr = net.HardwareAddr(arp.SourceHwAddress)
			//log.Printf("Macaddr %s", macAddr)
			if (arp.Operation == layers.ARPRequest) {

				if macAddr.String() == buttonMac {
					log.Printf("Pushed button!")
					if pause {
						log.Printf("debounced")
						continue
					}
					pause = true;
					waiter = time.After(time.Second*3)

					for _ ,device := range devices {
						device.Toggle()
					}
				}
				continue
			}
		}
	}
}
