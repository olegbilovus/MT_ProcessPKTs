package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
)

type TsharkPacket struct {
	Source struct {
		Layers struct {
			SNI []string `json:"tls.handshake.extensions_server_name"`
			IP  []string `json:"ip.dst"`
		} `json:"layers"`
	} `json:"_source"`
}

type SNI struct {
	SNI string
	IPs []string
}

func (s *SNI) InsertIP(ip string) {
	if !slices.Contains[[]string](s.IPs, ip) {
		s.IPs = append(s.IPs, ip)
	}
}
func main() {
	var pcapFile = flag.String("pcap", "capture.pcap", "path to the pcap file")
	var verbose = flag.Bool("v", false, "verbose print")
	flag.Parse()

	cmd := exec.Command(
		"tshark",
		"-r", *pcapFile,
		"-Y", "tls.handshake.type == 1",
		"-T", "json",
		"-e", "tls.handshake.extensions_server_name",
		"-e", "ip.dst",
	)

	fmt.Fprintln(os.Stderr, cmd.String())

	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to run tshark: %v", err)
	}

	var packets []TsharkPacket
	if err := json.Unmarshal(output, &packets); err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}

	sniMap := make(map[string]*SNI)
	uniqueSNIs := make([]string, 0)

	for _, pkt := range packets {
		sni := ""
		ip := ""
		if len(pkt.Source.Layers.SNI) > 0 {
			sni = pkt.Source.Layers.SNI[0]
		}
		if len(pkt.Source.Layers.IP) > 0 {
			ip = pkt.Source.Layers.IP[0]
		}
		if sni != "" && ip != "" {
			if sniMap[sni] == nil {
				uniqueSNIs = append(uniqueSNIs, sni)
				sniMap[sni] = &SNI{
					SNI: sni,
					IPs: make([]string, 0),
				}
			}
			sniMap[sni].InsertIP(ip)
		}
	}

	if *verbose {
		printSNIs(uniqueSNIs, sniMap)
	}

	fmt.Printf("\n[Found %d unique SNIs]\n", len(sniMap))
}

func printSNIs(uniqueSNIs []string, sniMap map[string]*SNI) {
	sort.Strings(uniqueSNIs)

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "SNI\tIPs")
	for _, sniVal := range uniqueSNIs {
		sni := sniMap[sniVal]
		fmt.Fprintf(w, "%s\t%s\n", sni.SNI, strings.Join(sni.IPs, ", "))
	}
	w.Flush()
}
