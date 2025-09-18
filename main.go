package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

//goland:noinspection D
func main() {
	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true,
		PadLevelText: true,
		CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
			filename := path.Base(frame.File) + ":" + strconv.Itoa(frame.Line)
			return "", filename
		}})
	log.SetLevel(log.TraceLevel)

	var pcapFile = flag.String("pcap", "capture.pcap", "path to the pcap file")
	var filter = flag.String("filter", "", "filter to use")
	var verbose = flag.Bool("v", false, "verbose output")
	flag.Parse()

	var err error

	client, err := NewQuestDBClient("http://127.0.0.1:9000")
	if err != nil {
		log.Fatalf("Failed to create QuestDB client: %v", err)
	}
	tableName := "packets_" + filepath.Base(*pcapFile)
	tableName = strings.TrimSuffix(tableName, filepath.Ext(tableName))
	if err := CreatePacketTable(client, tableName); err != nil {
		log.Fatalln(err)
	}

	cmd := exec.Command(
		"tshark",
		"-r", *pcapFile,
		"-Y", *filter,
		"-T", "json",
		"-e", "frame.time_epoch",
		"-e", "ip.src",
		"-e", "ip.dst",
		"-e", "frame.len",
		"-e", "ip.proto",
		"-e", "tcp.port",
		"-e", "udp.port",
		"-e", "tls.handshake.extensions_server_name",
		"-e", "tls.handshake.extensions_alpn_str",
		"-e", "tcp.stream",
		"-e", "udp.stream",
	)

	fmt.Fprintln(os.Stderr, cmd.String())

	output, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to run tshark: %v", err)
	}

	// This can use a lot of memory depending on the number of packets
	var tsPackets []TsharkPacket
	if err := json.Unmarshal(output, &tsPackets); err != nil {
		log.Fatalf("Failed to parse JSON: %v", err)
	}

	sniMap := make(map[IpProto]map[int]*TLS)

	var pkts = make([]*Packet, 0, len(tsPackets))
	prevTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tsPkt := range tsPackets {
		pkt, err := tsPkt.ToPacket()
		if err != nil {
			log.Fatalln(err)
		}

		if prevTime == pkt.Time {
			pkt.Time = pkt.Time.Add(15 * time.Microsecond)
		}
		if prevTime == pkt.Time {
			log.Fatalf("prev and current pkt time are the same: %s", tsPkt.Source.Layers.TimeEpoch[0])
		}
		prevTime = pkt.Time

		if _, ok := sniMap[pkt.IpProto]; !ok {
			sniMap[pkt.IpProto] = make(map[int]*TLS)
		}

		if _, ok := sniMap[pkt.IpProto][pkt.StreamIndex]; !ok {
			sniMap[pkt.IpProto][pkt.StreamIndex] = &TLS{}
		}

		tls := sniMap[pkt.IpProto][pkt.StreamIndex]
		if pkt.TLS != nil {
			if len(pkt.TLS.Sni) != 0 {
				tls.Sni = pkt.TLS.Sni
			}
			if len(pkt.TLS.Alpn) != 0 {
				tls.Alpn = pkt.TLS.Alpn
			}
		}
		pkt.TLS = tls

		pkts = append(pkts, pkt)
		if *verbose {
			log.Debugln(pkt)
		}
	}

	log.Printf("found %d pkts", len(pkts))

	savedPkts, err := SendPacketsToQuestDB(pkts, client, tableName)
	if err != nil {
		log.Fatalf("error saving pkts: %v", err)
	}

	log.Printf("saved %d pkts in table: %s", savedPkts, tableName)
}
