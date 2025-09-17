package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/questdb/go-questdb-client/v4"
)

//goland:noinspection D
func main() {
	var pcapFile = flag.String("pcap", "capture.pcap", "path to the pcap file")
	var filter = flag.String("filter", "", "filter to use")
	flag.Parse()

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

	ctx := context.TODO()

	client, err := questdb.LineSenderFromConf(ctx, "http::addr=localhost:9000;username=admin;password=quest;retry_timeout=0")
	if err != nil {
		panic("Failed to create client")
	}
	defer client.Close(ctx)

	sniMap := make(map[IpProto]map[int]*TLS)

	var pkts = make([]*Packet, 0, len(tsPackets))
	prevTime := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tsPkt := range tsPackets {
		pkt, err := tsPkt.ToPacket()
		if err != nil {
			log.Fatalln(err)
		}

		if prevTime == pkt.Time {
			pkt.Time = pkt.Time.Add(15 * time.Nanosecond)
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
			if len(pkt.TLS.sni) != 0 {
				tls.sni = pkt.TLS.sni
			}
			if len(pkt.TLS.alpn) != 0 {
				tls.alpn = pkt.TLS.alpn
			}
		}
		pkt.TLS = tls

		pkts = append(pkts, pkt)
		fmt.Println(pkt)
	}

	fmt.Printf("found %d pkts", len(pkts))
}
