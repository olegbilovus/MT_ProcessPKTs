package main

import (
	"context"
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

	"github.com/questdb/go-questdb-client/v4"
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
	tableName := "packets_" + filepath.Base(*pcapFile)
	tableName = strings.TrimSuffix(tableName, filepath.Ext(tableName))

	if err := InitQuestDB("http://127.0.0.1:9000", tableName); err != nil {
		log.Fatalf("failed to init QuestDB: %v", err)
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
		log.Fatalf("failed to run tshark: %v", err)
	}

	// This can use a lot of memory depending on the number of packets
	var tsPackets []TsharkPacket
	if err := json.Unmarshal(output, &tsPackets); err != nil {
		log.Fatalf("failed to parse JSON: %v", err)
	}

	sniMap := make(map[IpProto]map[int]*TLS)
	var pkts = make([]*Packet, 0, len(tsPackets))
	for _, tsPkt := range tsPackets {
		pkt, err := tsPkt.ToPacket()
		if err != nil {
			log.Fatalln(err)
		}

		if _, ok := sniMap[pkt.IpProto]; !ok {
			sniMap[pkt.IpProto] = make(map[int]*TLS)
		}

		if _, ok := sniMap[pkt.IpProto][pkt.StreamIndex]; !ok {
			sniMap[pkt.IpProto][pkt.StreamIndex] = &TLS{UNKNOWN, UNKNOWN}
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

	ctx := context.TODO()

	client, err := questdb.LineSenderFromConf(ctx, "http::addr=localhost:9000;username=admin;password=quest;retry_timeout=0")
	if err != nil {
		log.Fatalf("failed to create QuestDB client: %v", err)
	}
	defer client.Close(ctx)

	for _, pkt := range pkts {
		err := client.Table(tableName).
			Symbol("ip_proto", pkt.IpProto.String()).
			Symbol("tls_sni", pkt.Sni).
			Symbol("tls_alpn", pkt.Alpn).
			Symbol("ip_src_type", pkt.IpSrcType.String()).
			Symbol("ip_dst_type", pkt.IpDstType.String()).
			StringColumn("ip_src", pkt.IpSrc).
			Int64Column("port_src", int64(pkt.PortSrc)).
			StringColumn("ip_dst", pkt.IpDst).
			Int64Column("port_dst", int64(pkt.PortDst)).
			Int64Column("frame_len", int64(pkt.FrameLen)).
			Int64Column("stream_index", int64(pkt.StreamIndex)).
			At(ctx, pkt.Time)
		if err != nil {
			log.Fatalln(err)
		}
	}

	if err := client.Flush(ctx); err != nil {
		log.Fatalln(err)
	}

	log.Infof("saved pkts in QuestDB on table: %s", tableName)
}
