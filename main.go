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
	"time"

	"github.com/olegbilovus/MT_ProcessPKTs/netify"
	"github.com/questdb/go-questdb-client/v4"
	log "github.com/sirupsen/logrus"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
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
	log.SetLevel(log.InfoLevel)

	var pcapFile = flag.String("pcap", "capture.pcap", "path to the pcap file")
	var filter = flag.String("filter", "", "filter to use")
	var name = flag.String("name", "", "name of the experiment. It will overwrite any existing ones")

	var netifyApiKey = flag.String("netify-apikey", "", "Netify API key")
	var netifyCacheServerPort = flag.Int("netify-cache-port", 0, "Netify cache server port. Default is random port")
	var netifyCacheFilesDir = flag.String("netify-cache-dir", "netify_cache", "where to cache Netify responses")
	flag.Parse()

	var err error

	experimentName := *name

	if len(experimentName) == 0 {
		experimentName = filepath.Base(*pcapFile)
		experimentName = strings.TrimSuffix(experimentName, filepath.Ext(experimentName))
	}

	if err := InitQuestDB("http://127.0.0.1:9000", experimentName); err != nil {
		log.Fatalf("failed to init QuestDB: %v", err)
	}

	if len(*netifyApiKey) == 0 {
		log.Fatalln("invalid Netify api key")
	}
	if len(*netifyCacheFilesDir) == 0 {
		log.Fatalln("invalid Netify cache files dir")
	}

	netifyCacheServer := netify.CacheServer{
		ApiKey:          *netifyApiKey,
		CacheServerPort: *netifyCacheServerPort,
		CacheFilesDir:   *netifyCacheFilesDir,
	}
	if err := netifyCacheServer.Init(); err != nil {
		log.Fatalf("error starting Netify cache server: %v", err)
	}
	defer func() {
		if err := netifyCacheServer.Shutdown(); err != nil {
			log.Fatalf("error shutting down Netify cache server: %v", err)
		}
	}()

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

	pkts, err := getPackets(cmd)
	if err != nil {
		log.Fatalln(err)
	}

	log.Printf("found %d pkts", len(pkts))

	ctx := context.TODO()

	client, err := questdb.LineSenderFromConf(ctx, "http::addr=localhost:9000;username=admin;password=quest;retry_timeout=0")
	if err != nil {
		log.Fatalf("failed to create QuestDB client: %v", err)
	}
	defer client.Close(ctx)

	p := mpb.New(mpb.WithAutoRefresh())
	bar := p.AddBar(int64(len(pkts)),
		mpb.PrependDecorators(decor.Name("pkt", decor.WC{C: decor.DindentRight | decor.DextraSpace}),
			decor.CountersNoUnit("%3d/%3d", decor.WCSyncWidth)),
	)

	ipsMap := map[string]*netify.IPData{}
	hostnamesMap := map[string]*netify.HostnameData{}
	/* Can not run this in multiple goroutines because of Netify low rate limit and because of concurrency,
	it would request the same resources to Netify multiple times before caching which would lead to a higher api consumption
	*/
	for _, pkt := range pkts {
		start := time.Now()
		ips := map[string]*NetifyIP{
			pkt.IpSrc: &pkt.IpSrcNetify,
			pkt.IpDst: &pkt.IpDstNetify,
		}

		for ip, ipNetify := range ips {
			ipNetifyData, ok := ipsMap[ip]
			if !ok {
				if ipNetifyData, err = netifyCacheServer.QueryIPData(ip); err != nil {
					log.WithField("ip", ip).Fatalf("error getting Netify Ip data: %v", err)
				}
				ipsMap[ip] = ipNetifyData
			}

			var additionalAppTag, additionalAppCategoryTag string
			if len(ipNetifyData.Data.ApplicationList) == 1 {
				additionalAppTag = ipNetifyData.Data.ApplicationList[0].Tag
				additionalAppCategoryTag = ipNetifyData.Data.ApplicationList[0].Category.Tag
			}
			ipNetify.AppTag = DefaultIfEmpty(ipNetifyData.Data.RDNS.Application.Tag, ipNetifyData.Data.TlsCertificate.Application.Tag, additionalAppTag)
			ipNetify.AppCategoryTag = DefaultIfEmpty(ipNetifyData.Data.RDNS.Application.Category.Tag, ipNetifyData.Data.TlsCertificate.Application.Category.Tag, additionalAppCategoryTag)
			geoData := ipNetifyData.Data.Geolocation
			if geoData != nil {
				ipNetify.GeoContinent = geoData.Continent.Label
				ipNetify.GeoCountry = geoData.Country.Label
				ipNetify.GeoCity = geoData.City.Label
				if lon, err := strconv.ParseFloat(geoData.Coordinates.Longitude, 64); err == nil {
					ipNetify.GeoLongitude = lon
				} else {
					log.Fatalf("error parsing geo_lon from Netify: %v", err)
				}
				if lat, err := strconv.ParseFloat(geoData.Coordinates.Latitude, 64); err == nil {
					ipNetify.GeoLatitude = lat
				} else {
					log.Fatalf("error parsing geo_lat from Netify: %v", err)
				}
			}
		}

		if len(pkt.Sni) != 0 && pkt.Sni != UNKNOWN {
			netifySNI, ok := hostnamesMap[pkt.Sni]
			if !ok {
				netifySNI, err = netifyCacheServer.QueryHostnameData(pkt.Sni)
				if err != nil {
					if strings.ContainsAny(err.Error(), "404") {
						netifySNI = &netify.HostnameData{}
						log.WithField("tls_sni", pkt.Sni).Warning("could not find Netify Hostname data: %v", err)
					} else {
						log.WithField("tls_sni", pkt.Sni).Fatalf("error getting Netify Hostname data: %v", err)
					}
				}
				hostnamesMap[pkt.Sni] = netifySNI
			}
			pkt.SNINetify.AppTag = DefaultIfEmpty(netifySNI.Data.Application.Tag)
			pkt.SNINetify.AppCategoryTag = DefaultIfEmpty(netifySNI.Data.Application.Category.Tag)
			if netifySNI.Data.Domain != nil {
				pkt.SNINetify.DomainCategoryTag = DefaultIfEmpty(netifySNI.Data.Domain.Category.Tag)
			} else {
				pkt.SNINetify.DomainCategoryTag = UNKNOWN
			}
		} else {
			pkt.SNINetify.AppTag = UNKNOWN
			pkt.SNINetify.AppCategoryTag = UNKNOWN
			pkt.SNINetify.DomainCategoryTag = UNKNOWN
		}

		err := client.Table(GetTableName(experimentName)).
			Symbol("ip_proto", pkt.IpProto.String()).
			Symbol("tls_sni", pkt.Sni).
			Symbol("tls_alpn", pkt.Alpn).
			Symbol("ip_src_type", pkt.IpSrcType.String()).
			Symbol("ip_dst_type", pkt.IpDstType.String()).
			Symbol("ip_src_netify_app_tag", pkt.IpSrcNetify.AppTag).
			Symbol("ip_src_netify_app_category_tag", pkt.IpSrcNetify.AppCategoryTag).
			Symbol("ip_src_netify_geo_continent", pkt.IpSrcNetify.GeoContinent).
			Symbol("ip_src_netify_geo_country", pkt.IpSrcNetify.GeoCountry).
			Symbol("ip_src_netify_geo_city", pkt.IpSrcNetify.GeoCity).
			Symbol("ip_dst_netify_app_tag", pkt.IpDstNetify.AppTag).
			Symbol("ip_dst_netify_app_category_tag", pkt.IpDstNetify.AppCategoryTag).
			Symbol("ip_dst_netify_geo_continent", pkt.IpDstNetify.GeoContinent).
			Symbol("ip_dst_netify_geo_country", pkt.IpDstNetify.GeoCountry).
			Symbol("ip_dst_netify_geo_city", pkt.IpDstNetify.GeoCity).
			Symbol("tls_sni_netify_app_tag", pkt.SNINetify.AppTag).
			Symbol("tls_sni_netify_app_category_tag", pkt.SNINetify.AppCategoryTag).
			Symbol("tls_sni_netify_domain_tag", pkt.SNINetify.DomainCategoryTag).
			Float64Column("ip_src_netify_geo_lon", pkt.IpSrcNetify.GeoLongitude).
			Float64Column("ip_src_netify_geo_lat", pkt.IpSrcNetify.GeoLatitude).
			Float64Column("ip_dst_netify_geo_lon", pkt.IpDstNetify.GeoLongitude).
			Float64Column("ip_dst_netify_geo_lat", pkt.IpDstNetify.GeoLatitude).
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

		bar.EwmaIncrement(time.Since(start))
	}

	bar.Completed()

	if err := client.Flush(ctx); err != nil {
		log.Fatalln(err)
	}

	ipsCached, ipsRequested := netifyCacheServer.IPCacheStats()
	hostnamesCached, hostnameRequested := netifyCacheServer.HostnameCacheStats()
	log.WithFields(log.Fields{
		"ips_cached":          ipsCached,
		"ips_requested":       ipsRequested,
		"hostnames_cached":    hostnamesCached,
		"hostnames_requested": hostnameRequested,
	}).Info("Netify cache server stats")

	log.Infof("saved pkts in QuestDB on table: %s", GetTableName(experimentName))
}

func getTsharkPackets(cmd *exec.Cmd) ([]TsharkPacket, error) {
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to run tshark: %v", err)
	}

	// This can use a lot of memory depending on the number of packets
	var tsPackets []TsharkPacket
	if err := json.Unmarshal(output, &tsPackets); err != nil {
		return nil, fmt.Errorf("failed to parse JSON: %v", err)
	}

	return tsPackets, nil
}

//goland:noinspection D
func getPackets(cmd *exec.Cmd) ([]*Packet, error) {
	tsPackets, err := getTsharkPackets(cmd)
	if err != nil {
		return nil, err
	}
	log.Info("got tshark packets")

	sniMap := make(map[IpProto]map[int]*TLS)
	var pkts = make([]*Packet, 0, len(tsPackets))
	for _, tsPkt := range tsPackets {
		pkt, err := tsPkt.ToPacket()
		if err != nil {
			return nil, err
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
	}

	return pkts, nil
}
