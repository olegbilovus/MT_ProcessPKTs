package packet

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/olegbilovus/MT_ProcessPKTs/internal/utility"
)

type TsharkPacket struct {
	Source struct {
		Layers struct {
			TimeEpoch      []string `json:"frame.time_epoch"`
			IpSrc          []string `json:"ip.src"`
			IpDst          []string `json:"ip.dst"`
			FrameLen       []string `json:"frame.len"`
			IpProtocol     []string `json:"ip.proto"`
			TcpPorts       []string `json:"tcp.port"`
			UdpPorts       []string `json:"udp.port"`
			SNI            []string `json:"tls.handshake.extensions_server_name"`
			ALPN           []string `json:"tls.handshake.extensions_alpn_str"`
			TcpStreamIndex []string `json:"tcp.stream"`
			UdpStreamIndex []string `json:"udp.stream"`
		} `json:"layers"`
	} `json:"_source"`
}

//goland:noinspection D
func (p *TsharkPacket) ToPacket() (*Packet, error) {
	tsPkt := p.Source.Layers
	var (
		pktTime time.Time
		err     error
	)
	if pktTime, err = utility.ConvertTimestamp(tsPkt.TimeEpoch[0]); err != nil {
		return nil, err
	}

	var protocolID int
	if protocolID, err = strconv.Atoi(tsPkt.IpProtocol[len(tsPkt.IpProtocol)-1]); err != nil {
		return nil, fmt.Errorf("invalid protocol id: %v", err)
	}

	var protocol IpProto
	if protocol, err = NewIpProto(protocolID); err != nil {
		return nil, err
	}

	var (
		portsArray     []string
		streamIndexStr string
	)
	switch protocol {
	case TCP:
		portsArray = tsPkt.TcpPorts
		streamIndexStr = tsPkt.TcpStreamIndex[0]
	case UDP:
		portsArray = tsPkt.UdpPorts
		streamIndexStr = tsPkt.UdpStreamIndex[0]
	default:
		return nil, fmt.Errorf("no valid protocol found")
	}
	if len(portsArray) != 2 {
		return nil, fmt.Errorf("could not find 2 ports")
	}
	var portSrc, portDst int
	if portSrc, err = strconv.Atoi(portsArray[0]); err != nil {
		return nil, fmt.Errorf("invalid port src: %v", err)
	}
	if portDst, err = strconv.Atoi(portsArray[1]); err != nil {
		return nil, fmt.Errorf("invalid port src: %v", err)
	}

	var streamIndex int
	if streamIndex, err = strconv.Atoi(streamIndexStr); err != nil {
		return nil, fmt.Errorf("invalid stream index: %v", err)
	}

	if len(tsPkt.IpSrc[0]) == 0 {
		return nil, fmt.Errorf("invalid ip src: %v", tsPkt.IpSrc[0])
	}
	if len(tsPkt.IpDst[0]) == 0 {
		return nil, fmt.Errorf("invalid ip dst: %v", tsPkt.IpDst[0])
	}

	var frameLen int
	if frameLen, err = strconv.Atoi(tsPkt.FrameLen[0]); err != nil {
		return nil, fmt.Errorf("invalid frame len: %v", err)
	}

	var tls *TLS = nil
	if len(tsPkt.SNI) != 0 {
		sni := tsPkt.SNI[0]
		if len(sni) != 0 {
			tls = &TLS{Sni: sni}
		}
	}
	if len(tsPkt.ALPN) != 0 {
		alpn := tsPkt.ALPN[0]
		if len(alpn) != 0 {
			if tls != nil {
				tls.Alpn = alpn
			} else {
				tls = &TLS{Alpn: alpn}
			}
		}
	}

	pkt := &Packet{
		Time:        pktTime,
		IpSrc:       tsPkt.IpSrc[0],
		PortSrc:     portSrc,
		IpDst:       tsPkt.IpDst[0],
		PortDst:     portDst,
		FrameLen:    frameLen,
		IpProto:     protocol,
		TLS:         tls,
		StreamIndex: streamIndex,
	}

	pkt.IpSrcType = GetIpType(pkt.IpSrc)
	pkt.IpDstType = GetIpType(pkt.IpDst)

	return pkt, nil
}

type TLS struct {
	Sni  string `json:"tls_sni"`
	Alpn string `json:"tls_alpn"`
}

func (t TLS) String() string {
	return t.Sni + " - " + t.Alpn
}

type IpType int

const (
	LOCAL IpType = iota
	PUBLIC
)

func (p IpType) String() string {
	switch p {
	case LOCAL:

		return "LOCAL"
	case PUBLIC:
		return "PUBLIC"
	default:
		return utility.UNKNOWN

	}
}

func GetIpType(ipStr string) IpType {
	ip := net.ParseIP(ipStr)
	if ip.IsLoopback() || ip.IsPrivate() {
		return LOCAL
	}
	return PUBLIC
}

type NetifyIP struct {
	AppTag         string  `json:"app_tag"`
	AppCategoryTag string  `json:"app_category_tag"`
	GeoContinent   string  `json:"geo_continent"`
	GeoCountry     string  `json:"geo_country"`
	GeoCity        string  `json:"geo_city"`
	GeoLongitude   float64 `json:"geo_lon"`
	GeoLatitude    float64 `json:"geo_lat"`
}

type Packet struct {
	Time      time.Time `json:"ts"`
	IpSrc     string    `json:"ip_src"`
	IpSrcType IpType    `json:"ip_src_type"`
	PortSrc   int       `json:"port_src"`
	IpDst     string    `json:"ip_dst"`
	IpDstType IpType    `json:"ip_dst_type"`
	PortDst   int       `json:"port_dst"`
	FrameLen  int       `json:"frame_len"`
	IpProto   IpProto   `json:"ip_proto"`
	*TLS
	StreamIndex int      `json:"stream_index"`
	IpSrcNetify NetifyIP `json:"ip_src_netify"`
	IpDstNetify NetifyIP `json:"ip_dst_netify"`
	SNINetify   struct {
		AppTag            string `json:"app_tag"`
		AppCategoryTag    string `json:"app_category_tag"`
		DomainCategoryTag string `json:"domain_category_tag"`
	} `json:"tls_sni_netify"`
}

func (p *Packet) String() string {
	return fmt.Sprintf("[%d][%v] %s:%d -> %s:%d \t %db %s -- %s", p.StreamIndex, p.Time, p.IpSrc, p.PortSrc, p.IpDst, p.PortDst, p.FrameLen, p.IpProto, p.TLS)
}
