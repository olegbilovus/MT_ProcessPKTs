package packet

import (
	"fmt"

	"github.com/olegbilovus/MT_ProcessPKTs/internal/utility"
)

type IpProto int

const (
	HOPOPT                            IpProto = 0   // 0: IPv6 Hop-by-Hop Option
	ICMP                              IpProto = 1   // 1: Internet Control Message
	IGMP                              IpProto = 2   // 2: Internet Group Management
	GGP                               IpProto = 3   // 3: Gateway-to-Gateway
	IPv4                              IpProto = 4   // 4: IPv4 encapsulation
	ST                                IpProto = 5   // 5: Stream
	TCP                               IpProto = 6   // 6: Transmission Control
	CBT                               IpProto = 7   // 7: CBT
	EGP                               IpProto = 8   // 8: Exterior Gateway Protocol
	IGP                               IpProto = 9   // 9: any private interior gateway
	BBN_RCC_MON                       IpProto = 10  // 10: BBN RCC Monitoring
	NVP_II                            IpProto = 11  // 11: Network Voice Protocol
	PUP                               IpProto = 12  // 12: PUP
	ARGUS                             IpProto = 13  // 13: ARGUS (deprecated)
	EMCON                             IpProto = 14  // 14: EMCON
	XNET                              IpProto = 15  // 15: Cross Net Debugger
	CHAOS                             IpProto = 16  // 16: Chaos
	UDP                               IpProto = 17  // 17: User Datagram
	MUX                               IpProto = 18  // 18: Multiplexing
	DCN_MEAS                          IpProto = 19  // 19: DCN Measurement Subsystems
	HMP                               IpProto = 20  // 20: Host Monitoring
	PRM                               IpProto = 21  // 21: Packet Radio Measurement
	XNS_IDP                           IpProto = 22  // 22: XEROX NS IDP
	TRUNK_1                           IpProto = 23  // 23: Trunk-1
	TRUNK_2                           IpProto = 24  // 24: Trunk-2
	LEAF_1                            IpProto = 25  // 25: Leaf-1
	LEAF_2                            IpProto = 26  // 26: Leaf-2
	RDP                               IpProto = 27  // 27: Reliable Data Protocol
	IRTP                              IpProto = 28  // 28: Internet Reliable Transaction
	ISO_TP4                           IpProto = 29  // 29: ISO Transport Protocol Class 4
	NETBLT                            IpProto = 30  // 30: Bulk Data Transfer Protocol
	MFE_NSP                           IpProto = 31  // 31: MFE Network Services Protocol
	MERIT_INP                         IpProto = 32  // 32: MERIT Internodal Protocol
	DCCP                              IpProto = 33  // 33: Datagram Congestion Control Protocol
	_3PC                              IpProto = 34  // 34: Third Party Connect Protocol
	IDPR                              IpProto = 35  // 35: Inter-Domain Policy Routing Protocol
	XTP                               IpProto = 36  // 36: XTP
	DDP                               IpProto = 37  // 37: Datagram Delivery Protocol
	IDPR_CMTP                         IpProto = 38  // 38: IDPR Control Message Transport Proto
	TP_PLUS                           IpProto = 39  // 39: TP++ Transport Protocol
	IL                                IpProto = 40  // 40: IL Transport Protocol
	IPv6                              IpProto = 41  // 41: IPv6 encapsulation
	SDRP                              IpProto = 42  // 42: Source Demand Routing Protocol
	IPv6_ROUTE                        IpProto = 43  // 43: Routing Header for IPv6
	IPv6_FRAG                         IpProto = 44  // 44: Fragment Header for IPv6
	IDRP                              IpProto = 45  // 45: Inter-Domain Routing Protocol
	RSVP                              IpProto = 46  // 46: Reservation Protocol
	GRE                               IpProto = 47  // 47: Generic Routing Encapsulation
	DSR                               IpProto = 48  // 48: Dynamic Source Routing Protocol
	BNA                               IpProto = 49  // 49: BNA
	ESP                               IpProto = 50  // 50: Encap Security Payload
	AH                                IpProto = 51  // 51: Authentication Header
	I_NLSP                            IpProto = 52  // 52: Integrated Net Layer Security TUBA
	SWIPE                             IpProto = 53  // 53: IP with Encryption (deprecated)
	NARP                              IpProto = 54  // 54: NBMA Address Resolution Protocol
	Min_IPv4                          IpProto = 55  // 55: Minimal IPv4 Encapsulation
	TLSP                              IpProto = 56  // 56: Transport Layer Security Protocol using Kryptonet key management
	SKIP                              IpProto = 57  // 57: SKIP
	IPv6_ICMP                         IpProto = 58  // 58: ICMP for IPv6
	IPv6_NoNxt                        IpProto = 59  // 59: No Next Header for IPv6
	IPv6_Opts                         IpProto = 60  // 60: Destination Options for IPv6
	any_host_internal                 IpProto = 61  // 61: any host internal protocol
	CFTP                              IpProto = 62  // 62: CFTP
	any_local_network                 IpProto = 63  // 63: any local network
	SAT_EXPAK                         IpProto = 64  // 64: SATNET and Backroom EXPAK
	KRYPTOLAN                         IpProto = 65  // 65: Kryptolan
	RVD                               IpProto = 66  // 66: MIT Remote Virtual Disk Protocol
	IPPC                              IpProto = 67  // 67: Internet Pluribus Packet Core
	any_distributed_file_system       IpProto = 68  // 68: any distributed file system
	SAT_MON                           IpProto = 69  // 69: SATNET Monitoring
	VISA                              IpProto = 70  // 70: VISA Protocol
	IPCV                              IpProto = 71  // 71: Internet Packet Core Utility
	CPNX                              IpProto = 72  // 72: Computer Protocol Network Executive
	CPHB                              IpProto = 73  // 73: Computer Protocol Heart Beat
	WSN                               IpProto = 74  // 74: Wang Span Network
	PVP                               IpProto = 75  // 75: Packet Video Protocol
	BR_SAT_MON                        IpProto = 76  // 76: Backroom SATNET Monitoring
	SUN_ND                            IpProto = 77  // 77: SUN ND PROTOCOL-Temporary
	WB_MON                            IpProto = 78  // 78: WIDEBAND Monitoring
	WB_EXPAK                          IpProto = 79  // 79: WIDEBAND EXPAK
	ISO_IP                            IpProto = 80  // 80: ISO Internet Protocol
	VMTP                              IpProto = 81  // 81: VMTP
	SECURE_VMTP                       IpProto = 82  // 82: SECURE-VMTP
	VINES                             IpProto = 83  // 83: VINES
	IPTM                              IpProto = 84  // 84: Internet Protocol Traffic Manager
	NSFNET_IGP                        IpProto = 85  // 85: NSFNET-IGP
	DGP                               IpProto = 86  // 86: Dissimilar Gateway Protocol
	TCF                               IpProto = 87  // 87: TCF
	EIGRP                             IpProto = 88  // 88: EIGRP
	OSPFIGP                           IpProto = 89  // 89: OSPFIGP
	Sprite_RPC                        IpProto = 90  // 90: Sprite RPC Protocol
	LARP                              IpProto = 91  // 91: Locus Address Resolution Protocol
	MTP                               IpProto = 92  // 92: Multicast Transport Protocol
	AX_25                             IpProto = 93  // 93: AX.25 Frames
	IPIP                              IpProto = 94  // 94: IP-within-IP Encapsulation Protocol
	MICP                              IpProto = 95  // 95: Mobile Internetworking Control Pro. (deprecated)
	SCC_SP                            IpProto = 96  // 96: Semaphore Communications Sec. Pro.
	ETHERIP                           IpProto = 97  // 97: Ethernet-within-IP Encapsulation
	ENCAP                             IpProto = 98  // 98: Encapsulation Header
	private_encryption_scheme         IpProto = 99  // 99: any private encryption scheme
	GMTP                              IpProto = 100 // 100: GMTP
	IFMP                              IpProto = 101 // 101: Ipsilon Flow Management Protocol
	PNNI                              IpProto = 102 // 102: PNNI over IP
	PIM                               IpProto = 103 // 103: Protocol Independent Multicast
	ARIS                              IpProto = 104 // 104: ARIS
	SCPS                              IpProto = 105 // 105: SCPS
	QNX                               IpProto = 106 // 106: QNX
	AN                                IpProto = 107 // 107: Active Networks
	IPComp                            IpProto = 108 // 108: IP Payload Compression Protocol
	SNP                               IpProto = 109 // 109: Sitara Networks Protocol
	Compaq_Peer                       IpProto = 110 // 110: Compaq Peer Protocol
	IPX_in_IP                         IpProto = 111 // 111: IPX in IP
	VRRP                              IpProto = 112 // 112: Virtual Router Redundancy Protocol
	PGM                               IpProto = 113 // 113: PGM Reliable Transport Protocol
	any_0_hop_protocol                IpProto = 114 // 114: any 0-hop protocol
	L2TP                              IpProto = 115 // 115: Layer Two Tunneling Protocol
	DDX                               IpProto = 116 // 116: D-II Data Exchange (DDX)
	IATP                              IpProto = 117 // 117: Interactive Agent Transfer Protocol
	STP                               IpProto = 118 // 118: Schedule Transfer Protocol
	SRP                               IpProto = 119 // 119: SpectraLink Radio Protocol
	UTI                               IpProto = 120 // 120: UTI
	SMP                               IpProto = 121 // 121: Simple Message Protocol
	SM                                IpProto = 122 // 122: Simple Multicast Protocol (deprecated)
	PTP                               IpProto = 123 // 123: Performance Transparency Protocol
	ISIS_over_IP                      IpProto = 124 // 124: ISIS over IPv4
	FIRE                              IpProto = 125 // 125: FIRE
	CRTP                              IpProto = 126 // 126: Combat Radio Transport Protocol
	CRUDP                             IpProto = 127 // 127: Combat Radio User Datagram
	SSCOPMCE                          IpProto = 128 // 128:
	IPLT                              IpProto = 129 // 129:
	SPS                               IpProto = 130 // 130: Secure Packet Shield
	PIPE                              IpProto = 131 // 131: Private IP Encapsulation within IP
	SCTP                              IpProto = 132 // 132: Stream Control Transmission Protocol
	FC                                IpProto = 133 // 133: Fibre Channel
	RSVP_E2E_IGNORE                   IpProto = 134 // 134:
	Mobility_Header                   IpProto = 135 // 135:
	UDPLite                           IpProto = 136 // 136:
	MPLS_in_IP                        IpProto = 137 // 137:
	manet                             IpProto = 138 // 138: MANET Protocols
	HIP                               IpProto = 139 // 139: Host Identity Protocol
	Shim6                             IpProto = 140 // 140: Shim6 Protocol
	WESP                              IpProto = 141 // 141: Wrapped Encapsulating Security Payload
	ROHC                              IpProto = 142 // 142: Robust Header Compression
	Ethernet                          IpProto = 143 // 143: Ethernet
	AGGFRAG                           IpProto = 144 // 144: AGGFRAG encapsulation payload for ESP
	NSH                               IpProto = 145 // 145: Network Service Header
	Homa                              IpProto = 146 // 146: Homa
	BIT_EMU                           IpProto = 147 // 147: Bit-stream Emulation
	Unassigned                        IpProto = 148 // 148-252: Unassigned
	Experimentation_Testing_IpProto   IpProto = 253 // 253: Use for experimentation and testing
	Experimentation_Testing_IpProto_2 IpProto = 254 // 254: Use for experimentation and testing
	Reserved                          IpProto = 255 // 255: Reserved
)

// String method to return the protocol name instead of its integer value
func (p IpProto) String() string {
	switch p {
	case HOPOPT:
		return "HOPOPT"
	case ICMP:
		return "ICMP"
	case IGMP:
		return "IGMP"
	case GGP:
		return "GGP"
	case IPv4:
		return "IPv4"
	case ST:
		return "ST"
	case TCP:
		return "TCP"
	case CBT:
		return "CBT"
	case EGP:
		return "EGP"
	case IGP:
		return "IGP"
	case BBN_RCC_MON:
		return "BBN_RCC_MON"
	case NVP_II:
		return "NVP-II"
	case PUP:
		return "PUP"
	case ARGUS:
		return "ARGUS (deprecated)"
	case EMCON:
		return "EMCON"
	case XNET:
		return "XNET"
	case CHAOS:
		return "CHAOS"
	case UDP:
		return "UDP"
	case MUX:
		return "MUX"
	case DCN_MEAS:
		return "DCN-MEAS"
	case HMP:
		return "HMP"
	case PRM:
		return "PRM"
	case XNS_IDP:
		return "XNS-IDP"
	case TRUNK_1:
		return "TRUNK-1"
	case TRUNK_2:
		return "TRUNK-2"
	case LEAF_1:
		return "LEAF-1"
	case LEAF_2:
		return "LEAF-2"
	case RDP:
		return "RDP"
	case IRTP:
		return "IRTP"
	case ISO_TP4:
		return "ISO-TP4"
	case NETBLT:
		return "NETBLT"
	case MFE_NSP:
		return "MFE-NSP"
	case MERIT_INP:
		return "MERIT-INP"
	case DCCP:
		return "DCCP"
	case _3PC:
		return "3PC"
	case IDPR:
		return "IDPR"
	case XTP:
		return "XTP"
	case DDP:
		return "DDP"
	case IDPR_CMTP:
		return "IDPR-CMTP"
	case TP_PLUS:
		return "TP++"
	case IL:
		return "IL"
	case IPv6:
		return "IPv6"
	case SDRP:
		return "SDRP"
	case IPv6_ROUTE:
		return "IPv6-Route"
	case IPv6_FRAG:
		return "IPv6-Frag"
	case IDRP:
		return "IDRP"
	case RSVP:
		return "RSVP"
	case GRE:
		return "GRE"
	case DSR:
		return "DSR"
	case BNA:
		return "BNA"
	case ESP:
		return "ESP"
	case AH:
		return "AH"
	case I_NLSP:
		return "I-NLSP"
	case SWIPE:
		return "SWIPE (deprecated)"
	case NARP:
		return "NARP"
	case Min_IPv4:
		return "Min-IPv4"
	case TLSP:
		return "TLSP"
	case SKIP:
		return "SKIP"
	case IPv6_ICMP:
		return "IPv6-ICMP"
	case IPv6_NoNxt:
		return "IPv6-NoNxt"
	case IPv6_Opts:
		return "IPv6-Opts"
	case any_host_internal:
		return "any host internal protocol"
	case CFTP:
		return "CFTP"
	case any_local_network:
		return "any local network"
	case SAT_EXPAK:
		return "SAT-EXPAK"
	case KRYPTOLAN:
		return "KRYPTOLAN"
	case RVD:
		return "RVD"
	case IPPC:
		return "IPPC"
	case any_distributed_file_system:
		return "any distributed file system"
	case SAT_MON:
		return "SAT-MON"
	case VISA:
		return "VISA"
	case IPCV:
		return "IPCV"
	case CPNX:
		return "CPNX"
	case CPHB:
		return "CPHB"
	case WSN:
		return "WSN"
	case PVP:
		return "PVP"
	case BR_SAT_MON:
		return "BR-SAT-MON"
	case SUN_ND:
		return "SUN-ND"
	case WB_MON:
		return "WB-MON"
	case WB_EXPAK:
		return "WB-EXPAK"
	case ISO_IP:
		return "ISO-IP"
	case VMTP:
		return "VMTP"
	case SECURE_VMTP:
		return "SECURE-VMTP"
	case VINES:
		return "VINES"
	case IPTM:
		return "IPTM"
	case NSFNET_IGP:
		return "NSFNET-IGP"
	case DGP:
		return "DGP"
	case TCF:
		return "TCF"
	case EIGRP:
		return "EIGRP"
	case OSPFIGP:
		return "OSPF-IGP"
	case Sprite_RPC:
		return "Sprite-RPC"
	case LARP:
		return "LARP"
	case MTP:
		return "MTP"
	case AX_25:
		return "AX.25"
	case IPIP:
		return "IPIP"
	case MICP:
		return "MICP (deprecated)"
	case SCC_SP:
		return "SCC-SP"
	case ETHERIP:
		return "ETHERIP"
	case ENCAP:
		return "ENCAP"
	case private_encryption_scheme:
		return "any private encryption scheme"
	case GMTP:
		return "GMTP"
	case IFMP:
		return "IFMP"
	case PNNI:
		return "PNNI"
	case PIM:
		return "PIM"
	case ARIS:
		return "ARIS"
	case SCPS:
		return "SCPS"
	case QNX:
		return "QNX"
	case AN:
		return "A/N"
	case IPComp:
		return "IPComp"
	case SNP:
		return "SNP"
	case Compaq_Peer:
		return "Compaq-Peer"
	case IPX_in_IP:
		return "IPX-in-IP"
	case VRRP:
		return "VRRP"
	case PGM:
		return "PGM"
	case any_0_hop_protocol:
		return "any 0-hop protocol"
	case L2TP:
		return "L2TP"
	case DDX:
		return "DDX"
	case IATP:
		return "IATP"
	case STP:
		return "STP"
	case SRP:
		return "SRP"
	case UTI:
		return "UTI"
	case SMP:
		return "SMP"
	case SM:
		return "SM (deprecated)"
	case PTP:
		return "PTP"
	case ISIS_over_IP:
		return "ISIS over IPv4"
	case FIRE:
		return "FIRE"
	case CRTP:
		return "CRTP"
	case CRUDP:
		return "CRUDP"
	case SSCOPMCE:
		return "SSCOPMCE"
	case IPLT:
		return "IPLT"
	case SPS:
		return "SPS"
	case PIPE:
		return "PIPE"
	case SCTP:
		return "SCTP"
	case FC:
		return "FC"
	case RSVP_E2E_IGNORE:
		return "RSVP-E2E-IGNORE"
	case Mobility_Header:
		return "Mobility Header"
	case UDPLite:
		return "UDPLite"
	case MPLS_in_IP:
		return "MPLS-in-IP"
	case manet:
		return "manet"
	case HIP:
		return "HIP"
	case Shim6:
		return "Shim6"
	case WESP:
		return "WESP"
	case ROHC:
		return "ROHC"
	case Ethernet:
		return "Ethernet"
	case AGGFRAG:
		return "AGGFRAG"
	case NSH:
		return "NSH"
	case Homa:
		return "Homa"
	case BIT_EMU:
		return "BIT-EMU"
	case Unassigned:
		return "Unassigned"
	case Experimentation_Testing_IpProto:
		return "Use for experimentation and testing"
	case Experimentation_Testing_IpProto_2:
		return "Use for experimentation and testing"
	case Reserved:
		return "Reserved"
	default:
		return utility.UNKNOWN
	}
}

func NewIpProto(proto int) (IpProto, error) {
	if proto < 0 || proto > 255 {
		return -1, fmt.Errorf("invalid IP protocol number: %d", proto)
	}
	return IpProto(proto), nil
}
