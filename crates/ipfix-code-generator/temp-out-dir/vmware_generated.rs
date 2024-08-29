#[allow(non_camel_case_types)]
#[repr(u16)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum IE {
    /// NSX-T-Data-Center 3.2 - Logical Swith: tenantProtocol
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    tenantProtocol = 880,
    /// NSX-T-Data-Center 3.2 - Logical Swith: tenantSourceIPv4
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    tenantSourceIPv4 = 881,
    /// NSX-T-Data-Center 3.2 - Logical Swith: tenantDestIPv4
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    tenantDestIPv4 = 882,
    /// NSX-T-Data-Center 3.2 - Logical Swith: tenantSourceIPv6
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    tenantSourceIPv6 = 883,
    /// NSX-T-Data-Center 3.2 - Logical Swith: tenantDestIPv6
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    tenantDestIPv6 = 884,
    /// NSX-T-Data-Center 3.2 - Logical Swith: tenantSourcePort
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    tenantSourcePort = 886,
    /// NSX-T-Data-Center 3.2 - Logical Swith: tenantDestPort
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    tenantDestPort = 887,
    /// NSX-T-Data-Center 3.2 - Logical Swith: egressInterfaceAttr
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    egressInterfaceAttr = 888,
    /// NSX-T-Data-Center 3.2 - Logical Swith: vxlanExportRole
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    vxlanExportRole = 889,
    /// NSX-T-Data-Center 3.2 - Logical Swith: ingressInterfaceAttr
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    ingressInterfaceAttr = 890,
    /// NSX-T-Data-Center 3.2 - Logical Swith: virtualObsID
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    virtualObsID = 898,
    /// NSX-T-Data-Center 3.2 - Distributed Firewall: ruleId
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    ruleId = 950,
    /// NSX-T-Data-Center 3.2 - Distributed Firewall: vmUuid
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    vmUuid = 951,
    /// NSX-T-Data-Center 3.2 - Distributed Firewall: vnicIndex
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    vnicIndex = 952,
    /// NSX-T-Data-Center 3.2 - Distributed Firewall: sessionFlags
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    sessionFlags = 953,
    /// NSX-T-Data-Center 3.2 - Distributed Firewall: flowDirection
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    flowDirection = 954,
    /// NSX-T-Data-Center 3.2 - Distributed Firewall: algControlFlowId
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    algControlFlowId = 955,
    /// NSX-T-Data-Center 3.2 - Distributed Firewall: algType
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    algType = 956,
    /// NSX-T-Data-Center 3.2 - Distributed Firewall: algFlowType
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    algFlowType = 957,
    /// NSX-T-Data-Center 3.2 - Distributed Firewall: averageLatency
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    averageLatency = 958,
    /// NSX-T-Data-Center 3.2 - Distributed Firewall: retransmissionCount
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    retransmissionCount = 959,
    /// NSX-T-Data-Center 3.2 - Distributed Firewall: vifUuid
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    vifUuid = 960,
    /// NSX-T-Data-Center 3.2 - Distributed Firewall: vifId
    ///
    /// Reference: [https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html](https://docs.vmware.com/en/VMware-NSX-T-Data-Center/3.2/administration/GUID-F7304386-EFAE-4479-9E3B-251519969D4C.html)
    vifId = 961,
}

impl super::InformationElementTemplate for IE {
    fn semantics(&self) -> Option<super::InformationElementSemantics> {
        match self {
            Self::tenantProtocol => Some(super::InformationElementSemantics::identifier),
            Self::tenantSourceIPv4 => Some(super::InformationElementSemantics::default),
            Self::tenantDestIPv4 => Some(super::InformationElementSemantics::default),
            Self::tenantSourceIPv6 => Some(super::InformationElementSemantics::default),
            Self::tenantDestIPv6 => Some(super::InformationElementSemantics::default),
            Self::tenantSourcePort => Some(super::InformationElementSemantics::identifier),
            Self::tenantDestPort => Some(super::InformationElementSemantics::identifier),
            Self::egressInterfaceAttr => Some(super::InformationElementSemantics::identifier),
            Self::vxlanExportRole => Some(super::InformationElementSemantics::identifier),
            Self::ingressInterfaceAttr => Some(super::InformationElementSemantics::identifier),
            Self::virtualObsID => Some(super::InformationElementSemantics::default),
            Self::ruleId => Some(super::InformationElementSemantics::identifier),
            Self::vmUuid => Some(super::InformationElementSemantics::default),
            Self::vnicIndex => Some(super::InformationElementSemantics::identifier),
            Self::sessionFlags => Some(super::InformationElementSemantics::identifier),
            Self::flowDirection => Some(super::InformationElementSemantics::identifier),
            Self::algControlFlowId => Some(super::InformationElementSemantics::identifier),
            Self::algType => Some(super::InformationElementSemantics::identifier),
            Self::algFlowType => Some(super::InformationElementSemantics::identifier),
            Self::averageLatency => Some(super::InformationElementSemantics::identifier),
            Self::retransmissionCount => Some(super::InformationElementSemantics::identifier),
            Self::vifUuid => Some(super::InformationElementSemantics::default),
            Self::vifId => Some(super::InformationElementSemantics::default),
        }
    }

    fn data_type(&self) -> super::InformationElementDataType {
        match self {
            Self::tenantProtocol => super::InformationElementDataType::unsigned8,
            Self::tenantSourceIPv4 => super::InformationElementDataType::ipv4Address,
            Self::tenantDestIPv4 => super::InformationElementDataType::ipv4Address,
            Self::tenantSourceIPv6 => super::InformationElementDataType::ipv6Address,
            Self::tenantDestIPv6 => super::InformationElementDataType::ipv6Address,
            Self::tenantSourcePort => super::InformationElementDataType::unsigned16,
            Self::tenantDestPort => super::InformationElementDataType::unsigned16,
            Self::egressInterfaceAttr => super::InformationElementDataType::unsigned16,
            Self::vxlanExportRole => super::InformationElementDataType::unsigned8,
            Self::ingressInterfaceAttr => super::InformationElementDataType::unsigned16,
            Self::virtualObsID => super::InformationElementDataType::string,
            Self::ruleId => super::InformationElementDataType::unsigned32,
            Self::vmUuid => super::InformationElementDataType::string,
            Self::vnicIndex => super::InformationElementDataType::unsigned32,
            Self::sessionFlags => super::InformationElementDataType::unsigned8,
            Self::flowDirection => super::InformationElementDataType::unsigned8,
            Self::algControlFlowId => super::InformationElementDataType::unsigned64,
            Self::algType => super::InformationElementDataType::unsigned8,
            Self::algFlowType => super::InformationElementDataType::unsigned8,
            Self::averageLatency => super::InformationElementDataType::unsigned32,
            Self::retransmissionCount => super::InformationElementDataType::unsigned32,
            Self::vifUuid => super::InformationElementDataType::octetArray,
            Self::vifId => super::InformationElementDataType::string,
        }
    }

    fn units(&self) -> Option<super::InformationElementUnits> {
        match self {
            Self::tenantProtocol => None,
            Self::tenantSourceIPv4 => None,
            Self::tenantDestIPv4 => None,
            Self::tenantSourceIPv6 => None,
            Self::tenantDestIPv6 => None,
            Self::tenantSourcePort => None,
            Self::tenantDestPort => None,
            Self::egressInterfaceAttr => None,
            Self::vxlanExportRole => None,
            Self::ingressInterfaceAttr => None,
            Self::virtualObsID => None,
            Self::ruleId => None,
            Self::vmUuid => None,
            Self::vnicIndex => None,
            Self::sessionFlags => None,
            Self::flowDirection => None,
            Self::algControlFlowId => None,
            Self::algType => None,
            Self::algFlowType => None,
            Self::averageLatency => None,
            Self::retransmissionCount => None,
            Self::vifUuid => None,
            Self::vifId => None,
        }
    }

    fn value_range(&self) -> Option<std::ops::Range<u64>> {
        match self {
            Self::tenantProtocol => None,
            Self::tenantSourceIPv4 => None,
            Self::tenantDestIPv4 => None,
            Self::tenantSourceIPv6 => None,
            Self::tenantDestIPv6 => None,
            Self::tenantSourcePort => None,
            Self::tenantDestPort => None,
            Self::egressInterfaceAttr => None,
            Self::vxlanExportRole => None,
            Self::ingressInterfaceAttr => None,
            Self::virtualObsID => None,
            Self::ruleId => None,
            Self::vmUuid => None,
            Self::vnicIndex => None,
            Self::sessionFlags => None,
            Self::flowDirection => None,
            Self::algControlFlowId => None,
            Self::algType => None,
            Self::algFlowType => None,
            Self::averageLatency => None,
            Self::retransmissionCount => None,
            Self::vifUuid => None,
            Self::vifId => None,
        }
    }

    fn id(&self) -> u16 {
        (*self) as u16
    }

    fn pen(&self) -> u32 {
        6876
    }

}
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct UndefinedIE(pub u16);
impl From<IE> for u16 {
    fn from(value: IE) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for IE {
    type Error = UndefinedIE;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
       // Remove Enterprise bit
       let value = value & 0x7FFF;
       match Self::from_repr(value) {
           Some(val) => Ok(val),
           None => Err(UndefinedIE(value)),
       }
    }
}



#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum tenantProtocol {
    /// IPv6 Hop-by-Hop Option
    ///
    /// Reference: [RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)
    HOPOPT = 0,
    /// Internet Control Message
    ///
    /// Reference: [RFC792](https://datatracker.ietf.org/doc/html/rfc792)
    ICMP = 1,
    /// Internet Group Management
    ///
    /// Reference: [RFC1112](https://datatracker.ietf.org/doc/html/rfc1112)
    IGMP = 2,
    /// Gateway-to-Gateway
    ///
    /// Reference: [RFC823](https://datatracker.ietf.org/doc/html/rfc823)
    GGP = 3,
    /// IPv4 encapsulation
    ///
    /// Reference: [RFC2003](https://datatracker.ietf.org/doc/html/rfc2003)
    IPv4 = 4,
    /// Stream
    ///
    /// Reference: [RFC1190](https://datatracker.ietf.org/doc/html/rfc1190)
    /// Reference: [RFC1819](https://datatracker.ietf.org/doc/html/rfc1819)
    ST = 5,
    /// Transmission Control
    ///
    /// Reference: [RFC9293](https://datatracker.ietf.org/doc/html/rfc9293)
    TCP = 6,
    /// CBT
    ///
    CBT = 7,
    /// Exterior Gateway Protocol
    ///
    /// Reference: [RFC888](https://datatracker.ietf.org/doc/html/rfc888)
    EGP = 8,
    /// any private interior gateway
    /// (used by Cisco for their IGRP)
    ///
    IGP = 9,
    /// BBN RCC Monitoring
    ///
    BBNRCCMON = 10,
    /// Network Voice Protocol
    ///
    /// Reference: [RFC741](https://datatracker.ietf.org/doc/html/rfc741)
    NVPII = 11,
    /// PUP
    PUP = 12,
    /// ARGUS
    ///
    ARGUSdeprecated = 13,
    /// EMCON
    ///
    EMCON = 14,
    /// Cross Net Debugger
    ///
    XNET = 15,
    /// Chaos
    ///
    CHAOS = 16,
    /// User Datagram
    ///
    /// Reference: [RFC768](https://datatracker.ietf.org/doc/html/rfc768)
    UDP = 17,
    /// Multiplexing
    ///
    MUX = 18,
    /// DCN Measurement Subsystems
    ///
    DCNMEAS = 19,
    /// Host Monitoring
    ///
    /// Reference: [RFC869](https://datatracker.ietf.org/doc/html/rfc869)
    HMP = 20,
    /// Packet Radio Measurement
    ///
    PRM = 21,
    /// XEROX NS IDP
    XNSIDP = 22,
    /// Trunk-1
    ///
    TRUNK1 = 23,
    /// Trunk-2
    ///
    TRUNK2 = 24,
    /// Leaf-1
    ///
    LEAF1 = 25,
    /// Leaf-2
    ///
    LEAF2 = 26,
    /// Reliable Data Protocol
    ///
    /// Reference: [RFC908](https://datatracker.ietf.org/doc/html/rfc908)
    RDP = 27,
    /// Internet Reliable Transaction
    ///
    /// Reference: [RFC938](https://datatracker.ietf.org/doc/html/rfc938)
    IRTP = 28,
    /// ISO Transport Protocol Class 4
    ///
    /// Reference: [RFC905](https://datatracker.ietf.org/doc/html/rfc905)
    ISOTP4 = 29,
    /// Bulk Data Transfer Protocol
    ///
    /// Reference: [RFC969](https://datatracker.ietf.org/doc/html/rfc969)
    NETBLT = 30,
    /// MFE Network Services Protocol
    ///
    MFENSP = 31,
    /// MERIT Internodal Protocol
    ///
    MERITINP = 32,
    /// Datagram Congestion Control Protocol
    ///
    /// Reference: [RFC4340](https://datatracker.ietf.org/doc/html/rfc4340)
    DCCP = 33,
    /// Third Party Connect Protocol
    ///
    ThreePC = 34,
    /// Inter-Domain Policy Routing Protocol
    ///
    IDPR = 35,
    /// XTP
    ///
    XTP = 36,
    /// Datagram Delivery Protocol
    ///
    DDP = 37,
    /// IDPR Control Message Transport Proto
    ///
    IDPRCMTP = 38,
    /// TP++ Transport Protocol
    ///
    TP = 39,
    /// IL Transport Protocol
    ///
    IL = 40,
    /// IPv6 encapsulation
    ///
    /// Reference: [RFC2473](https://datatracker.ietf.org/doc/html/rfc2473)
    IPv6 = 41,
    /// Source Demand Routing Protocol
    ///
    SDRP = 42,
    /// Routing Header for IPv6
    ///
    IPv6Route = 43,
    /// Fragment Header for IPv6
    ///
    IPv6Frag = 44,
    /// Inter-Domain Routing Protocol
    ///
    IDRP = 45,
    /// Reservation Protocol
    ///
    /// Reference: [RFC2205](https://datatracker.ietf.org/doc/html/rfc2205)
    /// Reference: [RFC3209](https://datatracker.ietf.org/doc/html/rfc3209)
    RSVP = 46,
    /// Generic Routing Encapsulation
    ///
    /// Reference: [RFC2784](https://datatracker.ietf.org/doc/html/rfc2784)
    GRE = 47,
    /// Dynamic Source Routing Protocol
    ///
    /// Reference: [RFC4728](https://datatracker.ietf.org/doc/html/rfc4728)
    DSR = 48,
    /// BNA
    BNA = 49,
    /// Encap Security Payload
    ///
    /// Reference: [RFC4303](https://datatracker.ietf.org/doc/html/rfc4303)
    ESP = 50,
    /// Authentication Header
    ///
    /// Reference: [RFC4302](https://datatracker.ietf.org/doc/html/rfc4302)
    AH = 51,
    /// Integrated Net Layer Security  TUBA
    ///
    INLSP = 52,
    /// IP with Encryption
    ///
    SWIPEdeprecated = 53,
    /// NBMA Address Resolution Protocol
    ///
    /// Reference: [RFC1735](https://datatracker.ietf.org/doc/html/rfc1735)
    NARP = 54,
    /// Minimal IPv4 Encapsulation
    ///
    /// Reference: [RFC2004](https://datatracker.ietf.org/doc/html/rfc2004)
    MinIPv4 = 55,
    /// Transport Layer Security Protocol
    /// using Kryptonet key management
    ///
    TLSP = 56,
    /// SKIP
    ///
    SKIP = 57,
    /// ICMP for IPv6
    ///
    /// Reference: [RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)
    IPv6ICMP = 58,
    /// No Next Header for IPv6
    ///
    /// Reference: [RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)
    IPv6NoNxt = 59,
    /// Destination Options for IPv6
    ///
    /// Reference: [RFC8200](https://datatracker.ietf.org/doc/html/rfc8200)
    IPv6Opts = 60,
    /// any host internal protocol
    ///
    anyhostinternalprotocol = 61,
    /// CFTP
    ///
    CFTP = 62,
    /// any local network
    ///
    anylocalnetwork = 63,
    /// SATNET and Backroom EXPAK
    ///
    SATEXPAK = 64,
    /// Kryptolan
    KRYPTOLAN = 65,
    /// MIT Remote Virtual Disk Protocol
    ///
    RVD = 66,
    /// Internet Pluribus Packet Core
    ///
    IPPC = 67,
    /// any distributed file system
    ///
    anydistributedfilesystem = 68,
    /// SATNET Monitoring
    ///
    SATMON = 69,
    /// VISA Protocol
    ///
    VISA = 70,
    /// Internet Packet Core Utility
    ///
    IPCV = 71,
    /// Computer Protocol Network Executive
    CPNX = 72,
    /// Computer Protocol Heart Beat
    CPHB = 73,
    /// Wang Span Network
    WSN = 74,
    /// Packet Video Protocol
    ///
    PVP = 75,
    /// Backroom SATNET Monitoring
    ///
    BRSATMON = 76,
    /// SUN ND PROTOCOL-Temporary
    ///
    SUNND = 77,
    /// WIDEBAND Monitoring
    ///
    WBMON = 78,
    /// WIDEBAND EXPAK
    ///
    WBEXPAK = 79,
    /// ISO Internet Protocol
    ///
    ISOIP = 80,
    /// VMTP
    ///
    VMTP = 81,
    /// SECURE-VMTP
    ///
    SECUREVMTP = 82,
    /// VINES
    VINES = 83,
    /// Internet Protocol Traffic Manager
    ///
    IPTM = 84,
    /// NSFNET-IGP
    ///
    NSFNETIGP = 85,
    /// Dissimilar Gateway Protocol
    ///
    DGP = 86,
    /// TCF
    ///
    TCF = 87,
    /// EIGRP
    ///
    /// Reference: [RFC7868](https://datatracker.ietf.org/doc/html/rfc7868)
    EIGRP = 88,
    /// OSPFIGP
    ///
    /// Reference: [RFC1583](https://datatracker.ietf.org/doc/html/rfc1583)
    /// Reference: [RFC2328](https://datatracker.ietf.org/doc/html/rfc2328)
    /// Reference: [RFC5340](https://datatracker.ietf.org/doc/html/rfc5340)
    OSPFIGP = 89,
    /// Sprite RPC Protocol
    SpriteRPC = 90,
    /// Locus Address Resolution Protocol
    LARP = 91,
    /// Multicast Transport Protocol
    ///
    MTP = 92,
    /// AX.25 Frames
    ///
    AX25 = 93,
    /// IP-within-IP Encapsulation Protocol
    ///
    IPIP = 94,
    /// Mobile Internetworking Control Pro.
    ///
    MICPdeprecated = 95,
    /// Semaphore Communications Sec. Pro.
    ///
    SCCSP = 96,
    /// Ethernet-within-IP Encapsulation
    ///
    /// Reference: [RFC3378](https://datatracker.ietf.org/doc/html/rfc3378)
    ETHERIP = 97,
    /// Encapsulation Header
    ///
    /// Reference: [RFC1241](https://datatracker.ietf.org/doc/html/rfc1241)
    ENCAP = 98,
    /// any private encryption scheme
    ///
    anyprivateencryptionscheme = 99,
    /// GMTP
    GMTP = 100,
    /// Ipsilon Flow Management Protocol
    ///
    IFMP = 101,
    /// PNNI over IP
    ///
    PNNI = 102,
    /// Protocol Independent Multicast
    ///
    /// Reference: [RFC7761](https://datatracker.ietf.org/doc/html/rfc7761)
    PIM = 103,
    /// ARIS
    ///
    ARIS = 104,
    /// SCPS
    ///
    SCPS = 105,
    /// QNX
    ///
    QNX = 106,
    /// Active Networks
    ///
    AN = 107,
    /// IP Payload Compression Protocol
    ///
    /// Reference: [RFC2393](https://datatracker.ietf.org/doc/html/rfc2393)
    IPComp = 108,
    /// Sitara Networks Protocol
    ///
    SNP = 109,
    /// Compaq Peer Protocol
    ///
    CompaqPeer = 110,
    /// IPX in IP
    ///
    IPXinIP = 111,
    /// Virtual Router Redundancy Protocol
    ///
    /// Reference: [RFC9568](https://datatracker.ietf.org/doc/html/rfc9568)
    VRRP = 112,
    /// PGM Reliable Transport Protocol
    ///
    PGM = 113,
    /// any 0-hop protocol
    ///
    any0hopprotocol = 114,
    /// Layer Two Tunneling Protocol
    ///
    /// Reference: [RFC3931](https://datatracker.ietf.org/doc/html/rfc3931)
    L2TP = 115,
    /// D-II Data Exchange (DDX)
    ///
    DDX = 116,
    /// Interactive Agent Transfer Protocol
    ///
    IATP = 117,
    /// Schedule Transfer Protocol
    ///
    STP = 118,
    /// SpectraLink Radio Protocol
    ///
    SRP = 119,
    /// UTI
    ///
    UTI = 120,
    /// Simple Message Protocol
    ///
    SMP = 121,
    /// Simple Multicast Protocol
    ///
    /// Reference: [RFC Draft DRAFT-PERLMAN-SIMPLE-MULTICAST](https://datatracker.ietf.org/doc/html/draft-perlman-simple-multicast)
    SMdeprecated = 122,
    /// Performance Transparency Protocol
    ///
    PTP = 123,
    /// ISIS over IPv4
    ///
    ISISoverIPv4 = 124,
    /// FIRE
    ///
    FIRE = 125,
    /// Combat Radio Transport Protocol
    ///
    CRTP = 126,
    /// Combat Radio User Datagram
    ///
    CRUDP = 127,
    /// SSCOPMCE
    ///
    SSCOPMCE = 128,
    /// IPLT
    IPLT = 129,
    /// Secure Packet Shield
    ///
    SPS = 130,
    /// Private IP Encapsulation within IP
    ///
    PIPE = 131,
    /// Stream Control Transmission Protocol
    ///
    SCTP = 132,
    /// Fibre Channel
    ///
    /// Reference: [RFC6172](https://datatracker.ietf.org/doc/html/rfc6172)
    FC = 133,
    /// RSVP-E2E-IGNORE
    ///
    /// Reference: [RFC3175](https://datatracker.ietf.org/doc/html/rfc3175)
    RSVPE2EIGNORE = 134,
    /// Mobility Header
    ///
    /// Reference: [RFC6275](https://datatracker.ietf.org/doc/html/rfc6275)
    MobilityHeader = 135,
    /// UDPLite
    ///
    /// Reference: [RFC3828](https://datatracker.ietf.org/doc/html/rfc3828)
    UDPLite = 136,
    /// MPLS-in-IP
    ///
    /// Reference: [RFC4023](https://datatracker.ietf.org/doc/html/rfc4023)
    MPLSinIP = 137,
    /// MANET Protocols
    ///
    /// Reference: [RFC5498](https://datatracker.ietf.org/doc/html/rfc5498)
    manet = 138,
    /// Host Identity Protocol
    ///
    /// Reference: [RFC7401](https://datatracker.ietf.org/doc/html/rfc7401)
    HIP = 139,
    /// Shim6 Protocol
    ///
    /// Reference: [RFC5533](https://datatracker.ietf.org/doc/html/rfc5533)
    Shim6 = 140,
    /// Wrapped Encapsulating Security Payload
    ///
    /// Reference: [RFC5840](https://datatracker.ietf.org/doc/html/rfc5840)
    WESP = 141,
    /// Robust Header Compression
    ///
    /// Reference: [RFC5858](https://datatracker.ietf.org/doc/html/rfc5858)
    ROHC = 142,
    /// Ethernet
    ///
    /// Reference: [RFC8986](https://datatracker.ietf.org/doc/html/rfc8986)
    Ethernet = 143,
    /// AGGFRAG encapsulation payload for ESP
    ///
    /// Reference: [RFC9347](https://datatracker.ietf.org/doc/html/rfc9347)
    AGGFRAG = 144,
    /// Network Service Header
    ///
    /// Reference: [RFC9491](https://datatracker.ietf.org/doc/html/rfc9491)
    NSH = 145,
    Unassigned(u8),
}
impl From<tenantProtocol> for u8 {
    fn from(value: tenantProtocol) -> Self {
        match value {
            tenantProtocol::HOPOPT => 0,
            tenantProtocol::ICMP => 1,
            tenantProtocol::IGMP => 2,
            tenantProtocol::GGP => 3,
            tenantProtocol::IPv4 => 4,
            tenantProtocol::ST => 5,
            tenantProtocol::TCP => 6,
            tenantProtocol::CBT => 7,
            tenantProtocol::EGP => 8,
            tenantProtocol::IGP => 9,
            tenantProtocol::BBNRCCMON => 10,
            tenantProtocol::NVPII => 11,
            tenantProtocol::PUP => 12,
            tenantProtocol::ARGUSdeprecated => 13,
            tenantProtocol::EMCON => 14,
            tenantProtocol::XNET => 15,
            tenantProtocol::CHAOS => 16,
            tenantProtocol::UDP => 17,
            tenantProtocol::MUX => 18,
            tenantProtocol::DCNMEAS => 19,
            tenantProtocol::HMP => 20,
            tenantProtocol::PRM => 21,
            tenantProtocol::XNSIDP => 22,
            tenantProtocol::TRUNK1 => 23,
            tenantProtocol::TRUNK2 => 24,
            tenantProtocol::LEAF1 => 25,
            tenantProtocol::LEAF2 => 26,
            tenantProtocol::RDP => 27,
            tenantProtocol::IRTP => 28,
            tenantProtocol::ISOTP4 => 29,
            tenantProtocol::NETBLT => 30,
            tenantProtocol::MFENSP => 31,
            tenantProtocol::MERITINP => 32,
            tenantProtocol::DCCP => 33,
            tenantProtocol::ThreePC => 34,
            tenantProtocol::IDPR => 35,
            tenantProtocol::XTP => 36,
            tenantProtocol::DDP => 37,
            tenantProtocol::IDPRCMTP => 38,
            tenantProtocol::TP => 39,
            tenantProtocol::IL => 40,
            tenantProtocol::IPv6 => 41,
            tenantProtocol::SDRP => 42,
            tenantProtocol::IPv6Route => 43,
            tenantProtocol::IPv6Frag => 44,
            tenantProtocol::IDRP => 45,
            tenantProtocol::RSVP => 46,
            tenantProtocol::GRE => 47,
            tenantProtocol::DSR => 48,
            tenantProtocol::BNA => 49,
            tenantProtocol::ESP => 50,
            tenantProtocol::AH => 51,
            tenantProtocol::INLSP => 52,
            tenantProtocol::SWIPEdeprecated => 53,
            tenantProtocol::NARP => 54,
            tenantProtocol::MinIPv4 => 55,
            tenantProtocol::TLSP => 56,
            tenantProtocol::SKIP => 57,
            tenantProtocol::IPv6ICMP => 58,
            tenantProtocol::IPv6NoNxt => 59,
            tenantProtocol::IPv6Opts => 60,
            tenantProtocol::anyhostinternalprotocol => 61,
            tenantProtocol::CFTP => 62,
            tenantProtocol::anylocalnetwork => 63,
            tenantProtocol::SATEXPAK => 64,
            tenantProtocol::KRYPTOLAN => 65,
            tenantProtocol::RVD => 66,
            tenantProtocol::IPPC => 67,
            tenantProtocol::anydistributedfilesystem => 68,
            tenantProtocol::SATMON => 69,
            tenantProtocol::VISA => 70,
            tenantProtocol::IPCV => 71,
            tenantProtocol::CPNX => 72,
            tenantProtocol::CPHB => 73,
            tenantProtocol::WSN => 74,
            tenantProtocol::PVP => 75,
            tenantProtocol::BRSATMON => 76,
            tenantProtocol::SUNND => 77,
            tenantProtocol::WBMON => 78,
            tenantProtocol::WBEXPAK => 79,
            tenantProtocol::ISOIP => 80,
            tenantProtocol::VMTP => 81,
            tenantProtocol::SECUREVMTP => 82,
            tenantProtocol::VINES => 83,
            tenantProtocol::IPTM => 84,
            tenantProtocol::NSFNETIGP => 85,
            tenantProtocol::DGP => 86,
            tenantProtocol::TCF => 87,
            tenantProtocol::EIGRP => 88,
            tenantProtocol::OSPFIGP => 89,
            tenantProtocol::SpriteRPC => 90,
            tenantProtocol::LARP => 91,
            tenantProtocol::MTP => 92,
            tenantProtocol::AX25 => 93,
            tenantProtocol::IPIP => 94,
            tenantProtocol::MICPdeprecated => 95,
            tenantProtocol::SCCSP => 96,
            tenantProtocol::ETHERIP => 97,
            tenantProtocol::ENCAP => 98,
            tenantProtocol::anyprivateencryptionscheme => 99,
            tenantProtocol::GMTP => 100,
            tenantProtocol::IFMP => 101,
            tenantProtocol::PNNI => 102,
            tenantProtocol::PIM => 103,
            tenantProtocol::ARIS => 104,
            tenantProtocol::SCPS => 105,
            tenantProtocol::QNX => 106,
            tenantProtocol::AN => 107,
            tenantProtocol::IPComp => 108,
            tenantProtocol::SNP => 109,
            tenantProtocol::CompaqPeer => 110,
            tenantProtocol::IPXinIP => 111,
            tenantProtocol::VRRP => 112,
            tenantProtocol::PGM => 113,
            tenantProtocol::any0hopprotocol => 114,
            tenantProtocol::L2TP => 115,
            tenantProtocol::DDX => 116,
            tenantProtocol::IATP => 117,
            tenantProtocol::STP => 118,
            tenantProtocol::SRP => 119,
            tenantProtocol::UTI => 120,
            tenantProtocol::SMP => 121,
            tenantProtocol::SMdeprecated => 122,
            tenantProtocol::PTP => 123,
            tenantProtocol::ISISoverIPv4 => 124,
            tenantProtocol::FIRE => 125,
            tenantProtocol::CRTP => 126,
            tenantProtocol::CRUDP => 127,
            tenantProtocol::SSCOPMCE => 128,
            tenantProtocol::IPLT => 129,
            tenantProtocol::SPS => 130,
            tenantProtocol::PIPE => 131,
            tenantProtocol::SCTP => 132,
            tenantProtocol::FC => 133,
            tenantProtocol::RSVPE2EIGNORE => 134,
            tenantProtocol::MobilityHeader => 135,
            tenantProtocol::UDPLite => 136,
            tenantProtocol::MPLSinIP => 137,
            tenantProtocol::manet => 138,
            tenantProtocol::HIP => 139,
            tenantProtocol::Shim6 => 140,
            tenantProtocol::WESP => 141,
            tenantProtocol::ROHC => 142,
            tenantProtocol::Ethernet => 143,
            tenantProtocol::AGGFRAG => 144,
            tenantProtocol::NSH => 145,
            tenantProtocol::Unassigned(x) => x,
        }
    }
}
impl From<u8> for tenantProtocol {
    fn from(value: u8) -> Self {
        match value {
            0 => tenantProtocol::HOPOPT,
            1 => tenantProtocol::ICMP,
            2 => tenantProtocol::IGMP,
            3 => tenantProtocol::GGP,
            4 => tenantProtocol::IPv4,
            5 => tenantProtocol::ST,
            6 => tenantProtocol::TCP,
            7 => tenantProtocol::CBT,
            8 => tenantProtocol::EGP,
            9 => tenantProtocol::IGP,
            10 => tenantProtocol::BBNRCCMON,
            11 => tenantProtocol::NVPII,
            12 => tenantProtocol::PUP,
            13 => tenantProtocol::ARGUSdeprecated,
            14 => tenantProtocol::EMCON,
            15 => tenantProtocol::XNET,
            16 => tenantProtocol::CHAOS,
            17 => tenantProtocol::UDP,
            18 => tenantProtocol::MUX,
            19 => tenantProtocol::DCNMEAS,
            20 => tenantProtocol::HMP,
            21 => tenantProtocol::PRM,
            22 => tenantProtocol::XNSIDP,
            23 => tenantProtocol::TRUNK1,
            24 => tenantProtocol::TRUNK2,
            25 => tenantProtocol::LEAF1,
            26 => tenantProtocol::LEAF2,
            27 => tenantProtocol::RDP,
            28 => tenantProtocol::IRTP,
            29 => tenantProtocol::ISOTP4,
            30 => tenantProtocol::NETBLT,
            31 => tenantProtocol::MFENSP,
            32 => tenantProtocol::MERITINP,
            33 => tenantProtocol::DCCP,
            34 => tenantProtocol::ThreePC,
            35 => tenantProtocol::IDPR,
            36 => tenantProtocol::XTP,
            37 => tenantProtocol::DDP,
            38 => tenantProtocol::IDPRCMTP,
            39 => tenantProtocol::TP,
            40 => tenantProtocol::IL,
            41 => tenantProtocol::IPv6,
            42 => tenantProtocol::SDRP,
            43 => tenantProtocol::IPv6Route,
            44 => tenantProtocol::IPv6Frag,
            45 => tenantProtocol::IDRP,
            46 => tenantProtocol::RSVP,
            47 => tenantProtocol::GRE,
            48 => tenantProtocol::DSR,
            49 => tenantProtocol::BNA,
            50 => tenantProtocol::ESP,
            51 => tenantProtocol::AH,
            52 => tenantProtocol::INLSP,
            53 => tenantProtocol::SWIPEdeprecated,
            54 => tenantProtocol::NARP,
            55 => tenantProtocol::MinIPv4,
            56 => tenantProtocol::TLSP,
            57 => tenantProtocol::SKIP,
            58 => tenantProtocol::IPv6ICMP,
            59 => tenantProtocol::IPv6NoNxt,
            60 => tenantProtocol::IPv6Opts,
            61 => tenantProtocol::anyhostinternalprotocol,
            62 => tenantProtocol::CFTP,
            63 => tenantProtocol::anylocalnetwork,
            64 => tenantProtocol::SATEXPAK,
            65 => tenantProtocol::KRYPTOLAN,
            66 => tenantProtocol::RVD,
            67 => tenantProtocol::IPPC,
            68 => tenantProtocol::anydistributedfilesystem,
            69 => tenantProtocol::SATMON,
            70 => tenantProtocol::VISA,
            71 => tenantProtocol::IPCV,
            72 => tenantProtocol::CPNX,
            73 => tenantProtocol::CPHB,
            74 => tenantProtocol::WSN,
            75 => tenantProtocol::PVP,
            76 => tenantProtocol::BRSATMON,
            77 => tenantProtocol::SUNND,
            78 => tenantProtocol::WBMON,
            79 => tenantProtocol::WBEXPAK,
            80 => tenantProtocol::ISOIP,
            81 => tenantProtocol::VMTP,
            82 => tenantProtocol::SECUREVMTP,
            83 => tenantProtocol::VINES,
            84 => tenantProtocol::IPTM,
            85 => tenantProtocol::NSFNETIGP,
            86 => tenantProtocol::DGP,
            87 => tenantProtocol::TCF,
            88 => tenantProtocol::EIGRP,
            89 => tenantProtocol::OSPFIGP,
            90 => tenantProtocol::SpriteRPC,
            91 => tenantProtocol::LARP,
            92 => tenantProtocol::MTP,
            93 => tenantProtocol::AX25,
            94 => tenantProtocol::IPIP,
            95 => tenantProtocol::MICPdeprecated,
            96 => tenantProtocol::SCCSP,
            97 => tenantProtocol::ETHERIP,
            98 => tenantProtocol::ENCAP,
            99 => tenantProtocol::anyprivateencryptionscheme,
            100 => tenantProtocol::GMTP,
            101 => tenantProtocol::IFMP,
            102 => tenantProtocol::PNNI,
            103 => tenantProtocol::PIM,
            104 => tenantProtocol::ARIS,
            105 => tenantProtocol::SCPS,
            106 => tenantProtocol::QNX,
            107 => tenantProtocol::AN,
            108 => tenantProtocol::IPComp,
            109 => tenantProtocol::SNP,
            110 => tenantProtocol::CompaqPeer,
            111 => tenantProtocol::IPXinIP,
            112 => tenantProtocol::VRRP,
            113 => tenantProtocol::PGM,
            114 => tenantProtocol::any0hopprotocol,
            115 => tenantProtocol::L2TP,
            116 => tenantProtocol::DDX,
            117 => tenantProtocol::IATP,
            118 => tenantProtocol::STP,
            119 => tenantProtocol::SRP,
            120 => tenantProtocol::UTI,
            121 => tenantProtocol::SMP,
            122 => tenantProtocol::SMdeprecated,
            123 => tenantProtocol::PTP,
            124 => tenantProtocol::ISISoverIPv4,
            125 => tenantProtocol::FIRE,
            126 => tenantProtocol::CRTP,
            127 => tenantProtocol::CRUDP,
            128 => tenantProtocol::SSCOPMCE,
            129 => tenantProtocol::IPLT,
            130 => tenantProtocol::SPS,
            131 => tenantProtocol::PIPE,
            132 => tenantProtocol::SCTP,
            133 => tenantProtocol::FC,
            134 => tenantProtocol::RSVPE2EIGNORE,
            135 => tenantProtocol::MobilityHeader,
            136 => tenantProtocol::UDPLite,
            137 => tenantProtocol::MPLSinIP,
            138 => tenantProtocol::manet,
            139 => tenantProtocol::HIP,
            140 => tenantProtocol::Shim6,
            141 => tenantProtocol::WESP,
            142 => tenantProtocol::ROHC,
            143 => tenantProtocol::Ethernet,
            144 => tenantProtocol::AGGFRAG,
            145 => tenantProtocol::NSH,
            x => tenantProtocol::Unassigned(x),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct tenantSourceIPv4(pub std::net::Ipv4Addr);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct tenantDestIPv4(pub std::net::Ipv4Addr);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct tenantSourceIPv6(pub std::net::Ipv6Addr);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct tenantDestIPv6(pub std::net::Ipv6Addr);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct tenantSourcePort(pub u16);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct tenantDestPort(pub u16);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct egressInterfaceAttr(pub u16);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct vxlanExportRole(pub u8);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct ingressInterfaceAttr(pub u16);

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct virtualObsID(pub String);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct ruleId(pub u32);

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct vmUuid(pub String);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct vnicIndex(pub u32);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct sessionFlags(pub u8);

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum flowDirection {
    /// Ingress flow
    ingress = 0,
    /// Egress flow
    egress = 1,
    Unassigned(u8),
}
impl From<flowDirection> for u8 {
    fn from(value: flowDirection) -> Self {
        match value {
            flowDirection::ingress => 0,
            flowDirection::egress => 1,
            flowDirection::Unassigned(x) => x,
        }
    }
}
impl From<u8> for flowDirection {
    fn from(value: u8) -> Self {
        match value {
            0 => flowDirection::ingress,
            1 => flowDirection::egress,
            x => flowDirection::Unassigned(x),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct algControlFlowId(pub u64);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct algType(pub u8);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct algFlowType(pub u8);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct averageLatency(pub u32);

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct retransmissionCount(pub u32);

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct vifUuid(pub Vec<u8>);

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub struct vifId(pub String);

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Field {
    tenantProtocol(tenantProtocol),
    tenantSourceIPv4(tenantSourceIPv4),
    tenantDestIPv4(tenantDestIPv4),
    tenantSourceIPv6(tenantSourceIPv6),
    tenantDestIPv6(tenantDestIPv6),
    tenantSourcePort(tenantSourcePort),
    tenantDestPort(tenantDestPort),
    egressInterfaceAttr(egressInterfaceAttr),
    vxlanExportRole(vxlanExportRole),
    ingressInterfaceAttr(ingressInterfaceAttr),
    virtualObsID(virtualObsID),
    ruleId(ruleId),
    vmUuid(vmUuid),
    vnicIndex(vnicIndex),
    sessionFlags(sessionFlags),
    flowDirection(flowDirection),
    algControlFlowId(algControlFlowId),
    algType(algType),
    algFlowType(algFlowType),
    averageLatency(averageLatency),
    retransmissionCount(retransmissionCount),
    vifUuid(vifUuid),
    vifId(vifId),
}
