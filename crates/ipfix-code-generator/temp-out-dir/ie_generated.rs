pub type MacAddress = [u8; 6];

/// A trait to inidcate that we can get the [IE] for a given element
    pub trait HasIE {
        fn ie(&self) -> IE;
    }
    #[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum InformationElementStatus {
    current = 0,
    deprecated = 1,
}

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum InformationElementSemantics {

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  default = 0,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  quantity = 1,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  totalCounter = 2,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  deltaCounter = 3,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  identifier = 4,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  flags = 5,

  /// [RFC6313](https://datatracker.ietf.org/doc/html/rfc6313)
  list = 6,

  /// [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
  snmpCounter = 7,

  /// [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
  snmpGauge = 8,
}

#[allow(non_camel_case_types)]
#[repr(u8)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum InformationElementUnits {

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  none = 0,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  bits = 1,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  octets = 2,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  packets = 3,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  flows = 4,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  seconds = 5,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  milliseconds = 6,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  microseconds = 7,

  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  nanoseconds = 8,

  /// For example, for IPv4 header length
  ///
  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  fourOctetWords = 9,

  /// For example, for reliability reporting
  ///
  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  messages = 10,

  /// For example, for TTL
  ///
  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  hops = 11,

  /// For example, for MPLS label stack
  ///
  /// [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
  entries = 12,

  /// For example, Layer 2 frames
  ///
  frames = 13,

  /// [RFC8045](https://datatracker.ietf.org/doc/html/rfc8045)
  ports = 14,

  /// The units of the inferred Information Element
  ///
  /// [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
  inferred = 15,
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum IE {
    Unknown{pen: u32, id: u16},
    Nokia(nokia::IE),
    NetGauze(netgauze::IE),
    Cisco(cisco::IE),
    VMWare(vmware::IE),
    /// The number of octets since the previous report (if any)
    /// in incoming packets for this Flow at the Observation Point.
    /// The number of octets includes IP header(s) and IP payload.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    octetDeltaCount,
    /// The number of incoming packets since the previous report
    /// (if any) for this Flow at the Observation Point.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    packetDeltaCount,
    /// The conservative count of Original Flows contributing
    /// to this Aggregated Flow; may be distributed via any of the methods
    /// expressed by the valueDistributionMethod Information Element.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    deltaFlowCount,
    /// The value of the protocol number in the IP packet header.
    /// The protocol number identifies the IP packet payload type.
    /// Protocol numbers are defined in the IANA Protocol Numbers
    /// registry.In Internet Protocol version 4 (IPv4), this is carried in the
    /// Protocol field.  In Internet Protocol version 6 (IPv6), this
    /// is carried in the Next Header field in the last extension
    /// header of the packet.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    protocolIdentifier,
    /// For IPv4 packets, this is the value of the TOS field in
    /// the IPv4 packet header.  For IPv6 packets, this is the
    /// value of the Traffic Class field in the IPv6 packet header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ipClassOfService,
    /// TCP control bits observed for the packets of this Flow. This information is
    /// encoded as a bit field; each TCP control bit has a corresponding bit in that
    /// field. A bit is set to 1 if any observed packet of this Flow has the
    /// corresponding TCP control bit set to 1. The bit is cleared to 0 otherwise.PerAs the most significant 4 bits of octets 12 and 13 (counting from zero) of the
    /// TCP headerAll TCP control bits (including those unassigned) MUST be exported as observed
    /// in the TCP headers of the packets of this Flow.If exported as a single octet with reduced-size encoding (Section 6.2 ofExporting Processes exporting this Information Element on behalf of a Metering
    /// Process that is not capable of observing any of the flags with bit offset
    /// positions 4 to 7 SHOULD use reduced-size encoding, and only export the least
    /// significant 8 bits of this Information Element.Note that previous revisions of this Information Element's definition specified
    /// that flags with bit offset positions 8 and 9 must be exported as zero, even if
    /// observed. Collectors should therefore not assume that a value of zero for these
    /// bits in this Information Element indicates the bits were never set in the observed
    /// traffic, especially if these bits are zero in every Flow Record sent by a given
    /// Exporter.Note also that the "TCP Header Flags" registry
    ///
    /// Reference: [RFC9293](https://datatracker.ietf.org/doc/html/rfc9293)
    /// Reference: [RFC9565](https://datatracker.ietf.org/doc/html/rfc9565)
    tcpControlBits,
    /// The source port identifier in the transport protocol header.
    /// For transport protocols such as UDP, TCP, SCTP, and DCCP,
    /// this is the source port number given in the respective header.
    /// This field MAY also be used for future transport protocols that
    /// have 16-bit source port identifiers.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    sourceTransportPort,
    /// The IPv4 source address in the IP packet header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    sourceIPv4Address,
    /// The number of contiguous bits that are relevant in the
    /// sourceIPv4Prefix Information Element.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    sourceIPv4PrefixLength,
    /// The index of the IP interface where packets of this Flow
    /// are being received.  The value matches the value of managed
    /// object 'ifIndex' as defined in
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ingressInterface,
    /// The destination port identifier in the transport protocol header.
    /// For transport protocols such as UDP, TCP, SCTP, and DCCP, this is
    /// the destination port number given in the respective header. This
    /// field MAY also be used for future transport protocols that have
    /// 16-bit destination port identifiers.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    destinationTransportPort,
    /// The IPv4 destination address in the IP packet header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    destinationIPv4Address,
    /// The number of contiguous bits that are relevant in the
    /// destinationIPv4Prefix Information Element.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    destinationIPv4PrefixLength,
    /// The index of the IP interface where packets of
    /// this Flow are being sent.  The value matches the value of
    /// managed object 'ifIndex' as defined in
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    egressInterface,
    /// The IPv4 address of the next IPv4 hop.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ipNextHopIPv4Address,
    /// The autonomous system (AS) number of the source IP address.
    /// If AS path information for this Flow is only available as
    /// an unordered AS set (and not as an ordered AS sequence),
    /// then the value of this Information Element is 0.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    bgpSourceAsNumber,
    /// The autonomous system (AS) number of the destination IP
    /// address.  If AS path information for this Flow is only
    /// available as an unordered AS set (and not as an ordered AS
    /// sequence), then the value of this Information Element is 0.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    bgpDestinationAsNumber,
    /// The IPv4 address of the next (adjacent) BGP hop.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    bgpNextHopIPv4Address,
    /// The number of outgoing multicast packets since the
    /// previous report (if any) sent for packets of this Flow
    /// by a multicast daemon within the Observation Domain.
    /// This property cannot necessarily be observed at the
    /// Observation Point, but may be retrieved by other means.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postMCastPacketDeltaCount,
    /// The number of octets since the previous report (if any)
    /// in outgoing multicast packets sent for packets of this
    /// Flow by a multicast daemon within the Observation Domain.
    /// This property cannot necessarily be observed at the
    /// Observation Point, but may be retrieved by other means.
    /// The number of octets includes IP header(s) and IP payload.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postMCastOctetDeltaCount,
    /// The relative timestamp of the last packet of this Flow. It indicates the
    /// number of milliseconds since the last (re-)initialization of the IPFIX
    /// Device (sysUpTime). sysUpTime can be calculated from
    /// systemInitTimeMilliseconds.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowEndSysUpTime,
    /// The relative timestamp of the first packet of this Flow. It indicates
    /// the number of milliseconds since the last (re-)initialization of the
    /// IPFIX Device (sysUpTime). sysUpTime can be calculated from
    /// systemInitTimeMilliseconds.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowStartSysUpTime,
    /// The definition of this Information Element is identical
    /// to the definition of Information Element
    /// 'octetDeltaCount', except that it reports a
    /// potentially modified value caused by a middlebox
    /// function after the packet passed the Observation Point.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postOctetDeltaCount,
    /// The definition of this Information Element is identical
    /// to the definition of Information Element
    /// 'packetDeltaCount', except that it reports a
    /// potentially modified value caused by a middlebox
    /// function after the packet passed the Observation Point.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postPacketDeltaCount,
    /// Length of the smallest packet observed for this Flow.
    /// The packet length includes the IP header(s) length and
    /// the IP payload length.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    minimumIpTotalLength,
    /// Length of the largest packet observed for this Flow.
    /// The packet length includes the IP header(s) length and
    /// the IP payload length.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    maximumIpTotalLength,
    /// The IPv6 source address in the IP packet header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    sourceIPv6Address,
    /// The IPv6 destination address in the IP packet header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    destinationIPv6Address,
    /// The number of contiguous bits that are relevant in the
    /// sourceIPv6Prefix Information Element.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    sourceIPv6PrefixLength,
    /// The number of contiguous bits that are relevant in the
    /// destinationIPv6Prefix Information Element.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    destinationIPv6PrefixLength,
    /// The value of the IPv6 Flow Label field in the IP packet header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowLabelIPv6,
    /// Type and Code of the IPv4 ICMP message.  The combination of
    /// both values is reported as (ICMP type * 256) + ICMP code.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    icmpTypeCodeIPv4,
    /// The type field of the IGMP message.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    igmpType,
    /// Deprecated in favor of 305 samplingPacketInterval.  When using
    /// sampled NetFlow, the rate at which packets are sampled -- e.g., a
    /// value of 100 indicates that one of every 100 packets is sampled.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    samplingInterval,
    /// Deprecated in favor of 304 selectorAlgorithm.  The type of
    /// algorithm used for sampled NetFlow:
    /// 
    /// ```text
    /// 1 - Deterministic Sampling,
    /// 2 - Random Sampling.
    /// ```
    /// The values are not compatible with the selectorAlgorithm IE, where
    /// "Deterministic" has been replaced by "Systematic count-based" (1)
    /// or "Systematic time-based" (2), and "Random" is (3).  Conversion
    /// is required; see
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    samplingAlgorithm,
    /// The number of seconds after which an active Flow is timed out
    /// anyway, even if there is still a continuous flow of packets.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowActiveTimeout,
    /// A Flow is considered to be timed out if no packets belonging
    /// to the Flow have been observed for the number of seconds
    /// specified by this field.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowIdleTimeout,
    /// Type of flow switching engine in a router/switch:
    /// 
    /// ```text
    /// RP = 0,
    /// VIP/Line card = 1,
    /// PFC/DFC = 2.
    /// ```
    /// Reserved for internal use on the Collector.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    engineType,
    /// Versatile Interface Processor (VIP) or line card slot number of the flow switching engine in a
    /// router/switch.  Reserved for internal use on the Collector.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    engineId,
    /// The total number of octets that the Exporting Process
    /// has sent since the Exporting Process (re-)initialization
    /// to a particular Collecting Process.
    /// The value of this Information Element is calculated by
    /// summing up the IPFIX Message Header length values of all
    /// IPFIX Messages that were successfully sent to the Collecting
    /// Process.  The reported number excludes octets in the IPFIX
    /// Message that carries the counter value.
    /// If this Information Element is sent to a particular
    /// Collecting Process, then by default it specifies the number
    /// of octets sent to this Collecting Process.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    exportedOctetTotalCount,
    /// The total number of IPFIX Messages that the Exporting Process
    /// has sent since the Exporting Process (re-)initialization to
    /// a particular Collecting Process.
    /// The reported number excludes the IPFIX Message that carries
    /// the counter value.
    /// If this Information Element is sent to a particular
    /// Collecting Process, then by default it specifies the number
    /// of IPFIX Messages sent to this Collecting Process.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    exportedMessageTotalCount,
    /// The total number of Flow Records that the Exporting
    /// Process has sent as Data Records since the Exporting
    /// Process (re-)initialization to a particular Collecting
    /// Process.  The reported number excludes Flow Records in
    /// the IPFIX Message that carries the counter value.
    /// If this Information Element is sent to a particular
    /// Collecting Process, then by default it specifies the number
    /// of Flow Records sent to this process.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    exportedFlowRecordTotalCount,
    /// This is a platform-specific field for the Catalyst 5000/Catalyst 6000
    /// family.  It is used to store the address of a router that is being
    /// shortcut when performing MultiLayer Switching.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    ipv4RouterSc,
    /// IPv4 source address prefix.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    sourceIPv4Prefix,
    /// IPv4 destination address prefix.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    destinationIPv4Prefix,
    /// This field identifies the control protocol that allocated the
    /// top-of-stack label. Values for this field are listed in the MPLS
    /// label type registry.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    mplsTopLabelType,
    /// The IPv4 address of the system that the MPLS top label will
    /// cause this Flow to be forwarded to.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsTopLabelIPv4Address,
    /// Deprecated in favor of 302 selectorId.  The unique identifier
    /// associated with samplerName.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    samplerId,
    /// Deprecated in favor of 304 selectorAlgorithm.  The values are not
    /// compatible: selectorAlgorithm=3 is random sampling.  The type of
    /// algorithm used for sampling data: 1 - Deterministic, 2 - Random
    /// Sampling.  Use with samplerRandomInterval.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    samplerMode,
    /// Deprecated in favor of 305 samplingPacketInterval.  Packet
    /// interval at which to sample -- in case of random sampling.  Used in
    /// connection with the samplerMode 0x02 (random sampling) value.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    samplerRandomInterval,
    /// Deprecated in favor of 302 selectorId.  Characterizes the traffic
    /// class, i.e., QoS treatment.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    classId,
    /// Minimum TTL value observed for any packet in this Flow.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    minimumTTL,
    /// Maximum TTL value observed for any packet in this Flow.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    maximumTTL,
    /// The value of the Identification field
    /// in the IPv4 packet header or in the IPv6 Fragment header,
    /// respectively.  The value is 0 for IPv6 if there is
    /// no fragment header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    fragmentIdentification,
    /// The definition of this Information Element is identical
    /// to the definition of Information Element
    /// 'ipClassOfService', except that it reports a
    /// potentially modified value caused by a middlebox
    /// function after the packet passed the Observation Point.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postIpClassOfService,
    /// The IEEE 802 source MAC address field.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    sourceMacAddress,
    /// The definition of this Information Element is identical
    /// to the definition of Information Element
    /// 'destinationMacAddress', except that it reports a
    /// potentially modified value caused by a middlebox
    /// function after the packet passed the Observation Point.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postDestinationMacAddress,
    /// Virtual LAN identifier associated with ingress interface. For dot1q vlans, see 243
    /// dot1qVlanId.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    vlanId,
    /// Virtual LAN identifier associated with egress interface. For postdot1q vlans, see 254, postDot1qVlanId.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postVlanId,
    /// The IP version field in the IP packet header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ipVersion,
    /// The direction of the Flow observed at the Observation
    /// Point.  There are only two values defined.
    /// 
    /// ```text
    /// 0x00: ingress flow
    /// 0x01: egress flow
    /// ```
    /// 
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowDirection,
    /// The IPv6 address of the next IPv6 hop.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ipNextHopIPv6Address,
    /// The IPv6 address of the next (adjacent) BGP hop.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    bgpNextHopIPv6Address,
    /// Deprecated in favor of the ipv6ExtensionHeadersFull
    /// IE.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    ipv6ExtensionHeaders,
    /// The Label, Exp, and S fields from the top MPLS label
    /// stack entry, i.e., from the last label that was pushed.The size of this Information Element is 3 octets.
    /// 
    /// ```text
    /// 0                   1                   2
    /// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                Label                  | Exp |S|
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// 
    /// Label:  Label Value, 20 bits
    /// Exp:    Experimental Use, 3 bits
    /// S:      Bottom of Stack, 1 bit
    /// ```
    /// 
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsTopLabelStackSection,
    /// The Label, Exp, and S fields from the label stack entry that
    /// was pushed immediately before the label stack entry that would
    /// be reported by mplsTopLabelStackSection.  See the definition of
    /// mplsTopLabelStackSection for further details.The size of this Information Element is 3 octets.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsLabelStackSection2,
    /// The Label, Exp, and S fields from the label stack entry that
    /// was pushed immediately before the label stack entry that would
    /// be reported by mplsLabelStackSection2.  See the definition of
    /// mplsTopLabelStackSection for further details.The size of this Information Element is 3 octets.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsLabelStackSection3,
    /// The Label, Exp, and S fields from the label stack entry that
    /// was pushed immediately before the label stack entry that would
    /// be reported by mplsLabelStackSection3.  See the definition of
    /// mplsTopLabelStackSection for further details.The size of this Information Element is 3 octets.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsLabelStackSection4,
    /// The Label, Exp, and S fields from the label stack entry that
    /// was pushed immediately before the label stack entry that would
    /// be reported by mplsLabelStackSection4.  See the definition of
    /// mplsTopLabelStackSection for further details.The size of this Information Element is 3 octets.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsLabelStackSection5,
    /// The Label, Exp, and S fields from the label stack entry that
    /// was pushed immediately before the label stack entry that would
    /// be reported by mplsLabelStackSection5.  See the definition of
    /// mplsTopLabelStackSection for further details.The size of this Information Element is 3 octets.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsLabelStackSection6,
    /// The Label, Exp, and S fields from the label stack entry that
    /// was pushed immediately before the label stack entry that would
    /// be reported by mplsLabelStackSection6.  See the definition of
    /// mplsTopLabelStackSection for further details.The size of this Information Element is 3 octets.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsLabelStackSection7,
    /// The Label, Exp, and S fields from the label stack entry that
    /// was pushed immediately before the label stack entry that would
    /// be reported by mplsLabelStackSection7.  See the definition of
    /// mplsTopLabelStackSection for further details.The size of this Information Element is 3 octets.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsLabelStackSection8,
    /// The Label, Exp, and S fields from the label stack entry that
    /// was pushed immediately before the label stack entry that would
    /// be reported by mplsLabelStackSection8.  See the definition of
    /// mplsTopLabelStackSection for further details.The size of this Information Element is 3 octets.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsLabelStackSection9,
    /// The Label, Exp, and S fields from the label stack entry that
    /// was pushed immediately before the label stack entry that would
    /// be reported by mplsLabelStackSection9.  See the definition of
    /// mplsTopLabelStackSection for further details.The size of this Information Element is 3 octets.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsLabelStackSection10,
    /// The IEEE 802 destination MAC address field.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    destinationMacAddress,
    /// The definition of this Information Element is identical
    /// to the definition of Information Element
    /// 'sourceMacAddress', except that it reports a
    /// potentially modified value caused by a middlebox
    /// function after the packet passed the Observation Point.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postSourceMacAddress,
    /// A short name uniquely describing an interface, eg "Eth1/0".
    ///
    interfaceName,
    /// The description of an interface, eg "FastEthernet 1/0" or "ISP
    /// connection".
    ///
    interfaceDescription,
    /// Deprecated in favor of 335 selectorName.  Name of the flow
    /// sampler.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    samplerName,
    /// The total number of octets in incoming packets
    /// for this Flow at the Observation Point since the Metering
    /// Process (re-)initialization for this Observation Point.  The
    /// number of octets includes IP header(s) and IP payload.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    octetTotalCount,
    /// The total number of incoming packets for this Flow
    /// at the Observation Point since the Metering Process
    /// (re-)initialization for this Observation Point.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    packetTotalCount,
    /// Flow flags and the value of the sampler ID (samplerId) combined in
    /// one bitmapped field.  Reserved for internal use on the Collector.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    flagsAndSamplerId,
    /// The value of the IP fragment offset field in the
    /// IPv4 packet header or the IPv6 Fragment header,
    /// respectively.  The value is 0 for IPv6 if there is
    /// no fragment header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    fragmentOffset,
    /// This Information Element describes the forwarding
    /// status of the flow and any attached reasons.
    /// IPFIX reduced-size encoding is used as required.A structure is currently associated with the
    /// least-significant byte. Future versions may be
    /// defined to associate meanings with the remaining
    /// bits.The current version of the Information Element
    /// should be exported as unsigned8.The layout of the encoding is as follows:
    /// 
    /// ```text
    /// MSB  -  0   1   2   3   4   5   6   7  -  LSB
    /// +---+---+---+---+---+---+---+---+
    /// | Status|  Reason code or flags |
    /// +---+---+---+---+---+---+---+---+
    /// ```
    /// 
    /// 
    /// ```text
    /// Examples:
    /// 
    /// value : 0x40 = 64
    /// binary: 01000000
    /// decode: 01        -> Forward
    /// 000000  -> No further information
    /// 
    /// value : 0x89 = 137
    /// binary: 10001001
    /// decode: 10        -> Drop
    /// 001001  -> Bad TTL
    /// ```
    /// 
    ///
    /// Reference: [RFC Errata 5262](https://www.rfc-editor.org/errata_search.php?eid=5262)
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    forwardingStatus,
    /// The value of the VPN route distinguisher of a corresponding
    /// entry in a VPN routing and forwarding table.  Route
    /// distinguisher ensures that the same address can be used in
    /// several different MPLS VPNs and that it is possible for BGP to
    /// carry several completely different routes to that address, one
    /// for each VPN.  According to
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsVpnRouteDistinguisher,
    /// The prefix length of the subnet of the mplsTopLabelIPv4Address or
    /// mplsTopLabelIPv6Address that the MPLS top label will cause the Flow
    /// to be forwarded to.
    ///
    mplsTopLabelPrefixLength,
    /// BGP Policy Accounting Source Traffic Index.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    srcTrafficIndex,
    /// BGP Policy Accounting Destination Traffic Index.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    dstTrafficIndex,
    /// Specifies the description of an application.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    applicationDescription,
    /// Specifies an Application ID per
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    applicationId,
    /// Specifies the name of an application.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    applicationName,
    /// The definition of this Information Element is identical to the
    /// definition of Information Element 'ipDiffServCodePoint', except
    /// that it reports a potentially modified value caused by a
    /// middlebox function after the packet passed the Observation
    /// Point.
    ///
    postIpDiffServCodePoint,
    /// The amount of multicast replication that's applied to a traffic
    /// stream.
    ///
    multicastReplicationFactor,
    /// Deprecated in favor of 335 selectorName.  Traffic Class Name,
    /// associated with the classId Information Element.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    className,
    /// A unique identifier for the engine that determined
    /// the Selector ID. Thus, the Classification Engine ID
    /// defines the context for the Selector ID. The
    /// Classification Engine can be considered a specific
    /// registry for application assignments.Values for this field are listed in the Classification
    /// Engine IDs registry.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    classificationEngineId,
    /// Deprecated in favor of 409 sectionOffset.  Layer 2 packet
    /// section offset.  Potentially a generic packet section offset.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    layer2packetSectionOffset,
    /// Deprecated in favor of 312 dataLinkFrameSize.  Layer 2 packet
    /// section size.  Potentially a generic packet section size.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    layer2packetSectionSize,
    /// Deprecated in favor of 315 dataLinkFrameSection.  Layer 2 packet
    /// section data.
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    layer2packetSectionData,
    /// The autonomous system (AS) number of the first AS in the AS
    /// path to the destination IP address.  The path is deduced
    /// by looking up the destination IP address of the Flow in the
    /// BGP routing information base.  If AS path information for
    /// this Flow is only available as an unordered AS set (and not
    /// as an ordered AS sequence), then the value of this Information
    /// Element is 0.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    bgpNextAdjacentAsNumber,
    /// The autonomous system (AS) number of the last AS in the AS
    /// path from the source IP address.  The path is deduced
    /// by looking up the source IP address of the Flow in the BGP
    /// routing information base.  If AS path information for this
    /// Flow is only available as an unordered AS set (and not as
    /// an ordered AS sequence), then the value of this Information
    /// Element is 0.  In case of BGP asymmetry, the
    /// bgpPrevAdjacentAsNumber might not be able to report the correct
    /// value.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    bgpPrevAdjacentAsNumber,
    /// The IPv4 address used by the Exporting Process.  This is used
    /// by the Collector to identify the Exporter in cases where the
    /// identity of the Exporter may have been obscured by the use of
    /// a proxy.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    exporterIPv4Address,
    /// The IPv6 address used by the Exporting Process.  This is used
    /// by the Collector to identify the Exporter in cases where the
    /// identity of the Exporter may have been obscured by the use of
    /// a proxy.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    exporterIPv6Address,
    /// The number of octets since the previous report (if any)
    /// in packets of this Flow dropped by packet treatment.
    /// The number of octets includes IP header(s) and IP payload.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    droppedOctetDeltaCount,
    /// The number of packets since the previous report (if any)
    /// of this Flow dropped by packet treatment.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    droppedPacketDeltaCount,
    /// The total number of octets in packets of this Flow dropped
    /// by packet treatment since the Metering Process
    /// (re-)initialization for this Observation Point.
    /// The number of octets includes IP header(s) and IP payload.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    droppedOctetTotalCount,
    /// The number of packets of this Flow dropped by packet
    /// treatment since the Metering Process
    /// (re-)initialization for this Observation Point.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    droppedPacketTotalCount,
    /// The reason for Flow termination. Values are listed in the flowEndReason registry.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    flowEndReason,
    /// An identifier of a set of common properties that is
    /// unique per Observation Domain and Transport Session.
    /// Typically, this Information Element is used to link to
    /// information reported in separate Data Records.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    commonPropertiesId,
    /// An identifier of an Observation Point that is unique per
    /// Observation Domain.  It is RECOMMENDED that this identifier is
    /// also unique per IPFIX Device.  Typically, this Information
    /// Element is used for limiting the scope of other Information
    /// Elements.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    observationPointId,
    /// Type and Code of the IPv6 ICMP message.  The combination of
    /// both values is reported as (ICMP type * 256) + ICMP code.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    icmpTypeCodeIPv6,
    /// The IPv6 address of the system that the MPLS top label will
    /// cause this Flow to be forwarded to.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsTopLabelIPv6Address,
    /// An identifier of a line card that is unique per IPFIX
    /// Device hosting an Observation Point.  Typically, this
    /// Information Element is used for limiting the scope
    /// of other Information Elements.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    lineCardId,
    /// An identifier of a line port that is unique per IPFIX
    /// Device hosting an Observation Point.  Typically, this
    /// Information Element is used for limiting the scope
    /// of other Information Elements.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    portId,
    /// An identifier of a Metering Process that is unique per
    /// IPFIX Device.  Typically, this Information Element is used
    /// for limiting the scope of other Information Elements.
    /// Note that process identifiers are typically assigned
    /// dynamically.
    /// The Metering Process may be re-started with a different ID.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    meteringProcessId,
    /// An identifier of an Exporting Process that is unique per
    /// IPFIX Device.  Typically, this Information Element is used
    /// for limiting the scope of other Information Elements.
    /// Note that process identifiers are typically assigned
    /// dynamically.  The Exporting Process may be re-started
    /// with a different ID.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    exportingProcessId,
    /// An identifier of a Template that is locally unique within a
    /// combination of a Transport session and an Observation Domain.Template IDs 0-255 are reserved for Template Sets, Options
    /// Template Sets, and other reserved Sets yet to be created.
    /// Template IDs of Data Sets are numbered from 256 to 65535.Typically, this Information Element is used for limiting
    /// the scope of other Information Elements.
    /// Note that after a re-start of the Exporting Process Template
    /// identifiers may be re-assigned.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    templateId,
    /// The identifier of the 802.11 (Wi-Fi) channel used.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    wlanChannelId,
    /// The Service Set IDentifier (SSID) identifying an 802.11
    /// (Wi-Fi) network used.  According to IEEE.802-11.1999, the
    /// SSID is encoded into a string of up to 32 characters.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    wlanSSID,
    /// An identifier of a Flow that is unique within an Observation
    /// Domain.  This Information Element can be used to distinguish
    /// between different Flows if Flow Keys such as IP addresses and
    /// port numbers are not reported or are reported in separate
    /// records.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowId,
    /// An identifier of an Observation Domain that is locally
    /// unique to an Exporting Process.  The Exporting Process uses
    /// the Observation Domain ID to uniquely identify to the
    /// Collecting Process the Observation Domain where Flows
    /// were metered.  It is RECOMMENDED that this identifier is
    /// also unique per IPFIX Device.A value of 0 indicates that no specific Observation Domain
    /// is identified by this Information Element.Typically, this Information Element is used for limiting
    /// the scope of other Information Elements.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    observationDomainId,
    /// The absolute timestamp of the first packet of this Flow.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowStartSeconds,
    /// The absolute timestamp of the last packet of this Flow.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowEndSeconds,
    /// The absolute timestamp of the first packet of this Flow.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowStartMilliseconds,
    /// The absolute timestamp of the last packet of this Flow.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowEndMilliseconds,
    /// The absolute timestamp of the first packet of this Flow.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowStartMicroseconds,
    /// The absolute timestamp of the last packet of this Flow.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowEndMicroseconds,
    /// The absolute timestamp of the first packet of this Flow.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowStartNanoseconds,
    /// The absolute timestamp of the last packet of this Flow.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowEndNanoseconds,
    /// This is a relative timestamp only valid within the scope
    /// of a single IPFIX Message.  It contains the negative time
    /// offset of the first observed packet of this Flow relative
    /// to the export time specified in the IPFIX Message Header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowStartDeltaMicroseconds,
    /// This is a relative timestamp only valid within the scope
    /// of a single IPFIX Message.  It contains the negative time
    /// offset of the last observed packet of this Flow relative
    /// to the export time specified in the IPFIX Message Header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowEndDeltaMicroseconds,
    /// The absolute timestamp of the last (re-)initialization of the
    /// IPFIX Device.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    systemInitTimeMilliseconds,
    /// The difference in time between the first observed packet
    /// of this Flow and the last observed packet of this Flow.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowDurationMilliseconds,
    /// The difference in time between the first observed packet
    /// of this Flow and the last observed packet of this Flow.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    flowDurationMicroseconds,
    /// The total number of Flows observed in the Observation Domain
    /// since the Metering Process (re-)initialization for this
    /// Observation Point.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    observedFlowTotalCount,
    /// The total number of observed IP packets that the
    /// Metering Process did not process since the
    /// (re-)initialization of the Metering Process.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ignoredPacketTotalCount,
    /// The total number of octets in observed IP packets
    /// (including the IP header) that the Metering Process
    /// did not process since the (re-)initialization of the
    /// Metering Process.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ignoredOctetTotalCount,
    /// The total number of Flow Records that were generated by the
    /// Metering Process and dropped by the Metering Process or
    /// by the Exporting Process instead of being sent to the
    /// Collecting Process. There are several potential reasons for
    /// this including resource shortage and special Flow export
    /// policies.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    notSentFlowTotalCount,
    /// The total number of packets in Flow Records that were
    /// generated by the Metering Process and dropped
    /// by the Metering Process or by the Exporting Process
    /// instead of being sent to the Collecting Process.
    /// There are several potential reasons for this including
    /// resource shortage and special Flow export policies.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    notSentPacketTotalCount,
    /// The total number of octets in packets in Flow Records
    /// that were generated by the Metering Process and
    /// dropped by the Metering Process or by the Exporting
    /// Process instead of being sent to the Collecting Process.
    /// There are several potential reasons for this including
    /// resource shortage and special Flow export policies.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    notSentOctetTotalCount,
    /// IPv6 destination address prefix.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    destinationIPv6Prefix,
    /// IPv6 source address prefix.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    sourceIPv6Prefix,
    /// The definition of this Information Element is identical
    /// to the definition of Information Element
    /// 'octetTotalCount', except that it reports a
    /// potentially modified value caused by a middlebox
    /// function after the packet passed the Observation Point.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postOctetTotalCount,
    /// The definition of this Information Element is identical
    /// to the definition of Information Element
    /// 'packetTotalCount', except that it reports a
    /// potentially modified value caused by a middlebox
    /// function after the packet passed the Observation Point.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postPacketTotalCount,
    /// This set of bit fields is used for marking the Information
    /// Elements of a Data Record that serve as Flow Key.  Each bit
    /// represents an Information Element in the Data Record, with
    /// the n-th least significant bit representing the n-th Information
    /// Element.
    /// A bit set to value 1 indicates that the corresponding
    /// Information Element is a Flow Key of the reported Flow.
    /// A bit set to value 0 indicates that this is not the case.If the Data Record contains more than 64 Information Elements,
    /// the corresponding Template SHOULD be designed such that all
    /// Flow Keys are among the first 64 Information Elements, because
    /// the flowKeyIndicator only contains 64 bits.  If the Data Record
    /// contains less than 64 Information Elements, then the bits in
    /// the flowKeyIndicator for which no corresponding Information
    /// Element exists MUST have the value 0.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Errata 4984](https://www.rfc-editor.org/errata_search.php?eid=4984)
    flowKeyIndicator,
    /// The total number of outgoing multicast packets sent for
    /// packets of this Flow by a multicast daemon within the
    /// Observation Domain since the Metering Process
    /// (re-)initialization.  This property cannot necessarily
    /// be observed at the Observation Point, but may be retrieved
    /// by other means.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postMCastPacketTotalCount,
    /// The total number of octets in outgoing multicast packets
    /// sent for packets of this Flow by a multicast daemon in the
    /// Observation Domain since the Metering Process
    /// (re-)initialization.  This property cannot necessarily be
    /// observed at the Observation Point, but may be retrieved by
    /// other means.
    /// The number of octets includes IP header(s) and IP payload.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postMCastOctetTotalCount,
    /// Type of the IPv4 ICMP message.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    icmpTypeIPv4,
    /// Code of the IPv4 ICMP message.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    icmpCodeIPv4,
    /// Type of the IPv6 ICMP message.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    icmpTypeIPv6,
    /// Code of the IPv6 ICMP message.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    icmpCodeIPv6,
    /// The source port identifier in the UDP header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    udpSourcePort,
    /// The destination port identifier in the UDP header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    udpDestinationPort,
    /// The source port identifier in the TCP header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpSourcePort,
    /// The destination port identifier in the TCP header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpDestinationPort,
    /// The sequence number in the TCP header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpSequenceNumber,
    /// The acknowledgement number in the TCP header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpAcknowledgementNumber,
    /// The window field in the TCP header.
    /// If the TCP window scale is supported,
    /// then TCP window scale must be known
    /// to fully interpret the value of this information.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpWindowSize,
    /// The urgent pointer in the TCP header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpUrgentPointer,
    /// The length of the TCP header.  Note that the value of this
    /// Information Element is different from the value of the Data
    /// Offset field in the TCP header.  The Data Offset field
    /// indicates the length of the TCP header in units of 4 octets.
    /// This Information Elements specifies the length of the TCP
    /// header in units of octets.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpHeaderLength,
    /// The length of the IP header.  For IPv6, the value of this
    /// Information Element is 40.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ipHeaderLength,
    /// The total length of the IPv4 packet.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    totalLengthIPv4,
    /// This Information Element reports the value of the Payload
    /// Length field in the IPv6 header.  Note that IPv6 extension
    /// headers belong to the payload.  Also note that in case of a
    /// jumbo payload option the value of the Payload Length field in
    /// the IPv6 header is zero and so will be the value reported
    /// by this Information Element.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    payloadLengthIPv6,
    /// For IPv4, the value of the Information Element matches
    /// the value of the Time to Live (TTL) field in the IPv4 packet
    /// header.  For IPv6, the value of the Information Element
    /// matches the value of the Hop Limit field in the IPv6
    /// packet header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ipTTL,
    /// The value of the Next Header field of the IPv6 header.
    /// The value identifies the type of the following IPv6
    /// extension header or of the following IP payload.
    /// Valid values are defined in the IANA
    /// Protocol Numbers registry.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    nextHeaderIPv6,
    /// The size of the MPLS packet without the label stack.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsPayloadLength,
    /// The value of a Differentiated Services Code Point (DSCP)
    /// encoded in the Differentiated Services field.  The
    /// Differentiated Services field spans the most significant
    /// 6 bits of the IPv4 TOS field or the IPv6 Traffic Class
    /// field, respectively.This Information Element encodes only the 6 bits of the
    /// Differentiated Services field.  Therefore, its value may
    /// range from 0 to 63.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ipDiffServCodePoint,
    /// The value of the IP Precedence.  The IP Precedence value
    /// is encoded in the first 3 bits of the IPv4 TOS field
    /// or the IPv6 Traffic Class field, respectively.This Information Element encodes only these 3 bits.
    /// Therefore, its value may range from 0 to 7.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ipPrecedence,
    /// Fragmentation properties indicated by flags in the IPv4
    /// packet header or the IPv6 Fragment header, respectively.
    /// 
    /// ```text
    /// Bit 0:    (RS) Reserved.
    /// The value of this bit MUST be 0 until specified
    /// otherwise.
    /// 
    /// Bit 1:    (DF) 0 = May Fragment,  1 = Don't Fragment.
    /// Corresponds to the value of the DF flag in the
    /// IPv4 header.  Will always be 0 for IPv6 unless
    /// a "don't fragment" feature is introduced to IPv6.
    /// 
    /// Bit 2:    (MF) 0 = Last Fragment, 1 = More Fragments.
    /// Corresponds to the MF flag in the IPv4 header
    /// or to the M flag in the IPv6 Fragment header,
    /// respectively.  The value is 0 for IPv6 if there
    /// is no fragment header.
    /// 
    /// Bits 3-7: (DC) Don't Care.
    /// The values of these bits are irrelevant.
    /// 
    /// 0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// | R | D | M | D | D | D | D | D |
    /// | S | F | F | C | C | C | C | C |
    /// +---+---+---+---+---+---+---+---+
    /// ```
    /// 
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    fragmentFlags,
    /// The sum of the squared numbers of octets per incoming
    /// packet since the previous report (if any) for this
    /// Flow at the Observation Point.
    /// The number of octets includes IP header(s) and IP payload.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    octetDeltaSumOfSquares,
    /// The total sum of the squared numbers of octets in incoming
    /// packets for this Flow at the Observation Point since the
    /// Metering Process (re-)initialization for this Observation
    /// Point.  The number of octets includes IP header(s) and IP
    /// payload.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    octetTotalSumOfSquares,
    /// The TTL field from the top MPLS label stack entry,
    /// i.e., the last label that was pushed.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsTopLabelTTL,
    /// The length of the MPLS label stack in units of octets.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsLabelStackLength,
    /// The number of labels in the MPLS label stack.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsLabelStackDepth,
    /// The Exp field from the top MPLS label stack entry,
    /// i.e., the last label that was pushed.
    /// 
    /// ```text
    /// Bits 0-4:  Don't Care, value is irrelevant.
    /// Bits 5-7:  MPLS Exp field.
    /// 
    /// 0   1   2   3   4   5   6   7
    /// +---+---+---+---+---+---+---+---+
    /// |     don't care    |    Exp    |
    /// +---+---+---+---+---+---+---+---+
    /// ```
    /// 
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    mplsTopLabelExp,
    /// The effective length of the IP payload.For IPv4 packets, the value of this Information Element is
    /// the difference between the total length of the IPv4 packet
    /// (as reported by Information Element totalLengthIPv4) and the
    /// length of the IPv4 header (as reported by Information Element
    /// headerLengthIPv4).For IPv6, the value of the Payload Length field
    /// in the IPv6 header is reported except in the case that
    /// the value of this field is zero and that there is a valid
    /// jumbo payload option.  In this case, the value of the
    /// Jumbo Payload Length field in the jumbo payload option
    /// is reported.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ipPayloadLength,
    /// The value of the Length field in the UDP header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    udpMessageLength,
    /// If the IP destination address is not a reserved multicast
    /// address, then the value of all bits of the octet (including
    /// the reserved ones) is zero.The first bit of this octet is set to 1 if the Version
    /// field of the IP header has the value 4 and if the
    /// Destination Address field contains a reserved multicast
    /// address in the range from 224.0.0.0 to 239.255.255.255.
    /// Otherwise, this bit is set to 0.The second and third bits of this octet are reserved for
    /// future use.The remaining bits of the octet are only set to values
    /// other than zero if the IP Destination Address is a
    /// reserved IPv6 multicast address.  Then the fourth bit
    /// of the octet is set to the value of the T flag in the
    /// IPv6 multicast address and the remaining four bits are
    /// set to the value of the scope field in the IPv6
    /// multicast address.
    /// 
    /// ```text
    /// 0      1      2      3      4      5      6      7
    /// +------+------+------+------+------+------+------+------+
    /// |   IPv6 multicast scope    |  T   | RES. | RES. | MCv4 |
    /// +------+------+------+------+------+------+------+------+
    /// 
    /// Bits 0-3:  set to value of multicast scope if IPv6 multicast
    /// Bit  4:    set to value of T flag, if IPv6 multicast
    /// Bits 5-6:  reserved for future use
    /// Bit  7:    set to 1 if IPv4 multicast
    /// ```
    /// 
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    isMulticast,
    /// The value of the Internet Header Length (IHL) field in
    /// the IPv4 header.  It specifies the length of the header
    /// in units of 4 octets.  Please note that its unit is
    /// different from most of the other Information Elements
    /// reporting length values.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ipv4IHL,
    /// IPv4 options in packets of this Flow.
    /// The information is encoded in a set of bit fields.  For
    /// each valid IPv4 option type, there is a bit in this set.
    /// The bit is set to 1 if any observed packet of this Flow
    /// contains the corresponding IPv4 option type.  Otherwise,
    /// if no observed packet of this Flow contained the
    /// respective IPv4 option type, the value of the
    /// corresponding bit is 0.The list of valid IPv4 options is maintained by IANA.
    /// Note that for identifying an option not just the 5-bit
    /// Option Number, but all 8 bits of the Option Type need to
    /// match one of the IPv4 options specified at
    /// <http://www.iana.org/assignments/ip-parameters.Options> are mapped to bits according to their option numbers.
    /// Option number X is mapped to bit X.
    /// The mapping is illustrated by the figure below.
    /// 
    /// ```text
    /// 0      1      2      3      4      5      6      7
    /// +------+------+------+------+------+------+------+------+
    /// ... |  RR  |CIPSO |E-SEC |  TS  | LSR  |  SEC | NOP  | EOOL |
    /// +------+------+------+------+------+------+------+------+
    /// 
    /// 8      9     10     11     12     13     14     15
    /// +------+------+------+------+------+------+------+------+
    /// ... |ENCODE| VISA | FINN | MTUR | MTUP | ZSU  | SSR  | SID  | ...
    /// +------+------+------+------+------+------+------+------+
    /// 
    /// 16     17     18     19     20     21     22     23
    /// +------+------+------+------+------+------+------+------+
    /// ... | DPS  |NSAPA | SDB  |RTRALT|ADDEXT|  TR  | EIP  |IMITD | ...
    /// +------+------+------+------+------+------+------+------+
    /// 
    /// 24     25     26     27     28     29     30     31
    /// +------+------+------+------+------+------+------+------+
    /// ... |      | EXP  |   to be assigned by IANA  |  QS  | UMP  |
    /// +------+------+------+------+------+------+------+------+
    /// 
    /// Type   Option
    /// Bit Value  Name    Reference
    /// ---+-----+-------+------------------------------------
    /// 0      7   RR      Record Route, RFC 791
    /// 1    134   CIPSO   Commercial Security
    /// 2    133   E-SEC   Extended Security, RFC 1108
    /// 3     68   TS      Time Stamp, RFC 791
    /// 4    131   LSR     Loose Source Route, RFC791
    /// 5    130   SEC     Security, RFC 1108
    /// 6      1   NOP     No Operation, RFC 791
    /// 7      0   EOOL    End of Options List, RFC 791
    /// 8     15   ENCODE
    /// 9    142   VISA    Experimental Access Control
    /// 10   205   FINN    Experimental Flow Control
    /// 11    12   MTUR    (obsoleted) MTU Reply, RFC 1191
    /// 12    11   MTUP    (obsoleted) MTU Probe, RFC 1191
    /// 13    10   ZSU     Experimental Measurement
    /// 14   137   SSR     Strict Source Route, RFC 791
    /// 15   136   SID     Stream ID, RFC 791
    /// 16   151   DPS     Dynamic Packet State
    /// 17   150   NSAPA   NSAP Address
    /// 18   149   SDB     Selective Directed Broadcast
    /// 19   147   ADDEXT  Address Extension
    /// 20   148   RTRALT  Router Alert, RFC 2113
    /// 21    82   TR      Traceroute, RFC 3193
    /// 22   145   EIP     Extended Internet Protocol, RFC 1385
    /// 23   144   IMITD   IMI Traffic Descriptor
    /// 25    30   EXP     RFC3692-style Experiment
    /// 25    94   EXP     RFC3692-style Experiment
    /// 25   158   EXP     RFC3692-style Experiment
    /// 25   222   EXP     RFC3692-style Experiment
    /// 30    25   QS      Quick-Start
    /// 31   152   UMP     Upstream Multicast Pkt.
    /// ...  ...   ...     Further options numbers
    /// may be assigned by IANA
    /// ```
    /// 
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ipv4Options,
    /// Deprecated in favor of the tcpOptionsFull IE.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    tcpOptions,
    /// The value of this Information Element is always a sequence of
    /// 0x00 values.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    paddingOctets,
    /// An IPv4 address to which the Exporting Process sends Flow
    /// information.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    collectorIPv4Address,
    /// An IPv6 address to which the Exporting Process sends Flow
    /// information.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    collectorIPv6Address,
    /// The index of the interface from which IPFIX Messages sent
    /// by the Exporting Process to a Collector leave the IPFIX
    /// Device.  The value matches the value of
    /// managed object 'ifIndex' as defined in
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    exportInterface,
    /// The protocol version used by the Exporting Process for
    /// sending Flow information.  The protocol version is given
    /// by the value of the Version Number field in the Message
    /// Header.The protocol version is 10 for IPFIX and 9 for NetFlow
    /// version 9.
    /// A value of 0 indicates that no export protocol is in use.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    exportProtocolVersion,
    /// The value of the protocol number used by the Exporting Process
    /// for sending Flow information.
    /// The protocol number identifies the IP packet payload type.
    /// Protocol numbers are defined in the IANA Protocol Numbers
    /// registry.In Internet Protocol version 4 (IPv4), this is carried in the
    /// Protocol field.  In Internet Protocol version 6 (IPv6), this
    /// is carried in the Next Header field in the last extension
    /// header of the packet.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    exportTransportProtocol,
    /// The destination port identifier to which the Exporting Process sends
    /// Flow information. For transport protocols such as UDP, TCP, and SCTP,
    /// this is the destination port number. This field MAY also be used for
    /// future transport protocols that have 16-bit source port identifiers.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    collectorTransportPort,
    /// The source port identifier from which the Exporting
    /// Process sends Flow information. For transport protocols
    /// such as UDP, TCP, and SCTP, this is the source port
    /// number. This field MAY also be used for future transport
    /// protocols that have 16-bit source port identifiers.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    exporterTransportPort,
    /// The total number of packets of this Flow with
    /// TCP "Synchronize sequence numbers" (SYN) flag set.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpSynTotalCount,
    /// The total number of packets of this Flow with
    /// TCP "No more data from sender" (FIN) flag set.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpFinTotalCount,
    /// The total number of packets of this Flow with
    /// TCP "Reset the connection" (RST) flag set.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpRstTotalCount,
    /// The total number of packets of this Flow with
    /// TCP "Push Function" (PSH) flag set.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpPshTotalCount,
    /// The total number of packets of this Flow with
    /// TCP "Acknowledgment field significant" (ACK) flag set.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpAckTotalCount,
    /// The total number of packets of this Flow with
    /// TCP "Urgent Pointer field significant" (URG) flag set.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpUrgTotalCount,
    /// The total length of the IP packet.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    ipTotalLength,
    /// The definition of this Information Element is identical to the
    /// definition of Information Element 'sourceIPv4Address', except
    /// that it reports a modified value caused by a NAT middlebox
    /// function after the packet passed the Observation Point.
    ///
    postNATSourceIPv4Address,
    /// The definition of this Information Element is identical to the
    /// definition of Information Element 'destinationIPv4Address',
    /// except that it reports a modified value caused by a NAT
    /// middlebox function after the packet passed the Observation
    /// Point.
    ///
    postNATDestinationIPv4Address,
    /// The definition of this Information Element is identical to the
    /// definition of Information Element 'sourceTransportPort', except
    /// that it reports a modified value caused by a Network Address
    /// Port Translation (NAPT) middlebox function after the packet
    /// passed the Observation Point.
    ///
    postNAPTSourceTransportPort,
    /// The definition of this Information Element is identical to the
    /// definition of Information Element 'destinationTransportPort',
    /// except that it reports a modified value caused by a Network
    /// Address Port Translation (NAPT) middlebox function after the
    /// packet passed the Observation Point.
    ///
    postNAPTDestinationTransportPort,
    /// Indicates whether the session was created because traffic
    /// originated in the private or public address realm.
    /// postNATSourceIPv4Address, postNATDestinationIPv4Address,
    /// postNAPTSourceTransportPort, and postNAPTDestinationTransportPort
    /// are qualified with the address realm in perspective.Values are listed in the natOriginatingAddressRealm registry.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    natOriginatingAddressRealm,
    /// This Information Element identifies a NAT event. This IE
    /// identifies the type of a NAT event. Examples of NAT events
    /// include, but are not limited to, NAT translation create, NAT
    /// translation delete, Threshold Reached, or Threshold Exceeded,
    /// etc. Values for this Information Element are listed in the
    /// "NAT Event Type" registry.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    natEvent,
    /// The total number of layer 4 payload bytes in a flow from the
    /// initiator since the previous report. The initiator is the device
    /// which triggered the session creation, and remains the same for
    /// the life of the session.
    ///
    initiatorOctets,
    /// The total number of layer 4 payload bytes in a flow from the
    /// responder since the previous report. The responder is the device
    /// which replies to the initiator, and remains the same for the life
    /// of the session.
    ///
    responderOctets,
    /// Indicates a firewall event. Allowed values are listed in
    /// the firewallEvent registry.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    firewallEvent,
    /// An unique identifier of the VRFname where the packets of this
    /// flow are being received.  This identifier is unique per Metering
    /// Process
    ///
    ingressVRFID,
    /// An unique identifier of the VRFname where the packets of this
    /// flow are being sent.  This identifier is unique per Metering
    /// Process
    ///
    egressVRFID,
    /// The name of a VPN Routing and Forwarding table (VRF).
    ///
    VRFname,
    /// The definition of this Information Element is identical to the
    /// definition of Information Element 'mplsTopLabelExp', except
    /// that it reports a potentially modified value caused by a
    /// middlebox function after the packet passed the Observation
    /// Point.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    postMplsTopLabelExp,
    /// The scale of the window field in the TCP header.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    tcpWindowScale,
    /// A description of the direction assignment method used to
    /// assign the Biflow Source and Destination. This Information Element
    /// MAY be present in a Flow Data Record, or applied to all flows
    /// exported from an Exporting Process or Observation Domain using
    /// IPFIX Options. If this Information Element is not present in a
    /// Flow Record or associated with a Biflow via scope, it is assumed
    /// that the configuration of the direction assignment method is
    /// done out-of-band. Note that when using IPFIX Options to apply this
    /// Information Element to all flows within an Observation Domain or
    /// from an Exporting Process, the Option SHOULD be sent reliably. If
    /// reliable transport is not available (i.e., when using UDP), this
    /// Information Element SHOULD appear in each Flow Record. Values are
    /// listed in the biflowDirection registry.
    ///
    /// Reference: [RFC5103](https://datatracker.ietf.org/doc/html/rfc5103)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    biflowDirection,
    /// The difference between the length of an Ethernet frame (minus the
    /// FCS) and the length of its MAC Client Data section (including any
    /// padding) as defined in section 3.1 of [IEEE.802-3.2005].  It does
    /// not include the Preamble, SFD and Extension field lengths.
    ///
    ethernetHeaderLength,
    /// The length of the MAC Client Data section (including any padding)
    /// of a frame as defined in section 3.1 of [IEEE.802-3.2005].
    ///
    ethernetPayloadLength,
    /// The total length of the Ethernet frame (excluding the Preamble,
    /// SFD, Extension and FCS fields) as described in section 3.1 of
    /// [IEEE.802-3.2005].
    ///
    ethernetTotalLength,
    /// The value of the 12-bit VLAN Identifier portion of the Tag Control
    /// Information field of an Ethernet frame.  The structure and
    /// semantics within the Tag Control Information field are defined in
    /// [IEEE802.1Q].  In Provider Bridged Networks, it represents the
    /// Service VLAN identifier in the Service VLAN Tag (S-TAG) Tag
    /// Control Information (TCI) field or the Customer VLAN identifier in
    /// the Customer VLAN Tag (C-TAG) Tag Control Information (TCI) field
    /// as described in [IEEE802.1Q].  In Provider Backbone Bridged
    /// Networks, it represents the Backbone VLAN identifier in the
    /// Backbone VLAN Tag (B-TAG) Tag Control Information (TCI) field as
    /// described in [IEEE802.1Q].  In a virtual link between a host
    /// system and EVB bridge, it represents the Service VLAN identifier
    /// indicating S-channel as described in [IEEE802.1Qbg].In the case of a multi-tagged frame, it represents the outer tag's
    /// VLAN identifier, except for I-TAG.
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    dot1qVlanId,
    /// The value of the 3-bit User Priority portion of the Tag Control
    /// Information field of an Ethernet frame.  The structure and
    /// semantics within the Tag Control Information field are defined in
    /// [IEEE802.1Q].  In the case of multi-tagged frame, it represents
    /// the 3-bit Priority Code Point (PCP) portion of the outer tag's Tag
    /// Control Information (TCI) field as described in [IEEE802.1Q],
    /// except for I-TAG.
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    dot1qPriority,
    /// The value represents the Customer VLAN identifier in the Customer
    /// VLAN Tag (C-TAG) Tag Control Information (TCI) field as described
    /// in [IEEE802.1Q].
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    dot1qCustomerVlanId,
    /// The value represents the 3-bit Priority Code Point (PCP) portion
    /// of the Customer VLAN Tag (C-TAG) Tag Control Information (TCI)
    /// field as described in [IEEE802.1Q].
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    dot1qCustomerPriority,
    /// The EVC Service Attribute which uniquely identifies the Ethernet
    /// Virtual Connection (EVC) within a Metro Ethernet Network, as
    /// defined in section 6.2 of MEF 10.1.  The MetroEVCID is encoded in
    /// a string of up to 100 characters.
    ///
    metroEvcId,
    /// The 3-bit EVC Service Attribute which identifies the type of
    /// service provided by an EVC.
    ///
    metroEvcType,
    /// A 32-bit non-zero connection identifier, which together with the
    /// pseudoWireType, identifies the Pseudo Wire (PW) as defined in
    ///
    pseudoWireId,
    /// The value of this information element identifies the type of MPLS
    /// Pseudo Wire (PW) as defined in
    ///
    pseudoWireType,
    /// The 32-bit Preferred Pseudo Wire (PW) MPLS Control Word as
    /// defined in Section 3 of
    ///
    pseudoWireControlWord,
    /// The index of a networking device's physical interface (example, a
    /// switch port) where packets of this flow are being received.
    ///
    ingressPhysicalInterface,
    /// The index of a networking device's physical interface (example, a
    /// switch port) where packets of this flow are being sent.
    ///
    egressPhysicalInterface,
    /// The definition of this Information Element is identical to the
    /// definition of Information Element 'dot1qVlanId', except that it
    /// reports a potentially modified value caused by a middlebox
    /// function after the packet passed the Observation Point.
    ///
    postDot1qVlanId,
    /// The definition of this Information Element is identical to the
    /// definition of Information Element 'dot1qCustomerVlanId', except
    /// that it reports a potentially modified value caused by a
    /// middlebox function after the packet passed the Observation Point.
    ///
    postDot1qCustomerVlanId,
    /// The Ethernet type field of an Ethernet frame that identifies the
    /// MAC client protocol carried in the payload as defined in
    /// paragraph 1.4.349 of [IEEE.802-3.2005].
    ///
    ethernetType,
    /// The definition of this Information Element is identical to the
    /// definition of Information Element 'ipPrecedence', except that
    /// it reports a potentially modified value caused by a middlebox
    /// function after the packet passed the Observation Point.
    ///
    postIpPrecedence,
    /// The absolute timestamp at which the data within the scope
    /// containing this Information Element was received by a
    /// Collecting Process. This Information Element SHOULD be
    /// bound to its containing IPFIX Message via IPFIX Options
    /// and the messageScope Information Element.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    /// Reference: [RFC Errata 3559](https://www.rfc-editor.org/errata_search.php?eid=3559)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    collectionTimeMilliseconds,
    /// The value of the SCTP Stream Identifier used by the
    /// Exporting Process for exporting IPFIX Message data.  This is
    /// carried in the Stream Identifier field of the header of the SCTP
    /// DATA chunk containing the IPFIX Message(s).
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    exportSctpStreamId,
    /// The absolute Export Time of the latest IPFIX Message
    /// within the scope containing this Information Element. This
    /// Information Element SHOULD be bound to its containing IPFIX
    /// Transport Session via IPFIX Options and the sessionScope
    /// Information Element.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    maxExportSeconds,
    /// The latest absolute timestamp of the last packet
    /// within any Flow within the scope containing this Information
    /// Element, rounded up to the second if necessary.  This Information
    /// Element SHOULD be bound to its containing IPFIX Transport Session
    /// via IPFIX Options and the sessionScope Information Element.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    maxFlowEndSeconds,
    /// The MD5 checksum of the IPFIX Message containing this record.
    /// This Information Element SHOULD be bound to its containing IPFIX
    /// Message via an options record and the messageScope Information
    /// lement, and SHOULD appear only once in a given IPFIX Message.
    /// To calculate the value of this Information Element, first buffer
    /// the containing IPFIX Message, setting the value of this Information
    /// Element to all zeroes. Then calculate the MD5 checksum of the
    /// resulting buffer as defined in
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    /// Reference: [RFC1321](https://datatracker.ietf.org/doc/html/rfc1321)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    messageMD5Checksum,
    /// The presence of this Information Element as scope in
    /// an Options Template signifies that the options described by the
    /// Template apply to the IPFIX Message that contains them. It is
    /// defined for general purpose message scoping of options, and
    /// proposed specifically to allow the attachment a checksum to a
    /// message via IPFIX Options. The value of this Information Element
    /// MUST be written as 0 by the File Writer or Exporting Process. The
    /// value of this Information Element MUST be ignored by the File
    /// Reader or the Collecting Process.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    messageScope,
    /// The absolute Export Time of the earliest IPFIX Message
    /// within the scope containing this Information Element.  This
    /// Information Element SHOULD be bound to its containing IPFIX
    /// Transport Session via an options record and the sessionScope
    /// Information Element.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    minExportSeconds,
    /// The earliest absolute timestamp of the first packet
    /// within any Flow within the scope containing this Information
    /// Element, rounded down to the second if necessary.  This
    /// Information Element SHOULD be bound to its containing IPFIX
    /// Transport Session via an options record and the sessionScope
    /// Information Element.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    minFlowStartSeconds,
    /// This Information Element is used to encapsulate non-
    /// IPFIX data into an IPFIX Message stream, for the purpose of
    /// allowing a non-IPFIX data processor to store a data stream inline
    /// within an IPFIX File.  A Collecting Process or File Writer MUST
    /// NOT try to interpret this binary data.  This Information Element
    /// differs from paddingOctets as its contents are meaningful in some
    /// non-IPFIX context, while the contents of paddingOctets MUST be
    /// 0x00 and are intended only for Information Element alignment.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    opaqueOctets,
    /// The presence of this Information Element as scope in
    /// an Options Template signifies that the options described by the
    /// Template apply to the IPFIX Transport Session that contains them.
    /// Note that as all options are implicitly scoped to Transport
    /// Session and Observation Domain, this Information Element is
    /// equivalent to a "null" scope.  It is defined for general purpose
    /// session scoping of options, and proposed specifically to allow the
    /// attachment of time window to an IPFIX File via IPFIX Options.  The
    /// value of this Information Element MUST be written as 0 by the File
    /// Writer or Exporting Process.  The value of this Information
    /// Element MUST be ignored by the File Reader or the Collecting
    /// Process.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    sessionScope,
    /// The latest absolute timestamp of the last packet
    /// within any Flow within the scope containing this Information
    /// Element, rounded up to the microsecond if necessary.  This
    /// Information Element SHOULD be bound to its containing IPFIX
    /// Transport Session via IPFIX Options and the sessionScope
    /// Information Element.  This Information Element SHOULD be used only
    /// in Transport Sessions containing Flow Records with microsecond-
    /// precision (or better) timestamp Information Elements.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    maxFlowEndMicroseconds,
    /// The latest absolute timestamp of the last packet
    /// within any Flow within the scope containing this Information
    /// Element, rounded up to the millisecond if necessary.  This
    /// Information Element SHOULD be bound to its containing IPFIX
    /// Transport Session via IPFIX Options and the sessionScope
    /// Information Element.  This Information Element SHOULD be used only
    /// in Transport Sessions containing Flow Records with millisecond-
    /// precision (or better) timestamp Information Elements.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    maxFlowEndMilliseconds,
    /// The latest absolute timestamp of the last packet
    /// within any Flow within the scope containing this Information
    /// Element.  This Information Element SHOULD be bound to its
    /// containing IPFIX Transport Session via IPFIX Options and the
    /// sessionScope Information Element.  This Information Element SHOULD
    /// be used only in Transport Sessions containing Flow Records with
    /// nanosecond-precision timestamp Information Elements.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    maxFlowEndNanoseconds,
    /// The earliest absolute timestamp of the first packet
    /// within any Flow within the scope containing this Information
    /// Element, rounded down to the microsecond if necessary.  This
    /// Information Element SHOULD be bound to its containing IPFIX
    /// Transport Session via an options record and the sessionScope
    /// Information Element.  This Information Element SHOULD be used only
    /// in Transport Sessions containing Flow Records with microsecond-
    /// precision (or better) timestamp Information Elements.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    minFlowStartMicroseconds,
    /// The earliest absolute timestamp of the first packet
    /// within any Flow within the scope containing this Information
    /// Element, rounded down to the millisecond if necessary.  This
    /// Information Element SHOULD be bound to its containing IPFIX
    /// Transport Session via an options record and the sessionScope
    /// Information Element.  This Information Element SHOULD be used only
    /// in Transport Sessions containing Flow Records with millisecond-
    /// precision (or better) timestamp Information Elements.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    minFlowStartMilliseconds,
    /// The earliest absolute timestamp of the first packet
    /// within any Flow within the scope containing this Information
    /// Element.  This Information Element SHOULD be bound to its
    /// containing IPFIX Transport Session via an options record and the
    /// sessionScope Information Element.  This Information Element SHOULD
    /// be used only in Transport Sessions containing Flow Records with
    /// nanosecond-precision timestamp Information Elements.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    minFlowStartNanoseconds,
    /// The full X.509 certificate, encoded in ASN.1 DER
    /// format, used by the Collector when IPFIX Messages were transmitted
    /// using TLS or DTLS.  This Information Element SHOULD be bound to
    /// its containing IPFIX Transport Session via an options record and
    /// the sessionScope Information Element, or to its containing IPFIX
    /// Message via an options record and the messageScope Information
    /// Element.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    collectorCertificate,
    /// The full X.509 certificate, encoded in ASN.1 DER
    /// format, used by the Collector when IPFIX Messages were transmitted
    /// using TLS or DTLS.  This Information Element SHOULD be bound to
    /// its containing IPFIX Transport Session via an options record and
    /// the sessionScope Information Element, or to its containing IPFIX
    /// Message via an options record and the messageScope Information
    /// Element.
    ///
    /// Reference: [RFC5655](https://datatracker.ietf.org/doc/html/rfc5655)
    exporterCertificate,
    /// The export reliability of Data Records, within this SCTP
    /// stream, for the element(s) in the Options Template
    /// scope.  A typical example of an element for which the
    /// export reliability will be reported is the templateID,
    /// as specified in the Data Records Reliability Options
    /// Template.  A value of 'True' means that the Exporting
    /// Process MUST send any Data Records associated with the
    /// element(s) reliably within this SCTP stream.  A value of
    /// 'False' means that the Exporting Process MAY send any
    /// Data Records associated with the element(s) unreliably
    /// within this SCTP stream.
    ///
    /// Reference: [RFC6526](https://datatracker.ietf.org/doc/html/rfc6526)
    dataRecordsReliability,
    /// Type of observation point. Values are listed in the
    /// observationPointType registry.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    observationPointType,
    /// This information element counts the number of TCP or UDP
    /// connections which were opened during the observation period. The
    /// observation period may be specified by the flow start and end timestamps.
    ///
    newConnectionDeltaCount,
    /// This information element aggregates the total time in
    /// seconds for all of the TCP or UDP connections which were in use during
    /// the observation period. For example if there are 5 concurrent
    /// connections each for 10 seconds, the value would be 50 s.
    ///
    connectionSumDurationSeconds,
    /// This information element identifies a transaction within a
    /// connection. A transaction is a meaningful exchange of application data
    /// between two network devices or a client and server. A transactionId is
    /// assigned the first time a flow is reported, so that later reports for
    /// the same flow will have the same transactionId. A different
    /// transactionId is used for each transaction within a TCP or UDP
    /// connection. The identifiers need not be sequential.
    ///
    connectionTransactionId,
    /// The definition of this Information Element is identical to
    /// the definition of Information Element 'sourceIPv6Address', except that
    /// it reports a modified value caused by a NAT64 middlebox function after
    /// the packet passed the Observation Point.
    /// 
    /// See
    ///
    postNATSourceIPv6Address,
    /// The definition of this Information Element is identical to
    /// the definition of Information Element 'destinationIPv6Address', except
    /// that it reports a modified value caused by a NAT64 middlebox function
    /// after the packet passed the Observation Point.
    /// 
    /// See
    ///
    postNATDestinationIPv6Address,
    /// Locally unique identifier of a NAT pool.
    ///
    natPoolId,
    /// The name of a NAT pool identified by a natPoolID.
    ///
    natPoolName,
    /// A flag word describing specialized modifications to
    /// the anonymization policy in effect for the anonymization technique
    /// applied to a referenced Information Element within a referenced
    /// Template.  When flags are clear (0), the normal policy (as
    /// described by anonymizationTechnique) applies without modification.
    /// 
    /// ```text
    /// MSB   14  13  12  11  10   9   8   7   6   5   4   3   2   1  LSB
    /// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    /// |                Reserved                       |LOR|PmA|   SC  |
    /// +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
    /// 
    /// anonymizationFlags IE
    /// 
    /// +--------+----------+-----------------------------------------------+
    /// | bit(s) | name     | description                                   |
    /// | (LSB = |          |                                               |
    /// | 0)     |          |                                               |
    /// +--------+----------+-----------------------------------------------+
    /// | 0-1    | SC       | Stability Class: see the Stability Class      |
    /// |        |          | table below, and Section 5.1 of [RFC6235](<https://datatracker.ietf.org/doc/rfc6235>).    |
    /// | 2      | PmA      | Perimeter Anonymization: when set (1),        |
    /// |        |          | source- Information Elements as described in  |
    /// |        |          | [RFC5103] are interpreted as external         |
    /// |        |          | addresses, and destination- Information       |
    /// |        |          | Elements as described in [RFC5103] are        |
    /// |        |          | interpreted as internal addresses, for the    |
    /// |        |          | purposes of associating                       |
    /// |        |          | anonymizationTechnique to Information         |
    /// |        |          | Elements only; see Section 7.2.2 of [RFC6235] |
    /// |        |          | for details.                                  |
    /// |        |          | This bit MUST NOT be set when associated with |
    /// |        |          | a non-endpoint (i.e., source- or              |
    /// |        |          | destination-) Information Element.  SHOULD be |
    /// |        |          | consistent within a record (i.e., if a        |
    /// |        |          | source- Information Element has this flag     |
    /// |        |          | set, the corresponding destination- element   |
    /// |        |          | SHOULD have this flag set, and vice versa.)   |
    /// | 3      | LOR      | Low-Order Unchanged: when set (1), the        |
    /// |        |          | low-order bits of the anonymized Information  |
    /// |        |          | Element contain real data.  This modification |
    /// |        |          | is intended for the anonymization of          |
    /// |        |          | network-level addresses while leaving         |
    /// |        |          | host-level addresses intact in order to       |
    /// |        |          | preserve host level-structure, which could    |
    /// |        |          | otherwise be used to reverse anonymization.   |
    /// |        |          | MUST NOT be set when associated with a        |
    /// |        |          | truncation-based anonymizationTechnique.      |
    /// | 4-15   | Reserved | Reserved for future use: SHOULD be cleared    |
    /// |        |          | (0) by the Exporting Process and MUST be      |
    /// |        |          | ignored by the Collecting Process.            |
    /// +--------+----------+-----------------------------------------------+
    /// ```
    /// The Stability Class portion of this flags word describes the
    /// stability class of the anonymization technique applied to a
    /// referenced Information Element within a referenced Template.
    /// Stability classes refer to the stability of the parameters of the
    /// anonymization technique, and therefore the comparability of the
    /// mapping between the real and anonymized values over time.  This
    /// determines which anonymized datasets may be compared with each
    /// other.  Values are as follows:
    /// 
    /// ```text
    /// +-----+-----+-------------------------------------------------------+
    /// | Bit | Bit | Description                                           |
    /// | 1   | 0   |                                                       |
    /// +-----+-----+-------------------------------------------------------+
    /// | 0   | 0   | Undefined: the Exporting Process makes no             |
    /// |     |     | representation as to how stable the mapping is, or    |
    /// |     |     | over what time period values of this field will       |
    /// |     |     | remain comparable; while the Collecting Process MAY   |
    /// |     |     | assume Session level stability, Session level         |
    /// |     |     | stability is not guaranteed.  Processes SHOULD assume |
    /// |     |     | this is the case in the absence of stability class    |
    /// |     |     | information; this is the default stability class.     |
    /// | 0   | 1   | Session: the Exporting Process will ensure that the   |
    /// |     |     | parameters of the anonymization technique are stable  |
    /// |     |     | during the Transport Session.  All the values of the  |
    /// |     |     | described Information Element for each Record         |
    /// |     |     | described by the referenced Template within the       |
    /// |     |     | Transport Session are comparable.  The Exporting      |
    /// |     |     | Process SHOULD endeavour to ensure at least this      |
    /// |     |     | stability class.                                      |
    /// | 1   | 0   | Exporter-Collector Pair: the Exporting Process will   |
    /// |     |     | ensure that the parameters of the anonymization       |
    /// |     |     | technique are stable across Transport Sessions over   |
    /// |     |     | time with the given Collecting Process, but may use   |
    /// |     |     | different parameters for different Collecting         |
    /// |     |     | Processes.  Data exported to different Collecting     |
    /// |     |     | Processes are not comparable.                         |
    /// | 1   | 1   | Stable: the Exporting Process will ensure that the    |
    /// |     |     | parameters of the anonymization technique are stable  |
    /// |     |     | across Transport Sessions over time, regardless of    |
    /// |     |     | the Collecting Process to which it is sent.           |
    /// +-----+-----+-------------------------------------------------------+
    /// ```
    /// 
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    anonymizationFlags,
    /// A description of the anonymization technique applied to a
    /// referenced Information Element within a referenced Template.
    /// Each technique may be applicable only to certain Information
    /// Elements and recommended only for certain Information Elements.
    /// Values are listed in the anonymizationTechnique registry.
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    anonymizationTechnique,
    /// A zero-based index of an Information Element
    /// referenced by informationElementId within a Template referenced by
    /// templateId; used to disambiguate scope for templates containing
    /// multiple identical Information Elements.
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    informationElementIndex,
    /// Specifies if the Application ID is based on peer-to-peer
    /// technology.Possible values are: { "yes", "y", 1 },
    /// { "no", "n", 2 } and { "unassigned", "u", 0 }.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    p2pTechnology,
    /// Specifies if the Application ID is used as a tunnel technology.Possible values are: { "yes", "y", 1 }, { "no", "n", 2 } and
    /// { "unassigned", "u", 0 }.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    tunnelTechnology,
    /// Specifies if the Application ID is an encrypted networking
    /// protocol.Possible values are: { "yes", "y", 1 },
    /// { "no", "n", 2 } and { "unassigned", "u", 0 }.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    encryptedTechnology,
    /// Specifies a generic Information Element with a basicList abstract
    /// data type.  For example, a list of port numbers, a list of
    /// interface indexes, etc.
    ///
    /// Reference: [RFC6313](https://datatracker.ietf.org/doc/html/rfc6313)
    basicList,
    /// Specifies a generic Information Element with a subTemplateList
    /// abstract data type.
    ///
    /// Reference: [RFC6313](https://datatracker.ietf.org/doc/html/rfc6313)
    subTemplateList,
    /// Specifies a generic Information Element with a
    /// subTemplateMultiList abstract data type.
    ///
    /// Reference: [RFC6313](https://datatracker.ietf.org/doc/html/rfc6313)
    subTemplateMultiList,
    /// This element describes the "validity state" of the BGP route correspondent source or destination IP address. If the "validity state" for this Flow is only available, then the value of this Information Element is 255.
    ///
    bgpValidityState,
    /// IPSec Security Parameters Index (SPI).
    ///
    IPSecSPI,
    /// GRE key, which is used for identifying an individual traffic flow within a tunnel.
    ///
    greKey,
    /// This Information Element identifies the NAT type applied to packets of the Flow.
    /// 
    /// Values are listed in the natType registry.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    natType,
    /// The total number of layer 4 packets in a flow from the initiator
    /// since the previous report. The initiator is the device which
    /// triggered the session creation, and remains the same for the life
    /// of the session.
    ///
    initiatorPackets,
    /// The total number of layer 4 packets in a flow from the responder
    /// since the previous report. The responder is the device which
    /// replies to the initiator, and remains the same for the life of the
    /// session.
    ///
    responderPackets,
    /// The name of an observation domain identified by an
    /// observationDomainId.
    ///
    observationDomainName,
    /// From all the packets observed at an Observation Point, a subset of
    /// the packets is selected by a sequence of one or more Selectors.
    /// The selectionSequenceId is a unique value per Observation Domain,
    /// specifying the Observation Point and the sequence of Selectors
    /// through which the packets are selected.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    selectionSequenceId,
    /// The Selector ID is the unique ID identifying a Primitive Selector.
    /// Each Primitive Selector must have a unique ID in the Observation
    /// Domain.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    /// Reference: [RFC Errata 2052](https://www.rfc-editor.org/errata_search.php?eid=2052)
    selectorId,
    /// This Information Element contains the ID of another Information
    /// Element.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    informationElementId,
    /// This Information Element identifies the packet selection
    /// methods (e.g., Filtering, Sampling) that are applied by
    /// the Selection Process. Most of these methods have parameters.
    /// Further Information Elements are needed to fully specify packet
    /// selection with these methods and all their parameters. For the
    /// methods parameters, Information Elements are defined in the
    /// IPFIX IANA registryThere is a broad variety of possible parameters that could be
    /// used for Property match Filtering (5) but currently there are
    /// no agreed parameters specified.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    selectorAlgorithm,
    /// This Information Element specifies the number of packets that are
    /// consecutively sampled.  A value of 100 means that 100
    /// consecutive packets are sampled.For example, this Information Element may be used to describe the
    /// configuration of a systematic count-based Sampling Selector.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    samplingPacketInterval,
    /// This Information Element specifies the number of packets between
    /// two "samplingPacketInterval"s.  A value of 100 means that the next
    /// interval starts 100 packets (which are not sampled) after the
    /// current "samplingPacketInterval" is over.For example, this Information Element may be used to describe the
    /// configuration of a systematic count-based Sampling Selector.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    samplingPacketSpace,
    /// This Information Element specifies the time interval in
    /// microseconds during which all arriving packets are sampled.For example, this Information Element may be used to describe the
    /// configuration of a systematic time-based Sampling Selector.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    samplingTimeInterval,
    /// This Information Element specifies the time interval in
    /// microseconds between two "samplingTimeInterval"s.  A value of 100
    /// means that the next interval starts 100 microseconds (during which
    /// no packets are sampled) after the current "samplingTimeInterval"
    /// is over.For example, this Information Element may used to describe the
    /// configuration of a systematic time-based Sampling Selector.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    samplingTimeSpace,
    /// This Information Element specifies the number of elements taken
    /// from the parent Population for random Sampling methods.For example, this Information Element may be used to describe the
    /// configuration of a random n-out-of-N Sampling Selector.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    samplingSize,
    /// This Information Element specifies the number of elements in the
    /// parent Population for random Sampling methods.For example, this Information Element may be used to describe the
    /// configuration of a random n-out-of-N Sampling Selector.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    samplingPopulation,
    /// This Information Element specifies the probability that a packet
    /// is sampled, expressed as a value between 0 and 1.  The probability
    /// is equal for every packet.  A value of 0 means no packet was
    /// sampled since the probability is 0.For example, this Information Element may be used to describe the
    /// configuration of a uniform probabilistic Sampling Selector.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    samplingProbability,
    /// This Information Element specifies the length of the selected data
    /// link frame.The data link layer is defined in [ISO/IEC.7498-1:1994].
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    dataLinkFrameSize,
    /// This Information Element carries a series of n octets from the IP
    /// header of a sampled packet, starting sectionOffset octets into the
    /// IP header.However, if no sectionOffset field corresponding to this
    /// Information Element is present, then a sectionOffset of zero
    /// applies, and the octets MUST be from the start of the IP header.With sufficient length, this element also reports octets from the
    /// IP payload.  However, full packet capture of arbitrary packet
    /// streams is explicitly out of scope per the Security Considerations
    /// sections ofThe sectionExportedOctets expresses how much data was exported,
    /// while the remainder is padding.When the sectionExportedOctets field corresponding to this
    /// Information Element exists, this Information Element MAY have a
    /// fixed length and MAY be padded, or it MAY have a variable length.When the sectionExportedOctets field corresponding to this
    /// Information Element does not exist, this Information Element
    /// SHOULD have a variable length and MUST NOT be padded.  In this
    /// case, the size of the exported section may be constrained due to
    /// limitations in the IPFIX protocol.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    ipHeaderPacketSection,
    /// This Information Element carries a series of n octets from the IP
    /// payload of a sampled packet, starting sectionOffset octets into
    /// the IP payload.However, if no sectionOffset field corresponding to this
    /// Information Element is present, then a sectionOffset of zero
    /// applies, and the octets MUST be from the start of the IP payload.The IPv4 payload is that part of the packet that follows the IPv4
    /// header and any options, whichThe IPv6 payload is the rest of the packet following the 40-octet
    /// IPv6 header.  Note that any extension headers present are
    /// considered part of the payload.  SeeThe sectionExportedOctets expresses how much data was observed,
    /// while the remainder is padding.When the sectionExportedOctets field corresponding to this
    /// Information Element exists, this Information Element MAY have a
    /// fixed length and MAY be padded, or MAY have a variable length.When the sectionExportedOctets field corresponding to this
    /// Information Element does not exist, this Information Element
    /// SHOULD have a variable length and MUST NOT be padded.  In this
    /// case, the size of the exported section may be constrained due to
    /// limitations in the IPFIX protocol.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    ipPayloadPacketSection,
    /// This Information Element carries n octets from the data link frame
    /// of a selected frame, starting sectionOffset octets into the frame.However, if no sectionOffset field corresponding to this
    /// Information Element is present, then a sectionOffset of zero
    /// applies, and the octets MUST be from the start of the data link
    /// frame.The sectionExportedOctets expresses how much data was observed,
    /// while the remainder is padding.When the sectionExportedOctets field corresponding to this
    /// Information Element exists, this Information Element MAY have a
    /// fixed length and MAY be padded, or MAY have a variable length.When the sectionExportedOctets field corresponding to this
    /// Information Element does not exist, this Information Element
    /// SHOULD have a variable length and MUST NOT be padded.  In this
    /// case, the size of the exported section may be constrained due to
    /// limitations in the IPFIX protocol.Further Information Elements, i.e., dataLinkFrameType and
    /// dataLinkFrameSize, are needed to specify the data link type and the
    /// size of the data link frame of this Information Element.  A set of
    /// these Information Elements MAY be contained in a structured data
    /// type, as expressed inThe data link layer is defined in [ISO/IEC.7498-1:1994].
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    dataLinkFrameSection,
    /// This Information Element carries a series of n octets from the
    /// MPLS label stack of a sampled packet, starting sectionOffset
    /// octets into the MPLS label stack.However, if no sectionOffset field corresponding to this
    /// Information Element is present, then a sectionOffset of zero
    /// applies, and the octets MUST be from the head of the MPLS label
    /// stack.With sufficient length, this element also reports octets from the
    /// MPLS payload.  However, full packet capture of arbitrary packet
    /// streams is explicitly out of scope per the Security Considerations
    /// sections ofSeeSeeThe sectionExportedOctets expresses how much data was observed,
    /// while the remainder is padding.When the sectionExportedOctets field corresponding to this
    /// Information Element exists, this Information Element MAY have a
    /// fixed length and MAY be padded, or MAY have a variable length.When the sectionExportedOctets field corresponding to this
    /// Information Element does not exist, this Information Element
    /// SHOULD have a variable length and MUST NOT be padded.  In this
    /// case, the size of the exported section may be constrained due to
    /// limitations in the IPFIX protocol.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    mplsLabelStackSection,
    /// The mplsPayloadPacketSection carries a series of n octets from the
    /// MPLS payload of a sampled packet, starting sectionOffset octets
    /// into the MPLS payload, as it is data that follows immediately after
    /// the MPLS label stack.However, if no sectionOffset field corresponding to this
    /// Information Element is present, then a sectionOffset of zero
    /// applies, and the octets MUST be from the start of the MPLS
    /// payload.SeeSeeThe sectionExportedOctets expresses how much data was observed,
    /// while the remainder is padding.When the sectionExportedOctets field corresponding to this
    /// Information Element exists, this Information Element MAY have a
    /// fixed length and MAY be padded, or it MAY have a variable length.When the sectionExportedOctets field corresponding to this
    /// Information Element does not exist, this Information Element
    /// SHOULD have a variable length and MUST NOT be padded.  In this
    /// case, the size of the exported section may be constrained due to
    /// limitations in the IPFIX protocol.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    mplsPayloadPacketSection,
    /// This Information Element specifies the total number of packets
    /// observed by a Selector, for a specific value of SelectorId.This Information Element should be used in an Options Template
    /// scoped to the observation to which it refers.  See Section 3.4.2.1
    /// of the IPFIX protocol document
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    selectorIdTotalPktsObserved,
    /// This Information Element specifies the total number of packets
    /// selected by a Selector, for a specific value of SelectorId.This Information Element should be used in an Options Template
    /// scoped to the observation to which it refers.  See Section 3.4.2.1
    /// of the IPFIX protocol document
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    selectorIdTotalPktsSelected,
    /// This Information Element specifies the maximum possible
    /// measurement error of the reported value for a given Information
    /// Element.  The absoluteError has the same unit as the Information
    /// Element with which it is associated.  The real value of the metric can
    /// differ by absoluteError (positive or negative) from the measured
    /// value.This Information Element provides only the error for measured
    /// values.  If an Information Element contains an estimated value
    /// (from Sampling), the confidence boundaries and confidence level
    /// have to be provided instead, using the upperCILimit, lowerCILimit,
    /// and confidenceLevel Information Elements.This Information Element should be used in an Options Template
    /// scoped to the observation to which it refers.  See Section 3.4.2.1
    /// of the IPFIX protocol document
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    absoluteError,
    /// This Information Element specifies the maximum possible positive
    /// or negative error ratio for the reported value for a given
    /// Information Element as percentage of the measured value.  The real
    /// value of the metric can differ by relativeError percent (positive
    /// or negative) from the measured value.This Information Element provides only the error for measured
    /// values.  If an Information Element contains an estimated value
    /// (from Sampling), the confidence boundaries and confidence level
    /// have to be provided instead, using the upperCILimit, lowerCILimit,
    /// and confidenceLevel Information Elements.This Information Element should be used in an Options Template
    /// scoped to the observation to which it refers.  See Section 3.4.2.1
    /// of the IPFIX protocol document
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    relativeError,
    /// This Information Element specifies the absolute time in seconds of
    /// an observation.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    observationTimeSeconds,
    /// This Information Element specifies the absolute time in
    /// milliseconds of an observation.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    observationTimeMilliseconds,
    /// This Information Element specifies the absolute time in
    /// microseconds of an observation.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    observationTimeMicroseconds,
    /// This Information Element specifies the absolute time in
    /// nanoseconds of an observation.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    observationTimeNanoseconds,
    /// This Information Element specifies the value from the digest hash
    /// function.
    /// 
    /// See also Sections 6.2, 3.8 and 7.1 of
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    digestHashValue,
    /// This Information Element specifies the IP payload offset used by a
    /// Hash-based Selection Selector.
    /// 
    /// See also Sections 6.2, 3.8 and 7.1 of
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    hashIPPayloadOffset,
    /// This Information Element specifies the IP payload size used by a
    /// Hash-based Selection Selector.  See also Sections 6.2, 3.8 and 7.1 of
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    hashIPPayloadSize,
    /// This Information Element specifies the value for the beginning of
    /// a hash function's potential output range.See also Sections 6.2, 3.8 and 7.1 of
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    hashOutputRangeMin,
    /// This Information Element specifies the value for the end of a hash
    /// function's potential output range.See also Sections 6.2, 3.8 and 7.1 of
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    hashOutputRangeMax,
    /// This Information Element specifies the value for the beginning of
    /// a hash function's selected range.See also Sections 6.2, 3.8 and 7.1 of
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    hashSelectedRangeMin,
    /// This Information Element specifies the value for the end of a hash
    /// function's selected range.See also Sections 6.2, 3.8 and 7.1 of
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    hashSelectedRangeMax,
    /// This Information Element contains a boolean value that is TRUE if
    /// the output from this hash Selector has been configured to be
    /// included in the packet report as a packet digest, else FALSE.See also Sections 6.2, 3.8 and 7.1 of
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    hashDigestOutput,
    /// This Information Element specifies the initialiser value to the
    /// hash function.See also Sections 6.2, 3.8 and 7.1 of
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    hashInitialiserValue,
    /// The name of a selector identified by a selectorID.  Globally
    /// unique per Metering Process.
    ///
    selectorName,
    /// This Information Element specifies the upper limit of a confidence
    /// interval.  It is used to provide an accuracy statement for an
    /// estimated value.  The confidence limits define the range in which
    /// the real value is assumed to be with a certain probability p.
    /// Confidence limits always need to be associated with a confidence
    /// level that defines this probability p.  Please note that a
    /// confidence interval only provides a probability that the real
    /// value lies within the limits.  That means the real value can lie
    /// outside the confidence limits.The upperCILimit, lowerCILimit, and confidenceLevel Information
    /// Elements should all be used in an Options Template scoped to the
    /// observation to which they refer.  See Section 3.4.2.1 of the IPFIX
    /// protocol documentNote that the upperCILimit, lowerCILimit, and confidenceLevel are
    /// all required to specify confidence, and should be disregarded
    /// unless all three are specified together.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    upperCILimit,
    /// This Information Element specifies the lower limit of a confidence
    /// interval.  For further information, see the description of
    /// upperCILimit.The upperCILimit, lowerCILimit, and confidenceLevel Information
    /// Elements should all be used in an Options Template scoped to the
    /// observation to which they refer.  See Section 3.4.2.1 of the IPFIX
    /// protocol documentNote that the upperCILimit, lowerCILimit, and confidenceLevel are
    /// all required to specify confidence, and should be disregarded
    /// unless all three are specified together.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    lowerCILimit,
    /// This Information Element specifies the confidence level.  It is
    /// used to provide an accuracy statement for estimated values.  The
    /// confidence level provides the probability p with which the real
    /// value lies within a given range.  A confidence level always needs
    /// to be associated with confidence limits that define the range in
    /// which the real value is assumed to be.The upperCILimit, lowerCILimit, and confidenceLevel Information
    /// Elements should all be used in an Options Template scoped to the
    /// observation to which they refer.  See Section 3.4.2.1 of the IPFIX
    /// protocol documentNote that the upperCILimit, lowerCILimit, and confidenceLevel are
    /// all required to specify confidence, and should be disregarded
    /// unless all three are specified together.
    ///
    /// Reference: [RFC5477](https://datatracker.ietf.org/doc/html/rfc5477)
    confidenceLevel,
    /// A description of the abstract data type of an IPFIX information element.
    /// These are taken from the abstract data types defined in Section 3.1 of
    /// the IPFIX Information ModelThe
    ///
    /// Reference: [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    informationElementDataType,
    /// A UTF-8
    ///
    /// Reference: [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    informationElementDescription,
    /// A UTF-8
    ///
    /// Reference: [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
    informationElementName,
    /// Contains the inclusive low end of the range of
    /// acceptable values for an Information Element.
    ///
    /// Reference: [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
    informationElementRangeBegin,
    /// Contains the inclusive high end of the range of
    /// acceptable values for an Information Element.
    ///
    /// Reference: [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
    informationElementRangeEnd,
    /// A description of the semantics of an IPFIX Information
    /// Element. These are taken from the data type semantics defined
    /// in Section 3.2 of the IPFIX Information ModelThe
    ///
    /// Reference: [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    informationElementSemantics,
    /// A description of the units of an IPFIX Information Element.
    /// These correspond to the units implicitly defined in the Information
    /// Element definitions in Section 5 of the IPFIX Information ModelThese types are registered in the
    ///
    /// Reference: [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
    /// Reference: [RFC Errata 1822](https://www.rfc-editor.org/errata_search.php?eid=1822)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    informationElementUnits,
    /// A private enterprise number, as assigned by IANA.
    /// Within the context of an Information Element Type record, this
    /// element can be used along with the informationElementId element to
    /// scope properties to a specific Information Element.  To export
    /// type information about an IANA-assigned Information Element, set
    /// the privateEnterpriseNumber to 0, or do not export the
    /// privateEnterpriseNumber in the type record.  To export type
    /// information about an enterprise-specific Information Element,
    /// export the enterprise number in privateEnterpriseNumber, and
    /// export the Information Element number with the Enterprise bit
    /// cleared in informationElementId.  The Enterprise bit in the
    /// associated informationElementId Information Element MUST be
    /// ignored by the Collecting Process.
    ///
    /// Reference: [RFC5610](https://datatracker.ietf.org/doc/html/rfc5610)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    privateEnterpriseNumber,
    /// Instance Identifier of the interface to a Virtual Station. A Virtual
    /// Station is an end station instance: it can be a virtual machine or a
    /// physical host.
    ///
    virtualStationInterfaceId,
    /// Name of the interface to a Virtual Station. A Virtual Station is an end station
    /// instance: it can be a virtual machine or a physical host.
    ///
    virtualStationInterfaceName,
    /// Unique Identifier of a Virtual Station. A Virtual Station is an end station
    /// instance: it can be a virtual machine or a physical host.
    ///
    virtualStationUUID,
    /// Name of a Virtual Station. A Virtual Station is an end station
    /// instance: it can be a virtual machine or a physical host.
    ///
    virtualStationName,
    /// Identifier of a layer 2 network segment in an overlay network.
    /// The most significant byte identifies the layer 2 network
    /// overlay network encapsulation type:0x00 reserved0x01 VxLAN0x02 NVGREThe three lowest significant bytes
    /// hold the value of the layer 2
    /// overlay network segment identifier.For example:- a 24 bit segment ID VXLAN Network
    /// Identifier (VNI)- a 24 bit Tenant Network Identifier
    /// (TNI) for NVGRE
    ///
    layer2SegmentId,
    /// The number of layer 2 octets since the previous report (if any) in
    /// incoming packets for this Flow at the Observation Point.  The
    /// number of octets includes layer 2 header(s) and layer 2 payload.
    /// # memo: layer 2 version of octetDeltaCount (field #1)
    ///
    layer2OctetDeltaCount,
    /// The total number of layer 2 octets in incoming packets for this
    /// Flow at the Observation Point since the Metering Process
    /// (re-)initialization for this Observation Point.  The number of
    /// octets includes layer 2 header(s) and layer 2 payload.
    /// # memo: layer 2 version of octetTotalCount (field #85)
    ///
    layer2OctetTotalCount,
    /// The total number of incoming unicast packets metered at the
    /// Observation Point since the Metering Process (re-)initialization
    /// for this Observation Point.
    ///
    ingressUnicastPacketTotalCount,
    /// The total number of incoming multicast packets metered at the
    /// Observation Point since the Metering Process (re-)initialization
    /// for this Observation Point.
    ///
    ingressMulticastPacketTotalCount,
    /// The total number of incoming broadcast packets metered at the
    /// Observation Point since the Metering Process (re-)initialization
    /// for this Observation Point.
    ///
    ingressBroadcastPacketTotalCount,
    /// The total number of incoming unicast packets metered at the
    /// Observation Point since the Metering Process (re-)initialization
    /// for this Observation Point.
    ///
    egressUnicastPacketTotalCount,
    /// The total number of incoming broadcast packets metered at the
    /// Observation Point since the Metering Process (re-)initialization
    /// for this Observation Point.
    ///
    egressBroadcastPacketTotalCount,
    /// The absolute timestamp at which the monitoring interval
    /// started.
    /// A Monitoring interval is the period of time during which the Metering
    /// Process is running.
    ///
    monitoringIntervalStartMilliSeconds,
    /// The absolute timestamp at which the monitoring interval ended.
    /// A Monitoring interval is the period of time during which the Metering
    /// Process is running.
    ///
    monitoringIntervalEndMilliSeconds,
    /// The port number identifying the start of a range of port numbers.
    /// A value of zero indicates that the range start is not specified,
    /// i.e., the range is defined in some other way.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    portRangeStart,
    /// The port number identifying the end of a range of port numbers.
    /// A value of zero indicates that the range end is not specified,
    /// i.e., the range is defined in some other way.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    portRangeEnd,
    /// The step size in a port range. The default step size is 1,
    /// which indicates contiguous ports. A value of zero indicates
    /// that the step size is not specified, ie the range is defined
    /// in some other way.
    ///
    portRangeStepSize,
    /// The number of ports in a port range. A value of zero indicates
    /// that the number of ports is not specified, ie the range is defined
    /// in some other way.
    ///
    portRangeNumPorts,
    /// The IEEE 802 MAC address of a wireless station (STA).
    ///
    staMacAddress,
    /// The IPv4 address of a wireless station (STA).
    ///
    staIPv4Address,
    /// The IEEE 802 MAC address of a wireless access point (WTP).
    ///
    wtpMacAddress,
    /// The type of interface where packets of this Flow are being
    /// received. The value matches the value of managed object 'ifType'.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    ingressInterfaceType,
    /// The type of interface where packets of this Flow are being sent.
    /// The value matches the value of managed object 'ifType'.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    egressInterfaceType,
    /// The RTP sequence number per
    ///
    rtpSequenceNumber,
    /// User name associated with the flow.
    ///
    userName,
    /// An attribute that provides a first level categorization for
    /// each Application ID.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    applicationCategoryName,
    /// An attribute that provides a second level categorization
    /// for each Application ID.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    applicationSubCategoryName,
    /// An attribute that groups multiple Application IDs that
    /// belong to the same networking application.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    applicationGroupName,
    /// The non-conservative count of Original Flows
    /// contributing to this Aggregated Flow.  Non-conservative counts
    /// need not sum to the original count on re-aggregation.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    originalFlowsPresent,
    /// The conservative count of Original Flows whose first
    /// packet is represented within this Aggregated Flow.  Conservative
    /// counts must sum to the original count on re-aggregation.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    originalFlowsInitiated,
    /// The conservative count of Original Flows whose last
    /// packet is represented within this Aggregated Flow.  Conservative
    /// counts must sum to the original count on re-aggregation.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    originalFlowsCompleted,
    /// The count of distinct source IP address values for
    /// Original Flows contributing to this Aggregated Flow, without
    /// regard to IP version.  This Information Element is preferred to
    /// the IP-version-specific counters, unless it is important to
    /// separate the counts by version.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    distinctCountOfSourceIPAddress,
    /// The count of distinct destination IP address values for Original
    /// Flows contributing to this Aggregated Flow, without regard to IP
    /// version. This Information Element is preferred to the version-specific
    /// counters, unless it is important to separate the counts by version.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    distinctCountOfDestinationIPAddress,
    /// The count of distinct source IPv4 address values for
    /// Original Flows contributing to this Aggregated Flow.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    distinctCountOfSourceIPv4Address,
    /// The count of distinct destination IPv4 address values
    /// for Original Flows contributing to this Aggregated Flow.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    distinctCountOfDestinationIPv4Address,
    /// The count of distinct source IPv6 address values for
    /// Original Flows contributing to this Aggregated Flow.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    distinctCountOfSourceIPv6Address,
    /// The count of distinct destination IPv6 address values
    /// for Original Flows contributing to this Aggregated Flow.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    distinctCountOfDestinationIPv6Address,
    /// A description of the method used to distribute the counters
    /// from Contributing Flows into the Aggregated Flow records
    /// described by an associated scope, generally a Template.
    /// The method is deemed to apply to all the non-key Information
    /// Elements in the referenced scope for which value distribution
    /// is a valid operation; if the originalFlowsInitiated and/or
    /// originalFlowsCompleted Information Elements appear in the Template,
    /// they are not subject to this distribution method, as they each infer
    /// their own distribution method. The valueDistributionMethod registry
    /// is intended to list a complete set of possible value distribution methods.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    valueDistributionMethod,
    /// Interarrival jitter as defined in section 6.4.1 of
    ///
    rfc3550JitterMilliseconds,
    /// Interarrival jitter as defined in section 6.4.1 of
    ///
    rfc3550JitterMicroseconds,
    /// Interarrival jitter as defined in section 6.4.1 of
    ///
    rfc3550JitterNanoseconds,
    /// The value of the 1-bit Drop Eligible Indicator (DEI) field of the VLAN tag as
    /// described in 802.1Q-2011 subclause 9.6. In case of a QinQ frame, it represents
    /// the outer tag's DEI field and in case of an IEEE 802.1ad frame it represents
    /// the DEI field of the S-TAG. Note: in earlier versions of 802.1Q the same bit
    /// field in the incoming packet is occupied by the Canonical Format Indicator
    /// (CFI) field, except for S-TAGs.
    ///
    dot1qDEI,
    /// In case of a QinQ frame, it represents the inner tag's Drop Eligible Indicator
    /// (DEI) field and in case of an IEEE 802.1ad frame it represents the DEI field of
    /// the C-TAG.
    ///
    dot1qCustomerDEI,
    /// This Information Element identifies the Intermediate Flow
    /// Selection Process technique (e.g., Filtering, Sampling)
    /// that is applied by the Intermediate Flow Selection Process.
    /// Most of these techniques have parameters. Its configuration
    /// parameter(s) MUST be clearly specified. Further Information
    /// Elements are needed to fully specify packet selection with
    /// these methods and all their parameters. Further method
    /// identifiers may be added to the flowSelectorAlgorithm registry.
    /// It might be necessary to define new Information Elements to
    /// specify their parameters.
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    flowSelectorAlgorithm,
    /// This Information Element specifies the volume in octets of all
    /// Flows that are selected in the Intermediate Flow Selection Process
    /// since the previous report.
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    flowSelectedOctetDeltaCount,
    /// This Information Element specifies the volume in packets of all
    /// Flows that were selected in the Intermediate Flow Selection
    /// Process since the previous report.
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    flowSelectedPacketDeltaCount,
    /// This Information Element specifies the number of Flows that were
    /// selected in the Intermediate Flow Selection Process since the last
    /// report.
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    flowSelectedFlowDeltaCount,
    /// This Information Element specifies the total number of Flows
    /// observed by a Selector, for a specific value of SelectorId.  This
    /// Information Element should be used in an Options Template scoped
    /// to the observation to which it refers.  See Section 3.4.2.1 of the
    /// IPFIX protocol document
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    selectorIDTotalFlowsObserved,
    /// This Information Element specifies the total number of Flows
    /// selected by a Selector, for a specific value of SelectorId.  This
    /// Information Element should be used in an Options Template scoped
    /// to the observation to which it refers.  See Section 3.4.2.1 of the
    /// IPFIX protocol document
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    selectorIDTotalFlowsSelected,
    /// This Information Element specifies the number of Flows that are
    /// consecutively sampled.  A value of 100 means that 100 consecutive
    /// Flows are sampled.  For example, this Information Element may be
    /// used to describe the configuration of a systematic count-based
    /// Sampling Selector.
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    samplingFlowInterval,
    /// This Information Element specifies the number of Flows between two
    /// "samplingFlowInterval"s.  A value of 100 means that the next
    /// interval starts 100 Flows (which are not sampled) after the
    /// current "samplingFlowInterval" is over.  For example, this
    /// Information Element may be used to describe the configuration of a
    /// systematic count-based Sampling Selector.
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    samplingFlowSpacing,
    /// This Information Element specifies the time interval in
    /// microseconds during which all arriving Flows are sampled.  For
    /// example, this Information Element may be used to describe the
    /// configuration of a systematic time-based Sampling Selector.
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    flowSamplingTimeInterval,
    /// This Information Element specifies the time interval in
    /// microseconds between two "flowSamplingTimeInterval"s.  A value of
    /// 100 means that the next interval starts 100 microseconds (during
    /// which no Flows are sampled) after the current
    /// "flowsamplingTimeInterval" is over.  For example, this Information
    /// Element may used to describe the configuration of a systematic
    /// time-based Sampling Selector.
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    flowSamplingTimeSpacing,
    /// This Information Element specifies the Information Elements that
    /// are used by the Hash-based Flow Selector as the Hash Domain.
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    hashFlowDomain,
    /// The number of octets, excluding IP header(s) and Layer 4 transport
    /// protocol header(s), observed for this Flow at the Observation Point
    /// since the previous report (if any).
    ///
    transportOctetDeltaCount,
    /// The number of packets containing at least one octet beyond the IP header(s) and
    /// Layer 4 transport protocol header(s), observed for this Flow at the Observation
    /// Point since the previous report (if any).
    ///
    transportPacketDeltaCount,
    /// The IPv4 address used by the Exporting Process on an
    /// Original Exporter, as seen by the Collecting Process on an IPFIX
    /// Mediator.  Used to provide information about the Original
    /// Observation Points to a downstream Collector.
    ///
    /// Reference: [RFC7119](https://datatracker.ietf.org/doc/html/rfc7119)
    originalExporterIPv4Address,
    /// The IPv6 address used by the Exporting Process on an
    /// Original Exporter, as seen by the Collecting Process on an IPFIX
    /// Mediator.  Used to provide information about the Original
    /// Observation Points to a downstream Collector.
    ///
    /// Reference: [RFC7119](https://datatracker.ietf.org/doc/html/rfc7119)
    originalExporterIPv6Address,
    /// The Observation Domain ID reported by the Exporting
    /// Process on an Original Exporter, as seen by the Collecting Process
    /// on an IPFIX Mediator.  Used to provide information about the
    /// Original Observation Domain to a downstream Collector.  When
    /// cascading through multiple Mediators, this identifies the initial
    /// Observation Domain in the cascade.
    ///
    /// Reference: [RFC7119](https://datatracker.ietf.org/doc/html/rfc7119)
    originalObservationDomainId,
    /// Description: An identifier of an Intermediate Process that is
    /// unique per IPFIX Device. Typically, this Information Element is
    /// used for limiting the scope of other Information Elements. Note
    /// that process identifiers may be assigned dynamically; that is, an
    /// Intermediate Process may be restarted with a different ID.
    ///
    /// Reference: [RFC7119](https://datatracker.ietf.org/doc/html/rfc7119)
    intermediateProcessId,
    /// Description: The total number of received Data Records that the
    /// Intermediate Process did not process since the (re-)initialization
    /// of the Intermediate Process; includes only Data Records not
    /// examined or otherwise handled by the Intermediate Process due to
    /// resource constraints, not Data Records that were examined or
    /// otherwise handled by the Intermediate Process but those that
    /// merely do not contribute to any exported Data Record due to the
    /// operations performed by the Intermediate Process.
    ///
    /// Reference: [RFC7119](https://datatracker.ietf.org/doc/html/rfc7119)
    ignoredDataRecordTotalCount,
    /// This Information Element specifies the type of the selected data
    /// link frame. Data link types are defined in the dataLinkFrameType
    /// registry.Further values may be assigned by IANA. Note that the assigned
    /// values are bits so that multiple observations can be OR'd
    /// together.
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    dataLinkFrameType,
    /// This Information Element specifies the offset of the packet
    /// section (e.g., dataLinkFrameSection, ipHeaderPacketSection,
    /// ipPayloadPacketSection, mplsLabelStackSection, and
    /// mplsPayloadPacketSection).  If this Information Element is
    /// omitted, it defaults to zero (i.e., no offset).If multiple sectionOffset Information Elements are specified
    /// within a single Template, then they apply to the packet section
    /// Information Elements in order: the first sectionOffset applies to
    /// the first packet section, the second to the second, and so on.
    /// Note that the "closest" sectionOffset and packet section
    /// Information Elements within a given Template are not necessarily
    /// related.  If there are fewer sectionOffset Information Elements
    /// than packet section Information Elements, then subsequent packet
    /// section Information Elements have no offset, i.e., a sectionOffset
    /// of zero applies to those packet section Information Elements.  If
    /// there are more sectionOffset Information Elements than the number
    /// of packet section Information Elements, then the additional
    /// sectionOffset Information Elements are meaningless.
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    sectionOffset,
    /// This Information Element specifies the observed length of the
    /// packet section (e.g., dataLinkFrameSection, ipHeaderPacketSection,
    /// ipPayloadPacketSection, mplsLabelStackSection, and
    /// mplsPayloadPacketSection) when padding is used.The packet section may be of a fixed size larger than the
    /// sectionExportedOctets.  In this case, octets in the packet section
    /// beyond the sectionExportedOctets MUST follow the
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    sectionExportedOctets,
    /// This Information Element, which is 16 octets long, represents the
    /// Backbone Service Instance Tag (I-TAG) Tag Control Information
    /// (TCI) field of an Ethernet frame as described in [IEEE802.1Q].  It
    /// encodes the Backbone Service Instance Priority Code Point (I-PCP),
    /// Backbone Service Instance Drop Eligible Indicator (I-DEI), Use Customer Addresses (UCAs),
    /// Backbone Service Instance Identifier (I-SID), Encapsulated
    /// Customer Destination Address (C-DA), Encapsulated Customer Source
    /// Address (C-SA), and reserved fields.  The structure and semantics
    /// within the Tag Control Information field are defined in
    /// [IEEE802.1Q].
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    dot1qServiceInstanceTag,
    /// The value of the 24-bit Backbone Service Instance Identifier
    /// (I-SID) portion of the Backbone Service Instance Tag (I-TAG) Tag
    /// Control Information (TCI) field of an Ethernet frame as described
    /// in [IEEE802.1Q].
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    dot1qServiceInstanceId,
    /// The value of the 3-bit Backbone Service Instance Priority Code
    /// Point (I-PCP) portion of the Backbone Service Instance Tag (I-TAG)
    /// Tag Control Information (TCI) field of an Ethernet frame as
    /// described in [IEEE802.1Q].
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    dot1qServiceInstancePriority,
    /// The value of the Encapsulated Customer Source Address (C-SA)
    /// portion of the Backbone Service Instance Tag (I-TAG) Tag Control
    /// Information (TCI) field of an Ethernet frame as described in
    /// [IEEE802.1Q].
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    dot1qCustomerSourceMacAddress,
    /// The value of the Encapsulated Customer Destination Address (C-DA)
    /// portion of the Backbone Service Instance Tag (I-TAG) Tag Control
    /// Information (TCI) field of an Ethernet frame as described in
    /// [IEEE802.1Q].
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    dot1qCustomerDestinationMacAddress,
    /// The definition of this Information Element is identical to the
    /// definition of the layer2OctetDeltaCount Information Element,
    /// except that it reports a potentially modified value caused by a
    /// middlebox function after the packet passed the Observation Point.This Information Element is the layer 2 version of
    /// postOctetDeltaCount (ElementId #23).
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    postLayer2OctetDeltaCount,
    /// The number of layer 2 octets since the previous report (if any) in
    /// outgoing multicast packets sent for packets of this Flow by a
    /// multicast daemon within the Observation Domain.  This property
    /// cannot necessarily be observed at the Observation Point but may
    /// be retrieved by other means.  The number of octets includes layer
    /// 2 header(s) and layer 2 payload.This Information Element is the layer 2 version of
    /// postMCastOctetDeltaCount (ElementId #20).
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    postMCastLayer2OctetDeltaCount,
    /// The definition of this Information Element is identical to the
    /// definition of the layer2OctetTotalCount Information Element,
    /// except that it reports a potentially modified value caused by a
    /// middlebox function after the packet passed the Observation Point.This Information Element is the layer 2 version of
    /// postOctetTotalCount (ElementId #171).
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    postLayer2OctetTotalCount,
    /// The total number of layer 2 octets in outgoing multicast packets
    /// sent for packets of this Flow by a multicast daemon in the
    /// Observation Domain since the Metering Process (re-)initialization.
    /// This property cannot necessarily be observed at the Observation
    /// Point but may be retrieved by other means.  The number of octets
    /// includes layer 2 header(s) and layer 2 payload.This Information Element is the layer 2 version of
    /// postMCastOctetTotalCount (ElementId #175).
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    postMCastLayer2OctetTotalCount,
    /// Layer 2 length of the smallest packet observed for this Flow.  The
    /// packet length includes the length of the layer 2 header(s) and the
    /// length of the layer 2 payload.This Information Element is the layer 2 version of
    /// minimumIpTotalLength (ElementId #25).
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    minimumLayer2TotalLength,
    /// Layer 2 length of the largest packet observed for this Flow.  The
    /// packet length includes the length of the layer 2 header(s) and the length of the layer
    /// 2 payload.This Information Element is the layer 2 version of
    /// maximumIpTotalLength (ElementId #26).
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    maximumLayer2TotalLength,
    /// The number of layer 2 octets since the previous report (if any) in
    /// packets of this Flow dropped by packet treatment.  The number of
    /// octets includes layer 2 header(s) and layer 2 payload.This Information Element is the layer 2 version of
    /// droppedOctetDeltaCount (ElementId #132).
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    droppedLayer2OctetDeltaCount,
    /// The total number of octets in observed layer 2 packets (including
    /// the layer 2 header) that were dropped by packet treatment since
    /// the (re-)initialization of the Metering Process.This Information Element is the layer 2 version of
    /// droppedOctetTotalCount (ElementId #134).
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    droppedLayer2OctetTotalCount,
    /// The total number of octets in observed layer 2 packets (including
    /// the layer 2 header) that the Metering Process did not process
    /// since the (re-)initialization of the Metering Process.This Information Element is the layer 2 version of
    /// ignoredOctetTotalCount (ElementId #165).
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    ignoredLayer2OctetTotalCount,
    /// The total number of octets in observed layer 2 packets (including
    /// the layer 2 header) that the Metering Process did not process
    /// since the (re-)initialization of the Metering Process.This Information Element is the layer 2 version of
    /// notSentOctetTotalCount (ElementId #168).
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    notSentLayer2OctetTotalCount,
    /// The sum of the squared numbers of layer 2 octets per incoming
    /// packet since the previous report (if any) for this Flow at the
    /// Observation Point.  The number of octets includes layer 2
    /// header(s) and layer 2 payload.This Information Element is the layer 2 version of
    /// octetDeltaSumOfSquares (ElementId #198).
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    layer2OctetDeltaSumOfSquares,
    /// The total sum of the squared numbers of layer 2 octets in incoming
    /// packets for this Flow at the Observation Point since the Metering
    /// Process (re-)initialization for this Observation Point.  The
    /// number of octets includes layer 2 header(s) and layer 2 payload.This Information Element is the layer 2 version of
    /// octetTotalSumOfSquares (ElementId #199).
    ///
    /// Reference: [RFC7133](https://datatracker.ietf.org/doc/html/rfc7133)
    layer2OctetTotalSumOfSquares,
    /// The number of incoming layer 2 frames since the
    /// previous report (if any) for this Flow at the
    /// Observation Point.
    ///
    layer2FrameDeltaCount,
    /// The total number of incoming layer 2 frames
    /// for this Flow at the Observation Point since
    /// the Metering Process (re-)initialization for
    /// this Observation Point.
    ///
    layer2FrameTotalCount,
    /// The destination IPv4 address of the PSN tunnel carrying the pseudowire.
    ///
    pseudoWireDestinationIPv4Address,
    /// The total number of observed layer 2 frames that the Metering Process
    /// did not process since the (re-)initialization of the Metering Process.
    /// This Information Element is the layer 2 version of ignoredPacketTotalCount (ElementId #164).
    ///
    ignoredLayer2FrameTotalCount,
    /// An IPFIX Information Element that denotes that the
    /// integer value of a MIB object will be exported.  The MIB Object
    /// Identifier ("mibObjectIdentifier") for this field MUST be exported
    /// in a MIB Field Option or via another means.  This Information
    /// Element is used for MIB objects with the Base syntax of Integer32
    /// and INTEGER with IPFIX reduced-size encoding used as required.
    /// The value is encoded as per the standard IPFIX Abstract Data Type
    /// of signed32.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectValueInteger,
    /// An IPFIX Information Element that denotes that an
    /// Octet String or Opaque value of a MIB object will be exported.
    /// The MIB Object Identifier ("mibObjectIdentifier") for this field
    /// MUST be exported in a MIB Field Option or via another means.  This
    /// Information Element is used for MIB objects with the Base syntax
    /// of OCTET STRING and Opaque.  The value is encoded as per the
    /// standard IPFIX Abstract Data Type of octetArray.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectValueOctetString,
    /// An IPFIX Information Element that denotes that an
    /// Object Identifier or OID value of a MIB object will be exported.
    /// The MIB Object Identifier ("mibObjectIdentifier") for this field
    /// MUST be exported in a MIB Field Option or via another means.  This
    /// Information Element is used for MIB objects with the Base syntax
    /// of OBJECT IDENTIFIER.  Note: In this case, the
    /// "mibObjectIdentifier" defines which MIB object is being exported,
    /// and the "mibObjectValueOID" field will contain the OID value of
    /// that MIB object.  The mibObjectValueOID Information Element is
    /// encoded as ASN.1/BER [X.690] in an octetArray.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectValueOID,
    /// An IPFIX Information Element that denotes that a set
    /// of Enumerated flags or bits from a MIB object will be exported.
    /// The MIB Object Identifier ("mibObjectIdentifier") for this field
    /// MUST be exported in a MIB Field Option or via another means.  This
    /// Information Element is used for MIB objects with the Base syntax
    /// of BITS.  The flags or bits are encoded as per the standard IPFIX
    /// Abstract Data Type of octetArray, with sufficient length to
    /// accommodate the required number of bits.  If the number of bits is
    /// not an integer multiple of octets, then the most significant bits
    /// at the end of the octetArray MUST be set to 0.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectValueBits,
    /// An IPFIX Information Element that denotes that the
    /// IPv4 address value of a MIB object will be exported.  The MIB
    /// Object Identifier ("mibObjectIdentifier") for this field MUST be
    /// exported in a MIB Field Option or via another means.  This
    /// Information Element is used for MIB objects with the Base syntax
    /// of IpAddress.  The value is encoded as per the standard IPFIX
    /// Abstract Data Type of ipv4Address.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectValueIPAddress,
    /// An IPFIX Information Element that denotes that the
    /// counter value of a MIB object will be exported.  The MIB Object
    /// Identifier ("mibObjectIdentifier") for this field MUST be exported
    /// in a MIB Field Option or via another means.  This Information
    /// Element is used for MIB objects with the Base syntax of Counter32
    /// or Counter64 with IPFIX reduced-size encoding used as required.
    /// The value is encoded as per the standard IPFIX Abstract Data Type
    /// of unsigned64.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectValueCounter,
    /// An IPFIX Information Element that denotes that the
    /// Gauge value of a MIB object will be exported.  The MIB Object
    /// Identifier ("mibObjectIdentifier") for this field MUST be exported
    /// in a MIB Field Option or via another means.  This Information
    /// Element is used for MIB objects with the Base syntax of Gauge32.
    /// The value is encoded as per the standard IPFIX Abstract Data Type
    /// of unsigned32.  This value represents a non-negative integer that
    /// may increase or decrease but that shall never exceed a maximum
    /// value or fall below a minimum value.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectValueGauge,
    /// An IPFIX Information Element that denotes that the
    /// TimeTicks value of a MIB object will be exported.  The MIB Object
    /// Identifier ("mibObjectIdentifier") for this field MUST be exported
    /// in a MIB Field Option or via another means.  This Information
    /// Element is used for MIB objects with the Base syntax of TimeTicks.
    /// The value is encoded as per the standard IPFIX Abstract Data Type
    /// of unsigned32.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectValueTimeTicks,
    /// An IPFIX Information Element that denotes that an
    /// unsigned integer value of a MIB object will be exported.  The MIB
    /// Object Identifier ("mibObjectIdentifier") for this field MUST be
    /// exported in a MIB Field Option or via another means.  This
    /// Information Element is used for MIB objects with the Base syntax
    /// of unsigned32 with IPFIX reduced-size encoding used as required.
    /// The value is encoded as per the standard IPFIX Abstract Data Type
    /// of unsigned32.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectValueUnsigned,
    /// An IPFIX Information Element that denotes that a
    /// complete or partial conceptual table will be exported.  The MIB
    /// Object Identifier ("mibObjectIdentifier") for this field MUST be
    /// exported in a MIB Field Option or via another means.  This
    /// Information Element is used for MIB objects with a syntax of
    /// SEQUENCE OF.  This is encoded as a subTemplateList of mibObjectValue
    /// Information Elements.  The Template specified in the
    /// subTemplateList MUST be an Options Template and MUST include all
    /// the objects listed in the INDEX clause as Scope Fields.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectValueTable,
    /// An IPFIX Information Element that denotes that a
    /// single row of a conceptual table will be exported.  The MIB Object
    /// Identifier ("mibObjectIdentifier") for this field MUST be exported
    /// in a MIB Field Option or via another means.  This Information
    /// Element is used for MIB objects with a syntax of SEQUENCE.  This
    /// is encoded as a subTemplateList of mibObjectValue Information
    /// Elements.  The subTemplateList exported MUST contain exactly one
    /// row (i.e., one instance of the subTemplate).  The Template
    /// specified in the subTemplateList MUST be an Options Template and
    /// MUST include all the objects listed in the INDEX clause as Scope
    /// Fields.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectValueRow,
    /// An IPFIX Information Element that denotes that a MIB
    /// Object Identifier (MIB OID) is exported in the (Options)
    /// Template Record.  The mibObjectIdentifier Information Element
    /// contains the OID assigned to the MIB object type definition
    /// encoded as ASN.1/BER [X.690].
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectIdentifier,
    /// A non-negative sub-identifier of an Object Identifier (OID).
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibSubIdentifier,
    /// A set of bit fields that is used for marking the
    /// Information Elements of a Data Record that serve as INDEX MIB
    /// objects for an indexed columnar MIB object.  Each bit represents
    /// an Information Element in the Data Record, with the n-th least
    /// significant bit representing the n-th Information Element.  A bit
    /// set to 1 indicates that the corresponding Information Element is
    /// an index of the columnar object represented by the mibObjectValue.
    /// A bit set to 0 indicates that this is not the case.If the Data Record contains more than 64 Information Elements, the
    /// corresponding Template SHOULD be designed such that all index
    /// fields are among the first 64 Information Elements, because the
    /// mibIndexIndicator only contains 64 bits.  If the Data Record
    /// contains less than 64 Information Elements, then the extra bits in
    /// the mibIndexIndicator for which no corresponding Information
    /// Element exists MUST have the value 0 and must be disregarded by
    /// the Collector.  This Information Element may be exported with
    /// IPFIX reduced-size encoding.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibIndexIndicator,
    /// Indicates when in the lifetime of the Flow the MIB
    /// value was retrieved from the MIB for a mibObjectIdentifier.
    /// This is used to indicate if the value exported was collected
    /// from the MIB closer to Flow creation or Flow export time and
    /// refers to the Timestamp fields included in the same Data
    /// Record.This field SHOULD be used when exporting a mibObjectValue that
    /// specifies counters or statistics. If the MIB value was sampled
    /// by SNMP prior to the IPFIX Metering Process or Exporting
    /// Process retrieving the value (i.e., the data is already stale)
    /// and it is important to know the exact sampling time, then an
    /// additional observationTime* element should be paired with the
    /// OID using IPFIX Structured DataValues are listed in the mibCaptureTimeSemantics registry.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    mibCaptureTimeSemantics,
    /// A mibContextEngineID that specifies the SNMP engine
    /// ID for a MIB field being exported over IPFIX.  Definition as per
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibContextEngineID,
    /// An Information Element that denotes that a MIB
    /// context name is specified for a MIB field being exported over
    /// IPFIX.  Reference
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibContextName,
    /// The name (called a descriptor in
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectName,
    /// The value of the DESCRIPTION clause of a MIB object
    /// type definition.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectDescription,
    /// The value of the SYNTAX clause of a MIB object type
    /// definition, which may include a textual convention or sub-typing.
    /// See
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibObjectSyntax,
    /// The textual name of the MIB module that defines a MIB
    /// object.
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    mibModuleName,
    /// The International Mobile Subscription Identity (IMSI). The
    /// IMSI is a decimal digit string with up to a maximum of 15 ASCII/UTF-8
    /// encoded digits (0x30 - 0x39).
    ///
    mobileIMSI,
    /// The Mobile Station International Subscriber Directory Number
    /// (MSISDN). The MSISDN is a decimal digit string with up to a maximum of 15
    /// ASCII/UTF-8 encoded digits (0x30 - 0x39).
    ///
    mobileMSISDN,
    /// The HTTP Response Status Code, as defined in
    /// section 6 of
    ///
    httpStatusCode,
    /// This Information Element contains the maximum
    /// number of IP source transport ports that can be used by an end
    /// user when sending IP packets; each user is associated with one
    /// or more (source) IPv4 or IPv6 addresses. This Information
    /// Element is particularly useful in address-sharing deployments
    /// that adhere to REQ-4 of
    ///
    /// Reference: [RFC8045](https://datatracker.ietf.org/doc/html/rfc8045)
    /// Reference: [RFC Errata 5009](https://www.rfc-editor.org/errata_search.php?eid=5009)
    sourceTransportPortsLimit,
    /// The HTTP request method, as defined in section 4 of
    ///
    httpRequestMethod,
    /// The HTTP request host, as defined in section 5.4 of
    ///
    httpRequestHost,
    /// The HTTP request target, as defined in section 2 of
    ///
    httpRequestTarget,
    /// The version of an HTTP/1.1 message as indicated by the
    /// HTTP-version field, defined in section 2.6 of
    ///
    httpMessageVersion,
    /// This Information Element uniquely identifies an Instance of the NAT
    /// that runs on a NAT middlebox function after the packet passes the
    /// Observation Point. natInstanceID is defined in
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    natInstanceID,
    /// This Information Element represents the internal address realm where
    /// the packet is originated from or destined to. By definition, a NAT
    /// mapping can be created from two address realms, one from internal and
    /// one from external. Realms are implementation dependent and can represent
    /// a Virtual Routing and Forwarding (VRF) ID, a VLAN ID, or some unique
    /// identifier. Realms are optional and, when left unspecified, would mean
    /// that the external and internal realms are the same.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    internalAddressRealm,
    /// This Information Element represents the external address realm where
    /// the packet is originated from or destined to.
    /// 
    /// See the internalAddressRealm IE for the detailed definition.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    externalAddressRealm,
    /// This Information Element identifies the type of a NAT Quota Exceeded event.
    /// Values for this Information Element are listed in the "NAT Quota Exceeded
    /// Event Type" registry.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    natQuotaExceededEvent,
    /// This Information Element identifies a type of a NAT Threshold event.
    /// Values for this Information Element are listed in the "NAT Threshold
    /// Event Type" registry.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-FIXES-12](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-fixes-12)
    natThresholdEvent,
    /// The HTTP User-Agent header field as defined in section 5.5.3 of
    ///
    httpUserAgent,
    /// The HTTP Content-Type header field as defined in section 3.1.1.5 of
    ///
    httpContentType,
    /// The HTTP reason phrase as defined in section 6.1 of of
    ///
    httpReasonPhrase,
    /// This element represents the maximum session entries that
    /// can be created by the NAT device.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    maxSessionEntries,
    /// This element represents the maximum BIB entries that can
    /// be created by the NAT device.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    maxBIBEntries,
    /// This element represents the maximum NAT entries that can
    /// be created per user by the NAT device.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    maxEntriesPerUser,
    /// This element represents the maximum subscribers or
    /// maximum hosts that are allowed by the NAT device.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    maxSubscribers,
    /// This element represents the maximum fragments that the
    /// NAT device can store for reassembling the packet.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    maxFragmentsPendingReassembly,
    /// This element represents the high threshold value of the
    /// number of public IP addresses in the address pool.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    addressPoolHighThreshold,
    /// This element represents the low threshold value of the
    /// number of public IP addresses in the address pool.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    addressPoolLowThreshold,
    /// This element represents the high threshold value of the
    /// number of address and port mappings.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    addressPortMappingHighThreshold,
    /// This element represents the low threshold value of the
    /// number of address and port mappings.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    addressPortMappingLowThreshold,
    /// This element represents the high threshold value of the
    /// number of address and port mappings that a single user is allowed to
    /// create on a NAT device.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    addressPortMappingPerUserHighThreshold,
    /// This element represents the high threshold value of the
    /// number of address and port mappings that a single user is allowed to
    /// create on a NAT device in a paired address pooling behavior.
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    globalAddressMappingHighThreshold,
    /// VPN ID in the format specified by
    ///
    vpnIdentifier,
    /// BGP community as defined in
    ///
    /// Reference: [RFC8549](https://datatracker.ietf.org/doc/html/rfc8549)
    bgpCommunity,
    /// basicList of zero or more bgpCommunity IEs, containing the BGP
    /// communities corresponding with source IP address of a specific flow
    ///
    /// Reference: [RFC8549](https://datatracker.ietf.org/doc/html/rfc8549)
    bgpSourceCommunityList,
    /// basicList of zero or more bgpCommunity IEs, containing the BGP
    /// communities corresponding with destination IP address of a specific flow
    ///
    /// Reference: [RFC8549](https://datatracker.ietf.org/doc/html/rfc8549)
    bgpDestinationCommunityList,
    /// BGP Extended Community as defined in
    ///
    /// Reference: [RFC8549](https://datatracker.ietf.org/doc/html/rfc8549)
    bgpExtendedCommunity,
    /// basicList of zero or more bgpExtendedCommunity IEs,
    /// containing the BGP Extended Communities corresponding with source
    /// IP address of a specific flow
    ///
    /// Reference: [RFC8549](https://datatracker.ietf.org/doc/html/rfc8549)
    bgpSourceExtendedCommunityList,
    /// basicList of zero or more bgpExtendedCommunity IEs,
    /// containing the BGP Extended Communities corresponding
    /// with destination IP address of a specific flow
    ///
    /// Reference: [RFC8549](https://datatracker.ietf.org/doc/html/rfc8549)
    bgpDestinationExtendedCommunityList,
    /// BGP Large Community as defined in
    ///
    /// Reference: [RFC8549](https://datatracker.ietf.org/doc/html/rfc8549)
    bgpLargeCommunity,
    /// basicList of zero or more bgpLargeCommunity IEs,
    /// containing the BGP Large Communities corresponding
    /// with source IP address of a specific flow
    ///
    /// Reference: [RFC8549](https://datatracker.ietf.org/doc/html/rfc8549)
    bgpSourceLargeCommunityList,
    /// basicList of zero or more bgpLargeCommunity IEs,
    /// containing the BGP Large Communities corresponding
    /// with destination IP address of a specific flow
    ///
    /// Reference: [RFC8549](https://datatracker.ietf.org/doc/html/rfc8549)
    bgpDestinationLargeCommunityList,
    /// The 8-bit Flags field defined in the SRH (Section 2 of
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    srhFlagsIPv6,
    /// The 16-bit Tag field defined in the SRH (Section 2 of
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    srhTagIPv6,
    /// The 128-bit IPv6 address that represents an SRv6 segment.
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    srhSegmentIPv6,
    /// The 128-bit IPv6 address that represents the active SRv6 segment.
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    srhActiveSegmentIPv6,
    /// The ordered basicList
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    srhSegmentIPv6BasicList,
    /// The SRv6 Segment List as defined in Section 2 of
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    srhSegmentIPv6ListSection,
    /// The 8-bit unsigned integer defining the number of segments
    /// remaining to reach the end of the Segment List from the SRH.
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    srhSegmentsIPv6Left,
    /// The SRH and its TLVs as defined in Section 2 of
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    srhIPv6Section,
    /// The designator of the routing protocol or PCEP
    /// extension where the active SRv6 segment has been learned
    /// from.  Values for this Information Element are listed in the
    /// "IPFIX IPv6 SRH Segment Type (Value 500)” subregistry; see
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    srhIPv6ActiveSegmentType,
    /// The length of the SRH segment IPv6 locator specified as the number of significant
    /// bits. Together with srhSegmentIPv6, it enables the calculation of the SRv6 Locator.
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    /// Reference: [RFC Errata 7728](https://www.rfc-editor.org/errata_search.php?eid=7728)
    srhSegmentIPv6LocatorLength,
    /// The 16-bit unsigned integer that represents an SRv6 Endpoint behavior as per Section 4 of
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    srhSegmentIPv6EndpointBehavior,
    /// The checksum in the transport header. For the transport protocols UDP and TCP, this is the
    /// checksum given in the respective header. This field MAY also be used for future transport
    /// protocols that have 16-bit checksum values.
    ///
    transportChecksum,
    /// This Information Element carries a series of n octets from the ICMP header of a sampled
    /// packet, starting sectionOffset octets into the ICMP header.However, if no sectionOffset field corresponding to this Information Element is present,
    /// then a sectionOffset of zero applies, and the octets MUST be from the start of the ICMP header.With sufficient length, this element also reports octets from the ICMP payload. However,
    /// full packet capture of arbitrary packet streams is explicitly out of scope per
    /// the Security Considerations sections ofThe sectionExportedOctets expresses how much data was exported, while the remainder is padding.When the sectionExportedOctets field corresponding to this Information Element exists,
    /// this Information Element MAY have a fixed length and MAY be padded, or it MAY have a variable length.When the sectionExportedOctets field corresponding to this Information Element does not exist,
    /// this Information Element SHOULD have a variable length and MUST NOT be padded. In this case,
    /// the size of the exported section may be constrained due to limitations in the IPFIX protocol.
    ///
    icmpHeaderPacketSection,
    /// 8-bit flags field indicating the version of GTP-U protocol, protocol type and
    /// presence of extension header, sequence number and N-PDU number defined in
    /// Section 5.1 of the 3GPP specification
    ///
    /// Reference: [RFC Draft DRAFT-VOYERSRIRAM-OPSAWG-IPFIX-GTPU-05](https://datatracker.ietf.org/doc/html/draft-voyersriram-opsawg-ipfix-gtpu-05)
    gtpuFlags,
    /// 8-bit Message type field indicating the type of GTP-U message
    /// defined in section 5.1 of the 3GPP specification
    ///
    /// Reference: [RFC Draft DRAFT-VOYERSRIRAM-OPSAWG-IPFIX-GTPU-05](https://datatracker.ietf.org/doc/html/draft-voyersriram-opsawg-ipfix-gtpu-05)
    gtpuMsgType,
    /// 32-bit tunnel endpoint identifier field defined in
    /// section 5.1 of the 3GPP specification
    ///
    /// Reference: [RFC Draft DRAFT-VOYERSRIRAM-OPSAWG-IPFIX-GTPU-05](https://datatracker.ietf.org/doc/html/draft-voyersriram-opsawg-ipfix-gtpu-05)
    gtpuTEid,
    /// 16-bit sequence number field defined in section 5.1 (Optional Fields)
    /// of the 3GPP specification
    ///
    /// Reference: [RFC Draft DRAFT-VOYERSRIRAM-OPSAWG-IPFIX-GTPU-05](https://datatracker.ietf.org/doc/html/draft-voyersriram-opsawg-ipfix-gtpu-05)
    gtpuSequenceNum,
    /// 6-bit QoS flow identifier field defined in PDU Session
    /// Container extension header of GTP-U.  This is defined in section
    /// 5.5.3.3 of the 3GPP specificationThe basic encoding is 8 bits.  The layout of basic encoding is as
    /// follows:
    /// 
    /// ```text
    /// MSB -   0     1    2    3    4    5    6    7   - LSB
    /// +----+----+----+----+----+----+----+----+
    /// |Reserved |       6 bit QFI value       |
    /// +----+----+----+----+----+----+----+----+
    /// 
    /// Examples:
    /// value : 0x08
    /// binary: 00001000
    /// decode: 001000 - QFI value
    /// value : 0x3e
    /// binary: 00111110
    /// decode: 111110 - QFI value
    /// ```
    /// 
    ///
    /// Reference: [RFC Draft DRAFT-VOYERSRIRAM-OPSAWG-IPFIX-GTPU-05](https://datatracker.ietf.org/doc/html/draft-voyersriram-opsawg-ipfix-gtpu-05)
    gtpuQFI,
    /// 4-bit PDU type field defined in PDU Session Container
    /// extension header of GTP-U.  This is defined in section 5.5.3 of
    /// the 3GPP specificationThe basic encoding is 8 bits. The layout of basic encoding is as
    /// follows:
    /// 
    /// ```text
    /// MSB -   0     1    2    3    4    5    6    7   - LSB
    /// +----+----+----+----+----+----+----+----+
    /// |     Reserved      |  4 bit PDU Type   |
    /// +----+----+----+----+----+----+----+----+
    /// Examples:
    /// value : 0x01
    /// binary: 00000001
    /// decode: 0001 - PDU Type value
    /// ```
    /// 
    ///
    /// Reference: [RFC Draft DRAFT-VOYERSRIRAM-OPSAWG-IPFIX-GTPU-05](https://datatracker.ietf.org/doc/html/draft-voyersriram-opsawg-ipfix-gtpu-05)
    gtpuPduType,
    /// Ordered basicList
    ///
    bgpSourceAsPathList,
    /// Ordered basicList
    ///
    bgpDestinationAsPathList,
    /// Type of an IPv6 extension header observed in at least one packet of this Flow.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    ipv6ExtensionHeaderType,
    /// The number of consecutive occurrences of the same extension header type in a Flow.
    /// 
    /// This IE is reported, e.g., in the ipv6ExtensionHeaderTypeCountList IE.
    /// 
    /// The type of the extension header is provided in the ipv6ExtensionHeaderType IE.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    ipv6ExtensionHeaderCount,
    /// IPv6 extension headers observed in packets of this Flow. The information is encoded in a
    /// set of bit fields. For each IPv6 extension header, there is a bit in this set. The bit is
    /// set to 1 if any observed packet of this Flow contains the corresponding IPv6 extension
    /// header. Otherwise, if no observed packet of this Flow contains the respective IPv6
    /// extension header, the value of the corresponding bit is 0.The IPv6 extension header associated with each bit is provided inThe "No Next Header" (bit 2) value (Section 4.7 ofExtension headers observed in a Flow with varying extension header chain MUST NOT be grouped in
    /// the ipv6ExtensionHeadersFull IE if the ipv6ExtensionHeaderChainLengthList IE is also present.If the ipv6ExtensionHeaderChainLengthList IE is not present, then extension headers observed in
    /// a Flow with varying extension header chain MAY be grouped in one single ipv6ExtensionHeadersFull
    /// IE or be exported in separate ipv6ExtensionHeadersFull IEs, one for each extension header chain.The ipv6ExtensionHeadersFull IE MUST NOT be exported if ipv6ExtensionHeaderTypeCountList IE is
    /// also present because of the overlapping scopes between these two IEs.The value of ipv6ExtensionHeadersFull IE may be encoded in fewer octets per the guidelines in
    /// Section 6.2 of
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    ipv6ExtensionHeadersFull,
    /// As per Section 4.1 ofThis IE is a subTemplateList of ipv6ExtensionHeaderType and ipv6ExtensionHeaderCount IEs.Each header chain in Flow with varying extension header chain MUST be exported in a separate IE.The same extension header type may appear several times in an ipv6ExtensionHeaderTypeCountList IE.
    /// For example, if an IPv6 packet of a Flow includes a Hop-by-Hop Options header, a Destination Options
    /// header, a Fragment header, and Destination Options header, the ipv6ExtensionHeaderTypeCountList IE
    /// will report:* the count of Hop-by-Hop Options headers,* the occurrences of the Destination Options headers that are observed before a Fragment header,* the occurrences of the Fragment headers, and* the occurrences of the Destination Options headers that are observed right after a Fragment header.If an implementation determines that an observed packet of a Flow includes an extension header
    /// (including an extension header that it does not support), then the exact observed code of that
    /// extension header MUST be echoed in the ipv6ExtensionHeaderTypeCountList IE. How an implementation
    /// disambiguates between unknown upper-layer protocols vs. extension headers is not IPFIX-specific.
    /// Refer, for example, to Section 2.2 of
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    ipv6ExtensionHeaderTypeCountList,
    /// When set to "false", this IE indicates that the exported extension headers information
    /// (e.g., ipv6ExtensionHeadersFull or ipv6ExtensionHeaderTypeCountList) does not match the
    /// full enclosed extension headers, but only up to a limit that is typically set by hardware
    /// or software.When set to "true", this IE indicates that the exported extension header information
    /// matches the full enclosed extension headers.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    ipv6ExtensionHeadersLimit,
    /// In theory, there are no limits on the number of IPv6 extension headers that may be present in a
    /// packet other than the path MTU. However, it was regularly reported that IPv6 packets with
    /// extension headers are often dropped in the Internet (e.g.,As discussed in Section 1.2 ofThe ipv6ExtensionHeadersChainLength IE is used to report, in octets, the length of an extension
    /// header chain observed in a Flow. The length is the sum of the length of all extension headers of
    /// the chain. Exporting such information might help identifying root causes of performance degradation,
    /// including packet drops.Each header chain length of a Flow with varying extension header chain MUST be exported in a separate
    /// ipv6ExtensionHeadersChainLength IE.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    ipv6ExtensionHeadersChainLength,
    /// This IE is used to report the chains and their length as observed in a Flow with varying extension header chain.This IE is a subTemplateList of ipv6ExtensionHeadersFull and ipv6ExtensionHeadersChainLength IEs.If several extension header chains are observed in a Flow, each header chain MUST be exported in a separate
    /// ipv6ExtensionHeaderChainLengthList IE.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    ipv6ExtensionHeaderChainLengthList,
    /// TCP options in packets of this Flow. The information is encoded in a set of bit fields.
    /// For each TCP option, there is a bit in this set. The bit is set to 1 if any observed
    /// packet of this Flow contains the corresponding TCP option. Otherwise, if no observed
    /// packet of this Flow contains the respective TCP option, the value of the corresponding
    /// bit is 0.Options are mapped to bits according to their option numbers. TCP option Kind 0
    /// corresponds to the least-significant bit in the tcpOptionsFull IE while Kind 255
    /// corresponds to the most-significant bit of the IE. This approach allows an observer
    /// to export any observed TCP option even if it does not support that option and without
    /// requiring updating a mapping table.The value of tcpOptionsFull IE may be encoded in fewer octets per the guidelines in
    /// Section 6.2 ofThe presence of tcpSharedOptionExID16List or tcpSharedOptionExID32List IEs is an indication
    /// that a shared TCP option (Kind=253 or 254) is observed in a Flow. The presence of
    /// tcpSharedOptionExID16List or tcpSharedOptionExID32List IEs takes precedence over setting the
    /// corresponding bits in the tcpOptionsFull IE for the same Flow. In order to optimize the use of
    /// the reduced-size encoding in the presence of tcpSharedOptionExID16List or tcpSharedOptionExID32List IEs,
    /// the Exporter MUST NOT set to 1 the shared TCP options (Kind=253 or 254) flags of the tcpOptionsFull IE
    /// that is reported for the same Flow.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    tcpOptionsFull,
    /// Reports an observed 2-byte ExID in a shared TCP option (Kind=253 or 254) in a Flow.A basicList of tcpSharedOptionExID16 is used to report tcpSharedOptionExID16List values.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    tcpSharedOptionExID16,
    /// Reports an observed 4-byte ExID in a shared TCP option (Kind=253 or 254) in a Flow.A basicList of tcpSharedOptionExID32 is used to report tcpSharedOptionExID32List values.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    tcpSharedOptionExID32,
    /// Reports observed 2-byte ExIDs in shared TCP options (Kind=253 or 254) in a Flow.A basicList of tcpSharedOptionExID16 IEs in which each tcpSharedOptionExID16 IE carries an observed 2-byte ExID in a shared option.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    tcpSharedOptionExID16List,
    /// Reports observed 4-byte ExIDs in shared TCP options (Kind=253 or 254) in a Flow.A basicList of tcpSharedOptionExID32 IEs in which each tcpSharedOptionExID32 IE carries an observed 4-byte ExID in a shared option.
    ///
    /// Reference: [RFC Draft RFC-IETF-OPSAWG-IPFIX-TCPO-V6EH-18](https://datatracker.ietf.org/doc/html/RFC-ietf-opsawg-ipfix-tcpo-v6eh-18)
    tcpSharedOptionExID32List,
}

#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum IEError {
    UndefinedIANAIE(u16),
    Nokia(nokia::UndefinedIE),
    NetGauze(netgauze::UndefinedIE),
    Cisco(cisco::UndefinedIE),
    VMWare(vmware::UndefinedIE),
}

impl std::fmt::Display for IEError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UndefinedIANAIE(id) => write!(f, "invalid IE id {id}"),
            Self::Nokia(e) => write!(f, "invalid nokia IE {}", e.0),
            Self::NetGauze(e) => write!(f, "invalid netgauze IE {}", e.0),
            Self::Cisco(e) => write!(f, "invalid cisco IE {}", e.0),
            Self::VMWare(e) => write!(f, "invalid vmware IE {}", e.0),
        }
    }
}

impl std::error::Error for IEError {}

impl TryFrom<(u32, u16)> for IE {
    type Error = IEError;

    fn try_from(value: (u32, u16)) -> Result<Self, Self::Error> {
        let (pen, code) = value;
        match pen {
            0 => {
                match code {
                    1 =>  Ok(IE::octetDeltaCount),
                    2 =>  Ok(IE::packetDeltaCount),
                    3 =>  Ok(IE::deltaFlowCount),
                    4 =>  Ok(IE::protocolIdentifier),
                    5 =>  Ok(IE::ipClassOfService),
                    6 =>  Ok(IE::tcpControlBits),
                    7 =>  Ok(IE::sourceTransportPort),
                    8 =>  Ok(IE::sourceIPv4Address),
                    9 =>  Ok(IE::sourceIPv4PrefixLength),
                    10 =>  Ok(IE::ingressInterface),
                    11 =>  Ok(IE::destinationTransportPort),
                    12 =>  Ok(IE::destinationIPv4Address),
                    13 =>  Ok(IE::destinationIPv4PrefixLength),
                    14 =>  Ok(IE::egressInterface),
                    15 =>  Ok(IE::ipNextHopIPv4Address),
                    16 =>  Ok(IE::bgpSourceAsNumber),
                    17 =>  Ok(IE::bgpDestinationAsNumber),
                    18 =>  Ok(IE::bgpNextHopIPv4Address),
                    19 =>  Ok(IE::postMCastPacketDeltaCount),
                    20 =>  Ok(IE::postMCastOctetDeltaCount),
                    21 =>  Ok(IE::flowEndSysUpTime),
                    22 =>  Ok(IE::flowStartSysUpTime),
                    23 =>  Ok(IE::postOctetDeltaCount),
                    24 =>  Ok(IE::postPacketDeltaCount),
                    25 =>  Ok(IE::minimumIpTotalLength),
                    26 =>  Ok(IE::maximumIpTotalLength),
                    27 =>  Ok(IE::sourceIPv6Address),
                    28 =>  Ok(IE::destinationIPv6Address),
                    29 =>  Ok(IE::sourceIPv6PrefixLength),
                    30 =>  Ok(IE::destinationIPv6PrefixLength),
                    31 =>  Ok(IE::flowLabelIPv6),
                    32 =>  Ok(IE::icmpTypeCodeIPv4),
                    33 =>  Ok(IE::igmpType),
                    34 =>  Ok(IE::samplingInterval),
                    35 =>  Ok(IE::samplingAlgorithm),
                    36 =>  Ok(IE::flowActiveTimeout),
                    37 =>  Ok(IE::flowIdleTimeout),
                    38 =>  Ok(IE::engineType),
                    39 =>  Ok(IE::engineId),
                    40 =>  Ok(IE::exportedOctetTotalCount),
                    41 =>  Ok(IE::exportedMessageTotalCount),
                    42 =>  Ok(IE::exportedFlowRecordTotalCount),
                    43 =>  Ok(IE::ipv4RouterSc),
                    44 =>  Ok(IE::sourceIPv4Prefix),
                    45 =>  Ok(IE::destinationIPv4Prefix),
                    46 =>  Ok(IE::mplsTopLabelType),
                    47 =>  Ok(IE::mplsTopLabelIPv4Address),
                    48 =>  Ok(IE::samplerId),
                    49 =>  Ok(IE::samplerMode),
                    50 =>  Ok(IE::samplerRandomInterval),
                    51 =>  Ok(IE::classId),
                    52 =>  Ok(IE::minimumTTL),
                    53 =>  Ok(IE::maximumTTL),
                    54 =>  Ok(IE::fragmentIdentification),
                    55 =>  Ok(IE::postIpClassOfService),
                    56 =>  Ok(IE::sourceMacAddress),
                    57 =>  Ok(IE::postDestinationMacAddress),
                    58 =>  Ok(IE::vlanId),
                    59 =>  Ok(IE::postVlanId),
                    60 =>  Ok(IE::ipVersion),
                    61 =>  Ok(IE::flowDirection),
                    62 =>  Ok(IE::ipNextHopIPv6Address),
                    63 =>  Ok(IE::bgpNextHopIPv6Address),
                    64 =>  Ok(IE::ipv6ExtensionHeaders),
                    70 =>  Ok(IE::mplsTopLabelStackSection),
                    71 =>  Ok(IE::mplsLabelStackSection2),
                    72 =>  Ok(IE::mplsLabelStackSection3),
                    73 =>  Ok(IE::mplsLabelStackSection4),
                    74 =>  Ok(IE::mplsLabelStackSection5),
                    75 =>  Ok(IE::mplsLabelStackSection6),
                    76 =>  Ok(IE::mplsLabelStackSection7),
                    77 =>  Ok(IE::mplsLabelStackSection8),
                    78 =>  Ok(IE::mplsLabelStackSection9),
                    79 =>  Ok(IE::mplsLabelStackSection10),
                    80 =>  Ok(IE::destinationMacAddress),
                    81 =>  Ok(IE::postSourceMacAddress),
                    82 =>  Ok(IE::interfaceName),
                    83 =>  Ok(IE::interfaceDescription),
                    84 =>  Ok(IE::samplerName),
                    85 =>  Ok(IE::octetTotalCount),
                    86 =>  Ok(IE::packetTotalCount),
                    87 =>  Ok(IE::flagsAndSamplerId),
                    88 =>  Ok(IE::fragmentOffset),
                    89 =>  Ok(IE::forwardingStatus),
                    90 =>  Ok(IE::mplsVpnRouteDistinguisher),
                    91 =>  Ok(IE::mplsTopLabelPrefixLength),
                    92 =>  Ok(IE::srcTrafficIndex),
                    93 =>  Ok(IE::dstTrafficIndex),
                    94 =>  Ok(IE::applicationDescription),
                    95 =>  Ok(IE::applicationId),
                    96 =>  Ok(IE::applicationName),
                    98 =>  Ok(IE::postIpDiffServCodePoint),
                    99 =>  Ok(IE::multicastReplicationFactor),
                    100 =>  Ok(IE::className),
                    101 =>  Ok(IE::classificationEngineId),
                    102 =>  Ok(IE::layer2packetSectionOffset),
                    103 =>  Ok(IE::layer2packetSectionSize),
                    104 =>  Ok(IE::layer2packetSectionData),
                    128 =>  Ok(IE::bgpNextAdjacentAsNumber),
                    129 =>  Ok(IE::bgpPrevAdjacentAsNumber),
                    130 =>  Ok(IE::exporterIPv4Address),
                    131 =>  Ok(IE::exporterIPv6Address),
                    132 =>  Ok(IE::droppedOctetDeltaCount),
                    133 =>  Ok(IE::droppedPacketDeltaCount),
                    134 =>  Ok(IE::droppedOctetTotalCount),
                    135 =>  Ok(IE::droppedPacketTotalCount),
                    136 =>  Ok(IE::flowEndReason),
                    137 =>  Ok(IE::commonPropertiesId),
                    138 =>  Ok(IE::observationPointId),
                    139 =>  Ok(IE::icmpTypeCodeIPv6),
                    140 =>  Ok(IE::mplsTopLabelIPv6Address),
                    141 =>  Ok(IE::lineCardId),
                    142 =>  Ok(IE::portId),
                    143 =>  Ok(IE::meteringProcessId),
                    144 =>  Ok(IE::exportingProcessId),
                    145 =>  Ok(IE::templateId),
                    146 =>  Ok(IE::wlanChannelId),
                    147 =>  Ok(IE::wlanSSID),
                    148 =>  Ok(IE::flowId),
                    149 =>  Ok(IE::observationDomainId),
                    150 =>  Ok(IE::flowStartSeconds),
                    151 =>  Ok(IE::flowEndSeconds),
                    152 =>  Ok(IE::flowStartMilliseconds),
                    153 =>  Ok(IE::flowEndMilliseconds),
                    154 =>  Ok(IE::flowStartMicroseconds),
                    155 =>  Ok(IE::flowEndMicroseconds),
                    156 =>  Ok(IE::flowStartNanoseconds),
                    157 =>  Ok(IE::flowEndNanoseconds),
                    158 =>  Ok(IE::flowStartDeltaMicroseconds),
                    159 =>  Ok(IE::flowEndDeltaMicroseconds),
                    160 =>  Ok(IE::systemInitTimeMilliseconds),
                    161 =>  Ok(IE::flowDurationMilliseconds),
                    162 =>  Ok(IE::flowDurationMicroseconds),
                    163 =>  Ok(IE::observedFlowTotalCount),
                    164 =>  Ok(IE::ignoredPacketTotalCount),
                    165 =>  Ok(IE::ignoredOctetTotalCount),
                    166 =>  Ok(IE::notSentFlowTotalCount),
                    167 =>  Ok(IE::notSentPacketTotalCount),
                    168 =>  Ok(IE::notSentOctetTotalCount),
                    169 =>  Ok(IE::destinationIPv6Prefix),
                    170 =>  Ok(IE::sourceIPv6Prefix),
                    171 =>  Ok(IE::postOctetTotalCount),
                    172 =>  Ok(IE::postPacketTotalCount),
                    173 =>  Ok(IE::flowKeyIndicator),
                    174 =>  Ok(IE::postMCastPacketTotalCount),
                    175 =>  Ok(IE::postMCastOctetTotalCount),
                    176 =>  Ok(IE::icmpTypeIPv4),
                    177 =>  Ok(IE::icmpCodeIPv4),
                    178 =>  Ok(IE::icmpTypeIPv6),
                    179 =>  Ok(IE::icmpCodeIPv6),
                    180 =>  Ok(IE::udpSourcePort),
                    181 =>  Ok(IE::udpDestinationPort),
                    182 =>  Ok(IE::tcpSourcePort),
                    183 =>  Ok(IE::tcpDestinationPort),
                    184 =>  Ok(IE::tcpSequenceNumber),
                    185 =>  Ok(IE::tcpAcknowledgementNumber),
                    186 =>  Ok(IE::tcpWindowSize),
                    187 =>  Ok(IE::tcpUrgentPointer),
                    188 =>  Ok(IE::tcpHeaderLength),
                    189 =>  Ok(IE::ipHeaderLength),
                    190 =>  Ok(IE::totalLengthIPv4),
                    191 =>  Ok(IE::payloadLengthIPv6),
                    192 =>  Ok(IE::ipTTL),
                    193 =>  Ok(IE::nextHeaderIPv6),
                    194 =>  Ok(IE::mplsPayloadLength),
                    195 =>  Ok(IE::ipDiffServCodePoint),
                    196 =>  Ok(IE::ipPrecedence),
                    197 =>  Ok(IE::fragmentFlags),
                    198 =>  Ok(IE::octetDeltaSumOfSquares),
                    199 =>  Ok(IE::octetTotalSumOfSquares),
                    200 =>  Ok(IE::mplsTopLabelTTL),
                    201 =>  Ok(IE::mplsLabelStackLength),
                    202 =>  Ok(IE::mplsLabelStackDepth),
                    203 =>  Ok(IE::mplsTopLabelExp),
                    204 =>  Ok(IE::ipPayloadLength),
                    205 =>  Ok(IE::udpMessageLength),
                    206 =>  Ok(IE::isMulticast),
                    207 =>  Ok(IE::ipv4IHL),
                    208 =>  Ok(IE::ipv4Options),
                    209 =>  Ok(IE::tcpOptions),
                    210 =>  Ok(IE::paddingOctets),
                    211 =>  Ok(IE::collectorIPv4Address),
                    212 =>  Ok(IE::collectorIPv6Address),
                    213 =>  Ok(IE::exportInterface),
                    214 =>  Ok(IE::exportProtocolVersion),
                    215 =>  Ok(IE::exportTransportProtocol),
                    216 =>  Ok(IE::collectorTransportPort),
                    217 =>  Ok(IE::exporterTransportPort),
                    218 =>  Ok(IE::tcpSynTotalCount),
                    219 =>  Ok(IE::tcpFinTotalCount),
                    220 =>  Ok(IE::tcpRstTotalCount),
                    221 =>  Ok(IE::tcpPshTotalCount),
                    222 =>  Ok(IE::tcpAckTotalCount),
                    223 =>  Ok(IE::tcpUrgTotalCount),
                    224 =>  Ok(IE::ipTotalLength),
                    225 =>  Ok(IE::postNATSourceIPv4Address),
                    226 =>  Ok(IE::postNATDestinationIPv4Address),
                    227 =>  Ok(IE::postNAPTSourceTransportPort),
                    228 =>  Ok(IE::postNAPTDestinationTransportPort),
                    229 =>  Ok(IE::natOriginatingAddressRealm),
                    230 =>  Ok(IE::natEvent),
                    231 =>  Ok(IE::initiatorOctets),
                    232 =>  Ok(IE::responderOctets),
                    233 =>  Ok(IE::firewallEvent),
                    234 =>  Ok(IE::ingressVRFID),
                    235 =>  Ok(IE::egressVRFID),
                    236 =>  Ok(IE::VRFname),
                    237 =>  Ok(IE::postMplsTopLabelExp),
                    238 =>  Ok(IE::tcpWindowScale),
                    239 =>  Ok(IE::biflowDirection),
                    240 =>  Ok(IE::ethernetHeaderLength),
                    241 =>  Ok(IE::ethernetPayloadLength),
                    242 =>  Ok(IE::ethernetTotalLength),
                    243 =>  Ok(IE::dot1qVlanId),
                    244 =>  Ok(IE::dot1qPriority),
                    245 =>  Ok(IE::dot1qCustomerVlanId),
                    246 =>  Ok(IE::dot1qCustomerPriority),
                    247 =>  Ok(IE::metroEvcId),
                    248 =>  Ok(IE::metroEvcType),
                    249 =>  Ok(IE::pseudoWireId),
                    250 =>  Ok(IE::pseudoWireType),
                    251 =>  Ok(IE::pseudoWireControlWord),
                    252 =>  Ok(IE::ingressPhysicalInterface),
                    253 =>  Ok(IE::egressPhysicalInterface),
                    254 =>  Ok(IE::postDot1qVlanId),
                    255 =>  Ok(IE::postDot1qCustomerVlanId),
                    256 =>  Ok(IE::ethernetType),
                    257 =>  Ok(IE::postIpPrecedence),
                    258 =>  Ok(IE::collectionTimeMilliseconds),
                    259 =>  Ok(IE::exportSctpStreamId),
                    260 =>  Ok(IE::maxExportSeconds),
                    261 =>  Ok(IE::maxFlowEndSeconds),
                    262 =>  Ok(IE::messageMD5Checksum),
                    263 =>  Ok(IE::messageScope),
                    264 =>  Ok(IE::minExportSeconds),
                    265 =>  Ok(IE::minFlowStartSeconds),
                    266 =>  Ok(IE::opaqueOctets),
                    267 =>  Ok(IE::sessionScope),
                    268 =>  Ok(IE::maxFlowEndMicroseconds),
                    269 =>  Ok(IE::maxFlowEndMilliseconds),
                    270 =>  Ok(IE::maxFlowEndNanoseconds),
                    271 =>  Ok(IE::minFlowStartMicroseconds),
                    272 =>  Ok(IE::minFlowStartMilliseconds),
                    273 =>  Ok(IE::minFlowStartNanoseconds),
                    274 =>  Ok(IE::collectorCertificate),
                    275 =>  Ok(IE::exporterCertificate),
                    276 =>  Ok(IE::dataRecordsReliability),
                    277 =>  Ok(IE::observationPointType),
                    278 =>  Ok(IE::newConnectionDeltaCount),
                    279 =>  Ok(IE::connectionSumDurationSeconds),
                    280 =>  Ok(IE::connectionTransactionId),
                    281 =>  Ok(IE::postNATSourceIPv6Address),
                    282 =>  Ok(IE::postNATDestinationIPv6Address),
                    283 =>  Ok(IE::natPoolId),
                    284 =>  Ok(IE::natPoolName),
                    285 =>  Ok(IE::anonymizationFlags),
                    286 =>  Ok(IE::anonymizationTechnique),
                    287 =>  Ok(IE::informationElementIndex),
                    288 =>  Ok(IE::p2pTechnology),
                    289 =>  Ok(IE::tunnelTechnology),
                    290 =>  Ok(IE::encryptedTechnology),
                    291 =>  Ok(IE::basicList),
                    292 =>  Ok(IE::subTemplateList),
                    293 =>  Ok(IE::subTemplateMultiList),
                    294 =>  Ok(IE::bgpValidityState),
                    295 =>  Ok(IE::IPSecSPI),
                    296 =>  Ok(IE::greKey),
                    297 =>  Ok(IE::natType),
                    298 =>  Ok(IE::initiatorPackets),
                    299 =>  Ok(IE::responderPackets),
                    300 =>  Ok(IE::observationDomainName),
                    301 =>  Ok(IE::selectionSequenceId),
                    302 =>  Ok(IE::selectorId),
                    303 =>  Ok(IE::informationElementId),
                    304 =>  Ok(IE::selectorAlgorithm),
                    305 =>  Ok(IE::samplingPacketInterval),
                    306 =>  Ok(IE::samplingPacketSpace),
                    307 =>  Ok(IE::samplingTimeInterval),
                    308 =>  Ok(IE::samplingTimeSpace),
                    309 =>  Ok(IE::samplingSize),
                    310 =>  Ok(IE::samplingPopulation),
                    311 =>  Ok(IE::samplingProbability),
                    312 =>  Ok(IE::dataLinkFrameSize),
                    313 =>  Ok(IE::ipHeaderPacketSection),
                    314 =>  Ok(IE::ipPayloadPacketSection),
                    315 =>  Ok(IE::dataLinkFrameSection),
                    316 =>  Ok(IE::mplsLabelStackSection),
                    317 =>  Ok(IE::mplsPayloadPacketSection),
                    318 =>  Ok(IE::selectorIdTotalPktsObserved),
                    319 =>  Ok(IE::selectorIdTotalPktsSelected),
                    320 =>  Ok(IE::absoluteError),
                    321 =>  Ok(IE::relativeError),
                    322 =>  Ok(IE::observationTimeSeconds),
                    323 =>  Ok(IE::observationTimeMilliseconds),
                    324 =>  Ok(IE::observationTimeMicroseconds),
                    325 =>  Ok(IE::observationTimeNanoseconds),
                    326 =>  Ok(IE::digestHashValue),
                    327 =>  Ok(IE::hashIPPayloadOffset),
                    328 =>  Ok(IE::hashIPPayloadSize),
                    329 =>  Ok(IE::hashOutputRangeMin),
                    330 =>  Ok(IE::hashOutputRangeMax),
                    331 =>  Ok(IE::hashSelectedRangeMin),
                    332 =>  Ok(IE::hashSelectedRangeMax),
                    333 =>  Ok(IE::hashDigestOutput),
                    334 =>  Ok(IE::hashInitialiserValue),
                    335 =>  Ok(IE::selectorName),
                    336 =>  Ok(IE::upperCILimit),
                    337 =>  Ok(IE::lowerCILimit),
                    338 =>  Ok(IE::confidenceLevel),
                    339 =>  Ok(IE::informationElementDataType),
                    340 =>  Ok(IE::informationElementDescription),
                    341 =>  Ok(IE::informationElementName),
                    342 =>  Ok(IE::informationElementRangeBegin),
                    343 =>  Ok(IE::informationElementRangeEnd),
                    344 =>  Ok(IE::informationElementSemantics),
                    345 =>  Ok(IE::informationElementUnits),
                    346 =>  Ok(IE::privateEnterpriseNumber),
                    347 =>  Ok(IE::virtualStationInterfaceId),
                    348 =>  Ok(IE::virtualStationInterfaceName),
                    349 =>  Ok(IE::virtualStationUUID),
                    350 =>  Ok(IE::virtualStationName),
                    351 =>  Ok(IE::layer2SegmentId),
                    352 =>  Ok(IE::layer2OctetDeltaCount),
                    353 =>  Ok(IE::layer2OctetTotalCount),
                    354 =>  Ok(IE::ingressUnicastPacketTotalCount),
                    355 =>  Ok(IE::ingressMulticastPacketTotalCount),
                    356 =>  Ok(IE::ingressBroadcastPacketTotalCount),
                    357 =>  Ok(IE::egressUnicastPacketTotalCount),
                    358 =>  Ok(IE::egressBroadcastPacketTotalCount),
                    359 =>  Ok(IE::monitoringIntervalStartMilliSeconds),
                    360 =>  Ok(IE::monitoringIntervalEndMilliSeconds),
                    361 =>  Ok(IE::portRangeStart),
                    362 =>  Ok(IE::portRangeEnd),
                    363 =>  Ok(IE::portRangeStepSize),
                    364 =>  Ok(IE::portRangeNumPorts),
                    365 =>  Ok(IE::staMacAddress),
                    366 =>  Ok(IE::staIPv4Address),
                    367 =>  Ok(IE::wtpMacAddress),
                    368 =>  Ok(IE::ingressInterfaceType),
                    369 =>  Ok(IE::egressInterfaceType),
                    370 =>  Ok(IE::rtpSequenceNumber),
                    371 =>  Ok(IE::userName),
                    372 =>  Ok(IE::applicationCategoryName),
                    373 =>  Ok(IE::applicationSubCategoryName),
                    374 =>  Ok(IE::applicationGroupName),
                    375 =>  Ok(IE::originalFlowsPresent),
                    376 =>  Ok(IE::originalFlowsInitiated),
                    377 =>  Ok(IE::originalFlowsCompleted),
                    378 =>  Ok(IE::distinctCountOfSourceIPAddress),
                    379 =>  Ok(IE::distinctCountOfDestinationIPAddress),
                    380 =>  Ok(IE::distinctCountOfSourceIPv4Address),
                    381 =>  Ok(IE::distinctCountOfDestinationIPv4Address),
                    382 =>  Ok(IE::distinctCountOfSourceIPv6Address),
                    383 =>  Ok(IE::distinctCountOfDestinationIPv6Address),
                    384 =>  Ok(IE::valueDistributionMethod),
                    385 =>  Ok(IE::rfc3550JitterMilliseconds),
                    386 =>  Ok(IE::rfc3550JitterMicroseconds),
                    387 =>  Ok(IE::rfc3550JitterNanoseconds),
                    388 =>  Ok(IE::dot1qDEI),
                    389 =>  Ok(IE::dot1qCustomerDEI),
                    390 =>  Ok(IE::flowSelectorAlgorithm),
                    391 =>  Ok(IE::flowSelectedOctetDeltaCount),
                    392 =>  Ok(IE::flowSelectedPacketDeltaCount),
                    393 =>  Ok(IE::flowSelectedFlowDeltaCount),
                    394 =>  Ok(IE::selectorIDTotalFlowsObserved),
                    395 =>  Ok(IE::selectorIDTotalFlowsSelected),
                    396 =>  Ok(IE::samplingFlowInterval),
                    397 =>  Ok(IE::samplingFlowSpacing),
                    398 =>  Ok(IE::flowSamplingTimeInterval),
                    399 =>  Ok(IE::flowSamplingTimeSpacing),
                    400 =>  Ok(IE::hashFlowDomain),
                    401 =>  Ok(IE::transportOctetDeltaCount),
                    402 =>  Ok(IE::transportPacketDeltaCount),
                    403 =>  Ok(IE::originalExporterIPv4Address),
                    404 =>  Ok(IE::originalExporterIPv6Address),
                    405 =>  Ok(IE::originalObservationDomainId),
                    406 =>  Ok(IE::intermediateProcessId),
                    407 =>  Ok(IE::ignoredDataRecordTotalCount),
                    408 =>  Ok(IE::dataLinkFrameType),
                    409 =>  Ok(IE::sectionOffset),
                    410 =>  Ok(IE::sectionExportedOctets),
                    411 =>  Ok(IE::dot1qServiceInstanceTag),
                    412 =>  Ok(IE::dot1qServiceInstanceId),
                    413 =>  Ok(IE::dot1qServiceInstancePriority),
                    414 =>  Ok(IE::dot1qCustomerSourceMacAddress),
                    415 =>  Ok(IE::dot1qCustomerDestinationMacAddress),
                    417 =>  Ok(IE::postLayer2OctetDeltaCount),
                    418 =>  Ok(IE::postMCastLayer2OctetDeltaCount),
                    420 =>  Ok(IE::postLayer2OctetTotalCount),
                    421 =>  Ok(IE::postMCastLayer2OctetTotalCount),
                    422 =>  Ok(IE::minimumLayer2TotalLength),
                    423 =>  Ok(IE::maximumLayer2TotalLength),
                    424 =>  Ok(IE::droppedLayer2OctetDeltaCount),
                    425 =>  Ok(IE::droppedLayer2OctetTotalCount),
                    426 =>  Ok(IE::ignoredLayer2OctetTotalCount),
                    427 =>  Ok(IE::notSentLayer2OctetTotalCount),
                    428 =>  Ok(IE::layer2OctetDeltaSumOfSquares),
                    429 =>  Ok(IE::layer2OctetTotalSumOfSquares),
                    430 =>  Ok(IE::layer2FrameDeltaCount),
                    431 =>  Ok(IE::layer2FrameTotalCount),
                    432 =>  Ok(IE::pseudoWireDestinationIPv4Address),
                    433 =>  Ok(IE::ignoredLayer2FrameTotalCount),
                    434 =>  Ok(IE::mibObjectValueInteger),
                    435 =>  Ok(IE::mibObjectValueOctetString),
                    436 =>  Ok(IE::mibObjectValueOID),
                    437 =>  Ok(IE::mibObjectValueBits),
                    438 =>  Ok(IE::mibObjectValueIPAddress),
                    439 =>  Ok(IE::mibObjectValueCounter),
                    440 =>  Ok(IE::mibObjectValueGauge),
                    441 =>  Ok(IE::mibObjectValueTimeTicks),
                    442 =>  Ok(IE::mibObjectValueUnsigned),
                    443 =>  Ok(IE::mibObjectValueTable),
                    444 =>  Ok(IE::mibObjectValueRow),
                    445 =>  Ok(IE::mibObjectIdentifier),
                    446 =>  Ok(IE::mibSubIdentifier),
                    447 =>  Ok(IE::mibIndexIndicator),
                    448 =>  Ok(IE::mibCaptureTimeSemantics),
                    449 =>  Ok(IE::mibContextEngineID),
                    450 =>  Ok(IE::mibContextName),
                    451 =>  Ok(IE::mibObjectName),
                    452 =>  Ok(IE::mibObjectDescription),
                    453 =>  Ok(IE::mibObjectSyntax),
                    454 =>  Ok(IE::mibModuleName),
                    455 =>  Ok(IE::mobileIMSI),
                    456 =>  Ok(IE::mobileMSISDN),
                    457 =>  Ok(IE::httpStatusCode),
                    458 =>  Ok(IE::sourceTransportPortsLimit),
                    459 =>  Ok(IE::httpRequestMethod),
                    460 =>  Ok(IE::httpRequestHost),
                    461 =>  Ok(IE::httpRequestTarget),
                    462 =>  Ok(IE::httpMessageVersion),
                    463 =>  Ok(IE::natInstanceID),
                    464 =>  Ok(IE::internalAddressRealm),
                    465 =>  Ok(IE::externalAddressRealm),
                    466 =>  Ok(IE::natQuotaExceededEvent),
                    467 =>  Ok(IE::natThresholdEvent),
                    468 =>  Ok(IE::httpUserAgent),
                    469 =>  Ok(IE::httpContentType),
                    470 =>  Ok(IE::httpReasonPhrase),
                    471 =>  Ok(IE::maxSessionEntries),
                    472 =>  Ok(IE::maxBIBEntries),
                    473 =>  Ok(IE::maxEntriesPerUser),
                    474 =>  Ok(IE::maxSubscribers),
                    475 =>  Ok(IE::maxFragmentsPendingReassembly),
                    476 =>  Ok(IE::addressPoolHighThreshold),
                    477 =>  Ok(IE::addressPoolLowThreshold),
                    478 =>  Ok(IE::addressPortMappingHighThreshold),
                    479 =>  Ok(IE::addressPortMappingLowThreshold),
                    480 =>  Ok(IE::addressPortMappingPerUserHighThreshold),
                    481 =>  Ok(IE::globalAddressMappingHighThreshold),
                    482 =>  Ok(IE::vpnIdentifier),
                    483 =>  Ok(IE::bgpCommunity),
                    484 =>  Ok(IE::bgpSourceCommunityList),
                    485 =>  Ok(IE::bgpDestinationCommunityList),
                    486 =>  Ok(IE::bgpExtendedCommunity),
                    487 =>  Ok(IE::bgpSourceExtendedCommunityList),
                    488 =>  Ok(IE::bgpDestinationExtendedCommunityList),
                    489 =>  Ok(IE::bgpLargeCommunity),
                    490 =>  Ok(IE::bgpSourceLargeCommunityList),
                    491 =>  Ok(IE::bgpDestinationLargeCommunityList),
                    492 =>  Ok(IE::srhFlagsIPv6),
                    493 =>  Ok(IE::srhTagIPv6),
                    494 =>  Ok(IE::srhSegmentIPv6),
                    495 =>  Ok(IE::srhActiveSegmentIPv6),
                    496 =>  Ok(IE::srhSegmentIPv6BasicList),
                    497 =>  Ok(IE::srhSegmentIPv6ListSection),
                    498 =>  Ok(IE::srhSegmentsIPv6Left),
                    499 =>  Ok(IE::srhIPv6Section),
                    500 =>  Ok(IE::srhIPv6ActiveSegmentType),
                    501 =>  Ok(IE::srhSegmentIPv6LocatorLength),
                    502 =>  Ok(IE::srhSegmentIPv6EndpointBehavior),
                    503 =>  Ok(IE::transportChecksum),
                    504 =>  Ok(IE::icmpHeaderPacketSection),
                    505 =>  Ok(IE::gtpuFlags),
                    506 =>  Ok(IE::gtpuMsgType),
                    507 =>  Ok(IE::gtpuTEid),
                    508 =>  Ok(IE::gtpuSequenceNum),
                    509 =>  Ok(IE::gtpuQFI),
                    510 =>  Ok(IE::gtpuPduType),
                    511 =>  Ok(IE::bgpSourceAsPathList),
                    512 =>  Ok(IE::bgpDestinationAsPathList),
                    513 =>  Ok(IE::ipv6ExtensionHeaderType),
                    514 =>  Ok(IE::ipv6ExtensionHeaderCount),
                    515 =>  Ok(IE::ipv6ExtensionHeadersFull),
                    516 =>  Ok(IE::ipv6ExtensionHeaderTypeCountList),
                    517 =>  Ok(IE::ipv6ExtensionHeadersLimit),
                    518 =>  Ok(IE::ipv6ExtensionHeadersChainLength),
                    519 =>  Ok(IE::ipv6ExtensionHeaderChainLengthList),
                    520 =>  Ok(IE::tcpOptionsFull),
                    521 =>  Ok(IE::tcpSharedOptionExID16),
                    522 =>  Ok(IE::tcpSharedOptionExID32),
                    523 =>  Ok(IE::tcpSharedOptionExID16List),
                    524 =>  Ok(IE::tcpSharedOptionExID32List),
                    _ =>  Err(IEError::UndefinedIANAIE(code)),
                }
            }
            637 => {
                match nokia::IE::try_from(code) {
                    Ok(ie) => Ok(Self::Nokia(ie)),
                    Err(err) => Err(IEError::Nokia(err)),
                }
            }
            3746 => {
                match netgauze::IE::try_from(code) {
                    Ok(ie) => Ok(Self::NetGauze(ie)),
                    Err(err) => Err(IEError::NetGauze(err)),
                }
            }
            9 => {
                match cisco::IE::try_from(code) {
                    Ok(ie) => Ok(Self::Cisco(ie)),
                    Err(err) => Err(IEError::Cisco(err)),
                }
            }
            6876 => {
                match vmware::IE::try_from(code) {
                    Ok(ie) => Ok(Self::VMWare(ie)),
                    Err(err) => Err(IEError::VMWare(err)),
                }
            }
           unknown => Ok(IE::Unknown{pen: unknown, id: code}),
       }
   }
}

impl super::InformationElementTemplate for IE {
    fn semantics(&self) -> Option<InformationElementSemantics> {
        match self {
            Self::Unknown{..} => None,
            Self::Nokia(ie) => ie.semantics(),
            Self::NetGauze(ie) => ie.semantics(),
            Self::Cisco(ie) => ie.semantics(),
            Self::VMWare(ie) => ie.semantics(),
            Self::octetDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::packetDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::deltaFlowCount => Some(InformationElementSemantics::deltaCounter),
            Self::protocolIdentifier => Some(InformationElementSemantics::identifier),
            Self::ipClassOfService => Some(InformationElementSemantics::identifier),
            Self::tcpControlBits => Some(InformationElementSemantics::flags),
            Self::sourceTransportPort => Some(InformationElementSemantics::identifier),
            Self::sourceIPv4Address => Some(InformationElementSemantics::default),
            Self::sourceIPv4PrefixLength => None,
            Self::ingressInterface => Some(InformationElementSemantics::identifier),
            Self::destinationTransportPort => Some(InformationElementSemantics::identifier),
            Self::destinationIPv4Address => Some(InformationElementSemantics::default),
            Self::destinationIPv4PrefixLength => None,
            Self::egressInterface => Some(InformationElementSemantics::identifier),
            Self::ipNextHopIPv4Address => Some(InformationElementSemantics::default),
            Self::bgpSourceAsNumber => Some(InformationElementSemantics::identifier),
            Self::bgpDestinationAsNumber => Some(InformationElementSemantics::identifier),
            Self::bgpNextHopIPv4Address => Some(InformationElementSemantics::default),
            Self::postMCastPacketDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::postMCastOctetDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::flowEndSysUpTime => None,
            Self::flowStartSysUpTime => None,
            Self::postOctetDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::postPacketDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::minimumIpTotalLength => None,
            Self::maximumIpTotalLength => None,
            Self::sourceIPv6Address => Some(InformationElementSemantics::default),
            Self::destinationIPv6Address => Some(InformationElementSemantics::default),
            Self::sourceIPv6PrefixLength => None,
            Self::destinationIPv6PrefixLength => None,
            Self::flowLabelIPv6 => Some(InformationElementSemantics::identifier),
            Self::icmpTypeCodeIPv4 => Some(InformationElementSemantics::identifier),
            Self::igmpType => Some(InformationElementSemantics::identifier),
            Self::samplingInterval => Some(InformationElementSemantics::quantity),
            Self::samplingAlgorithm => Some(InformationElementSemantics::identifier),
            Self::flowActiveTimeout => None,
            Self::flowIdleTimeout => None,
            Self::engineType => Some(InformationElementSemantics::identifier),
            Self::engineId => Some(InformationElementSemantics::identifier),
            Self::exportedOctetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::exportedMessageTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::exportedFlowRecordTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::ipv4RouterSc => Some(InformationElementSemantics::default),
            Self::sourceIPv4Prefix => Some(InformationElementSemantics::default),
            Self::destinationIPv4Prefix => Some(InformationElementSemantics::default),
            Self::mplsTopLabelType => Some(InformationElementSemantics::identifier),
            Self::mplsTopLabelIPv4Address => Some(InformationElementSemantics::default),
            Self::samplerId => Some(InformationElementSemantics::identifier),
            Self::samplerMode => Some(InformationElementSemantics::identifier),
            Self::samplerRandomInterval => Some(InformationElementSemantics::quantity),
            Self::classId => Some(InformationElementSemantics::identifier),
            Self::minimumTTL => None,
            Self::maximumTTL => None,
            Self::fragmentIdentification => Some(InformationElementSemantics::identifier),
            Self::postIpClassOfService => Some(InformationElementSemantics::identifier),
            Self::sourceMacAddress => Some(InformationElementSemantics::default),
            Self::postDestinationMacAddress => Some(InformationElementSemantics::default),
            Self::vlanId => Some(InformationElementSemantics::identifier),
            Self::postVlanId => Some(InformationElementSemantics::identifier),
            Self::ipVersion => Some(InformationElementSemantics::identifier),
            Self::flowDirection => Some(InformationElementSemantics::identifier),
            Self::ipNextHopIPv6Address => Some(InformationElementSemantics::default),
            Self::bgpNextHopIPv6Address => Some(InformationElementSemantics::default),
            Self::ipv6ExtensionHeaders => Some(InformationElementSemantics::flags),
            Self::mplsTopLabelStackSection => Some(InformationElementSemantics::default),
            Self::mplsLabelStackSection2 => Some(InformationElementSemantics::default),
            Self::mplsLabelStackSection3 => Some(InformationElementSemantics::default),
            Self::mplsLabelStackSection4 => Some(InformationElementSemantics::default),
            Self::mplsLabelStackSection5 => Some(InformationElementSemantics::default),
            Self::mplsLabelStackSection6 => Some(InformationElementSemantics::default),
            Self::mplsLabelStackSection7 => Some(InformationElementSemantics::default),
            Self::mplsLabelStackSection8 => Some(InformationElementSemantics::default),
            Self::mplsLabelStackSection9 => Some(InformationElementSemantics::default),
            Self::mplsLabelStackSection10 => Some(InformationElementSemantics::default),
            Self::destinationMacAddress => Some(InformationElementSemantics::default),
            Self::postSourceMacAddress => Some(InformationElementSemantics::default),
            Self::interfaceName => Some(InformationElementSemantics::default),
            Self::interfaceDescription => Some(InformationElementSemantics::default),
            Self::samplerName => None,
            Self::octetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::packetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::flagsAndSamplerId => Some(InformationElementSemantics::identifier),
            Self::fragmentOffset => Some(InformationElementSemantics::quantity),
            Self::forwardingStatus => Some(InformationElementSemantics::identifier),
            Self::mplsVpnRouteDistinguisher => Some(InformationElementSemantics::default),
            Self::mplsTopLabelPrefixLength => Some(InformationElementSemantics::quantity),
            Self::srcTrafficIndex => Some(InformationElementSemantics::identifier),
            Self::dstTrafficIndex => Some(InformationElementSemantics::identifier),
            Self::applicationDescription => Some(InformationElementSemantics::default),
            Self::applicationId => Some(InformationElementSemantics::default),
            Self::applicationName => Some(InformationElementSemantics::default),
            Self::postIpDiffServCodePoint => Some(InformationElementSemantics::identifier),
            Self::multicastReplicationFactor => Some(InformationElementSemantics::quantity),
            Self::className => None,
            Self::classificationEngineId => Some(InformationElementSemantics::identifier),
            Self::layer2packetSectionOffset => Some(InformationElementSemantics::quantity),
            Self::layer2packetSectionSize => Some(InformationElementSemantics::quantity),
            Self::layer2packetSectionData => None,
            Self::bgpNextAdjacentAsNumber => Some(InformationElementSemantics::identifier),
            Self::bgpPrevAdjacentAsNumber => Some(InformationElementSemantics::identifier),
            Self::exporterIPv4Address => Some(InformationElementSemantics::default),
            Self::exporterIPv6Address => Some(InformationElementSemantics::default),
            Self::droppedOctetDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::droppedPacketDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::droppedOctetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::droppedPacketTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::flowEndReason => Some(InformationElementSemantics::identifier),
            Self::commonPropertiesId => Some(InformationElementSemantics::identifier),
            Self::observationPointId => Some(InformationElementSemantics::identifier),
            Self::icmpTypeCodeIPv6 => Some(InformationElementSemantics::identifier),
            Self::mplsTopLabelIPv6Address => Some(InformationElementSemantics::default),
            Self::lineCardId => Some(InformationElementSemantics::identifier),
            Self::portId => Some(InformationElementSemantics::identifier),
            Self::meteringProcessId => Some(InformationElementSemantics::identifier),
            Self::exportingProcessId => Some(InformationElementSemantics::identifier),
            Self::templateId => Some(InformationElementSemantics::identifier),
            Self::wlanChannelId => Some(InformationElementSemantics::identifier),
            Self::wlanSSID => Some(InformationElementSemantics::default),
            Self::flowId => Some(InformationElementSemantics::identifier),
            Self::observationDomainId => Some(InformationElementSemantics::identifier),
            Self::flowStartSeconds => Some(InformationElementSemantics::default),
            Self::flowEndSeconds => Some(InformationElementSemantics::default),
            Self::flowStartMilliseconds => Some(InformationElementSemantics::default),
            Self::flowEndMilliseconds => Some(InformationElementSemantics::default),
            Self::flowStartMicroseconds => Some(InformationElementSemantics::default),
            Self::flowEndMicroseconds => Some(InformationElementSemantics::default),
            Self::flowStartNanoseconds => Some(InformationElementSemantics::default),
            Self::flowEndNanoseconds => Some(InformationElementSemantics::default),
            Self::flowStartDeltaMicroseconds => None,
            Self::flowEndDeltaMicroseconds => None,
            Self::systemInitTimeMilliseconds => Some(InformationElementSemantics::default),
            Self::flowDurationMilliseconds => None,
            Self::flowDurationMicroseconds => None,
            Self::observedFlowTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::ignoredPacketTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::ignoredOctetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::notSentFlowTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::notSentPacketTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::notSentOctetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::destinationIPv6Prefix => Some(InformationElementSemantics::default),
            Self::sourceIPv6Prefix => Some(InformationElementSemantics::default),
            Self::postOctetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::postPacketTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::flowKeyIndicator => Some(InformationElementSemantics::flags),
            Self::postMCastPacketTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::postMCastOctetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::icmpTypeIPv4 => Some(InformationElementSemantics::identifier),
            Self::icmpCodeIPv4 => Some(InformationElementSemantics::identifier),
            Self::icmpTypeIPv6 => Some(InformationElementSemantics::identifier),
            Self::icmpCodeIPv6 => Some(InformationElementSemantics::identifier),
            Self::udpSourcePort => Some(InformationElementSemantics::identifier),
            Self::udpDestinationPort => Some(InformationElementSemantics::identifier),
            Self::tcpSourcePort => Some(InformationElementSemantics::identifier),
            Self::tcpDestinationPort => Some(InformationElementSemantics::identifier),
            Self::tcpSequenceNumber => None,
            Self::tcpAcknowledgementNumber => None,
            Self::tcpWindowSize => None,
            Self::tcpUrgentPointer => None,
            Self::tcpHeaderLength => None,
            Self::ipHeaderLength => None,
            Self::totalLengthIPv4 => None,
            Self::payloadLengthIPv6 => None,
            Self::ipTTL => None,
            Self::nextHeaderIPv6 => None,
            Self::mplsPayloadLength => None,
            Self::ipDiffServCodePoint => Some(InformationElementSemantics::identifier),
            Self::ipPrecedence => Some(InformationElementSemantics::identifier),
            Self::fragmentFlags => Some(InformationElementSemantics::flags),
            Self::octetDeltaSumOfSquares => None,
            Self::octetTotalSumOfSquares => None,
            Self::mplsTopLabelTTL => None,
            Self::mplsLabelStackLength => None,
            Self::mplsLabelStackDepth => None,
            Self::mplsTopLabelExp => Some(InformationElementSemantics::flags),
            Self::ipPayloadLength => None,
            Self::udpMessageLength => None,
            Self::isMulticast => Some(InformationElementSemantics::flags),
            Self::ipv4IHL => None,
            Self::ipv4Options => Some(InformationElementSemantics::flags),
            Self::tcpOptions => Some(InformationElementSemantics::flags),
            Self::paddingOctets => Some(InformationElementSemantics::default),
            Self::collectorIPv4Address => Some(InformationElementSemantics::default),
            Self::collectorIPv6Address => Some(InformationElementSemantics::default),
            Self::exportInterface => Some(InformationElementSemantics::identifier),
            Self::exportProtocolVersion => Some(InformationElementSemantics::identifier),
            Self::exportTransportProtocol => Some(InformationElementSemantics::identifier),
            Self::collectorTransportPort => Some(InformationElementSemantics::identifier),
            Self::exporterTransportPort => Some(InformationElementSemantics::identifier),
            Self::tcpSynTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::tcpFinTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::tcpRstTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::tcpPshTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::tcpAckTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::tcpUrgTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::ipTotalLength => None,
            Self::postNATSourceIPv4Address => Some(InformationElementSemantics::default),
            Self::postNATDestinationIPv4Address => Some(InformationElementSemantics::default),
            Self::postNAPTSourceTransportPort => Some(InformationElementSemantics::identifier),
            Self::postNAPTDestinationTransportPort => Some(InformationElementSemantics::identifier),
            Self::natOriginatingAddressRealm => Some(InformationElementSemantics::identifier),
            Self::natEvent => Some(InformationElementSemantics::identifier),
            Self::initiatorOctets => Some(InformationElementSemantics::deltaCounter),
            Self::responderOctets => Some(InformationElementSemantics::deltaCounter),
            Self::firewallEvent => None,
            Self::ingressVRFID => None,
            Self::egressVRFID => None,
            Self::VRFname => Some(InformationElementSemantics::default),
            Self::postMplsTopLabelExp => Some(InformationElementSemantics::flags),
            Self::tcpWindowScale => None,
            Self::biflowDirection => Some(InformationElementSemantics::identifier),
            Self::ethernetHeaderLength => Some(InformationElementSemantics::quantity),
            Self::ethernetPayloadLength => Some(InformationElementSemantics::quantity),
            Self::ethernetTotalLength => Some(InformationElementSemantics::quantity),
            Self::dot1qVlanId => Some(InformationElementSemantics::identifier),
            Self::dot1qPriority => Some(InformationElementSemantics::identifier),
            Self::dot1qCustomerVlanId => Some(InformationElementSemantics::identifier),
            Self::dot1qCustomerPriority => Some(InformationElementSemantics::identifier),
            Self::metroEvcId => Some(InformationElementSemantics::default),
            Self::metroEvcType => Some(InformationElementSemantics::identifier),
            Self::pseudoWireId => Some(InformationElementSemantics::identifier),
            Self::pseudoWireType => Some(InformationElementSemantics::identifier),
            Self::pseudoWireControlWord => Some(InformationElementSemantics::identifier),
            Self::ingressPhysicalInterface => Some(InformationElementSemantics::identifier),
            Self::egressPhysicalInterface => Some(InformationElementSemantics::identifier),
            Self::postDot1qVlanId => Some(InformationElementSemantics::identifier),
            Self::postDot1qCustomerVlanId => Some(InformationElementSemantics::identifier),
            Self::ethernetType => Some(InformationElementSemantics::identifier),
            Self::postIpPrecedence => Some(InformationElementSemantics::identifier),
            Self::collectionTimeMilliseconds => Some(InformationElementSemantics::default),
            Self::exportSctpStreamId => Some(InformationElementSemantics::identifier),
            Self::maxExportSeconds => Some(InformationElementSemantics::default),
            Self::maxFlowEndSeconds => Some(InformationElementSemantics::default),
            Self::messageMD5Checksum => Some(InformationElementSemantics::default),
            Self::messageScope => None,
            Self::minExportSeconds => Some(InformationElementSemantics::default),
            Self::minFlowStartSeconds => Some(InformationElementSemantics::default),
            Self::opaqueOctets => Some(InformationElementSemantics::default),
            Self::sessionScope => None,
            Self::maxFlowEndMicroseconds => Some(InformationElementSemantics::default),
            Self::maxFlowEndMilliseconds => Some(InformationElementSemantics::default),
            Self::maxFlowEndNanoseconds => Some(InformationElementSemantics::default),
            Self::minFlowStartMicroseconds => Some(InformationElementSemantics::default),
            Self::minFlowStartMilliseconds => Some(InformationElementSemantics::default),
            Self::minFlowStartNanoseconds => Some(InformationElementSemantics::default),
            Self::collectorCertificate => Some(InformationElementSemantics::default),
            Self::exporterCertificate => Some(InformationElementSemantics::default),
            Self::dataRecordsReliability => Some(InformationElementSemantics::default),
            Self::observationPointType => Some(InformationElementSemantics::identifier),
            Self::newConnectionDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::connectionSumDurationSeconds => None,
            Self::connectionTransactionId => Some(InformationElementSemantics::identifier),
            Self::postNATSourceIPv6Address => Some(InformationElementSemantics::default),
            Self::postNATDestinationIPv6Address => Some(InformationElementSemantics::default),
            Self::natPoolId => Some(InformationElementSemantics::identifier),
            Self::natPoolName => Some(InformationElementSemantics::default),
            Self::anonymizationFlags => Some(InformationElementSemantics::flags),
            Self::anonymizationTechnique => Some(InformationElementSemantics::identifier),
            Self::informationElementIndex => Some(InformationElementSemantics::identifier),
            Self::p2pTechnology => Some(InformationElementSemantics::default),
            Self::tunnelTechnology => Some(InformationElementSemantics::default),
            Self::encryptedTechnology => Some(InformationElementSemantics::default),
            Self::basicList => Some(InformationElementSemantics::list),
            Self::subTemplateList => Some(InformationElementSemantics::list),
            Self::subTemplateMultiList => Some(InformationElementSemantics::list),
            Self::bgpValidityState => Some(InformationElementSemantics::identifier),
            Self::IPSecSPI => Some(InformationElementSemantics::identifier),
            Self::greKey => Some(InformationElementSemantics::identifier),
            Self::natType => Some(InformationElementSemantics::identifier),
            Self::initiatorPackets => Some(InformationElementSemantics::deltaCounter),
            Self::responderPackets => Some(InformationElementSemantics::deltaCounter),
            Self::observationDomainName => Some(InformationElementSemantics::default),
            Self::selectionSequenceId => Some(InformationElementSemantics::identifier),
            Self::selectorId => Some(InformationElementSemantics::identifier),
            Self::informationElementId => Some(InformationElementSemantics::identifier),
            Self::selectorAlgorithm => Some(InformationElementSemantics::identifier),
            Self::samplingPacketInterval => Some(InformationElementSemantics::quantity),
            Self::samplingPacketSpace => Some(InformationElementSemantics::quantity),
            Self::samplingTimeInterval => Some(InformationElementSemantics::quantity),
            Self::samplingTimeSpace => Some(InformationElementSemantics::quantity),
            Self::samplingSize => Some(InformationElementSemantics::quantity),
            Self::samplingPopulation => Some(InformationElementSemantics::quantity),
            Self::samplingProbability => Some(InformationElementSemantics::quantity),
            Self::dataLinkFrameSize => Some(InformationElementSemantics::quantity),
            Self::ipHeaderPacketSection => Some(InformationElementSemantics::default),
            Self::ipPayloadPacketSection => Some(InformationElementSemantics::default),
            Self::dataLinkFrameSection => Some(InformationElementSemantics::default),
            Self::mplsLabelStackSection => Some(InformationElementSemantics::default),
            Self::mplsPayloadPacketSection => Some(InformationElementSemantics::default),
            Self::selectorIdTotalPktsObserved => Some(InformationElementSemantics::totalCounter),
            Self::selectorIdTotalPktsSelected => Some(InformationElementSemantics::totalCounter),
            Self::absoluteError => Some(InformationElementSemantics::quantity),
            Self::relativeError => Some(InformationElementSemantics::quantity),
            Self::observationTimeSeconds => Some(InformationElementSemantics::default),
            Self::observationTimeMilliseconds => Some(InformationElementSemantics::default),
            Self::observationTimeMicroseconds => Some(InformationElementSemantics::default),
            Self::observationTimeNanoseconds => Some(InformationElementSemantics::default),
            Self::digestHashValue => Some(InformationElementSemantics::quantity),
            Self::hashIPPayloadOffset => Some(InformationElementSemantics::quantity),
            Self::hashIPPayloadSize => Some(InformationElementSemantics::quantity),
            Self::hashOutputRangeMin => Some(InformationElementSemantics::quantity),
            Self::hashOutputRangeMax => Some(InformationElementSemantics::quantity),
            Self::hashSelectedRangeMin => Some(InformationElementSemantics::quantity),
            Self::hashSelectedRangeMax => Some(InformationElementSemantics::quantity),
            Self::hashDigestOutput => Some(InformationElementSemantics::default),
            Self::hashInitialiserValue => Some(InformationElementSemantics::quantity),
            Self::selectorName => Some(InformationElementSemantics::default),
            Self::upperCILimit => Some(InformationElementSemantics::quantity),
            Self::lowerCILimit => Some(InformationElementSemantics::quantity),
            Self::confidenceLevel => Some(InformationElementSemantics::quantity),
            Self::informationElementDataType => None,
            Self::informationElementDescription => Some(InformationElementSemantics::default),
            Self::informationElementName => Some(InformationElementSemantics::default),
            Self::informationElementRangeBegin => Some(InformationElementSemantics::quantity),
            Self::informationElementRangeEnd => Some(InformationElementSemantics::quantity),
            Self::informationElementSemantics => None,
            Self::informationElementUnits => None,
            Self::privateEnterpriseNumber => Some(InformationElementSemantics::identifier),
            Self::virtualStationInterfaceId => Some(InformationElementSemantics::default),
            Self::virtualStationInterfaceName => Some(InformationElementSemantics::default),
            Self::virtualStationUUID => Some(InformationElementSemantics::default),
            Self::virtualStationName => Some(InformationElementSemantics::default),
            Self::layer2SegmentId => Some(InformationElementSemantics::identifier),
            Self::layer2OctetDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::layer2OctetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::ingressUnicastPacketTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::ingressMulticastPacketTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::ingressBroadcastPacketTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::egressUnicastPacketTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::egressBroadcastPacketTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::monitoringIntervalStartMilliSeconds => Some(InformationElementSemantics::default),
            Self::monitoringIntervalEndMilliSeconds => Some(InformationElementSemantics::default),
            Self::portRangeStart => Some(InformationElementSemantics::identifier),
            Self::portRangeEnd => Some(InformationElementSemantics::identifier),
            Self::portRangeStepSize => Some(InformationElementSemantics::identifier),
            Self::portRangeNumPorts => Some(InformationElementSemantics::identifier),
            Self::staMacAddress => Some(InformationElementSemantics::default),
            Self::staIPv4Address => Some(InformationElementSemantics::default),
            Self::wtpMacAddress => Some(InformationElementSemantics::default),
            Self::ingressInterfaceType => Some(InformationElementSemantics::identifier),
            Self::egressInterfaceType => Some(InformationElementSemantics::identifier),
            Self::rtpSequenceNumber => None,
            Self::userName => Some(InformationElementSemantics::default),
            Self::applicationCategoryName => Some(InformationElementSemantics::default),
            Self::applicationSubCategoryName => Some(InformationElementSemantics::default),
            Self::applicationGroupName => Some(InformationElementSemantics::default),
            Self::originalFlowsPresent => Some(InformationElementSemantics::deltaCounter),
            Self::originalFlowsInitiated => Some(InformationElementSemantics::deltaCounter),
            Self::originalFlowsCompleted => Some(InformationElementSemantics::deltaCounter),
            Self::distinctCountOfSourceIPAddress => Some(InformationElementSemantics::totalCounter),
            Self::distinctCountOfDestinationIPAddress => Some(InformationElementSemantics::totalCounter),
            Self::distinctCountOfSourceIPv4Address => Some(InformationElementSemantics::totalCounter),
            Self::distinctCountOfDestinationIPv4Address => Some(InformationElementSemantics::totalCounter),
            Self::distinctCountOfSourceIPv6Address => Some(InformationElementSemantics::totalCounter),
            Self::distinctCountOfDestinationIPv6Address => Some(InformationElementSemantics::totalCounter),
            Self::valueDistributionMethod => None,
            Self::rfc3550JitterMilliseconds => Some(InformationElementSemantics::quantity),
            Self::rfc3550JitterMicroseconds => Some(InformationElementSemantics::quantity),
            Self::rfc3550JitterNanoseconds => Some(InformationElementSemantics::quantity),
            Self::dot1qDEI => Some(InformationElementSemantics::default),
            Self::dot1qCustomerDEI => Some(InformationElementSemantics::default),
            Self::flowSelectorAlgorithm => Some(InformationElementSemantics::identifier),
            Self::flowSelectedOctetDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::flowSelectedPacketDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::flowSelectedFlowDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::selectorIDTotalFlowsObserved => None,
            Self::selectorIDTotalFlowsSelected => None,
            Self::samplingFlowInterval => None,
            Self::samplingFlowSpacing => None,
            Self::flowSamplingTimeInterval => None,
            Self::flowSamplingTimeSpacing => None,
            Self::hashFlowDomain => Some(InformationElementSemantics::identifier),
            Self::transportOctetDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::transportPacketDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::originalExporterIPv4Address => None,
            Self::originalExporterIPv6Address => None,
            Self::originalObservationDomainId => Some(InformationElementSemantics::identifier),
            Self::intermediateProcessId => Some(InformationElementSemantics::identifier),
            Self::ignoredDataRecordTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::dataLinkFrameType => Some(InformationElementSemantics::flags),
            Self::sectionOffset => Some(InformationElementSemantics::quantity),
            Self::sectionExportedOctets => Some(InformationElementSemantics::quantity),
            Self::dot1qServiceInstanceTag => Some(InformationElementSemantics::default),
            Self::dot1qServiceInstanceId => Some(InformationElementSemantics::identifier),
            Self::dot1qServiceInstancePriority => Some(InformationElementSemantics::identifier),
            Self::dot1qCustomerSourceMacAddress => Some(InformationElementSemantics::default),
            Self::dot1qCustomerDestinationMacAddress => Some(InformationElementSemantics::default),
            Self::postLayer2OctetDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::postMCastLayer2OctetDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::postLayer2OctetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::postMCastLayer2OctetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::minimumLayer2TotalLength => None,
            Self::maximumLayer2TotalLength => None,
            Self::droppedLayer2OctetDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::droppedLayer2OctetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::ignoredLayer2OctetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::notSentLayer2OctetTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::layer2OctetDeltaSumOfSquares => Some(InformationElementSemantics::deltaCounter),
            Self::layer2OctetTotalSumOfSquares => Some(InformationElementSemantics::totalCounter),
            Self::layer2FrameDeltaCount => Some(InformationElementSemantics::deltaCounter),
            Self::layer2FrameTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::pseudoWireDestinationIPv4Address => Some(InformationElementSemantics::default),
            Self::ignoredLayer2FrameTotalCount => Some(InformationElementSemantics::totalCounter),
            Self::mibObjectValueInteger => Some(InformationElementSemantics::quantity),
            Self::mibObjectValueOctetString => Some(InformationElementSemantics::default),
            Self::mibObjectValueOID => Some(InformationElementSemantics::default),
            Self::mibObjectValueBits => Some(InformationElementSemantics::flags),
            Self::mibObjectValueIPAddress => Some(InformationElementSemantics::default),
            Self::mibObjectValueCounter => Some(InformationElementSemantics::snmpCounter),
            Self::mibObjectValueGauge => Some(InformationElementSemantics::snmpGauge),
            Self::mibObjectValueTimeTicks => Some(InformationElementSemantics::quantity),
            Self::mibObjectValueUnsigned => Some(InformationElementSemantics::quantity),
            Self::mibObjectValueTable => Some(InformationElementSemantics::list),
            Self::mibObjectValueRow => Some(InformationElementSemantics::list),
            Self::mibObjectIdentifier => Some(InformationElementSemantics::default),
            Self::mibSubIdentifier => Some(InformationElementSemantics::identifier),
            Self::mibIndexIndicator => Some(InformationElementSemantics::flags),
            Self::mibCaptureTimeSemantics => Some(InformationElementSemantics::identifier),
            Self::mibContextEngineID => Some(InformationElementSemantics::default),
            Self::mibContextName => Some(InformationElementSemantics::default),
            Self::mibObjectName => Some(InformationElementSemantics::default),
            Self::mibObjectDescription => Some(InformationElementSemantics::default),
            Self::mibObjectSyntax => Some(InformationElementSemantics::default),
            Self::mibModuleName => Some(InformationElementSemantics::default),
            Self::mobileIMSI => Some(InformationElementSemantics::default),
            Self::mobileMSISDN => Some(InformationElementSemantics::default),
            Self::httpStatusCode => Some(InformationElementSemantics::identifier),
            Self::sourceTransportPortsLimit => Some(InformationElementSemantics::quantity),
            Self::httpRequestMethod => None,
            Self::httpRequestHost => None,
            Self::httpRequestTarget => None,
            Self::httpMessageVersion => None,
            Self::natInstanceID => Some(InformationElementSemantics::identifier),
            Self::internalAddressRealm => Some(InformationElementSemantics::identifier),
            Self::externalAddressRealm => Some(InformationElementSemantics::identifier),
            Self::natQuotaExceededEvent => Some(InformationElementSemantics::identifier),
            Self::natThresholdEvent => Some(InformationElementSemantics::identifier),
            Self::httpUserAgent => Some(InformationElementSemantics::default),
            Self::httpContentType => Some(InformationElementSemantics::default),
            Self::httpReasonPhrase => Some(InformationElementSemantics::default),
            Self::maxSessionEntries => Some(InformationElementSemantics::identifier),
            Self::maxBIBEntries => Some(InformationElementSemantics::identifier),
            Self::maxEntriesPerUser => Some(InformationElementSemantics::identifier),
            Self::maxSubscribers => Some(InformationElementSemantics::identifier),
            Self::maxFragmentsPendingReassembly => Some(InformationElementSemantics::identifier),
            Self::addressPoolHighThreshold => Some(InformationElementSemantics::identifier),
            Self::addressPoolLowThreshold => Some(InformationElementSemantics::identifier),
            Self::addressPortMappingHighThreshold => Some(InformationElementSemantics::identifier),
            Self::addressPortMappingLowThreshold => Some(InformationElementSemantics::identifier),
            Self::addressPortMappingPerUserHighThreshold => Some(InformationElementSemantics::identifier),
            Self::globalAddressMappingHighThreshold => Some(InformationElementSemantics::identifier),
            Self::vpnIdentifier => Some(InformationElementSemantics::default),
            Self::bgpCommunity => Some(InformationElementSemantics::identifier),
            Self::bgpSourceCommunityList => Some(InformationElementSemantics::list),
            Self::bgpDestinationCommunityList => Some(InformationElementSemantics::list),
            Self::bgpExtendedCommunity => Some(InformationElementSemantics::default),
            Self::bgpSourceExtendedCommunityList => Some(InformationElementSemantics::list),
            Self::bgpDestinationExtendedCommunityList => Some(InformationElementSemantics::list),
            Self::bgpLargeCommunity => Some(InformationElementSemantics::default),
            Self::bgpSourceLargeCommunityList => Some(InformationElementSemantics::list),
            Self::bgpDestinationLargeCommunityList => Some(InformationElementSemantics::list),
            Self::srhFlagsIPv6 => Some(InformationElementSemantics::flags),
            Self::srhTagIPv6 => Some(InformationElementSemantics::identifier),
            Self::srhSegmentIPv6 => Some(InformationElementSemantics::default),
            Self::srhActiveSegmentIPv6 => Some(InformationElementSemantics::default),
            Self::srhSegmentIPv6BasicList => Some(InformationElementSemantics::list),
            Self::srhSegmentIPv6ListSection => Some(InformationElementSemantics::default),
            Self::srhSegmentsIPv6Left => Some(InformationElementSemantics::quantity),
            Self::srhIPv6Section => Some(InformationElementSemantics::default),
            Self::srhIPv6ActiveSegmentType => Some(InformationElementSemantics::identifier),
            Self::srhSegmentIPv6LocatorLength => Some(InformationElementSemantics::default),
            Self::srhSegmentIPv6EndpointBehavior => Some(InformationElementSemantics::identifier),
            Self::transportChecksum => Some(InformationElementSemantics::default),
            Self::icmpHeaderPacketSection => Some(InformationElementSemantics::default),
            Self::gtpuFlags => Some(InformationElementSemantics::flags),
            Self::gtpuMsgType => Some(InformationElementSemantics::identifier),
            Self::gtpuTEid => Some(InformationElementSemantics::identifier),
            Self::gtpuSequenceNum => Some(InformationElementSemantics::identifier),
            Self::gtpuQFI => Some(InformationElementSemantics::identifier),
            Self::gtpuPduType => Some(InformationElementSemantics::identifier),
            Self::bgpSourceAsPathList => Some(InformationElementSemantics::list),
            Self::bgpDestinationAsPathList => Some(InformationElementSemantics::list),
            Self::ipv6ExtensionHeaderType => Some(InformationElementSemantics::identifier),
            Self::ipv6ExtensionHeaderCount => Some(InformationElementSemantics::totalCounter),
            Self::ipv6ExtensionHeadersFull => Some(InformationElementSemantics::flags),
            Self::ipv6ExtensionHeaderTypeCountList => Some(InformationElementSemantics::list),
            Self::ipv6ExtensionHeadersLimit => Some(InformationElementSemantics::default),
            Self::ipv6ExtensionHeadersChainLength => Some(InformationElementSemantics::identifier),
            Self::ipv6ExtensionHeaderChainLengthList => Some(InformationElementSemantics::list),
            Self::tcpOptionsFull => Some(InformationElementSemantics::flags),
            Self::tcpSharedOptionExID16 => Some(InformationElementSemantics::identifier),
            Self::tcpSharedOptionExID32 => Some(InformationElementSemantics::identifier),
            Self::tcpSharedOptionExID16List => Some(InformationElementSemantics::list),
            Self::tcpSharedOptionExID32List => Some(InformationElementSemantics::list),
        }
    }

    fn data_type(&self) -> InformationElementDataType {
        match self {
            Self::Unknown{..} => InformationElementDataType::octetArray,
            Self::Nokia(ie) => ie.data_type(),
            Self::NetGauze(ie) => ie.data_type(),
            Self::Cisco(ie) => ie.data_type(),
            Self::VMWare(ie) => ie.data_type(),
            Self::octetDeltaCount => InformationElementDataType::unsigned64,
            Self::packetDeltaCount => InformationElementDataType::unsigned64,
            Self::deltaFlowCount => InformationElementDataType::unsigned64,
            Self::protocolIdentifier => InformationElementDataType::unsigned8,
            Self::ipClassOfService => InformationElementDataType::unsigned8,
            Self::tcpControlBits => InformationElementDataType::unsigned16,
            Self::sourceTransportPort => InformationElementDataType::unsigned16,
            Self::sourceIPv4Address => InformationElementDataType::ipv4Address,
            Self::sourceIPv4PrefixLength => InformationElementDataType::unsigned8,
            Self::ingressInterface => InformationElementDataType::unsigned32,
            Self::destinationTransportPort => InformationElementDataType::unsigned16,
            Self::destinationIPv4Address => InformationElementDataType::ipv4Address,
            Self::destinationIPv4PrefixLength => InformationElementDataType::unsigned8,
            Self::egressInterface => InformationElementDataType::unsigned32,
            Self::ipNextHopIPv4Address => InformationElementDataType::ipv4Address,
            Self::bgpSourceAsNumber => InformationElementDataType::unsigned32,
            Self::bgpDestinationAsNumber => InformationElementDataType::unsigned32,
            Self::bgpNextHopIPv4Address => InformationElementDataType::ipv4Address,
            Self::postMCastPacketDeltaCount => InformationElementDataType::unsigned64,
            Self::postMCastOctetDeltaCount => InformationElementDataType::unsigned64,
            Self::flowEndSysUpTime => InformationElementDataType::unsigned32,
            Self::flowStartSysUpTime => InformationElementDataType::unsigned32,
            Self::postOctetDeltaCount => InformationElementDataType::unsigned64,
            Self::postPacketDeltaCount => InformationElementDataType::unsigned64,
            Self::minimumIpTotalLength => InformationElementDataType::unsigned64,
            Self::maximumIpTotalLength => InformationElementDataType::unsigned64,
            Self::sourceIPv6Address => InformationElementDataType::ipv6Address,
            Self::destinationIPv6Address => InformationElementDataType::ipv6Address,
            Self::sourceIPv6PrefixLength => InformationElementDataType::unsigned8,
            Self::destinationIPv6PrefixLength => InformationElementDataType::unsigned8,
            Self::flowLabelIPv6 => InformationElementDataType::unsigned32,
            Self::icmpTypeCodeIPv4 => InformationElementDataType::unsigned16,
            Self::igmpType => InformationElementDataType::unsigned8,
            Self::samplingInterval => InformationElementDataType::unsigned32,
            Self::samplingAlgorithm => InformationElementDataType::unsigned8,
            Self::flowActiveTimeout => InformationElementDataType::unsigned16,
            Self::flowIdleTimeout => InformationElementDataType::unsigned16,
            Self::engineType => InformationElementDataType::unsigned8,
            Self::engineId => InformationElementDataType::unsigned8,
            Self::exportedOctetTotalCount => InformationElementDataType::unsigned64,
            Self::exportedMessageTotalCount => InformationElementDataType::unsigned64,
            Self::exportedFlowRecordTotalCount => InformationElementDataType::unsigned64,
            Self::ipv4RouterSc => InformationElementDataType::ipv4Address,
            Self::sourceIPv4Prefix => InformationElementDataType::ipv4Address,
            Self::destinationIPv4Prefix => InformationElementDataType::ipv4Address,
            Self::mplsTopLabelType => InformationElementDataType::unsigned8,
            Self::mplsTopLabelIPv4Address => InformationElementDataType::ipv4Address,
            Self::samplerId => InformationElementDataType::unsigned32,
            Self::samplerMode => InformationElementDataType::unsigned8,
            Self::samplerRandomInterval => InformationElementDataType::unsigned32,
            Self::classId => InformationElementDataType::unsigned8,
            Self::minimumTTL => InformationElementDataType::unsigned8,
            Self::maximumTTL => InformationElementDataType::unsigned8,
            Self::fragmentIdentification => InformationElementDataType::unsigned32,
            Self::postIpClassOfService => InformationElementDataType::unsigned8,
            Self::sourceMacAddress => InformationElementDataType::macAddress,
            Self::postDestinationMacAddress => InformationElementDataType::macAddress,
            Self::vlanId => InformationElementDataType::unsigned16,
            Self::postVlanId => InformationElementDataType::unsigned16,
            Self::ipVersion => InformationElementDataType::unsigned8,
            Self::flowDirection => InformationElementDataType::unsigned8,
            Self::ipNextHopIPv6Address => InformationElementDataType::ipv6Address,
            Self::bgpNextHopIPv6Address => InformationElementDataType::ipv6Address,
            Self::ipv6ExtensionHeaders => InformationElementDataType::unsigned32,
            Self::mplsTopLabelStackSection => InformationElementDataType::octetArray,
            Self::mplsLabelStackSection2 => InformationElementDataType::octetArray,
            Self::mplsLabelStackSection3 => InformationElementDataType::octetArray,
            Self::mplsLabelStackSection4 => InformationElementDataType::octetArray,
            Self::mplsLabelStackSection5 => InformationElementDataType::octetArray,
            Self::mplsLabelStackSection6 => InformationElementDataType::octetArray,
            Self::mplsLabelStackSection7 => InformationElementDataType::octetArray,
            Self::mplsLabelStackSection8 => InformationElementDataType::octetArray,
            Self::mplsLabelStackSection9 => InformationElementDataType::octetArray,
            Self::mplsLabelStackSection10 => InformationElementDataType::octetArray,
            Self::destinationMacAddress => InformationElementDataType::macAddress,
            Self::postSourceMacAddress => InformationElementDataType::macAddress,
            Self::interfaceName => InformationElementDataType::string,
            Self::interfaceDescription => InformationElementDataType::string,
            Self::samplerName => InformationElementDataType::string,
            Self::octetTotalCount => InformationElementDataType::unsigned64,
            Self::packetTotalCount => InformationElementDataType::unsigned64,
            Self::flagsAndSamplerId => InformationElementDataType::unsigned32,
            Self::fragmentOffset => InformationElementDataType::unsigned16,
            Self::forwardingStatus => InformationElementDataType::unsigned32,
            Self::mplsVpnRouteDistinguisher => InformationElementDataType::octetArray,
            Self::mplsTopLabelPrefixLength => InformationElementDataType::unsigned8,
            Self::srcTrafficIndex => InformationElementDataType::unsigned32,
            Self::dstTrafficIndex => InformationElementDataType::unsigned32,
            Self::applicationDescription => InformationElementDataType::string,
            Self::applicationId => InformationElementDataType::octetArray,
            Self::applicationName => InformationElementDataType::string,
            Self::postIpDiffServCodePoint => InformationElementDataType::unsigned8,
            Self::multicastReplicationFactor => InformationElementDataType::unsigned32,
            Self::className => InformationElementDataType::string,
            Self::classificationEngineId => InformationElementDataType::unsigned8,
            Self::layer2packetSectionOffset => InformationElementDataType::unsigned16,
            Self::layer2packetSectionSize => InformationElementDataType::unsigned16,
            Self::layer2packetSectionData => InformationElementDataType::octetArray,
            Self::bgpNextAdjacentAsNumber => InformationElementDataType::unsigned32,
            Self::bgpPrevAdjacentAsNumber => InformationElementDataType::unsigned32,
            Self::exporterIPv4Address => InformationElementDataType::ipv4Address,
            Self::exporterIPv6Address => InformationElementDataType::ipv6Address,
            Self::droppedOctetDeltaCount => InformationElementDataType::unsigned64,
            Self::droppedPacketDeltaCount => InformationElementDataType::unsigned64,
            Self::droppedOctetTotalCount => InformationElementDataType::unsigned64,
            Self::droppedPacketTotalCount => InformationElementDataType::unsigned64,
            Self::flowEndReason => InformationElementDataType::unsigned8,
            Self::commonPropertiesId => InformationElementDataType::unsigned64,
            Self::observationPointId => InformationElementDataType::unsigned64,
            Self::icmpTypeCodeIPv6 => InformationElementDataType::unsigned16,
            Self::mplsTopLabelIPv6Address => InformationElementDataType::ipv6Address,
            Self::lineCardId => InformationElementDataType::unsigned32,
            Self::portId => InformationElementDataType::unsigned32,
            Self::meteringProcessId => InformationElementDataType::unsigned32,
            Self::exportingProcessId => InformationElementDataType::unsigned32,
            Self::templateId => InformationElementDataType::unsigned16,
            Self::wlanChannelId => InformationElementDataType::unsigned8,
            Self::wlanSSID => InformationElementDataType::string,
            Self::flowId => InformationElementDataType::unsigned64,
            Self::observationDomainId => InformationElementDataType::unsigned32,
            Self::flowStartSeconds => InformationElementDataType::dateTimeSeconds,
            Self::flowEndSeconds => InformationElementDataType::dateTimeSeconds,
            Self::flowStartMilliseconds => InformationElementDataType::dateTimeMilliseconds,
            Self::flowEndMilliseconds => InformationElementDataType::dateTimeMilliseconds,
            Self::flowStartMicroseconds => InformationElementDataType::dateTimeMicroseconds,
            Self::flowEndMicroseconds => InformationElementDataType::dateTimeMicroseconds,
            Self::flowStartNanoseconds => InformationElementDataType::dateTimeNanoseconds,
            Self::flowEndNanoseconds => InformationElementDataType::dateTimeNanoseconds,
            Self::flowStartDeltaMicroseconds => InformationElementDataType::unsigned32,
            Self::flowEndDeltaMicroseconds => InformationElementDataType::unsigned32,
            Self::systemInitTimeMilliseconds => InformationElementDataType::dateTimeMilliseconds,
            Self::flowDurationMilliseconds => InformationElementDataType::unsigned32,
            Self::flowDurationMicroseconds => InformationElementDataType::unsigned32,
            Self::observedFlowTotalCount => InformationElementDataType::unsigned64,
            Self::ignoredPacketTotalCount => InformationElementDataType::unsigned64,
            Self::ignoredOctetTotalCount => InformationElementDataType::unsigned64,
            Self::notSentFlowTotalCount => InformationElementDataType::unsigned64,
            Self::notSentPacketTotalCount => InformationElementDataType::unsigned64,
            Self::notSentOctetTotalCount => InformationElementDataType::unsigned64,
            Self::destinationIPv6Prefix => InformationElementDataType::ipv6Address,
            Self::sourceIPv6Prefix => InformationElementDataType::ipv6Address,
            Self::postOctetTotalCount => InformationElementDataType::unsigned64,
            Self::postPacketTotalCount => InformationElementDataType::unsigned64,
            Self::flowKeyIndicator => InformationElementDataType::unsigned64,
            Self::postMCastPacketTotalCount => InformationElementDataType::unsigned64,
            Self::postMCastOctetTotalCount => InformationElementDataType::unsigned64,
            Self::icmpTypeIPv4 => InformationElementDataType::unsigned8,
            Self::icmpCodeIPv4 => InformationElementDataType::unsigned8,
            Self::icmpTypeIPv6 => InformationElementDataType::unsigned8,
            Self::icmpCodeIPv6 => InformationElementDataType::unsigned8,
            Self::udpSourcePort => InformationElementDataType::unsigned16,
            Self::udpDestinationPort => InformationElementDataType::unsigned16,
            Self::tcpSourcePort => InformationElementDataType::unsigned16,
            Self::tcpDestinationPort => InformationElementDataType::unsigned16,
            Self::tcpSequenceNumber => InformationElementDataType::unsigned32,
            Self::tcpAcknowledgementNumber => InformationElementDataType::unsigned32,
            Self::tcpWindowSize => InformationElementDataType::unsigned16,
            Self::tcpUrgentPointer => InformationElementDataType::unsigned16,
            Self::tcpHeaderLength => InformationElementDataType::unsigned8,
            Self::ipHeaderLength => InformationElementDataType::unsigned8,
            Self::totalLengthIPv4 => InformationElementDataType::unsigned16,
            Self::payloadLengthIPv6 => InformationElementDataType::unsigned16,
            Self::ipTTL => InformationElementDataType::unsigned8,
            Self::nextHeaderIPv6 => InformationElementDataType::unsigned8,
            Self::mplsPayloadLength => InformationElementDataType::unsigned32,
            Self::ipDiffServCodePoint => InformationElementDataType::unsigned8,
            Self::ipPrecedence => InformationElementDataType::unsigned8,
            Self::fragmentFlags => InformationElementDataType::unsigned8,
            Self::octetDeltaSumOfSquares => InformationElementDataType::unsigned64,
            Self::octetTotalSumOfSquares => InformationElementDataType::unsigned64,
            Self::mplsTopLabelTTL => InformationElementDataType::unsigned8,
            Self::mplsLabelStackLength => InformationElementDataType::unsigned32,
            Self::mplsLabelStackDepth => InformationElementDataType::unsigned32,
            Self::mplsTopLabelExp => InformationElementDataType::unsigned8,
            Self::ipPayloadLength => InformationElementDataType::unsigned32,
            Self::udpMessageLength => InformationElementDataType::unsigned16,
            Self::isMulticast => InformationElementDataType::unsigned8,
            Self::ipv4IHL => InformationElementDataType::unsigned8,
            Self::ipv4Options => InformationElementDataType::unsigned32,
            Self::tcpOptions => InformationElementDataType::unsigned64,
            Self::paddingOctets => InformationElementDataType::octetArray,
            Self::collectorIPv4Address => InformationElementDataType::ipv4Address,
            Self::collectorIPv6Address => InformationElementDataType::ipv6Address,
            Self::exportInterface => InformationElementDataType::unsigned32,
            Self::exportProtocolVersion => InformationElementDataType::unsigned8,
            Self::exportTransportProtocol => InformationElementDataType::unsigned8,
            Self::collectorTransportPort => InformationElementDataType::unsigned16,
            Self::exporterTransportPort => InformationElementDataType::unsigned16,
            Self::tcpSynTotalCount => InformationElementDataType::unsigned64,
            Self::tcpFinTotalCount => InformationElementDataType::unsigned64,
            Self::tcpRstTotalCount => InformationElementDataType::unsigned64,
            Self::tcpPshTotalCount => InformationElementDataType::unsigned64,
            Self::tcpAckTotalCount => InformationElementDataType::unsigned64,
            Self::tcpUrgTotalCount => InformationElementDataType::unsigned64,
            Self::ipTotalLength => InformationElementDataType::unsigned64,
            Self::postNATSourceIPv4Address => InformationElementDataType::ipv4Address,
            Self::postNATDestinationIPv4Address => InformationElementDataType::ipv4Address,
            Self::postNAPTSourceTransportPort => InformationElementDataType::unsigned16,
            Self::postNAPTDestinationTransportPort => InformationElementDataType::unsigned16,
            Self::natOriginatingAddressRealm => InformationElementDataType::unsigned8,
            Self::natEvent => InformationElementDataType::unsigned8,
            Self::initiatorOctets => InformationElementDataType::unsigned64,
            Self::responderOctets => InformationElementDataType::unsigned64,
            Self::firewallEvent => InformationElementDataType::unsigned8,
            Self::ingressVRFID => InformationElementDataType::unsigned32,
            Self::egressVRFID => InformationElementDataType::unsigned32,
            Self::VRFname => InformationElementDataType::string,
            Self::postMplsTopLabelExp => InformationElementDataType::unsigned8,
            Self::tcpWindowScale => InformationElementDataType::unsigned16,
            Self::biflowDirection => InformationElementDataType::unsigned8,
            Self::ethernetHeaderLength => InformationElementDataType::unsigned8,
            Self::ethernetPayloadLength => InformationElementDataType::unsigned16,
            Self::ethernetTotalLength => InformationElementDataType::unsigned16,
            Self::dot1qVlanId => InformationElementDataType::unsigned16,
            Self::dot1qPriority => InformationElementDataType::unsigned8,
            Self::dot1qCustomerVlanId => InformationElementDataType::unsigned16,
            Self::dot1qCustomerPriority => InformationElementDataType::unsigned8,
            Self::metroEvcId => InformationElementDataType::string,
            Self::metroEvcType => InformationElementDataType::unsigned8,
            Self::pseudoWireId => InformationElementDataType::unsigned32,
            Self::pseudoWireType => InformationElementDataType::unsigned16,
            Self::pseudoWireControlWord => InformationElementDataType::unsigned32,
            Self::ingressPhysicalInterface => InformationElementDataType::unsigned32,
            Self::egressPhysicalInterface => InformationElementDataType::unsigned32,
            Self::postDot1qVlanId => InformationElementDataType::unsigned16,
            Self::postDot1qCustomerVlanId => InformationElementDataType::unsigned16,
            Self::ethernetType => InformationElementDataType::unsigned16,
            Self::postIpPrecedence => InformationElementDataType::unsigned8,
            Self::collectionTimeMilliseconds => InformationElementDataType::dateTimeMilliseconds,
            Self::exportSctpStreamId => InformationElementDataType::unsigned16,
            Self::maxExportSeconds => InformationElementDataType::dateTimeSeconds,
            Self::maxFlowEndSeconds => InformationElementDataType::dateTimeSeconds,
            Self::messageMD5Checksum => InformationElementDataType::octetArray,
            Self::messageScope => InformationElementDataType::unsigned8,
            Self::minExportSeconds => InformationElementDataType::dateTimeSeconds,
            Self::minFlowStartSeconds => InformationElementDataType::dateTimeSeconds,
            Self::opaqueOctets => InformationElementDataType::octetArray,
            Self::sessionScope => InformationElementDataType::unsigned8,
            Self::maxFlowEndMicroseconds => InformationElementDataType::dateTimeMicroseconds,
            Self::maxFlowEndMilliseconds => InformationElementDataType::dateTimeMilliseconds,
            Self::maxFlowEndNanoseconds => InformationElementDataType::dateTimeNanoseconds,
            Self::minFlowStartMicroseconds => InformationElementDataType::dateTimeMicroseconds,
            Self::minFlowStartMilliseconds => InformationElementDataType::dateTimeMilliseconds,
            Self::minFlowStartNanoseconds => InformationElementDataType::dateTimeNanoseconds,
            Self::collectorCertificate => InformationElementDataType::octetArray,
            Self::exporterCertificate => InformationElementDataType::octetArray,
            Self::dataRecordsReliability => InformationElementDataType::boolean,
            Self::observationPointType => InformationElementDataType::unsigned8,
            Self::newConnectionDeltaCount => InformationElementDataType::unsigned32,
            Self::connectionSumDurationSeconds => InformationElementDataType::unsigned64,
            Self::connectionTransactionId => InformationElementDataType::unsigned64,
            Self::postNATSourceIPv6Address => InformationElementDataType::ipv6Address,
            Self::postNATDestinationIPv6Address => InformationElementDataType::ipv6Address,
            Self::natPoolId => InformationElementDataType::unsigned32,
            Self::natPoolName => InformationElementDataType::string,
            Self::anonymizationFlags => InformationElementDataType::unsigned16,
            Self::anonymizationTechnique => InformationElementDataType::unsigned16,
            Self::informationElementIndex => InformationElementDataType::unsigned16,
            Self::p2pTechnology => InformationElementDataType::string,
            Self::tunnelTechnology => InformationElementDataType::string,
            Self::encryptedTechnology => InformationElementDataType::string,
            Self::basicList => InformationElementDataType::basicList,
            Self::subTemplateList => InformationElementDataType::subTemplateList,
            Self::subTemplateMultiList => InformationElementDataType::subTemplateMultiList,
            Self::bgpValidityState => InformationElementDataType::unsigned8,
            Self::IPSecSPI => InformationElementDataType::unsigned32,
            Self::greKey => InformationElementDataType::unsigned32,
            Self::natType => InformationElementDataType::unsigned8,
            Self::initiatorPackets => InformationElementDataType::unsigned64,
            Self::responderPackets => InformationElementDataType::unsigned64,
            Self::observationDomainName => InformationElementDataType::string,
            Self::selectionSequenceId => InformationElementDataType::unsigned64,
            Self::selectorId => InformationElementDataType::unsigned64,
            Self::informationElementId => InformationElementDataType::unsigned16,
            Self::selectorAlgorithm => InformationElementDataType::unsigned16,
            Self::samplingPacketInterval => InformationElementDataType::unsigned32,
            Self::samplingPacketSpace => InformationElementDataType::unsigned32,
            Self::samplingTimeInterval => InformationElementDataType::unsigned32,
            Self::samplingTimeSpace => InformationElementDataType::unsigned32,
            Self::samplingSize => InformationElementDataType::unsigned32,
            Self::samplingPopulation => InformationElementDataType::unsigned32,
            Self::samplingProbability => InformationElementDataType::float64,
            Self::dataLinkFrameSize => InformationElementDataType::unsigned16,
            Self::ipHeaderPacketSection => InformationElementDataType::octetArray,
            Self::ipPayloadPacketSection => InformationElementDataType::octetArray,
            Self::dataLinkFrameSection => InformationElementDataType::octetArray,
            Self::mplsLabelStackSection => InformationElementDataType::octetArray,
            Self::mplsPayloadPacketSection => InformationElementDataType::octetArray,
            Self::selectorIdTotalPktsObserved => InformationElementDataType::unsigned64,
            Self::selectorIdTotalPktsSelected => InformationElementDataType::unsigned64,
            Self::absoluteError => InformationElementDataType::float64,
            Self::relativeError => InformationElementDataType::float64,
            Self::observationTimeSeconds => InformationElementDataType::dateTimeSeconds,
            Self::observationTimeMilliseconds => InformationElementDataType::dateTimeMilliseconds,
            Self::observationTimeMicroseconds => InformationElementDataType::dateTimeMicroseconds,
            Self::observationTimeNanoseconds => InformationElementDataType::dateTimeNanoseconds,
            Self::digestHashValue => InformationElementDataType::unsigned64,
            Self::hashIPPayloadOffset => InformationElementDataType::unsigned64,
            Self::hashIPPayloadSize => InformationElementDataType::unsigned64,
            Self::hashOutputRangeMin => InformationElementDataType::unsigned64,
            Self::hashOutputRangeMax => InformationElementDataType::unsigned64,
            Self::hashSelectedRangeMin => InformationElementDataType::unsigned64,
            Self::hashSelectedRangeMax => InformationElementDataType::unsigned64,
            Self::hashDigestOutput => InformationElementDataType::boolean,
            Self::hashInitialiserValue => InformationElementDataType::unsigned64,
            Self::selectorName => InformationElementDataType::string,
            Self::upperCILimit => InformationElementDataType::float64,
            Self::lowerCILimit => InformationElementDataType::float64,
            Self::confidenceLevel => InformationElementDataType::float64,
            Self::informationElementDataType => InformationElementDataType::unsigned8,
            Self::informationElementDescription => InformationElementDataType::string,
            Self::informationElementName => InformationElementDataType::string,
            Self::informationElementRangeBegin => InformationElementDataType::unsigned64,
            Self::informationElementRangeEnd => InformationElementDataType::unsigned64,
            Self::informationElementSemantics => InformationElementDataType::unsigned8,
            Self::informationElementUnits => InformationElementDataType::unsigned16,
            Self::privateEnterpriseNumber => InformationElementDataType::unsigned32,
            Self::virtualStationInterfaceId => InformationElementDataType::octetArray,
            Self::virtualStationInterfaceName => InformationElementDataType::string,
            Self::virtualStationUUID => InformationElementDataType::octetArray,
            Self::virtualStationName => InformationElementDataType::string,
            Self::layer2SegmentId => InformationElementDataType::unsigned64,
            Self::layer2OctetDeltaCount => InformationElementDataType::unsigned64,
            Self::layer2OctetTotalCount => InformationElementDataType::unsigned64,
            Self::ingressUnicastPacketTotalCount => InformationElementDataType::unsigned64,
            Self::ingressMulticastPacketTotalCount => InformationElementDataType::unsigned64,
            Self::ingressBroadcastPacketTotalCount => InformationElementDataType::unsigned64,
            Self::egressUnicastPacketTotalCount => InformationElementDataType::unsigned64,
            Self::egressBroadcastPacketTotalCount => InformationElementDataType::unsigned64,
            Self::monitoringIntervalStartMilliSeconds => InformationElementDataType::dateTimeMilliseconds,
            Self::monitoringIntervalEndMilliSeconds => InformationElementDataType::dateTimeMilliseconds,
            Self::portRangeStart => InformationElementDataType::unsigned16,
            Self::portRangeEnd => InformationElementDataType::unsigned16,
            Self::portRangeStepSize => InformationElementDataType::unsigned16,
            Self::portRangeNumPorts => InformationElementDataType::unsigned16,
            Self::staMacAddress => InformationElementDataType::macAddress,
            Self::staIPv4Address => InformationElementDataType::ipv4Address,
            Self::wtpMacAddress => InformationElementDataType::macAddress,
            Self::ingressInterfaceType => InformationElementDataType::unsigned32,
            Self::egressInterfaceType => InformationElementDataType::unsigned32,
            Self::rtpSequenceNumber => InformationElementDataType::unsigned16,
            Self::userName => InformationElementDataType::string,
            Self::applicationCategoryName => InformationElementDataType::string,
            Self::applicationSubCategoryName => InformationElementDataType::string,
            Self::applicationGroupName => InformationElementDataType::string,
            Self::originalFlowsPresent => InformationElementDataType::unsigned64,
            Self::originalFlowsInitiated => InformationElementDataType::unsigned64,
            Self::originalFlowsCompleted => InformationElementDataType::unsigned64,
            Self::distinctCountOfSourceIPAddress => InformationElementDataType::unsigned64,
            Self::distinctCountOfDestinationIPAddress => InformationElementDataType::unsigned64,
            Self::distinctCountOfSourceIPv4Address => InformationElementDataType::unsigned32,
            Self::distinctCountOfDestinationIPv4Address => InformationElementDataType::unsigned32,
            Self::distinctCountOfSourceIPv6Address => InformationElementDataType::unsigned64,
            Self::distinctCountOfDestinationIPv6Address => InformationElementDataType::unsigned64,
            Self::valueDistributionMethod => InformationElementDataType::unsigned8,
            Self::rfc3550JitterMilliseconds => InformationElementDataType::unsigned32,
            Self::rfc3550JitterMicroseconds => InformationElementDataType::unsigned32,
            Self::rfc3550JitterNanoseconds => InformationElementDataType::unsigned32,
            Self::dot1qDEI => InformationElementDataType::boolean,
            Self::dot1qCustomerDEI => InformationElementDataType::boolean,
            Self::flowSelectorAlgorithm => InformationElementDataType::unsigned16,
            Self::flowSelectedOctetDeltaCount => InformationElementDataType::unsigned64,
            Self::flowSelectedPacketDeltaCount => InformationElementDataType::unsigned64,
            Self::flowSelectedFlowDeltaCount => InformationElementDataType::unsigned64,
            Self::selectorIDTotalFlowsObserved => InformationElementDataType::unsigned64,
            Self::selectorIDTotalFlowsSelected => InformationElementDataType::unsigned64,
            Self::samplingFlowInterval => InformationElementDataType::unsigned64,
            Self::samplingFlowSpacing => InformationElementDataType::unsigned64,
            Self::flowSamplingTimeInterval => InformationElementDataType::unsigned64,
            Self::flowSamplingTimeSpacing => InformationElementDataType::unsigned64,
            Self::hashFlowDomain => InformationElementDataType::unsigned16,
            Self::transportOctetDeltaCount => InformationElementDataType::unsigned64,
            Self::transportPacketDeltaCount => InformationElementDataType::unsigned64,
            Self::originalExporterIPv4Address => InformationElementDataType::ipv4Address,
            Self::originalExporterIPv6Address => InformationElementDataType::ipv6Address,
            Self::originalObservationDomainId => InformationElementDataType::unsigned32,
            Self::intermediateProcessId => InformationElementDataType::unsigned32,
            Self::ignoredDataRecordTotalCount => InformationElementDataType::unsigned64,
            Self::dataLinkFrameType => InformationElementDataType::unsigned16,
            Self::sectionOffset => InformationElementDataType::unsigned16,
            Self::sectionExportedOctets => InformationElementDataType::unsigned16,
            Self::dot1qServiceInstanceTag => InformationElementDataType::octetArray,
            Self::dot1qServiceInstanceId => InformationElementDataType::unsigned32,
            Self::dot1qServiceInstancePriority => InformationElementDataType::unsigned8,
            Self::dot1qCustomerSourceMacAddress => InformationElementDataType::macAddress,
            Self::dot1qCustomerDestinationMacAddress => InformationElementDataType::macAddress,
            Self::postLayer2OctetDeltaCount => InformationElementDataType::unsigned64,
            Self::postMCastLayer2OctetDeltaCount => InformationElementDataType::unsigned64,
            Self::postLayer2OctetTotalCount => InformationElementDataType::unsigned64,
            Self::postMCastLayer2OctetTotalCount => InformationElementDataType::unsigned64,
            Self::minimumLayer2TotalLength => InformationElementDataType::unsigned64,
            Self::maximumLayer2TotalLength => InformationElementDataType::unsigned64,
            Self::droppedLayer2OctetDeltaCount => InformationElementDataType::unsigned64,
            Self::droppedLayer2OctetTotalCount => InformationElementDataType::unsigned64,
            Self::ignoredLayer2OctetTotalCount => InformationElementDataType::unsigned64,
            Self::notSentLayer2OctetTotalCount => InformationElementDataType::unsigned64,
            Self::layer2OctetDeltaSumOfSquares => InformationElementDataType::unsigned64,
            Self::layer2OctetTotalSumOfSquares => InformationElementDataType::unsigned64,
            Self::layer2FrameDeltaCount => InformationElementDataType::unsigned64,
            Self::layer2FrameTotalCount => InformationElementDataType::unsigned64,
            Self::pseudoWireDestinationIPv4Address => InformationElementDataType::ipv4Address,
            Self::ignoredLayer2FrameTotalCount => InformationElementDataType::unsigned64,
            Self::mibObjectValueInteger => InformationElementDataType::signed32,
            Self::mibObjectValueOctetString => InformationElementDataType::octetArray,
            Self::mibObjectValueOID => InformationElementDataType::octetArray,
            Self::mibObjectValueBits => InformationElementDataType::octetArray,
            Self::mibObjectValueIPAddress => InformationElementDataType::ipv4Address,
            Self::mibObjectValueCounter => InformationElementDataType::unsigned64,
            Self::mibObjectValueGauge => InformationElementDataType::unsigned32,
            Self::mibObjectValueTimeTicks => InformationElementDataType::unsigned32,
            Self::mibObjectValueUnsigned => InformationElementDataType::unsigned32,
            Self::mibObjectValueTable => InformationElementDataType::subTemplateList,
            Self::mibObjectValueRow => InformationElementDataType::subTemplateList,
            Self::mibObjectIdentifier => InformationElementDataType::octetArray,
            Self::mibSubIdentifier => InformationElementDataType::unsigned32,
            Self::mibIndexIndicator => InformationElementDataType::unsigned64,
            Self::mibCaptureTimeSemantics => InformationElementDataType::unsigned8,
            Self::mibContextEngineID => InformationElementDataType::octetArray,
            Self::mibContextName => InformationElementDataType::string,
            Self::mibObjectName => InformationElementDataType::string,
            Self::mibObjectDescription => InformationElementDataType::string,
            Self::mibObjectSyntax => InformationElementDataType::string,
            Self::mibModuleName => InformationElementDataType::string,
            Self::mobileIMSI => InformationElementDataType::string,
            Self::mobileMSISDN => InformationElementDataType::string,
            Self::httpStatusCode => InformationElementDataType::unsigned16,
            Self::sourceTransportPortsLimit => InformationElementDataType::unsigned16,
            Self::httpRequestMethod => InformationElementDataType::string,
            Self::httpRequestHost => InformationElementDataType::string,
            Self::httpRequestTarget => InformationElementDataType::string,
            Self::httpMessageVersion => InformationElementDataType::string,
            Self::natInstanceID => InformationElementDataType::unsigned32,
            Self::internalAddressRealm => InformationElementDataType::octetArray,
            Self::externalAddressRealm => InformationElementDataType::octetArray,
            Self::natQuotaExceededEvent => InformationElementDataType::unsigned32,
            Self::natThresholdEvent => InformationElementDataType::unsigned32,
            Self::httpUserAgent => InformationElementDataType::string,
            Self::httpContentType => InformationElementDataType::string,
            Self::httpReasonPhrase => InformationElementDataType::string,
            Self::maxSessionEntries => InformationElementDataType::unsigned32,
            Self::maxBIBEntries => InformationElementDataType::unsigned32,
            Self::maxEntriesPerUser => InformationElementDataType::unsigned32,
            Self::maxSubscribers => InformationElementDataType::unsigned32,
            Self::maxFragmentsPendingReassembly => InformationElementDataType::unsigned32,
            Self::addressPoolHighThreshold => InformationElementDataType::unsigned32,
            Self::addressPoolLowThreshold => InformationElementDataType::unsigned32,
            Self::addressPortMappingHighThreshold => InformationElementDataType::unsigned32,
            Self::addressPortMappingLowThreshold => InformationElementDataType::unsigned32,
            Self::addressPortMappingPerUserHighThreshold => InformationElementDataType::unsigned32,
            Self::globalAddressMappingHighThreshold => InformationElementDataType::unsigned32,
            Self::vpnIdentifier => InformationElementDataType::octetArray,
            Self::bgpCommunity => InformationElementDataType::unsigned32,
            Self::bgpSourceCommunityList => InformationElementDataType::basicList,
            Self::bgpDestinationCommunityList => InformationElementDataType::basicList,
            Self::bgpExtendedCommunity => InformationElementDataType::octetArray,
            Self::bgpSourceExtendedCommunityList => InformationElementDataType::basicList,
            Self::bgpDestinationExtendedCommunityList => InformationElementDataType::basicList,
            Self::bgpLargeCommunity => InformationElementDataType::octetArray,
            Self::bgpSourceLargeCommunityList => InformationElementDataType::basicList,
            Self::bgpDestinationLargeCommunityList => InformationElementDataType::basicList,
            Self::srhFlagsIPv6 => InformationElementDataType::unsigned8,
            Self::srhTagIPv6 => InformationElementDataType::unsigned16,
            Self::srhSegmentIPv6 => InformationElementDataType::ipv6Address,
            Self::srhActiveSegmentIPv6 => InformationElementDataType::ipv6Address,
            Self::srhSegmentIPv6BasicList => InformationElementDataType::basicList,
            Self::srhSegmentIPv6ListSection => InformationElementDataType::octetArray,
            Self::srhSegmentsIPv6Left => InformationElementDataType::unsigned8,
            Self::srhIPv6Section => InformationElementDataType::octetArray,
            Self::srhIPv6ActiveSegmentType => InformationElementDataType::unsigned8,
            Self::srhSegmentIPv6LocatorLength => InformationElementDataType::unsigned8,
            Self::srhSegmentIPv6EndpointBehavior => InformationElementDataType::unsigned16,
            Self::transportChecksum => InformationElementDataType::unsigned16,
            Self::icmpHeaderPacketSection => InformationElementDataType::octetArray,
            Self::gtpuFlags => InformationElementDataType::unsigned8,
            Self::gtpuMsgType => InformationElementDataType::unsigned8,
            Self::gtpuTEid => InformationElementDataType::unsigned32,
            Self::gtpuSequenceNum => InformationElementDataType::unsigned16,
            Self::gtpuQFI => InformationElementDataType::unsigned8,
            Self::gtpuPduType => InformationElementDataType::unsigned8,
            Self::bgpSourceAsPathList => InformationElementDataType::basicList,
            Self::bgpDestinationAsPathList => InformationElementDataType::basicList,
            Self::ipv6ExtensionHeaderType => InformationElementDataType::unsigned8,
            Self::ipv6ExtensionHeaderCount => InformationElementDataType::unsigned8,
            Self::ipv6ExtensionHeadersFull => InformationElementDataType::unsigned256,
            Self::ipv6ExtensionHeaderTypeCountList => InformationElementDataType::subTemplateList,
            Self::ipv6ExtensionHeadersLimit => InformationElementDataType::boolean,
            Self::ipv6ExtensionHeadersChainLength => InformationElementDataType::unsigned32,
            Self::ipv6ExtensionHeaderChainLengthList => InformationElementDataType::subTemplateList,
            Self::tcpOptionsFull => InformationElementDataType::unsigned256,
            Self::tcpSharedOptionExID16 => InformationElementDataType::unsigned16,
            Self::tcpSharedOptionExID32 => InformationElementDataType::unsigned32,
            Self::tcpSharedOptionExID16List => InformationElementDataType::basicList,
            Self::tcpSharedOptionExID32List => InformationElementDataType::basicList,
        }
    }

    fn units(&self) -> Option<InformationElementUnits> {
        match self {
            Self::Unknown{..} => None,
            Self::Nokia(ie) => ie.units(),
            Self::NetGauze(ie) => ie.units(),
            Self::Cisco(ie) => ie.units(),
            Self::VMWare(ie) => ie.units(),
            Self::octetDeltaCount => Some(super::InformationElementUnits::octets),
            Self::packetDeltaCount => Some(super::InformationElementUnits::packets),
            Self::deltaFlowCount => Some(super::InformationElementUnits::flows),
            Self::protocolIdentifier => None,
            Self::ipClassOfService => None,
            Self::tcpControlBits => None,
            Self::sourceTransportPort => None,
            Self::sourceIPv4Address => None,
            Self::sourceIPv4PrefixLength => Some(super::InformationElementUnits::bits),
            Self::ingressInterface => None,
            Self::destinationTransportPort => None,
            Self::destinationIPv4Address => None,
            Self::destinationIPv4PrefixLength => Some(super::InformationElementUnits::bits),
            Self::egressInterface => None,
            Self::ipNextHopIPv4Address => None,
            Self::bgpSourceAsNumber => None,
            Self::bgpDestinationAsNumber => None,
            Self::bgpNextHopIPv4Address => None,
            Self::postMCastPacketDeltaCount => Some(super::InformationElementUnits::packets),
            Self::postMCastOctetDeltaCount => Some(super::InformationElementUnits::octets),
            Self::flowEndSysUpTime => Some(super::InformationElementUnits::milliseconds),
            Self::flowStartSysUpTime => Some(super::InformationElementUnits::milliseconds),
            Self::postOctetDeltaCount => Some(super::InformationElementUnits::octets),
            Self::postPacketDeltaCount => Some(super::InformationElementUnits::packets),
            Self::minimumIpTotalLength => Some(super::InformationElementUnits::octets),
            Self::maximumIpTotalLength => Some(super::InformationElementUnits::octets),
            Self::sourceIPv6Address => None,
            Self::destinationIPv6Address => None,
            Self::sourceIPv6PrefixLength => Some(super::InformationElementUnits::bits),
            Self::destinationIPv6PrefixLength => Some(super::InformationElementUnits::bits),
            Self::flowLabelIPv6 => None,
            Self::icmpTypeCodeIPv4 => None,
            Self::igmpType => None,
            Self::samplingInterval => Some(super::InformationElementUnits::packets),
            Self::samplingAlgorithm => None,
            Self::flowActiveTimeout => Some(super::InformationElementUnits::seconds),
            Self::flowIdleTimeout => Some(super::InformationElementUnits::seconds),
            Self::engineType => None,
            Self::engineId => None,
            Self::exportedOctetTotalCount => Some(super::InformationElementUnits::octets),
            Self::exportedMessageTotalCount => Some(super::InformationElementUnits::messages),
            Self::exportedFlowRecordTotalCount => Some(super::InformationElementUnits::flows),
            Self::ipv4RouterSc => None,
            Self::sourceIPv4Prefix => None,
            Self::destinationIPv4Prefix => None,
            Self::mplsTopLabelType => None,
            Self::mplsTopLabelIPv4Address => None,
            Self::samplerId => None,
            Self::samplerMode => None,
            Self::samplerRandomInterval => None,
            Self::classId => None,
            Self::minimumTTL => Some(super::InformationElementUnits::hops),
            Self::maximumTTL => Some(super::InformationElementUnits::hops),
            Self::fragmentIdentification => None,
            Self::postIpClassOfService => None,
            Self::sourceMacAddress => None,
            Self::postDestinationMacAddress => None,
            Self::vlanId => None,
            Self::postVlanId => None,
            Self::ipVersion => None,
            Self::flowDirection => None,
            Self::ipNextHopIPv6Address => None,
            Self::bgpNextHopIPv6Address => None,
            Self::ipv6ExtensionHeaders => None,
            Self::mplsTopLabelStackSection => None,
            Self::mplsLabelStackSection2 => None,
            Self::mplsLabelStackSection3 => None,
            Self::mplsLabelStackSection4 => None,
            Self::mplsLabelStackSection5 => None,
            Self::mplsLabelStackSection6 => None,
            Self::mplsLabelStackSection7 => None,
            Self::mplsLabelStackSection8 => None,
            Self::mplsLabelStackSection9 => None,
            Self::mplsLabelStackSection10 => None,
            Self::destinationMacAddress => None,
            Self::postSourceMacAddress => None,
            Self::interfaceName => None,
            Self::interfaceDescription => None,
            Self::samplerName => None,
            Self::octetTotalCount => Some(super::InformationElementUnits::octets),
            Self::packetTotalCount => Some(super::InformationElementUnits::packets),
            Self::flagsAndSamplerId => None,
            Self::fragmentOffset => None,
            Self::forwardingStatus => None,
            Self::mplsVpnRouteDistinguisher => None,
            Self::mplsTopLabelPrefixLength => Some(super::InformationElementUnits::bits),
            Self::srcTrafficIndex => None,
            Self::dstTrafficIndex => None,
            Self::applicationDescription => None,
            Self::applicationId => None,
            Self::applicationName => None,
            Self::postIpDiffServCodePoint => None,
            Self::multicastReplicationFactor => None,
            Self::className => None,
            Self::classificationEngineId => None,
            Self::layer2packetSectionOffset => None,
            Self::layer2packetSectionSize => None,
            Self::layer2packetSectionData => None,
            Self::bgpNextAdjacentAsNumber => None,
            Self::bgpPrevAdjacentAsNumber => None,
            Self::exporterIPv4Address => None,
            Self::exporterIPv6Address => None,
            Self::droppedOctetDeltaCount => Some(super::InformationElementUnits::octets),
            Self::droppedPacketDeltaCount => Some(super::InformationElementUnits::packets),
            Self::droppedOctetTotalCount => Some(super::InformationElementUnits::octets),
            Self::droppedPacketTotalCount => Some(super::InformationElementUnits::packets),
            Self::flowEndReason => None,
            Self::commonPropertiesId => None,
            Self::observationPointId => None,
            Self::icmpTypeCodeIPv6 => None,
            Self::mplsTopLabelIPv6Address => None,
            Self::lineCardId => None,
            Self::portId => None,
            Self::meteringProcessId => None,
            Self::exportingProcessId => None,
            Self::templateId => None,
            Self::wlanChannelId => None,
            Self::wlanSSID => None,
            Self::flowId => None,
            Self::observationDomainId => None,
            Self::flowStartSeconds => Some(super::InformationElementUnits::seconds),
            Self::flowEndSeconds => Some(super::InformationElementUnits::seconds),
            Self::flowStartMilliseconds => Some(super::InformationElementUnits::milliseconds),
            Self::flowEndMilliseconds => Some(super::InformationElementUnits::milliseconds),
            Self::flowStartMicroseconds => Some(super::InformationElementUnits::microseconds),
            Self::flowEndMicroseconds => Some(super::InformationElementUnits::microseconds),
            Self::flowStartNanoseconds => Some(super::InformationElementUnits::nanoseconds),
            Self::flowEndNanoseconds => Some(super::InformationElementUnits::nanoseconds),
            Self::flowStartDeltaMicroseconds => Some(super::InformationElementUnits::microseconds),
            Self::flowEndDeltaMicroseconds => Some(super::InformationElementUnits::microseconds),
            Self::systemInitTimeMilliseconds => Some(super::InformationElementUnits::milliseconds),
            Self::flowDurationMilliseconds => Some(super::InformationElementUnits::milliseconds),
            Self::flowDurationMicroseconds => Some(super::InformationElementUnits::microseconds),
            Self::observedFlowTotalCount => Some(super::InformationElementUnits::flows),
            Self::ignoredPacketTotalCount => Some(super::InformationElementUnits::packets),
            Self::ignoredOctetTotalCount => Some(super::InformationElementUnits::octets),
            Self::notSentFlowTotalCount => Some(super::InformationElementUnits::flows),
            Self::notSentPacketTotalCount => Some(super::InformationElementUnits::packets),
            Self::notSentOctetTotalCount => Some(super::InformationElementUnits::octets),
            Self::destinationIPv6Prefix => None,
            Self::sourceIPv6Prefix => None,
            Self::postOctetTotalCount => Some(super::InformationElementUnits::octets),
            Self::postPacketTotalCount => Some(super::InformationElementUnits::packets),
            Self::flowKeyIndicator => None,
            Self::postMCastPacketTotalCount => Some(super::InformationElementUnits::packets),
            Self::postMCastOctetTotalCount => Some(super::InformationElementUnits::octets),
            Self::icmpTypeIPv4 => None,
            Self::icmpCodeIPv4 => None,
            Self::icmpTypeIPv6 => None,
            Self::icmpCodeIPv6 => None,
            Self::udpSourcePort => None,
            Self::udpDestinationPort => None,
            Self::tcpSourcePort => None,
            Self::tcpDestinationPort => None,
            Self::tcpSequenceNumber => None,
            Self::tcpAcknowledgementNumber => None,
            Self::tcpWindowSize => None,
            Self::tcpUrgentPointer => None,
            Self::tcpHeaderLength => Some(super::InformationElementUnits::octets),
            Self::ipHeaderLength => Some(super::InformationElementUnits::octets),
            Self::totalLengthIPv4 => Some(super::InformationElementUnits::octets),
            Self::payloadLengthIPv6 => Some(super::InformationElementUnits::octets),
            Self::ipTTL => Some(super::InformationElementUnits::hops),
            Self::nextHeaderIPv6 => None,
            Self::mplsPayloadLength => Some(super::InformationElementUnits::octets),
            Self::ipDiffServCodePoint => None,
            Self::ipPrecedence => None,
            Self::fragmentFlags => None,
            Self::octetDeltaSumOfSquares => None,
            Self::octetTotalSumOfSquares => Some(super::InformationElementUnits::octets),
            Self::mplsTopLabelTTL => Some(super::InformationElementUnits::hops),
            Self::mplsLabelStackLength => Some(super::InformationElementUnits::octets),
            Self::mplsLabelStackDepth => Some(super::InformationElementUnits::entries),
            Self::mplsTopLabelExp => None,
            Self::ipPayloadLength => Some(super::InformationElementUnits::octets),
            Self::udpMessageLength => Some(super::InformationElementUnits::octets),
            Self::isMulticast => None,
            Self::ipv4IHL => Some(super::InformationElementUnits::fourOctetWords),
            Self::ipv4Options => None,
            Self::tcpOptions => None,
            Self::paddingOctets => None,
            Self::collectorIPv4Address => None,
            Self::collectorIPv6Address => None,
            Self::exportInterface => None,
            Self::exportProtocolVersion => None,
            Self::exportTransportProtocol => None,
            Self::collectorTransportPort => None,
            Self::exporterTransportPort => None,
            Self::tcpSynTotalCount => Some(super::InformationElementUnits::packets),
            Self::tcpFinTotalCount => Some(super::InformationElementUnits::packets),
            Self::tcpRstTotalCount => Some(super::InformationElementUnits::packets),
            Self::tcpPshTotalCount => Some(super::InformationElementUnits::packets),
            Self::tcpAckTotalCount => Some(super::InformationElementUnits::packets),
            Self::tcpUrgTotalCount => Some(super::InformationElementUnits::packets),
            Self::ipTotalLength => Some(super::InformationElementUnits::octets),
            Self::postNATSourceIPv4Address => None,
            Self::postNATDestinationIPv4Address => None,
            Self::postNAPTSourceTransportPort => None,
            Self::postNAPTDestinationTransportPort => None,
            Self::natOriginatingAddressRealm => None,
            Self::natEvent => None,
            Self::initiatorOctets => Some(super::InformationElementUnits::octets),
            Self::responderOctets => Some(super::InformationElementUnits::octets),
            Self::firewallEvent => None,
            Self::ingressVRFID => None,
            Self::egressVRFID => None,
            Self::VRFname => None,
            Self::postMplsTopLabelExp => None,
            Self::tcpWindowScale => None,
            Self::biflowDirection => None,
            Self::ethernetHeaderLength => Some(super::InformationElementUnits::octets),
            Self::ethernetPayloadLength => Some(super::InformationElementUnits::octets),
            Self::ethernetTotalLength => Some(super::InformationElementUnits::octets),
            Self::dot1qVlanId => None,
            Self::dot1qPriority => None,
            Self::dot1qCustomerVlanId => None,
            Self::dot1qCustomerPriority => None,
            Self::metroEvcId => None,
            Self::metroEvcType => None,
            Self::pseudoWireId => None,
            Self::pseudoWireType => None,
            Self::pseudoWireControlWord => None,
            Self::ingressPhysicalInterface => None,
            Self::egressPhysicalInterface => None,
            Self::postDot1qVlanId => None,
            Self::postDot1qCustomerVlanId => None,
            Self::ethernetType => None,
            Self::postIpPrecedence => None,
            Self::collectionTimeMilliseconds => Some(super::InformationElementUnits::milliseconds),
            Self::exportSctpStreamId => None,
            Self::maxExportSeconds => Some(super::InformationElementUnits::seconds),
            Self::maxFlowEndSeconds => Some(super::InformationElementUnits::seconds),
            Self::messageMD5Checksum => None,
            Self::messageScope => None,
            Self::minExportSeconds => Some(super::InformationElementUnits::seconds),
            Self::minFlowStartSeconds => Some(super::InformationElementUnits::seconds),
            Self::opaqueOctets => None,
            Self::sessionScope => None,
            Self::maxFlowEndMicroseconds => Some(super::InformationElementUnits::microseconds),
            Self::maxFlowEndMilliseconds => Some(super::InformationElementUnits::milliseconds),
            Self::maxFlowEndNanoseconds => Some(super::InformationElementUnits::nanoseconds),
            Self::minFlowStartMicroseconds => Some(super::InformationElementUnits::microseconds),
            Self::minFlowStartMilliseconds => Some(super::InformationElementUnits::milliseconds),
            Self::minFlowStartNanoseconds => Some(super::InformationElementUnits::nanoseconds),
            Self::collectorCertificate => None,
            Self::exporterCertificate => None,
            Self::dataRecordsReliability => None,
            Self::observationPointType => None,
            Self::newConnectionDeltaCount => None,
            Self::connectionSumDurationSeconds => Some(super::InformationElementUnits::seconds),
            Self::connectionTransactionId => None,
            Self::postNATSourceIPv6Address => None,
            Self::postNATDestinationIPv6Address => None,
            Self::natPoolId => None,
            Self::natPoolName => None,
            Self::anonymizationFlags => None,
            Self::anonymizationTechnique => None,
            Self::informationElementIndex => None,
            Self::p2pTechnology => None,
            Self::tunnelTechnology => None,
            Self::encryptedTechnology => None,
            Self::basicList => None,
            Self::subTemplateList => None,
            Self::subTemplateMultiList => None,
            Self::bgpValidityState => None,
            Self::IPSecSPI => None,
            Self::greKey => None,
            Self::natType => None,
            Self::initiatorPackets => Some(super::InformationElementUnits::packets),
            Self::responderPackets => Some(super::InformationElementUnits::packets),
            Self::observationDomainName => None,
            Self::selectionSequenceId => None,
            Self::selectorId => None,
            Self::informationElementId => None,
            Self::selectorAlgorithm => None,
            Self::samplingPacketInterval => Some(super::InformationElementUnits::packets),
            Self::samplingPacketSpace => Some(super::InformationElementUnits::packets),
            Self::samplingTimeInterval => Some(super::InformationElementUnits::microseconds),
            Self::samplingTimeSpace => Some(super::InformationElementUnits::microseconds),
            Self::samplingSize => Some(super::InformationElementUnits::packets),
            Self::samplingPopulation => Some(super::InformationElementUnits::packets),
            Self::samplingProbability => None,
            Self::dataLinkFrameSize => None,
            Self::ipHeaderPacketSection => None,
            Self::ipPayloadPacketSection => None,
            Self::dataLinkFrameSection => None,
            Self::mplsLabelStackSection => None,
            Self::mplsPayloadPacketSection => None,
            Self::selectorIdTotalPktsObserved => Some(super::InformationElementUnits::packets),
            Self::selectorIdTotalPktsSelected => Some(super::InformationElementUnits::packets),
            Self::absoluteError => Some(super::InformationElementUnits::inferred),
            Self::relativeError => None,
            Self::observationTimeSeconds => Some(super::InformationElementUnits::seconds),
            Self::observationTimeMilliseconds => Some(super::InformationElementUnits::milliseconds),
            Self::observationTimeMicroseconds => Some(super::InformationElementUnits::microseconds),
            Self::observationTimeNanoseconds => Some(super::InformationElementUnits::nanoseconds),
            Self::digestHashValue => None,
            Self::hashIPPayloadOffset => None,
            Self::hashIPPayloadSize => None,
            Self::hashOutputRangeMin => None,
            Self::hashOutputRangeMax => None,
            Self::hashSelectedRangeMin => None,
            Self::hashSelectedRangeMax => None,
            Self::hashDigestOutput => None,
            Self::hashInitialiserValue => None,
            Self::selectorName => None,
            Self::upperCILimit => None,
            Self::lowerCILimit => None,
            Self::confidenceLevel => None,
            Self::informationElementDataType => None,
            Self::informationElementDescription => None,
            Self::informationElementName => None,
            Self::informationElementRangeBegin => None,
            Self::informationElementRangeEnd => None,
            Self::informationElementSemantics => None,
            Self::informationElementUnits => None,
            Self::privateEnterpriseNumber => None,
            Self::virtualStationInterfaceId => None,
            Self::virtualStationInterfaceName => None,
            Self::virtualStationUUID => None,
            Self::virtualStationName => None,
            Self::layer2SegmentId => None,
            Self::layer2OctetDeltaCount => Some(super::InformationElementUnits::octets),
            Self::layer2OctetTotalCount => Some(super::InformationElementUnits::octets),
            Self::ingressUnicastPacketTotalCount => Some(super::InformationElementUnits::packets),
            Self::ingressMulticastPacketTotalCount => Some(super::InformationElementUnits::packets),
            Self::ingressBroadcastPacketTotalCount => Some(super::InformationElementUnits::packets),
            Self::egressUnicastPacketTotalCount => Some(super::InformationElementUnits::packets),
            Self::egressBroadcastPacketTotalCount => Some(super::InformationElementUnits::packets),
            Self::monitoringIntervalStartMilliSeconds => Some(super::InformationElementUnits::milliseconds),
            Self::monitoringIntervalEndMilliSeconds => Some(super::InformationElementUnits::milliseconds),
            Self::portRangeStart => None,
            Self::portRangeEnd => None,
            Self::portRangeStepSize => None,
            Self::portRangeNumPorts => None,
            Self::staMacAddress => None,
            Self::staIPv4Address => None,
            Self::wtpMacAddress => None,
            Self::ingressInterfaceType => None,
            Self::egressInterfaceType => None,
            Self::rtpSequenceNumber => None,
            Self::userName => None,
            Self::applicationCategoryName => None,
            Self::applicationSubCategoryName => None,
            Self::applicationGroupName => None,
            Self::originalFlowsPresent => Some(super::InformationElementUnits::flows),
            Self::originalFlowsInitiated => Some(super::InformationElementUnits::flows),
            Self::originalFlowsCompleted => Some(super::InformationElementUnits::flows),
            Self::distinctCountOfSourceIPAddress => None,
            Self::distinctCountOfDestinationIPAddress => None,
            Self::distinctCountOfSourceIPv4Address => None,
            Self::distinctCountOfDestinationIPv4Address => None,
            Self::distinctCountOfSourceIPv6Address => None,
            Self::distinctCountOfDestinationIPv6Address => None,
            Self::valueDistributionMethod => None,
            Self::rfc3550JitterMilliseconds => Some(super::InformationElementUnits::milliseconds),
            Self::rfc3550JitterMicroseconds => Some(super::InformationElementUnits::microseconds),
            Self::rfc3550JitterNanoseconds => Some(super::InformationElementUnits::nanoseconds),
            Self::dot1qDEI => None,
            Self::dot1qCustomerDEI => None,
            Self::flowSelectorAlgorithm => None,
            Self::flowSelectedOctetDeltaCount => Some(super::InformationElementUnits::octets),
            Self::flowSelectedPacketDeltaCount => Some(super::InformationElementUnits::packets),
            Self::flowSelectedFlowDeltaCount => Some(super::InformationElementUnits::flows),
            Self::selectorIDTotalFlowsObserved => Some(super::InformationElementUnits::flows),
            Self::selectorIDTotalFlowsSelected => Some(super::InformationElementUnits::flows),
            Self::samplingFlowInterval => Some(super::InformationElementUnits::flows),
            Self::samplingFlowSpacing => Some(super::InformationElementUnits::flows),
            Self::flowSamplingTimeInterval => Some(super::InformationElementUnits::microseconds),
            Self::flowSamplingTimeSpacing => Some(super::InformationElementUnits::microseconds),
            Self::hashFlowDomain => None,
            Self::transportOctetDeltaCount => Some(super::InformationElementUnits::octets),
            Self::transportPacketDeltaCount => Some(super::InformationElementUnits::packets),
            Self::originalExporterIPv4Address => None,
            Self::originalExporterIPv6Address => None,
            Self::originalObservationDomainId => None,
            Self::intermediateProcessId => None,
            Self::ignoredDataRecordTotalCount => None,
            Self::dataLinkFrameType => None,
            Self::sectionOffset => None,
            Self::sectionExportedOctets => None,
            Self::dot1qServiceInstanceTag => None,
            Self::dot1qServiceInstanceId => None,
            Self::dot1qServiceInstancePriority => None,
            Self::dot1qCustomerSourceMacAddress => None,
            Self::dot1qCustomerDestinationMacAddress => None,
            Self::postLayer2OctetDeltaCount => Some(super::InformationElementUnits::octets),
            Self::postMCastLayer2OctetDeltaCount => Some(super::InformationElementUnits::octets),
            Self::postLayer2OctetTotalCount => Some(super::InformationElementUnits::octets),
            Self::postMCastLayer2OctetTotalCount => Some(super::InformationElementUnits::octets),
            Self::minimumLayer2TotalLength => Some(super::InformationElementUnits::octets),
            Self::maximumLayer2TotalLength => Some(super::InformationElementUnits::octets),
            Self::droppedLayer2OctetDeltaCount => Some(super::InformationElementUnits::octets),
            Self::droppedLayer2OctetTotalCount => Some(super::InformationElementUnits::octets),
            Self::ignoredLayer2OctetTotalCount => Some(super::InformationElementUnits::octets),
            Self::notSentLayer2OctetTotalCount => Some(super::InformationElementUnits::octets),
            Self::layer2OctetDeltaSumOfSquares => Some(super::InformationElementUnits::octets),
            Self::layer2OctetTotalSumOfSquares => Some(super::InformationElementUnits::octets),
            Self::layer2FrameDeltaCount => Some(super::InformationElementUnits::frames),
            Self::layer2FrameTotalCount => Some(super::InformationElementUnits::frames),
            Self::pseudoWireDestinationIPv4Address => None,
            Self::ignoredLayer2FrameTotalCount => Some(super::InformationElementUnits::frames),
            Self::mibObjectValueInteger => None,
            Self::mibObjectValueOctetString => None,
            Self::mibObjectValueOID => None,
            Self::mibObjectValueBits => None,
            Self::mibObjectValueIPAddress => None,
            Self::mibObjectValueCounter => None,
            Self::mibObjectValueGauge => None,
            Self::mibObjectValueTimeTicks => None,
            Self::mibObjectValueUnsigned => None,
            Self::mibObjectValueTable => None,
            Self::mibObjectValueRow => None,
            Self::mibObjectIdentifier => None,
            Self::mibSubIdentifier => None,
            Self::mibIndexIndicator => None,
            Self::mibCaptureTimeSemantics => None,
            Self::mibContextEngineID => None,
            Self::mibContextName => None,
            Self::mibObjectName => None,
            Self::mibObjectDescription => None,
            Self::mibObjectSyntax => None,
            Self::mibModuleName => None,
            Self::mobileIMSI => None,
            Self::mobileMSISDN => None,
            Self::httpStatusCode => None,
            Self::sourceTransportPortsLimit => Some(super::InformationElementUnits::ports),
            Self::httpRequestMethod => None,
            Self::httpRequestHost => None,
            Self::httpRequestTarget => None,
            Self::httpMessageVersion => None,
            Self::natInstanceID => None,
            Self::internalAddressRealm => None,
            Self::externalAddressRealm => None,
            Self::natQuotaExceededEvent => None,
            Self::natThresholdEvent => None,
            Self::httpUserAgent => None,
            Self::httpContentType => None,
            Self::httpReasonPhrase => None,
            Self::maxSessionEntries => None,
            Self::maxBIBEntries => None,
            Self::maxEntriesPerUser => None,
            Self::maxSubscribers => None,
            Self::maxFragmentsPendingReassembly => None,
            Self::addressPoolHighThreshold => None,
            Self::addressPoolLowThreshold => None,
            Self::addressPortMappingHighThreshold => None,
            Self::addressPortMappingLowThreshold => None,
            Self::addressPortMappingPerUserHighThreshold => None,
            Self::globalAddressMappingHighThreshold => None,
            Self::vpnIdentifier => None,
            Self::bgpCommunity => None,
            Self::bgpSourceCommunityList => None,
            Self::bgpDestinationCommunityList => None,
            Self::bgpExtendedCommunity => None,
            Self::bgpSourceExtendedCommunityList => None,
            Self::bgpDestinationExtendedCommunityList => None,
            Self::bgpLargeCommunity => None,
            Self::bgpSourceLargeCommunityList => None,
            Self::bgpDestinationLargeCommunityList => None,
            Self::srhFlagsIPv6 => None,
            Self::srhTagIPv6 => None,
            Self::srhSegmentIPv6 => None,
            Self::srhActiveSegmentIPv6 => None,
            Self::srhSegmentIPv6BasicList => None,
            Self::srhSegmentIPv6ListSection => None,
            Self::srhSegmentsIPv6Left => None,
            Self::srhIPv6Section => None,
            Self::srhIPv6ActiveSegmentType => None,
            Self::srhSegmentIPv6LocatorLength => None,
            Self::srhSegmentIPv6EndpointBehavior => None,
            Self::transportChecksum => None,
            Self::icmpHeaderPacketSection => None,
            Self::gtpuFlags => None,
            Self::gtpuMsgType => None,
            Self::gtpuTEid => None,
            Self::gtpuSequenceNum => None,
            Self::gtpuQFI => None,
            Self::gtpuPduType => None,
            Self::bgpSourceAsPathList => None,
            Self::bgpDestinationAsPathList => None,
            Self::ipv6ExtensionHeaderType => None,
            Self::ipv6ExtensionHeaderCount => None,
            Self::ipv6ExtensionHeadersFull => None,
            Self::ipv6ExtensionHeaderTypeCountList => None,
            Self::ipv6ExtensionHeadersLimit => None,
            Self::ipv6ExtensionHeadersChainLength => None,
            Self::ipv6ExtensionHeaderChainLengthList => None,
            Self::tcpOptionsFull => None,
            Self::tcpSharedOptionExID16 => None,
            Self::tcpSharedOptionExID32 => None,
            Self::tcpSharedOptionExID16List => None,
            Self::tcpSharedOptionExID32List => None,
        }
    }

    fn value_range(&self) -> Option<std::ops::Range<u64>> {
        match self {
            Self::Unknown{..} => None,
            Self::Nokia(ie) => ie.value_range(),
            Self::NetGauze(ie) => ie.value_range(),
            Self::Cisco(ie) => ie.value_range(),
            Self::VMWare(ie) => ie.value_range(),
            Self::octetDeltaCount => None,
            Self::packetDeltaCount => None,
            Self::deltaFlowCount => None,
            Self::protocolIdentifier => None,
            Self::ipClassOfService => None,
            Self::tcpControlBits => None,
            Self::sourceTransportPort => None,
            Self::sourceIPv4Address => None,
            Self::sourceIPv4PrefixLength => Some(std::ops::Range{start: 0, end: 33}),
            Self::ingressInterface => None,
            Self::destinationTransportPort => None,
            Self::destinationIPv4Address => None,
            Self::destinationIPv4PrefixLength => Some(std::ops::Range{start: 0, end: 33}),
            Self::egressInterface => None,
            Self::ipNextHopIPv4Address => None,
            Self::bgpSourceAsNumber => None,
            Self::bgpDestinationAsNumber => None,
            Self::bgpNextHopIPv4Address => None,
            Self::postMCastPacketDeltaCount => None,
            Self::postMCastOctetDeltaCount => None,
            Self::flowEndSysUpTime => None,
            Self::flowStartSysUpTime => None,
            Self::postOctetDeltaCount => None,
            Self::postPacketDeltaCount => None,
            Self::minimumIpTotalLength => None,
            Self::maximumIpTotalLength => None,
            Self::sourceIPv6Address => None,
            Self::destinationIPv6Address => None,
            Self::sourceIPv6PrefixLength => Some(std::ops::Range{start: 0, end: 129}),
            Self::destinationIPv6PrefixLength => Some(std::ops::Range{start: 0, end: 129}),
            Self::flowLabelIPv6 => Some(std::ops::Range{start: 0, end: 1048576}),
            Self::icmpTypeCodeIPv4 => None,
            Self::igmpType => None,
            Self::samplingInterval => None,
            Self::samplingAlgorithm => None,
            Self::flowActiveTimeout => None,
            Self::flowIdleTimeout => None,
            Self::engineType => None,
            Self::engineId => None,
            Self::exportedOctetTotalCount => None,
            Self::exportedMessageTotalCount => None,
            Self::exportedFlowRecordTotalCount => None,
            Self::ipv4RouterSc => None,
            Self::sourceIPv4Prefix => None,
            Self::destinationIPv4Prefix => None,
            Self::mplsTopLabelType => None,
            Self::mplsTopLabelIPv4Address => None,
            Self::samplerId => None,
            Self::samplerMode => None,
            Self::samplerRandomInterval => None,
            Self::classId => None,
            Self::minimumTTL => None,
            Self::maximumTTL => None,
            Self::fragmentIdentification => None,
            Self::postIpClassOfService => None,
            Self::sourceMacAddress => None,
            Self::postDestinationMacAddress => None,
            Self::vlanId => None,
            Self::postVlanId => None,
            Self::ipVersion => None,
            Self::flowDirection => None,
            Self::ipNextHopIPv6Address => None,
            Self::bgpNextHopIPv6Address => None,
            Self::ipv6ExtensionHeaders => None,
            Self::mplsTopLabelStackSection => None,
            Self::mplsLabelStackSection2 => None,
            Self::mplsLabelStackSection3 => None,
            Self::mplsLabelStackSection4 => None,
            Self::mplsLabelStackSection5 => None,
            Self::mplsLabelStackSection6 => None,
            Self::mplsLabelStackSection7 => None,
            Self::mplsLabelStackSection8 => None,
            Self::mplsLabelStackSection9 => None,
            Self::mplsLabelStackSection10 => None,
            Self::destinationMacAddress => None,
            Self::postSourceMacAddress => None,
            Self::interfaceName => None,
            Self::interfaceDescription => None,
            Self::samplerName => None,
            Self::octetTotalCount => None,
            Self::packetTotalCount => None,
            Self::flagsAndSamplerId => None,
            Self::fragmentOffset => Some(std::ops::Range{start: 0, end: 8192}),
            Self::forwardingStatus => None,
            Self::mplsVpnRouteDistinguisher => None,
            Self::mplsTopLabelPrefixLength => Some(std::ops::Range{start: 0, end: 33}),
            Self::srcTrafficIndex => None,
            Self::dstTrafficIndex => None,
            Self::applicationDescription => None,
            Self::applicationId => None,
            Self::applicationName => None,
            Self::postIpDiffServCodePoint => Some(std::ops::Range{start: 0, end: 64}),
            Self::multicastReplicationFactor => None,
            Self::className => None,
            Self::classificationEngineId => None,
            Self::layer2packetSectionOffset => None,
            Self::layer2packetSectionSize => None,
            Self::layer2packetSectionData => None,
            Self::bgpNextAdjacentAsNumber => None,
            Self::bgpPrevAdjacentAsNumber => None,
            Self::exporterIPv4Address => None,
            Self::exporterIPv6Address => None,
            Self::droppedOctetDeltaCount => None,
            Self::droppedPacketDeltaCount => None,
            Self::droppedOctetTotalCount => None,
            Self::droppedPacketTotalCount => None,
            Self::flowEndReason => None,
            Self::commonPropertiesId => None,
            Self::observationPointId => None,
            Self::icmpTypeCodeIPv6 => None,
            Self::mplsTopLabelIPv6Address => None,
            Self::lineCardId => None,
            Self::portId => None,
            Self::meteringProcessId => None,
            Self::exportingProcessId => None,
            Self::templateId => None,
            Self::wlanChannelId => None,
            Self::wlanSSID => None,
            Self::flowId => None,
            Self::observationDomainId => None,
            Self::flowStartSeconds => None,
            Self::flowEndSeconds => None,
            Self::flowStartMilliseconds => None,
            Self::flowEndMilliseconds => None,
            Self::flowStartMicroseconds => None,
            Self::flowEndMicroseconds => None,
            Self::flowStartNanoseconds => None,
            Self::flowEndNanoseconds => None,
            Self::flowStartDeltaMicroseconds => None,
            Self::flowEndDeltaMicroseconds => None,
            Self::systemInitTimeMilliseconds => None,
            Self::flowDurationMilliseconds => None,
            Self::flowDurationMicroseconds => None,
            Self::observedFlowTotalCount => None,
            Self::ignoredPacketTotalCount => None,
            Self::ignoredOctetTotalCount => None,
            Self::notSentFlowTotalCount => None,
            Self::notSentPacketTotalCount => None,
            Self::notSentOctetTotalCount => None,
            Self::destinationIPv6Prefix => None,
            Self::sourceIPv6Prefix => None,
            Self::postOctetTotalCount => None,
            Self::postPacketTotalCount => None,
            Self::flowKeyIndicator => None,
            Self::postMCastPacketTotalCount => None,
            Self::postMCastOctetTotalCount => None,
            Self::icmpTypeIPv4 => None,
            Self::icmpCodeIPv4 => None,
            Self::icmpTypeIPv6 => None,
            Self::icmpCodeIPv6 => None,
            Self::udpSourcePort => None,
            Self::udpDestinationPort => None,
            Self::tcpSourcePort => None,
            Self::tcpDestinationPort => None,
            Self::tcpSequenceNumber => None,
            Self::tcpAcknowledgementNumber => None,
            Self::tcpWindowSize => None,
            Self::tcpUrgentPointer => None,
            Self::tcpHeaderLength => None,
            Self::ipHeaderLength => None,
            Self::totalLengthIPv4 => None,
            Self::payloadLengthIPv6 => None,
            Self::ipTTL => None,
            Self::nextHeaderIPv6 => None,
            Self::mplsPayloadLength => None,
            Self::ipDiffServCodePoint => Some(std::ops::Range{start: 0, end: 64}),
            Self::ipPrecedence => Some(std::ops::Range{start: 0, end: 8}),
            Self::fragmentFlags => None,
            Self::octetDeltaSumOfSquares => None,
            Self::octetTotalSumOfSquares => None,
            Self::mplsTopLabelTTL => None,
            Self::mplsLabelStackLength => None,
            Self::mplsLabelStackDepth => None,
            Self::mplsTopLabelExp => None,
            Self::ipPayloadLength => None,
            Self::udpMessageLength => None,
            Self::isMulticast => None,
            Self::ipv4IHL => None,
            Self::ipv4Options => None,
            Self::tcpOptions => None,
            Self::paddingOctets => None,
            Self::collectorIPv4Address => None,
            Self::collectorIPv6Address => None,
            Self::exportInterface => None,
            Self::exportProtocolVersion => None,
            Self::exportTransportProtocol => None,
            Self::collectorTransportPort => None,
            Self::exporterTransportPort => None,
            Self::tcpSynTotalCount => None,
            Self::tcpFinTotalCount => None,
            Self::tcpRstTotalCount => None,
            Self::tcpPshTotalCount => None,
            Self::tcpAckTotalCount => None,
            Self::tcpUrgTotalCount => None,
            Self::ipTotalLength => None,
            Self::postNATSourceIPv4Address => None,
            Self::postNATDestinationIPv4Address => None,
            Self::postNAPTSourceTransportPort => None,
            Self::postNAPTDestinationTransportPort => None,
            Self::natOriginatingAddressRealm => Some(std::ops::Range{start: 1, end: 3}),
            Self::natEvent => None,
            Self::initiatorOctets => None,
            Self::responderOctets => None,
            Self::firewallEvent => None,
            Self::ingressVRFID => None,
            Self::egressVRFID => None,
            Self::VRFname => None,
            Self::postMplsTopLabelExp => None,
            Self::tcpWindowScale => None,
            Self::biflowDirection => None,
            Self::ethernetHeaderLength => None,
            Self::ethernetPayloadLength => None,
            Self::ethernetTotalLength => None,
            Self::dot1qVlanId => None,
            Self::dot1qPriority => None,
            Self::dot1qCustomerVlanId => None,
            Self::dot1qCustomerPriority => None,
            Self::metroEvcId => None,
            Self::metroEvcType => None,
            Self::pseudoWireId => None,
            Self::pseudoWireType => None,
            Self::pseudoWireControlWord => None,
            Self::ingressPhysicalInterface => None,
            Self::egressPhysicalInterface => None,
            Self::postDot1qVlanId => None,
            Self::postDot1qCustomerVlanId => None,
            Self::ethernetType => None,
            Self::postIpPrecedence => Some(std::ops::Range{start: 0, end: 8}),
            Self::collectionTimeMilliseconds => None,
            Self::exportSctpStreamId => None,
            Self::maxExportSeconds => None,
            Self::maxFlowEndSeconds => None,
            Self::messageMD5Checksum => None,
            Self::messageScope => Some(std::ops::Range{start: 0, end: 1}),
            Self::minExportSeconds => None,
            Self::minFlowStartSeconds => None,
            Self::opaqueOctets => None,
            Self::sessionScope => Some(std::ops::Range{start: 0, end: 1}),
            Self::maxFlowEndMicroseconds => None,
            Self::maxFlowEndMilliseconds => None,
            Self::maxFlowEndNanoseconds => None,
            Self::minFlowStartMicroseconds => None,
            Self::minFlowStartMilliseconds => None,
            Self::minFlowStartNanoseconds => None,
            Self::collectorCertificate => None,
            Self::exporterCertificate => None,
            Self::dataRecordsReliability => None,
            Self::observationPointType => None,
            Self::newConnectionDeltaCount => None,
            Self::connectionSumDurationSeconds => None,
            Self::connectionTransactionId => None,
            Self::postNATSourceIPv6Address => None,
            Self::postNATDestinationIPv6Address => None,
            Self::natPoolId => None,
            Self::natPoolName => None,
            Self::anonymizationFlags => None,
            Self::anonymizationTechnique => None,
            Self::informationElementIndex => None,
            Self::p2pTechnology => None,
            Self::tunnelTechnology => None,
            Self::encryptedTechnology => None,
            Self::basicList => None,
            Self::subTemplateList => None,
            Self::subTemplateMultiList => None,
            Self::bgpValidityState => None,
            Self::IPSecSPI => None,
            Self::greKey => None,
            Self::natType => None,
            Self::initiatorPackets => None,
            Self::responderPackets => None,
            Self::observationDomainName => None,
            Self::selectionSequenceId => None,
            Self::selectorId => None,
            Self::informationElementId => None,
            Self::selectorAlgorithm => None,
            Self::samplingPacketInterval => None,
            Self::samplingPacketSpace => None,
            Self::samplingTimeInterval => None,
            Self::samplingTimeSpace => None,
            Self::samplingSize => None,
            Self::samplingPopulation => None,
            Self::samplingProbability => None,
            Self::dataLinkFrameSize => None,
            Self::ipHeaderPacketSection => None,
            Self::ipPayloadPacketSection => None,
            Self::dataLinkFrameSection => None,
            Self::mplsLabelStackSection => None,
            Self::mplsPayloadPacketSection => None,
            Self::selectorIdTotalPktsObserved => None,
            Self::selectorIdTotalPktsSelected => None,
            Self::absoluteError => None,
            Self::relativeError => None,
            Self::observationTimeSeconds => None,
            Self::observationTimeMilliseconds => None,
            Self::observationTimeMicroseconds => None,
            Self::observationTimeNanoseconds => None,
            Self::digestHashValue => None,
            Self::hashIPPayloadOffset => None,
            Self::hashIPPayloadSize => None,
            Self::hashOutputRangeMin => None,
            Self::hashOutputRangeMax => None,
            Self::hashSelectedRangeMin => None,
            Self::hashSelectedRangeMax => None,
            Self::hashDigestOutput => None,
            Self::hashInitialiserValue => None,
            Self::selectorName => None,
            Self::upperCILimit => None,
            Self::lowerCILimit => None,
            Self::confidenceLevel => None,
            Self::informationElementDataType => None,
            Self::informationElementDescription => None,
            Self::informationElementName => None,
            Self::informationElementRangeBegin => None,
            Self::informationElementRangeEnd => None,
            Self::informationElementSemantics => None,
            Self::informationElementUnits => None,
            Self::privateEnterpriseNumber => None,
            Self::virtualStationInterfaceId => None,
            Self::virtualStationInterfaceName => None,
            Self::virtualStationUUID => None,
            Self::virtualStationName => None,
            Self::layer2SegmentId => None,
            Self::layer2OctetDeltaCount => None,
            Self::layer2OctetTotalCount => None,
            Self::ingressUnicastPacketTotalCount => None,
            Self::ingressMulticastPacketTotalCount => None,
            Self::ingressBroadcastPacketTotalCount => None,
            Self::egressUnicastPacketTotalCount => None,
            Self::egressBroadcastPacketTotalCount => None,
            Self::monitoringIntervalStartMilliSeconds => None,
            Self::monitoringIntervalEndMilliSeconds => None,
            Self::portRangeStart => None,
            Self::portRangeEnd => None,
            Self::portRangeStepSize => None,
            Self::portRangeNumPorts => None,
            Self::staMacAddress => None,
            Self::staIPv4Address => None,
            Self::wtpMacAddress => None,
            Self::ingressInterfaceType => None,
            Self::egressInterfaceType => None,
            Self::rtpSequenceNumber => None,
            Self::userName => None,
            Self::applicationCategoryName => None,
            Self::applicationSubCategoryName => None,
            Self::applicationGroupName => None,
            Self::originalFlowsPresent => None,
            Self::originalFlowsInitiated => None,
            Self::originalFlowsCompleted => None,
            Self::distinctCountOfSourceIPAddress => None,
            Self::distinctCountOfDestinationIPAddress => None,
            Self::distinctCountOfSourceIPv4Address => None,
            Self::distinctCountOfDestinationIPv4Address => None,
            Self::distinctCountOfSourceIPv6Address => None,
            Self::distinctCountOfDestinationIPv6Address => None,
            Self::valueDistributionMethod => None,
            Self::rfc3550JitterMilliseconds => None,
            Self::rfc3550JitterMicroseconds => None,
            Self::rfc3550JitterNanoseconds => None,
            Self::dot1qDEI => None,
            Self::dot1qCustomerDEI => None,
            Self::flowSelectorAlgorithm => None,
            Self::flowSelectedOctetDeltaCount => None,
            Self::flowSelectedPacketDeltaCount => None,
            Self::flowSelectedFlowDeltaCount => None,
            Self::selectorIDTotalFlowsObserved => None,
            Self::selectorIDTotalFlowsSelected => None,
            Self::samplingFlowInterval => None,
            Self::samplingFlowSpacing => None,
            Self::flowSamplingTimeInterval => None,
            Self::flowSamplingTimeSpacing => None,
            Self::hashFlowDomain => None,
            Self::transportOctetDeltaCount => None,
            Self::transportPacketDeltaCount => None,
            Self::originalExporterIPv4Address => None,
            Self::originalExporterIPv6Address => None,
            Self::originalObservationDomainId => None,
            Self::intermediateProcessId => None,
            Self::ignoredDataRecordTotalCount => None,
            Self::dataLinkFrameType => None,
            Self::sectionOffset => None,
            Self::sectionExportedOctets => None,
            Self::dot1qServiceInstanceTag => None,
            Self::dot1qServiceInstanceId => Some(std::ops::Range{start: 0, end: 16777216}),
            Self::dot1qServiceInstancePriority => Some(std::ops::Range{start: 0, end: 8}),
            Self::dot1qCustomerSourceMacAddress => None,
            Self::dot1qCustomerDestinationMacAddress => None,
            Self::postLayer2OctetDeltaCount => None,
            Self::postMCastLayer2OctetDeltaCount => None,
            Self::postLayer2OctetTotalCount => None,
            Self::postMCastLayer2OctetTotalCount => None,
            Self::minimumLayer2TotalLength => None,
            Self::maximumLayer2TotalLength => None,
            Self::droppedLayer2OctetDeltaCount => None,
            Self::droppedLayer2OctetTotalCount => None,
            Self::ignoredLayer2OctetTotalCount => None,
            Self::notSentLayer2OctetTotalCount => None,
            Self::layer2OctetDeltaSumOfSquares => None,
            Self::layer2OctetTotalSumOfSquares => None,
            Self::layer2FrameDeltaCount => None,
            Self::layer2FrameTotalCount => None,
            Self::pseudoWireDestinationIPv4Address => None,
            Self::ignoredLayer2FrameTotalCount => None,
            Self::mibObjectValueInteger => None,
            Self::mibObjectValueOctetString => None,
            Self::mibObjectValueOID => None,
            Self::mibObjectValueBits => None,
            Self::mibObjectValueIPAddress => None,
            Self::mibObjectValueCounter => None,
            Self::mibObjectValueGauge => None,
            Self::mibObjectValueTimeTicks => None,
            Self::mibObjectValueUnsigned => None,
            Self::mibObjectValueTable => None,
            Self::mibObjectValueRow => None,
            Self::mibObjectIdentifier => None,
            Self::mibSubIdentifier => None,
            Self::mibIndexIndicator => None,
            Self::mibCaptureTimeSemantics => None,
            Self::mibContextEngineID => None,
            Self::mibContextName => None,
            Self::mibObjectName => None,
            Self::mibObjectDescription => None,
            Self::mibObjectSyntax => None,
            Self::mibModuleName => None,
            Self::mobileIMSI => None,
            Self::mobileMSISDN => None,
            Self::httpStatusCode => Some(std::ops::Range{start: 0, end: 1000}),
            Self::sourceTransportPortsLimit => Some(std::ops::Range{start: 1, end: 65536}),
            Self::httpRequestMethod => None,
            Self::httpRequestHost => None,
            Self::httpRequestTarget => None,
            Self::httpMessageVersion => None,
            Self::natInstanceID => None,
            Self::internalAddressRealm => None,
            Self::externalAddressRealm => None,
            Self::natQuotaExceededEvent => None,
            Self::natThresholdEvent => None,
            Self::httpUserAgent => None,
            Self::httpContentType => None,
            Self::httpReasonPhrase => None,
            Self::maxSessionEntries => None,
            Self::maxBIBEntries => None,
            Self::maxEntriesPerUser => None,
            Self::maxSubscribers => None,
            Self::maxFragmentsPendingReassembly => None,
            Self::addressPoolHighThreshold => None,
            Self::addressPoolLowThreshold => None,
            Self::addressPortMappingHighThreshold => None,
            Self::addressPortMappingLowThreshold => None,
            Self::addressPortMappingPerUserHighThreshold => None,
            Self::globalAddressMappingHighThreshold => None,
            Self::vpnIdentifier => None,
            Self::bgpCommunity => None,
            Self::bgpSourceCommunityList => None,
            Self::bgpDestinationCommunityList => None,
            Self::bgpExtendedCommunity => None,
            Self::bgpSourceExtendedCommunityList => None,
            Self::bgpDestinationExtendedCommunityList => None,
            Self::bgpLargeCommunity => None,
            Self::bgpSourceLargeCommunityList => None,
            Self::bgpDestinationLargeCommunityList => None,
            Self::srhFlagsIPv6 => None,
            Self::srhTagIPv6 => None,
            Self::srhSegmentIPv6 => None,
            Self::srhActiveSegmentIPv6 => None,
            Self::srhSegmentIPv6BasicList => None,
            Self::srhSegmentIPv6ListSection => None,
            Self::srhSegmentsIPv6Left => None,
            Self::srhIPv6Section => None,
            Self::srhIPv6ActiveSegmentType => None,
            Self::srhSegmentIPv6LocatorLength => None,
            Self::srhSegmentIPv6EndpointBehavior => None,
            Self::transportChecksum => None,
            Self::icmpHeaderPacketSection => None,
            Self::gtpuFlags => None,
            Self::gtpuMsgType => None,
            Self::gtpuTEid => None,
            Self::gtpuSequenceNum => None,
            Self::gtpuQFI => None,
            Self::gtpuPduType => None,
            Self::bgpSourceAsPathList => None,
            Self::bgpDestinationAsPathList => None,
            Self::ipv6ExtensionHeaderType => None,
            Self::ipv6ExtensionHeaderCount => None,
            Self::ipv6ExtensionHeadersFull => None,
            Self::ipv6ExtensionHeaderTypeCountList => None,
            Self::ipv6ExtensionHeadersLimit => None,
            Self::ipv6ExtensionHeadersChainLength => None,
            Self::ipv6ExtensionHeaderChainLengthList => None,
            Self::tcpOptionsFull => None,
            Self::tcpSharedOptionExID16 => None,
            Self::tcpSharedOptionExID32 => None,
            Self::tcpSharedOptionExID16List => None,
            Self::tcpSharedOptionExID32List => None,
        }
    }

    fn id(&self) -> u16{
        match self {
            Self::Unknown{id, ..} => *id,
            Self::Nokia(vendor_ie) => vendor_ie.id(),
            Self::NetGauze(vendor_ie) => vendor_ie.id(),
            Self::Cisco(vendor_ie) => vendor_ie.id(),
            Self::VMWare(vendor_ie) => vendor_ie.id(),
            Self::octetDeltaCount => 1,
            Self::packetDeltaCount => 2,
            Self::deltaFlowCount => 3,
            Self::protocolIdentifier => 4,
            Self::ipClassOfService => 5,
            Self::tcpControlBits => 6,
            Self::sourceTransportPort => 7,
            Self::sourceIPv4Address => 8,
            Self::sourceIPv4PrefixLength => 9,
            Self::ingressInterface => 10,
            Self::destinationTransportPort => 11,
            Self::destinationIPv4Address => 12,
            Self::destinationIPv4PrefixLength => 13,
            Self::egressInterface => 14,
            Self::ipNextHopIPv4Address => 15,
            Self::bgpSourceAsNumber => 16,
            Self::bgpDestinationAsNumber => 17,
            Self::bgpNextHopIPv4Address => 18,
            Self::postMCastPacketDeltaCount => 19,
            Self::postMCastOctetDeltaCount => 20,
            Self::flowEndSysUpTime => 21,
            Self::flowStartSysUpTime => 22,
            Self::postOctetDeltaCount => 23,
            Self::postPacketDeltaCount => 24,
            Self::minimumIpTotalLength => 25,
            Self::maximumIpTotalLength => 26,
            Self::sourceIPv6Address => 27,
            Self::destinationIPv6Address => 28,
            Self::sourceIPv6PrefixLength => 29,
            Self::destinationIPv6PrefixLength => 30,
            Self::flowLabelIPv6 => 31,
            Self::icmpTypeCodeIPv4 => 32,
            Self::igmpType => 33,
            Self::samplingInterval => 34,
            Self::samplingAlgorithm => 35,
            Self::flowActiveTimeout => 36,
            Self::flowIdleTimeout => 37,
            Self::engineType => 38,
            Self::engineId => 39,
            Self::exportedOctetTotalCount => 40,
            Self::exportedMessageTotalCount => 41,
            Self::exportedFlowRecordTotalCount => 42,
            Self::ipv4RouterSc => 43,
            Self::sourceIPv4Prefix => 44,
            Self::destinationIPv4Prefix => 45,
            Self::mplsTopLabelType => 46,
            Self::mplsTopLabelIPv4Address => 47,
            Self::samplerId => 48,
            Self::samplerMode => 49,
            Self::samplerRandomInterval => 50,
            Self::classId => 51,
            Self::minimumTTL => 52,
            Self::maximumTTL => 53,
            Self::fragmentIdentification => 54,
            Self::postIpClassOfService => 55,
            Self::sourceMacAddress => 56,
            Self::postDestinationMacAddress => 57,
            Self::vlanId => 58,
            Self::postVlanId => 59,
            Self::ipVersion => 60,
            Self::flowDirection => 61,
            Self::ipNextHopIPv6Address => 62,
            Self::bgpNextHopIPv6Address => 63,
            Self::ipv6ExtensionHeaders => 64,
            Self::mplsTopLabelStackSection => 70,
            Self::mplsLabelStackSection2 => 71,
            Self::mplsLabelStackSection3 => 72,
            Self::mplsLabelStackSection4 => 73,
            Self::mplsLabelStackSection5 => 74,
            Self::mplsLabelStackSection6 => 75,
            Self::mplsLabelStackSection7 => 76,
            Self::mplsLabelStackSection8 => 77,
            Self::mplsLabelStackSection9 => 78,
            Self::mplsLabelStackSection10 => 79,
            Self::destinationMacAddress => 80,
            Self::postSourceMacAddress => 81,
            Self::interfaceName => 82,
            Self::interfaceDescription => 83,
            Self::samplerName => 84,
            Self::octetTotalCount => 85,
            Self::packetTotalCount => 86,
            Self::flagsAndSamplerId => 87,
            Self::fragmentOffset => 88,
            Self::forwardingStatus => 89,
            Self::mplsVpnRouteDistinguisher => 90,
            Self::mplsTopLabelPrefixLength => 91,
            Self::srcTrafficIndex => 92,
            Self::dstTrafficIndex => 93,
            Self::applicationDescription => 94,
            Self::applicationId => 95,
            Self::applicationName => 96,
            Self::postIpDiffServCodePoint => 98,
            Self::multicastReplicationFactor => 99,
            Self::className => 100,
            Self::classificationEngineId => 101,
            Self::layer2packetSectionOffset => 102,
            Self::layer2packetSectionSize => 103,
            Self::layer2packetSectionData => 104,
            Self::bgpNextAdjacentAsNumber => 128,
            Self::bgpPrevAdjacentAsNumber => 129,
            Self::exporterIPv4Address => 130,
            Self::exporterIPv6Address => 131,
            Self::droppedOctetDeltaCount => 132,
            Self::droppedPacketDeltaCount => 133,
            Self::droppedOctetTotalCount => 134,
            Self::droppedPacketTotalCount => 135,
            Self::flowEndReason => 136,
            Self::commonPropertiesId => 137,
            Self::observationPointId => 138,
            Self::icmpTypeCodeIPv6 => 139,
            Self::mplsTopLabelIPv6Address => 140,
            Self::lineCardId => 141,
            Self::portId => 142,
            Self::meteringProcessId => 143,
            Self::exportingProcessId => 144,
            Self::templateId => 145,
            Self::wlanChannelId => 146,
            Self::wlanSSID => 147,
            Self::flowId => 148,
            Self::observationDomainId => 149,
            Self::flowStartSeconds => 150,
            Self::flowEndSeconds => 151,
            Self::flowStartMilliseconds => 152,
            Self::flowEndMilliseconds => 153,
            Self::flowStartMicroseconds => 154,
            Self::flowEndMicroseconds => 155,
            Self::flowStartNanoseconds => 156,
            Self::flowEndNanoseconds => 157,
            Self::flowStartDeltaMicroseconds => 158,
            Self::flowEndDeltaMicroseconds => 159,
            Self::systemInitTimeMilliseconds => 160,
            Self::flowDurationMilliseconds => 161,
            Self::flowDurationMicroseconds => 162,
            Self::observedFlowTotalCount => 163,
            Self::ignoredPacketTotalCount => 164,
            Self::ignoredOctetTotalCount => 165,
            Self::notSentFlowTotalCount => 166,
            Self::notSentPacketTotalCount => 167,
            Self::notSentOctetTotalCount => 168,
            Self::destinationIPv6Prefix => 169,
            Self::sourceIPv6Prefix => 170,
            Self::postOctetTotalCount => 171,
            Self::postPacketTotalCount => 172,
            Self::flowKeyIndicator => 173,
            Self::postMCastPacketTotalCount => 174,
            Self::postMCastOctetTotalCount => 175,
            Self::icmpTypeIPv4 => 176,
            Self::icmpCodeIPv4 => 177,
            Self::icmpTypeIPv6 => 178,
            Self::icmpCodeIPv6 => 179,
            Self::udpSourcePort => 180,
            Self::udpDestinationPort => 181,
            Self::tcpSourcePort => 182,
            Self::tcpDestinationPort => 183,
            Self::tcpSequenceNumber => 184,
            Self::tcpAcknowledgementNumber => 185,
            Self::tcpWindowSize => 186,
            Self::tcpUrgentPointer => 187,
            Self::tcpHeaderLength => 188,
            Self::ipHeaderLength => 189,
            Self::totalLengthIPv4 => 190,
            Self::payloadLengthIPv6 => 191,
            Self::ipTTL => 192,
            Self::nextHeaderIPv6 => 193,
            Self::mplsPayloadLength => 194,
            Self::ipDiffServCodePoint => 195,
            Self::ipPrecedence => 196,
            Self::fragmentFlags => 197,
            Self::octetDeltaSumOfSquares => 198,
            Self::octetTotalSumOfSquares => 199,
            Self::mplsTopLabelTTL => 200,
            Self::mplsLabelStackLength => 201,
            Self::mplsLabelStackDepth => 202,
            Self::mplsTopLabelExp => 203,
            Self::ipPayloadLength => 204,
            Self::udpMessageLength => 205,
            Self::isMulticast => 206,
            Self::ipv4IHL => 207,
            Self::ipv4Options => 208,
            Self::tcpOptions => 209,
            Self::paddingOctets => 210,
            Self::collectorIPv4Address => 211,
            Self::collectorIPv6Address => 212,
            Self::exportInterface => 213,
            Self::exportProtocolVersion => 214,
            Self::exportTransportProtocol => 215,
            Self::collectorTransportPort => 216,
            Self::exporterTransportPort => 217,
            Self::tcpSynTotalCount => 218,
            Self::tcpFinTotalCount => 219,
            Self::tcpRstTotalCount => 220,
            Self::tcpPshTotalCount => 221,
            Self::tcpAckTotalCount => 222,
            Self::tcpUrgTotalCount => 223,
            Self::ipTotalLength => 224,
            Self::postNATSourceIPv4Address => 225,
            Self::postNATDestinationIPv4Address => 226,
            Self::postNAPTSourceTransportPort => 227,
            Self::postNAPTDestinationTransportPort => 228,
            Self::natOriginatingAddressRealm => 229,
            Self::natEvent => 230,
            Self::initiatorOctets => 231,
            Self::responderOctets => 232,
            Self::firewallEvent => 233,
            Self::ingressVRFID => 234,
            Self::egressVRFID => 235,
            Self::VRFname => 236,
            Self::postMplsTopLabelExp => 237,
            Self::tcpWindowScale => 238,
            Self::biflowDirection => 239,
            Self::ethernetHeaderLength => 240,
            Self::ethernetPayloadLength => 241,
            Self::ethernetTotalLength => 242,
            Self::dot1qVlanId => 243,
            Self::dot1qPriority => 244,
            Self::dot1qCustomerVlanId => 245,
            Self::dot1qCustomerPriority => 246,
            Self::metroEvcId => 247,
            Self::metroEvcType => 248,
            Self::pseudoWireId => 249,
            Self::pseudoWireType => 250,
            Self::pseudoWireControlWord => 251,
            Self::ingressPhysicalInterface => 252,
            Self::egressPhysicalInterface => 253,
            Self::postDot1qVlanId => 254,
            Self::postDot1qCustomerVlanId => 255,
            Self::ethernetType => 256,
            Self::postIpPrecedence => 257,
            Self::collectionTimeMilliseconds => 258,
            Self::exportSctpStreamId => 259,
            Self::maxExportSeconds => 260,
            Self::maxFlowEndSeconds => 261,
            Self::messageMD5Checksum => 262,
            Self::messageScope => 263,
            Self::minExportSeconds => 264,
            Self::minFlowStartSeconds => 265,
            Self::opaqueOctets => 266,
            Self::sessionScope => 267,
            Self::maxFlowEndMicroseconds => 268,
            Self::maxFlowEndMilliseconds => 269,
            Self::maxFlowEndNanoseconds => 270,
            Self::minFlowStartMicroseconds => 271,
            Self::minFlowStartMilliseconds => 272,
            Self::minFlowStartNanoseconds => 273,
            Self::collectorCertificate => 274,
            Self::exporterCertificate => 275,
            Self::dataRecordsReliability => 276,
            Self::observationPointType => 277,
            Self::newConnectionDeltaCount => 278,
            Self::connectionSumDurationSeconds => 279,
            Self::connectionTransactionId => 280,
            Self::postNATSourceIPv6Address => 281,
            Self::postNATDestinationIPv6Address => 282,
            Self::natPoolId => 283,
            Self::natPoolName => 284,
            Self::anonymizationFlags => 285,
            Self::anonymizationTechnique => 286,
            Self::informationElementIndex => 287,
            Self::p2pTechnology => 288,
            Self::tunnelTechnology => 289,
            Self::encryptedTechnology => 290,
            Self::basicList => 291,
            Self::subTemplateList => 292,
            Self::subTemplateMultiList => 293,
            Self::bgpValidityState => 294,
            Self::IPSecSPI => 295,
            Self::greKey => 296,
            Self::natType => 297,
            Self::initiatorPackets => 298,
            Self::responderPackets => 299,
            Self::observationDomainName => 300,
            Self::selectionSequenceId => 301,
            Self::selectorId => 302,
            Self::informationElementId => 303,
            Self::selectorAlgorithm => 304,
            Self::samplingPacketInterval => 305,
            Self::samplingPacketSpace => 306,
            Self::samplingTimeInterval => 307,
            Self::samplingTimeSpace => 308,
            Self::samplingSize => 309,
            Self::samplingPopulation => 310,
            Self::samplingProbability => 311,
            Self::dataLinkFrameSize => 312,
            Self::ipHeaderPacketSection => 313,
            Self::ipPayloadPacketSection => 314,
            Self::dataLinkFrameSection => 315,
            Self::mplsLabelStackSection => 316,
            Self::mplsPayloadPacketSection => 317,
            Self::selectorIdTotalPktsObserved => 318,
            Self::selectorIdTotalPktsSelected => 319,
            Self::absoluteError => 320,
            Self::relativeError => 321,
            Self::observationTimeSeconds => 322,
            Self::observationTimeMilliseconds => 323,
            Self::observationTimeMicroseconds => 324,
            Self::observationTimeNanoseconds => 325,
            Self::digestHashValue => 326,
            Self::hashIPPayloadOffset => 327,
            Self::hashIPPayloadSize => 328,
            Self::hashOutputRangeMin => 329,
            Self::hashOutputRangeMax => 330,
            Self::hashSelectedRangeMin => 331,
            Self::hashSelectedRangeMax => 332,
            Self::hashDigestOutput => 333,
            Self::hashInitialiserValue => 334,
            Self::selectorName => 335,
            Self::upperCILimit => 336,
            Self::lowerCILimit => 337,
            Self::confidenceLevel => 338,
            Self::informationElementDataType => 339,
            Self::informationElementDescription => 340,
            Self::informationElementName => 341,
            Self::informationElementRangeBegin => 342,
            Self::informationElementRangeEnd => 343,
            Self::informationElementSemantics => 344,
            Self::informationElementUnits => 345,
            Self::privateEnterpriseNumber => 346,
            Self::virtualStationInterfaceId => 347,
            Self::virtualStationInterfaceName => 348,
            Self::virtualStationUUID => 349,
            Self::virtualStationName => 350,
            Self::layer2SegmentId => 351,
            Self::layer2OctetDeltaCount => 352,
            Self::layer2OctetTotalCount => 353,
            Self::ingressUnicastPacketTotalCount => 354,
            Self::ingressMulticastPacketTotalCount => 355,
            Self::ingressBroadcastPacketTotalCount => 356,
            Self::egressUnicastPacketTotalCount => 357,
            Self::egressBroadcastPacketTotalCount => 358,
            Self::monitoringIntervalStartMilliSeconds => 359,
            Self::monitoringIntervalEndMilliSeconds => 360,
            Self::portRangeStart => 361,
            Self::portRangeEnd => 362,
            Self::portRangeStepSize => 363,
            Self::portRangeNumPorts => 364,
            Self::staMacAddress => 365,
            Self::staIPv4Address => 366,
            Self::wtpMacAddress => 367,
            Self::ingressInterfaceType => 368,
            Self::egressInterfaceType => 369,
            Self::rtpSequenceNumber => 370,
            Self::userName => 371,
            Self::applicationCategoryName => 372,
            Self::applicationSubCategoryName => 373,
            Self::applicationGroupName => 374,
            Self::originalFlowsPresent => 375,
            Self::originalFlowsInitiated => 376,
            Self::originalFlowsCompleted => 377,
            Self::distinctCountOfSourceIPAddress => 378,
            Self::distinctCountOfDestinationIPAddress => 379,
            Self::distinctCountOfSourceIPv4Address => 380,
            Self::distinctCountOfDestinationIPv4Address => 381,
            Self::distinctCountOfSourceIPv6Address => 382,
            Self::distinctCountOfDestinationIPv6Address => 383,
            Self::valueDistributionMethod => 384,
            Self::rfc3550JitterMilliseconds => 385,
            Self::rfc3550JitterMicroseconds => 386,
            Self::rfc3550JitterNanoseconds => 387,
            Self::dot1qDEI => 388,
            Self::dot1qCustomerDEI => 389,
            Self::flowSelectorAlgorithm => 390,
            Self::flowSelectedOctetDeltaCount => 391,
            Self::flowSelectedPacketDeltaCount => 392,
            Self::flowSelectedFlowDeltaCount => 393,
            Self::selectorIDTotalFlowsObserved => 394,
            Self::selectorIDTotalFlowsSelected => 395,
            Self::samplingFlowInterval => 396,
            Self::samplingFlowSpacing => 397,
            Self::flowSamplingTimeInterval => 398,
            Self::flowSamplingTimeSpacing => 399,
            Self::hashFlowDomain => 400,
            Self::transportOctetDeltaCount => 401,
            Self::transportPacketDeltaCount => 402,
            Self::originalExporterIPv4Address => 403,
            Self::originalExporterIPv6Address => 404,
            Self::originalObservationDomainId => 405,
            Self::intermediateProcessId => 406,
            Self::ignoredDataRecordTotalCount => 407,
            Self::dataLinkFrameType => 408,
            Self::sectionOffset => 409,
            Self::sectionExportedOctets => 410,
            Self::dot1qServiceInstanceTag => 411,
            Self::dot1qServiceInstanceId => 412,
            Self::dot1qServiceInstancePriority => 413,
            Self::dot1qCustomerSourceMacAddress => 414,
            Self::dot1qCustomerDestinationMacAddress => 415,
            Self::postLayer2OctetDeltaCount => 417,
            Self::postMCastLayer2OctetDeltaCount => 418,
            Self::postLayer2OctetTotalCount => 420,
            Self::postMCastLayer2OctetTotalCount => 421,
            Self::minimumLayer2TotalLength => 422,
            Self::maximumLayer2TotalLength => 423,
            Self::droppedLayer2OctetDeltaCount => 424,
            Self::droppedLayer2OctetTotalCount => 425,
            Self::ignoredLayer2OctetTotalCount => 426,
            Self::notSentLayer2OctetTotalCount => 427,
            Self::layer2OctetDeltaSumOfSquares => 428,
            Self::layer2OctetTotalSumOfSquares => 429,
            Self::layer2FrameDeltaCount => 430,
            Self::layer2FrameTotalCount => 431,
            Self::pseudoWireDestinationIPv4Address => 432,
            Self::ignoredLayer2FrameTotalCount => 433,
            Self::mibObjectValueInteger => 434,
            Self::mibObjectValueOctetString => 435,
            Self::mibObjectValueOID => 436,
            Self::mibObjectValueBits => 437,
            Self::mibObjectValueIPAddress => 438,
            Self::mibObjectValueCounter => 439,
            Self::mibObjectValueGauge => 440,
            Self::mibObjectValueTimeTicks => 441,
            Self::mibObjectValueUnsigned => 442,
            Self::mibObjectValueTable => 443,
            Self::mibObjectValueRow => 444,
            Self::mibObjectIdentifier => 445,
            Self::mibSubIdentifier => 446,
            Self::mibIndexIndicator => 447,
            Self::mibCaptureTimeSemantics => 448,
            Self::mibContextEngineID => 449,
            Self::mibContextName => 450,
            Self::mibObjectName => 451,
            Self::mibObjectDescription => 452,
            Self::mibObjectSyntax => 453,
            Self::mibModuleName => 454,
            Self::mobileIMSI => 455,
            Self::mobileMSISDN => 456,
            Self::httpStatusCode => 457,
            Self::sourceTransportPortsLimit => 458,
            Self::httpRequestMethod => 459,
            Self::httpRequestHost => 460,
            Self::httpRequestTarget => 461,
            Self::httpMessageVersion => 462,
            Self::natInstanceID => 463,
            Self::internalAddressRealm => 464,
            Self::externalAddressRealm => 465,
            Self::natQuotaExceededEvent => 466,
            Self::natThresholdEvent => 467,
            Self::httpUserAgent => 468,
            Self::httpContentType => 469,
            Self::httpReasonPhrase => 470,
            Self::maxSessionEntries => 471,
            Self::maxBIBEntries => 472,
            Self::maxEntriesPerUser => 473,
            Self::maxSubscribers => 474,
            Self::maxFragmentsPendingReassembly => 475,
            Self::addressPoolHighThreshold => 476,
            Self::addressPoolLowThreshold => 477,
            Self::addressPortMappingHighThreshold => 478,
            Self::addressPortMappingLowThreshold => 479,
            Self::addressPortMappingPerUserHighThreshold => 480,
            Self::globalAddressMappingHighThreshold => 481,
            Self::vpnIdentifier => 482,
            Self::bgpCommunity => 483,
            Self::bgpSourceCommunityList => 484,
            Self::bgpDestinationCommunityList => 485,
            Self::bgpExtendedCommunity => 486,
            Self::bgpSourceExtendedCommunityList => 487,
            Self::bgpDestinationExtendedCommunityList => 488,
            Self::bgpLargeCommunity => 489,
            Self::bgpSourceLargeCommunityList => 490,
            Self::bgpDestinationLargeCommunityList => 491,
            Self::srhFlagsIPv6 => 492,
            Self::srhTagIPv6 => 493,
            Self::srhSegmentIPv6 => 494,
            Self::srhActiveSegmentIPv6 => 495,
            Self::srhSegmentIPv6BasicList => 496,
            Self::srhSegmentIPv6ListSection => 497,
            Self::srhSegmentsIPv6Left => 498,
            Self::srhIPv6Section => 499,
            Self::srhIPv6ActiveSegmentType => 500,
            Self::srhSegmentIPv6LocatorLength => 501,
            Self::srhSegmentIPv6EndpointBehavior => 502,
            Self::transportChecksum => 503,
            Self::icmpHeaderPacketSection => 504,
            Self::gtpuFlags => 505,
            Self::gtpuMsgType => 506,
            Self::gtpuTEid => 507,
            Self::gtpuSequenceNum => 508,
            Self::gtpuQFI => 509,
            Self::gtpuPduType => 510,
            Self::bgpSourceAsPathList => 511,
            Self::bgpDestinationAsPathList => 512,
            Self::ipv6ExtensionHeaderType => 513,
            Self::ipv6ExtensionHeaderCount => 514,
            Self::ipv6ExtensionHeadersFull => 515,
            Self::ipv6ExtensionHeaderTypeCountList => 516,
            Self::ipv6ExtensionHeadersLimit => 517,
            Self::ipv6ExtensionHeadersChainLength => 518,
            Self::ipv6ExtensionHeaderChainLengthList => 519,
            Self::tcpOptionsFull => 520,
            Self::tcpSharedOptionExID16 => 521,
            Self::tcpSharedOptionExID32 => 522,
            Self::tcpSharedOptionExID16List => 523,
            Self::tcpSharedOptionExID32List => 524,
        }
    }

    fn pen(&self) -> u32{
        match self {
            Self::Unknown{pen, ..} => *pen,
            Self::Nokia(vendor_ie) => vendor_ie.pen(),
            Self::NetGauze(vendor_ie) => vendor_ie.pen(),
            Self::Cisco(vendor_ie) => vendor_ie.pen(),
            Self::VMWare(vendor_ie) => vendor_ie.pen(),
            _ => 0,
        }
    }

}

#[allow(non_camel_case_types)]
#[derive(Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Field {
    Unknown{pen: u32, id: u16, value: Vec<u8>},
    Nokia(nokia::Field),
    NetGauze(netgauze::Field),
    Cisco(cisco::Field),
    VMWare(vmware::Field),
    octetDeltaCount(octetDeltaCount),
    packetDeltaCount(packetDeltaCount),
    deltaFlowCount(deltaFlowCount),
    protocolIdentifier(protocolIdentifier),
    ipClassOfService(ipClassOfService),
    tcpControlBits(netgauze_iana::tcp::TCPHeaderFlags),
    sourceTransportPort(sourceTransportPort),
    sourceIPv4Address(sourceIPv4Address),
    sourceIPv4PrefixLength(sourceIPv4PrefixLength),
    ingressInterface(ingressInterface),
    destinationTransportPort(destinationTransportPort),
    destinationIPv4Address(destinationIPv4Address),
    destinationIPv4PrefixLength(destinationIPv4PrefixLength),
    egressInterface(egressInterface),
    ipNextHopIPv4Address(ipNextHopIPv4Address),
    bgpSourceAsNumber(bgpSourceAsNumber),
    bgpDestinationAsNumber(bgpDestinationAsNumber),
    bgpNextHopIPv4Address(bgpNextHopIPv4Address),
    postMCastPacketDeltaCount(postMCastPacketDeltaCount),
    postMCastOctetDeltaCount(postMCastOctetDeltaCount),
    flowEndSysUpTime(flowEndSysUpTime),
    flowStartSysUpTime(flowStartSysUpTime),
    postOctetDeltaCount(postOctetDeltaCount),
    postPacketDeltaCount(postPacketDeltaCount),
    minimumIpTotalLength(minimumIpTotalLength),
    maximumIpTotalLength(maximumIpTotalLength),
    sourceIPv6Address(sourceIPv6Address),
    destinationIPv6Address(destinationIPv6Address),
    sourceIPv6PrefixLength(sourceIPv6PrefixLength),
    destinationIPv6PrefixLength(destinationIPv6PrefixLength),
    flowLabelIPv6(flowLabelIPv6),
    icmpTypeCodeIPv4(icmpTypeCodeIPv4),
    igmpType(igmpType),
    samplingInterval(samplingInterval),
    samplingAlgorithm(samplingAlgorithm),
    flowActiveTimeout(flowActiveTimeout),
    flowIdleTimeout(flowIdleTimeout),
    engineType(engineType),
    engineId(engineId),
    exportedOctetTotalCount(exportedOctetTotalCount),
    exportedMessageTotalCount(exportedMessageTotalCount),
    exportedFlowRecordTotalCount(exportedFlowRecordTotalCount),
    ipv4RouterSc(ipv4RouterSc),
    sourceIPv4Prefix(sourceIPv4Prefix),
    destinationIPv4Prefix(destinationIPv4Prefix),
    mplsTopLabelType(mplsTopLabelType),
    mplsTopLabelIPv4Address(mplsTopLabelIPv4Address),
    samplerId(samplerId),
    samplerMode(samplerMode),
    samplerRandomInterval(samplerRandomInterval),
    classId(classId),
    minimumTTL(minimumTTL),
    maximumTTL(maximumTTL),
    fragmentIdentification(fragmentIdentification),
    postIpClassOfService(postIpClassOfService),
    sourceMacAddress(sourceMacAddress),
    postDestinationMacAddress(postDestinationMacAddress),
    vlanId(vlanId),
    postVlanId(postVlanId),
    ipVersion(ipVersion),
    flowDirection(flowDirection),
    ipNextHopIPv6Address(ipNextHopIPv6Address),
    bgpNextHopIPv6Address(bgpNextHopIPv6Address),
    ipv6ExtensionHeaders(ipv6ExtensionHeaders),
    mplsTopLabelStackSection(mplsTopLabelStackSection),
    mplsLabelStackSection2(mplsLabelStackSection2),
    mplsLabelStackSection3(mplsLabelStackSection3),
    mplsLabelStackSection4(mplsLabelStackSection4),
    mplsLabelStackSection5(mplsLabelStackSection5),
    mplsLabelStackSection6(mplsLabelStackSection6),
    mplsLabelStackSection7(mplsLabelStackSection7),
    mplsLabelStackSection8(mplsLabelStackSection8),
    mplsLabelStackSection9(mplsLabelStackSection9),
    mplsLabelStackSection10(mplsLabelStackSection10),
    destinationMacAddress(destinationMacAddress),
    postSourceMacAddress(postSourceMacAddress),
    interfaceName(interfaceName),
    interfaceDescription(interfaceDescription),
    samplerName(samplerName),
    octetTotalCount(octetTotalCount),
    packetTotalCount(packetTotalCount),
    flagsAndSamplerId(flagsAndSamplerId),
    fragmentOffset(fragmentOffset),
    forwardingStatus(forwardingStatus),
    mplsVpnRouteDistinguisher(mplsVpnRouteDistinguisher),
    mplsTopLabelPrefixLength(mplsTopLabelPrefixLength),
    srcTrafficIndex(srcTrafficIndex),
    dstTrafficIndex(dstTrafficIndex),
    applicationDescription(applicationDescription),
    applicationId(applicationId),
    applicationName(applicationName),
    postIpDiffServCodePoint(postIpDiffServCodePoint),
    multicastReplicationFactor(multicastReplicationFactor),
    className(className),
    classificationEngineId(classificationEngineId),
    layer2packetSectionOffset(layer2packetSectionOffset),
    layer2packetSectionSize(layer2packetSectionSize),
    layer2packetSectionData(layer2packetSectionData),
    bgpNextAdjacentAsNumber(bgpNextAdjacentAsNumber),
    bgpPrevAdjacentAsNumber(bgpPrevAdjacentAsNumber),
    exporterIPv4Address(exporterIPv4Address),
    exporterIPv6Address(exporterIPv6Address),
    droppedOctetDeltaCount(droppedOctetDeltaCount),
    droppedPacketDeltaCount(droppedPacketDeltaCount),
    droppedOctetTotalCount(droppedOctetTotalCount),
    droppedPacketTotalCount(droppedPacketTotalCount),
    flowEndReason(flowEndReason),
    commonPropertiesId(commonPropertiesId),
    observationPointId(observationPointId),
    icmpTypeCodeIPv6(icmpTypeCodeIPv6),
    mplsTopLabelIPv6Address(mplsTopLabelIPv6Address),
    lineCardId(lineCardId),
    portId(portId),
    meteringProcessId(meteringProcessId),
    exportingProcessId(exportingProcessId),
    templateId(templateId),
    wlanChannelId(wlanChannelId),
    wlanSSID(wlanSSID),
    flowId(flowId),
    observationDomainId(observationDomainId),
    flowStartSeconds(flowStartSeconds),
    flowEndSeconds(flowEndSeconds),
    flowStartMilliseconds(flowStartMilliseconds),
    flowEndMilliseconds(flowEndMilliseconds),
    flowStartMicroseconds(flowStartMicroseconds),
    flowEndMicroseconds(flowEndMicroseconds),
    flowStartNanoseconds(flowStartNanoseconds),
    flowEndNanoseconds(flowEndNanoseconds),
    flowStartDeltaMicroseconds(flowStartDeltaMicroseconds),
    flowEndDeltaMicroseconds(flowEndDeltaMicroseconds),
    systemInitTimeMilliseconds(systemInitTimeMilliseconds),
    flowDurationMilliseconds(flowDurationMilliseconds),
    flowDurationMicroseconds(flowDurationMicroseconds),
    observedFlowTotalCount(observedFlowTotalCount),
    ignoredPacketTotalCount(ignoredPacketTotalCount),
    ignoredOctetTotalCount(ignoredOctetTotalCount),
    notSentFlowTotalCount(notSentFlowTotalCount),
    notSentPacketTotalCount(notSentPacketTotalCount),
    notSentOctetTotalCount(notSentOctetTotalCount),
    destinationIPv6Prefix(destinationIPv6Prefix),
    sourceIPv6Prefix(sourceIPv6Prefix),
    postOctetTotalCount(postOctetTotalCount),
    postPacketTotalCount(postPacketTotalCount),
    flowKeyIndicator(flowKeyIndicator),
    postMCastPacketTotalCount(postMCastPacketTotalCount),
    postMCastOctetTotalCount(postMCastOctetTotalCount),
    icmpTypeIPv4(icmpTypeIPv4),
    icmpCodeIPv4(icmpCodeIPv4),
    icmpTypeIPv6(icmpTypeIPv6),
    icmpCodeIPv6(icmpCodeIPv6),
    udpSourcePort(udpSourcePort),
    udpDestinationPort(udpDestinationPort),
    tcpSourcePort(tcpSourcePort),
    tcpDestinationPort(tcpDestinationPort),
    tcpSequenceNumber(tcpSequenceNumber),
    tcpAcknowledgementNumber(tcpAcknowledgementNumber),
    tcpWindowSize(tcpWindowSize),
    tcpUrgentPointer(tcpUrgentPointer),
    tcpHeaderLength(tcpHeaderLength),
    ipHeaderLength(ipHeaderLength),
    totalLengthIPv4(totalLengthIPv4),
    payloadLengthIPv6(payloadLengthIPv6),
    ipTTL(ipTTL),
    nextHeaderIPv6(nextHeaderIPv6),
    mplsPayloadLength(mplsPayloadLength),
    ipDiffServCodePoint(ipDiffServCodePoint),
    ipPrecedence(ipPrecedence),
    fragmentFlags(fragmentFlags),
    octetDeltaSumOfSquares(octetDeltaSumOfSquares),
    octetTotalSumOfSquares(octetTotalSumOfSquares),
    mplsTopLabelTTL(mplsTopLabelTTL),
    mplsLabelStackLength(mplsLabelStackLength),
    mplsLabelStackDepth(mplsLabelStackDepth),
    mplsTopLabelExp(mplsTopLabelExp),
    ipPayloadLength(ipPayloadLength),
    udpMessageLength(udpMessageLength),
    isMulticast(isMulticast),
    ipv4IHL(ipv4IHL),
    ipv4Options(ipv4Options),
    tcpOptions(tcpOptions),
    paddingOctets(paddingOctets),
    collectorIPv4Address(collectorIPv4Address),
    collectorIPv6Address(collectorIPv6Address),
    exportInterface(exportInterface),
    exportProtocolVersion(exportProtocolVersion),
    exportTransportProtocol(exportTransportProtocol),
    collectorTransportPort(collectorTransportPort),
    exporterTransportPort(exporterTransportPort),
    tcpSynTotalCount(tcpSynTotalCount),
    tcpFinTotalCount(tcpFinTotalCount),
    tcpRstTotalCount(tcpRstTotalCount),
    tcpPshTotalCount(tcpPshTotalCount),
    tcpAckTotalCount(tcpAckTotalCount),
    tcpUrgTotalCount(tcpUrgTotalCount),
    ipTotalLength(ipTotalLength),
    postNATSourceIPv4Address(postNATSourceIPv4Address),
    postNATDestinationIPv4Address(postNATDestinationIPv4Address),
    postNAPTSourceTransportPort(postNAPTSourceTransportPort),
    postNAPTDestinationTransportPort(postNAPTDestinationTransportPort),
    natOriginatingAddressRealm(natOriginatingAddressRealm),
    natEvent(natEvent),
    initiatorOctets(initiatorOctets),
    responderOctets(responderOctets),
    firewallEvent(firewallEvent),
    ingressVRFID(ingressVRFID),
    egressVRFID(egressVRFID),
    VRFname(VRFname),
    postMplsTopLabelExp(postMplsTopLabelExp),
    tcpWindowScale(tcpWindowScale),
    biflowDirection(biflowDirection),
    ethernetHeaderLength(ethernetHeaderLength),
    ethernetPayloadLength(ethernetPayloadLength),
    ethernetTotalLength(ethernetTotalLength),
    dot1qVlanId(dot1qVlanId),
    dot1qPriority(dot1qPriority),
    dot1qCustomerVlanId(dot1qCustomerVlanId),
    dot1qCustomerPriority(dot1qCustomerPriority),
    metroEvcId(metroEvcId),
    metroEvcType(metroEvcType),
    pseudoWireId(pseudoWireId),
    pseudoWireType(pseudoWireType),
    pseudoWireControlWord(pseudoWireControlWord),
    ingressPhysicalInterface(ingressPhysicalInterface),
    egressPhysicalInterface(egressPhysicalInterface),
    postDot1qVlanId(postDot1qVlanId),
    postDot1qCustomerVlanId(postDot1qCustomerVlanId),
    ethernetType(ethernetType),
    postIpPrecedence(postIpPrecedence),
    collectionTimeMilliseconds(collectionTimeMilliseconds),
    exportSctpStreamId(exportSctpStreamId),
    maxExportSeconds(maxExportSeconds),
    maxFlowEndSeconds(maxFlowEndSeconds),
    messageMD5Checksum(messageMD5Checksum),
    messageScope(messageScope),
    minExportSeconds(minExportSeconds),
    minFlowStartSeconds(minFlowStartSeconds),
    opaqueOctets(opaqueOctets),
    sessionScope(sessionScope),
    maxFlowEndMicroseconds(maxFlowEndMicroseconds),
    maxFlowEndMilliseconds(maxFlowEndMilliseconds),
    maxFlowEndNanoseconds(maxFlowEndNanoseconds),
    minFlowStartMicroseconds(minFlowStartMicroseconds),
    minFlowStartMilliseconds(minFlowStartMilliseconds),
    minFlowStartNanoseconds(minFlowStartNanoseconds),
    collectorCertificate(collectorCertificate),
    exporterCertificate(exporterCertificate),
    dataRecordsReliability(dataRecordsReliability),
    observationPointType(observationPointType),
    newConnectionDeltaCount(newConnectionDeltaCount),
    connectionSumDurationSeconds(connectionSumDurationSeconds),
    connectionTransactionId(connectionTransactionId),
    postNATSourceIPv6Address(postNATSourceIPv6Address),
    postNATDestinationIPv6Address(postNATDestinationIPv6Address),
    natPoolId(natPoolId),
    natPoolName(natPoolName),
    anonymizationFlags(anonymizationFlags),
    anonymizationTechnique(anonymizationTechnique),
    informationElementIndex(informationElementIndex),
    p2pTechnology(p2pTechnology),
    tunnelTechnology(tunnelTechnology),
    encryptedTechnology(encryptedTechnology),
    basicList(basicList),
    subTemplateList(subTemplateList),
    subTemplateMultiList(subTemplateMultiList),
    bgpValidityState(bgpValidityState),
    IPSecSPI(IPSecSPI),
    greKey(greKey),
    natType(natType),
    initiatorPackets(initiatorPackets),
    responderPackets(responderPackets),
    observationDomainName(observationDomainName),
    selectionSequenceId(selectionSequenceId),
    selectorId(selectorId),
    informationElementId(informationElementId),
    selectorAlgorithm(selectorAlgorithm),
    samplingPacketInterval(samplingPacketInterval),
    samplingPacketSpace(samplingPacketSpace),
    samplingTimeInterval(samplingTimeInterval),
    samplingTimeSpace(samplingTimeSpace),
    samplingSize(samplingSize),
    samplingPopulation(samplingPopulation),
    samplingProbability(samplingProbability),
    dataLinkFrameSize(dataLinkFrameSize),
    ipHeaderPacketSection(ipHeaderPacketSection),
    ipPayloadPacketSection(ipPayloadPacketSection),
    dataLinkFrameSection(dataLinkFrameSection),
    mplsLabelStackSection(mplsLabelStackSection),
    mplsPayloadPacketSection(mplsPayloadPacketSection),
    selectorIdTotalPktsObserved(selectorIdTotalPktsObserved),
    selectorIdTotalPktsSelected(selectorIdTotalPktsSelected),
    absoluteError(absoluteError),
    relativeError(relativeError),
    observationTimeSeconds(observationTimeSeconds),
    observationTimeMilliseconds(observationTimeMilliseconds),
    observationTimeMicroseconds(observationTimeMicroseconds),
    observationTimeNanoseconds(observationTimeNanoseconds),
    digestHashValue(digestHashValue),
    hashIPPayloadOffset(hashIPPayloadOffset),
    hashIPPayloadSize(hashIPPayloadSize),
    hashOutputRangeMin(hashOutputRangeMin),
    hashOutputRangeMax(hashOutputRangeMax),
    hashSelectedRangeMin(hashSelectedRangeMin),
    hashSelectedRangeMax(hashSelectedRangeMax),
    hashDigestOutput(hashDigestOutput),
    hashInitialiserValue(hashInitialiserValue),
    selectorName(selectorName),
    upperCILimit(upperCILimit),
    lowerCILimit(lowerCILimit),
    confidenceLevel(confidenceLevel),
    informationElementDataType(informationElementDataType),
    informationElementDescription(informationElementDescription),
    informationElementName(informationElementName),
    informationElementRangeBegin(informationElementRangeBegin),
    informationElementRangeEnd(informationElementRangeEnd),
    informationElementSemantics(informationElementSemantics),
    informationElementUnits(informationElementUnits),
    privateEnterpriseNumber(privateEnterpriseNumber),
    virtualStationInterfaceId(virtualStationInterfaceId),
    virtualStationInterfaceName(virtualStationInterfaceName),
    virtualStationUUID(virtualStationUUID),
    virtualStationName(virtualStationName),
    layer2SegmentId(layer2SegmentId),
    layer2OctetDeltaCount(layer2OctetDeltaCount),
    layer2OctetTotalCount(layer2OctetTotalCount),
    ingressUnicastPacketTotalCount(ingressUnicastPacketTotalCount),
    ingressMulticastPacketTotalCount(ingressMulticastPacketTotalCount),
    ingressBroadcastPacketTotalCount(ingressBroadcastPacketTotalCount),
    egressUnicastPacketTotalCount(egressUnicastPacketTotalCount),
    egressBroadcastPacketTotalCount(egressBroadcastPacketTotalCount),
    monitoringIntervalStartMilliSeconds(monitoringIntervalStartMilliSeconds),
    monitoringIntervalEndMilliSeconds(monitoringIntervalEndMilliSeconds),
    portRangeStart(portRangeStart),
    portRangeEnd(portRangeEnd),
    portRangeStepSize(portRangeStepSize),
    portRangeNumPorts(portRangeNumPorts),
    staMacAddress(staMacAddress),
    staIPv4Address(staIPv4Address),
    wtpMacAddress(wtpMacAddress),
    ingressInterfaceType(ingressInterfaceType),
    egressInterfaceType(egressInterfaceType),
    rtpSequenceNumber(rtpSequenceNumber),
    userName(userName),
    applicationCategoryName(applicationCategoryName),
    applicationSubCategoryName(applicationSubCategoryName),
    applicationGroupName(applicationGroupName),
    originalFlowsPresent(originalFlowsPresent),
    originalFlowsInitiated(originalFlowsInitiated),
    originalFlowsCompleted(originalFlowsCompleted),
    distinctCountOfSourceIPAddress(distinctCountOfSourceIPAddress),
    distinctCountOfDestinationIPAddress(distinctCountOfDestinationIPAddress),
    distinctCountOfSourceIPv4Address(distinctCountOfSourceIPv4Address),
    distinctCountOfDestinationIPv4Address(distinctCountOfDestinationIPv4Address),
    distinctCountOfSourceIPv6Address(distinctCountOfSourceIPv6Address),
    distinctCountOfDestinationIPv6Address(distinctCountOfDestinationIPv6Address),
    valueDistributionMethod(valueDistributionMethod),
    rfc3550JitterMilliseconds(rfc3550JitterMilliseconds),
    rfc3550JitterMicroseconds(rfc3550JitterMicroseconds),
    rfc3550JitterNanoseconds(rfc3550JitterNanoseconds),
    dot1qDEI(dot1qDEI),
    dot1qCustomerDEI(dot1qCustomerDEI),
    flowSelectorAlgorithm(flowSelectorAlgorithm),
    flowSelectedOctetDeltaCount(flowSelectedOctetDeltaCount),
    flowSelectedPacketDeltaCount(flowSelectedPacketDeltaCount),
    flowSelectedFlowDeltaCount(flowSelectedFlowDeltaCount),
    selectorIDTotalFlowsObserved(selectorIDTotalFlowsObserved),
    selectorIDTotalFlowsSelected(selectorIDTotalFlowsSelected),
    samplingFlowInterval(samplingFlowInterval),
    samplingFlowSpacing(samplingFlowSpacing),
    flowSamplingTimeInterval(flowSamplingTimeInterval),
    flowSamplingTimeSpacing(flowSamplingTimeSpacing),
    hashFlowDomain(hashFlowDomain),
    transportOctetDeltaCount(transportOctetDeltaCount),
    transportPacketDeltaCount(transportPacketDeltaCount),
    originalExporterIPv4Address(originalExporterIPv4Address),
    originalExporterIPv6Address(originalExporterIPv6Address),
    originalObservationDomainId(originalObservationDomainId),
    intermediateProcessId(intermediateProcessId),
    ignoredDataRecordTotalCount(ignoredDataRecordTotalCount),
    dataLinkFrameType(dataLinkFrameType),
    sectionOffset(sectionOffset),
    sectionExportedOctets(sectionExportedOctets),
    dot1qServiceInstanceTag(dot1qServiceInstanceTag),
    dot1qServiceInstanceId(dot1qServiceInstanceId),
    dot1qServiceInstancePriority(dot1qServiceInstancePriority),
    dot1qCustomerSourceMacAddress(dot1qCustomerSourceMacAddress),
    dot1qCustomerDestinationMacAddress(dot1qCustomerDestinationMacAddress),
    postLayer2OctetDeltaCount(postLayer2OctetDeltaCount),
    postMCastLayer2OctetDeltaCount(postMCastLayer2OctetDeltaCount),
    postLayer2OctetTotalCount(postLayer2OctetTotalCount),
    postMCastLayer2OctetTotalCount(postMCastLayer2OctetTotalCount),
    minimumLayer2TotalLength(minimumLayer2TotalLength),
    maximumLayer2TotalLength(maximumLayer2TotalLength),
    droppedLayer2OctetDeltaCount(droppedLayer2OctetDeltaCount),
    droppedLayer2OctetTotalCount(droppedLayer2OctetTotalCount),
    ignoredLayer2OctetTotalCount(ignoredLayer2OctetTotalCount),
    notSentLayer2OctetTotalCount(notSentLayer2OctetTotalCount),
    layer2OctetDeltaSumOfSquares(layer2OctetDeltaSumOfSquares),
    layer2OctetTotalSumOfSquares(layer2OctetTotalSumOfSquares),
    layer2FrameDeltaCount(layer2FrameDeltaCount),
    layer2FrameTotalCount(layer2FrameTotalCount),
    pseudoWireDestinationIPv4Address(pseudoWireDestinationIPv4Address),
    ignoredLayer2FrameTotalCount(ignoredLayer2FrameTotalCount),
    mibObjectValueInteger(mibObjectValueInteger),
    mibObjectValueOctetString(mibObjectValueOctetString),
    mibObjectValueOID(mibObjectValueOID),
    mibObjectValueBits(mibObjectValueBits),
    mibObjectValueIPAddress(mibObjectValueIPAddress),
    mibObjectValueCounter(mibObjectValueCounter),
    mibObjectValueGauge(mibObjectValueGauge),
    mibObjectValueTimeTicks(mibObjectValueTimeTicks),
    mibObjectValueUnsigned(mibObjectValueUnsigned),
    mibObjectValueTable(mibObjectValueTable),
    mibObjectValueRow(mibObjectValueRow),
    mibObjectIdentifier(mibObjectIdentifier),
    mibSubIdentifier(mibSubIdentifier),
    mibIndexIndicator(mibIndexIndicator),
    mibCaptureTimeSemantics(mibCaptureTimeSemantics),
    mibContextEngineID(mibContextEngineID),
    mibContextName(mibContextName),
    mibObjectName(mibObjectName),
    mibObjectDescription(mibObjectDescription),
    mibObjectSyntax(mibObjectSyntax),
    mibModuleName(mibModuleName),
    mobileIMSI(mobileIMSI),
    mobileMSISDN(mobileMSISDN),
    httpStatusCode(httpStatusCode),
    sourceTransportPortsLimit(sourceTransportPortsLimit),
    httpRequestMethod(httpRequestMethod),
    httpRequestHost(httpRequestHost),
    httpRequestTarget(httpRequestTarget),
    httpMessageVersion(httpMessageVersion),
    natInstanceID(natInstanceID),
    internalAddressRealm(internalAddressRealm),
    externalAddressRealm(externalAddressRealm),
    natQuotaExceededEvent(natQuotaExceededEvent),
    natThresholdEvent(natThresholdEvent),
    httpUserAgent(httpUserAgent),
    httpContentType(httpContentType),
    httpReasonPhrase(httpReasonPhrase),
    maxSessionEntries(maxSessionEntries),
    maxBIBEntries(maxBIBEntries),
    maxEntriesPerUser(maxEntriesPerUser),
    maxSubscribers(maxSubscribers),
    maxFragmentsPendingReassembly(maxFragmentsPendingReassembly),
    addressPoolHighThreshold(addressPoolHighThreshold),
    addressPoolLowThreshold(addressPoolLowThreshold),
    addressPortMappingHighThreshold(addressPortMappingHighThreshold),
    addressPortMappingLowThreshold(addressPortMappingLowThreshold),
    addressPortMappingPerUserHighThreshold(addressPortMappingPerUserHighThreshold),
    globalAddressMappingHighThreshold(globalAddressMappingHighThreshold),
    vpnIdentifier(vpnIdentifier),
    bgpCommunity(bgpCommunity),
    bgpSourceCommunityList(bgpSourceCommunityList),
    bgpDestinationCommunityList(bgpDestinationCommunityList),
    bgpExtendedCommunity(bgpExtendedCommunity),
    bgpSourceExtendedCommunityList(bgpSourceExtendedCommunityList),
    bgpDestinationExtendedCommunityList(bgpDestinationExtendedCommunityList),
    bgpLargeCommunity(bgpLargeCommunity),
    bgpSourceLargeCommunityList(bgpSourceLargeCommunityList),
    bgpDestinationLargeCommunityList(bgpDestinationLargeCommunityList),
    srhFlagsIPv6(srhFlagsIPv6),
    srhTagIPv6(srhTagIPv6),
    srhSegmentIPv6(srhSegmentIPv6),
    srhActiveSegmentIPv6(srhActiveSegmentIPv6),
    srhSegmentIPv6BasicList(srhSegmentIPv6BasicList),
    srhSegmentIPv6ListSection(srhSegmentIPv6ListSection),
    srhSegmentsIPv6Left(srhSegmentsIPv6Left),
    srhIPv6Section(srhIPv6Section),
    srhIPv6ActiveSegmentType(srhIPv6ActiveSegmentType),
    srhSegmentIPv6LocatorLength(srhSegmentIPv6LocatorLength),
    srhSegmentIPv6EndpointBehavior(srhSegmentIPv6EndpointBehavior),
    transportChecksum(transportChecksum),
    icmpHeaderPacketSection(icmpHeaderPacketSection),
    gtpuFlags(gtpuFlags),
    gtpuMsgType(gtpuMsgType),
    gtpuTEid(gtpuTEid),
    gtpuSequenceNum(gtpuSequenceNum),
    gtpuQFI(gtpuQFI),
    gtpuPduType(gtpuPduType),
    bgpSourceAsPathList(bgpSourceAsPathList),
    bgpDestinationAsPathList(bgpDestinationAsPathList),
    ipv6ExtensionHeaderType(ipv6ExtensionHeaderType),
    ipv6ExtensionHeaderCount(ipv6ExtensionHeaderCount),
    ipv6ExtensionHeadersFull(ipv6ExtensionHeadersFull),
    ipv6ExtensionHeaderTypeCountList(ipv6ExtensionHeaderTypeCountList),
    ipv6ExtensionHeadersLimit(ipv6ExtensionHeadersLimit),
    ipv6ExtensionHeadersChainLength(ipv6ExtensionHeadersChainLength),
    ipv6ExtensionHeaderChainLengthList(ipv6ExtensionHeaderChainLengthList),
    tcpOptionsFull(tcpOptionsFull),
    tcpSharedOptionExID16(tcpSharedOptionExID16),
    tcpSharedOptionExID32(tcpSharedOptionExID32),
    tcpSharedOptionExID16List(tcpSharedOptionExID16List),
    tcpSharedOptionExID32List(tcpSharedOptionExID32List),
}

impl HasIE for Field {
    /// Get the [IE] element for a given field
    fn ie(&self) -> IE {
        match self {
            Self::Unknown{pen, id, value: _value} => IE::Unknown{pen: *pen, id: *id},
            Self::Nokia(x) => IE::Nokia(x.ie()),
            Self::NetGauze(x) => IE::NetGauze(x.ie()),
            Self::Cisco(x) => IE::Cisco(x.ie()),
            Self::VMWare(x) => IE::VMWare(x.ie()),
            Self::octetDeltaCount(_) => IE::octetDeltaCount,
            Self::packetDeltaCount(_) => IE::packetDeltaCount,
            Self::deltaFlowCount(_) => IE::deltaFlowCount,
            Self::protocolIdentifier(_) => IE::protocolIdentifier,
            Self::ipClassOfService(_) => IE::ipClassOfService,
            Self::tcpControlBits(_) => IE::tcpControlBits,
            Self::sourceTransportPort(_) => IE::sourceTransportPort,
            Self::sourceIPv4Address(_) => IE::sourceIPv4Address,
            Self::sourceIPv4PrefixLength(_) => IE::sourceIPv4PrefixLength,
            Self::ingressInterface(_) => IE::ingressInterface,
            Self::destinationTransportPort(_) => IE::destinationTransportPort,
            Self::destinationIPv4Address(_) => IE::destinationIPv4Address,
            Self::destinationIPv4PrefixLength(_) => IE::destinationIPv4PrefixLength,
            Self::egressInterface(_) => IE::egressInterface,
            Self::ipNextHopIPv4Address(_) => IE::ipNextHopIPv4Address,
            Self::bgpSourceAsNumber(_) => IE::bgpSourceAsNumber,
            Self::bgpDestinationAsNumber(_) => IE::bgpDestinationAsNumber,
            Self::bgpNextHopIPv4Address(_) => IE::bgpNextHopIPv4Address,
            Self::postMCastPacketDeltaCount(_) => IE::postMCastPacketDeltaCount,
            Self::postMCastOctetDeltaCount(_) => IE::postMCastOctetDeltaCount,
            Self::flowEndSysUpTime(_) => IE::flowEndSysUpTime,
            Self::flowStartSysUpTime(_) => IE::flowStartSysUpTime,
            Self::postOctetDeltaCount(_) => IE::postOctetDeltaCount,
            Self::postPacketDeltaCount(_) => IE::postPacketDeltaCount,
            Self::minimumIpTotalLength(_) => IE::minimumIpTotalLength,
            Self::maximumIpTotalLength(_) => IE::maximumIpTotalLength,
            Self::sourceIPv6Address(_) => IE::sourceIPv6Address,
            Self::destinationIPv6Address(_) => IE::destinationIPv6Address,
            Self::sourceIPv6PrefixLength(_) => IE::sourceIPv6PrefixLength,
            Self::destinationIPv6PrefixLength(_) => IE::destinationIPv6PrefixLength,
            Self::flowLabelIPv6(_) => IE::flowLabelIPv6,
            Self::icmpTypeCodeIPv4(_) => IE::icmpTypeCodeIPv4,
            Self::igmpType(_) => IE::igmpType,
            Self::samplingInterval(_) => IE::samplingInterval,
            Self::samplingAlgorithm(_) => IE::samplingAlgorithm,
            Self::flowActiveTimeout(_) => IE::flowActiveTimeout,
            Self::flowIdleTimeout(_) => IE::flowIdleTimeout,
            Self::engineType(_) => IE::engineType,
            Self::engineId(_) => IE::engineId,
            Self::exportedOctetTotalCount(_) => IE::exportedOctetTotalCount,
            Self::exportedMessageTotalCount(_) => IE::exportedMessageTotalCount,
            Self::exportedFlowRecordTotalCount(_) => IE::exportedFlowRecordTotalCount,
            Self::ipv4RouterSc(_) => IE::ipv4RouterSc,
            Self::sourceIPv4Prefix(_) => IE::sourceIPv4Prefix,
            Self::destinationIPv4Prefix(_) => IE::destinationIPv4Prefix,
            Self::mplsTopLabelType(_) => IE::mplsTopLabelType,
            Self::mplsTopLabelIPv4Address(_) => IE::mplsTopLabelIPv4Address,
            Self::samplerId(_) => IE::samplerId,
            Self::samplerMode(_) => IE::samplerMode,
            Self::samplerRandomInterval(_) => IE::samplerRandomInterval,
            Self::classId(_) => IE::classId,
            Self::minimumTTL(_) => IE::minimumTTL,
            Self::maximumTTL(_) => IE::maximumTTL,
            Self::fragmentIdentification(_) => IE::fragmentIdentification,
            Self::postIpClassOfService(_) => IE::postIpClassOfService,
            Self::sourceMacAddress(_) => IE::sourceMacAddress,
            Self::postDestinationMacAddress(_) => IE::postDestinationMacAddress,
            Self::vlanId(_) => IE::vlanId,
            Self::postVlanId(_) => IE::postVlanId,
            Self::ipVersion(_) => IE::ipVersion,
            Self::flowDirection(_) => IE::flowDirection,
            Self::ipNextHopIPv6Address(_) => IE::ipNextHopIPv6Address,
            Self::bgpNextHopIPv6Address(_) => IE::bgpNextHopIPv6Address,
            Self::ipv6ExtensionHeaders(_) => IE::ipv6ExtensionHeaders,
            Self::mplsTopLabelStackSection(_) => IE::mplsTopLabelStackSection,
            Self::mplsLabelStackSection2(_) => IE::mplsLabelStackSection2,
            Self::mplsLabelStackSection3(_) => IE::mplsLabelStackSection3,
            Self::mplsLabelStackSection4(_) => IE::mplsLabelStackSection4,
            Self::mplsLabelStackSection5(_) => IE::mplsLabelStackSection5,
            Self::mplsLabelStackSection6(_) => IE::mplsLabelStackSection6,
            Self::mplsLabelStackSection7(_) => IE::mplsLabelStackSection7,
            Self::mplsLabelStackSection8(_) => IE::mplsLabelStackSection8,
            Self::mplsLabelStackSection9(_) => IE::mplsLabelStackSection9,
            Self::mplsLabelStackSection10(_) => IE::mplsLabelStackSection10,
            Self::destinationMacAddress(_) => IE::destinationMacAddress,
            Self::postSourceMacAddress(_) => IE::postSourceMacAddress,
            Self::interfaceName(_) => IE::interfaceName,
            Self::interfaceDescription(_) => IE::interfaceDescription,
            Self::samplerName(_) => IE::samplerName,
            Self::octetTotalCount(_) => IE::octetTotalCount,
            Self::packetTotalCount(_) => IE::packetTotalCount,
            Self::flagsAndSamplerId(_) => IE::flagsAndSamplerId,
            Self::fragmentOffset(_) => IE::fragmentOffset,
            Self::forwardingStatus(_) => IE::forwardingStatus,
            Self::mplsVpnRouteDistinguisher(_) => IE::mplsVpnRouteDistinguisher,
            Self::mplsTopLabelPrefixLength(_) => IE::mplsTopLabelPrefixLength,
            Self::srcTrafficIndex(_) => IE::srcTrafficIndex,
            Self::dstTrafficIndex(_) => IE::dstTrafficIndex,
            Self::applicationDescription(_) => IE::applicationDescription,
            Self::applicationId(_) => IE::applicationId,
            Self::applicationName(_) => IE::applicationName,
            Self::postIpDiffServCodePoint(_) => IE::postIpDiffServCodePoint,
            Self::multicastReplicationFactor(_) => IE::multicastReplicationFactor,
            Self::className(_) => IE::className,
            Self::classificationEngineId(_) => IE::classificationEngineId,
            Self::layer2packetSectionOffset(_) => IE::layer2packetSectionOffset,
            Self::layer2packetSectionSize(_) => IE::layer2packetSectionSize,
            Self::layer2packetSectionData(_) => IE::layer2packetSectionData,
            Self::bgpNextAdjacentAsNumber(_) => IE::bgpNextAdjacentAsNumber,
            Self::bgpPrevAdjacentAsNumber(_) => IE::bgpPrevAdjacentAsNumber,
            Self::exporterIPv4Address(_) => IE::exporterIPv4Address,
            Self::exporterIPv6Address(_) => IE::exporterIPv6Address,
            Self::droppedOctetDeltaCount(_) => IE::droppedOctetDeltaCount,
            Self::droppedPacketDeltaCount(_) => IE::droppedPacketDeltaCount,
            Self::droppedOctetTotalCount(_) => IE::droppedOctetTotalCount,
            Self::droppedPacketTotalCount(_) => IE::droppedPacketTotalCount,
            Self::flowEndReason(_) => IE::flowEndReason,
            Self::commonPropertiesId(_) => IE::commonPropertiesId,
            Self::observationPointId(_) => IE::observationPointId,
            Self::icmpTypeCodeIPv6(_) => IE::icmpTypeCodeIPv6,
            Self::mplsTopLabelIPv6Address(_) => IE::mplsTopLabelIPv6Address,
            Self::lineCardId(_) => IE::lineCardId,
            Self::portId(_) => IE::portId,
            Self::meteringProcessId(_) => IE::meteringProcessId,
            Self::exportingProcessId(_) => IE::exportingProcessId,
            Self::templateId(_) => IE::templateId,
            Self::wlanChannelId(_) => IE::wlanChannelId,
            Self::wlanSSID(_) => IE::wlanSSID,
            Self::flowId(_) => IE::flowId,
            Self::observationDomainId(_) => IE::observationDomainId,
            Self::flowStartSeconds(_) => IE::flowStartSeconds,
            Self::flowEndSeconds(_) => IE::flowEndSeconds,
            Self::flowStartMilliseconds(_) => IE::flowStartMilliseconds,
            Self::flowEndMilliseconds(_) => IE::flowEndMilliseconds,
            Self::flowStartMicroseconds(_) => IE::flowStartMicroseconds,
            Self::flowEndMicroseconds(_) => IE::flowEndMicroseconds,
            Self::flowStartNanoseconds(_) => IE::flowStartNanoseconds,
            Self::flowEndNanoseconds(_) => IE::flowEndNanoseconds,
            Self::flowStartDeltaMicroseconds(_) => IE::flowStartDeltaMicroseconds,
            Self::flowEndDeltaMicroseconds(_) => IE::flowEndDeltaMicroseconds,
            Self::systemInitTimeMilliseconds(_) => IE::systemInitTimeMilliseconds,
            Self::flowDurationMilliseconds(_) => IE::flowDurationMilliseconds,
            Self::flowDurationMicroseconds(_) => IE::flowDurationMicroseconds,
            Self::observedFlowTotalCount(_) => IE::observedFlowTotalCount,
            Self::ignoredPacketTotalCount(_) => IE::ignoredPacketTotalCount,
            Self::ignoredOctetTotalCount(_) => IE::ignoredOctetTotalCount,
            Self::notSentFlowTotalCount(_) => IE::notSentFlowTotalCount,
            Self::notSentPacketTotalCount(_) => IE::notSentPacketTotalCount,
            Self::notSentOctetTotalCount(_) => IE::notSentOctetTotalCount,
            Self::destinationIPv6Prefix(_) => IE::destinationIPv6Prefix,
            Self::sourceIPv6Prefix(_) => IE::sourceIPv6Prefix,
            Self::postOctetTotalCount(_) => IE::postOctetTotalCount,
            Self::postPacketTotalCount(_) => IE::postPacketTotalCount,
            Self::flowKeyIndicator(_) => IE::flowKeyIndicator,
            Self::postMCastPacketTotalCount(_) => IE::postMCastPacketTotalCount,
            Self::postMCastOctetTotalCount(_) => IE::postMCastOctetTotalCount,
            Self::icmpTypeIPv4(_) => IE::icmpTypeIPv4,
            Self::icmpCodeIPv4(_) => IE::icmpCodeIPv4,
            Self::icmpTypeIPv6(_) => IE::icmpTypeIPv6,
            Self::icmpCodeIPv6(_) => IE::icmpCodeIPv6,
            Self::udpSourcePort(_) => IE::udpSourcePort,
            Self::udpDestinationPort(_) => IE::udpDestinationPort,
            Self::tcpSourcePort(_) => IE::tcpSourcePort,
            Self::tcpDestinationPort(_) => IE::tcpDestinationPort,
            Self::tcpSequenceNumber(_) => IE::tcpSequenceNumber,
            Self::tcpAcknowledgementNumber(_) => IE::tcpAcknowledgementNumber,
            Self::tcpWindowSize(_) => IE::tcpWindowSize,
            Self::tcpUrgentPointer(_) => IE::tcpUrgentPointer,
            Self::tcpHeaderLength(_) => IE::tcpHeaderLength,
            Self::ipHeaderLength(_) => IE::ipHeaderLength,
            Self::totalLengthIPv4(_) => IE::totalLengthIPv4,
            Self::payloadLengthIPv6(_) => IE::payloadLengthIPv6,
            Self::ipTTL(_) => IE::ipTTL,
            Self::nextHeaderIPv6(_) => IE::nextHeaderIPv6,
            Self::mplsPayloadLength(_) => IE::mplsPayloadLength,
            Self::ipDiffServCodePoint(_) => IE::ipDiffServCodePoint,
            Self::ipPrecedence(_) => IE::ipPrecedence,
            Self::fragmentFlags(_) => IE::fragmentFlags,
            Self::octetDeltaSumOfSquares(_) => IE::octetDeltaSumOfSquares,
            Self::octetTotalSumOfSquares(_) => IE::octetTotalSumOfSquares,
            Self::mplsTopLabelTTL(_) => IE::mplsTopLabelTTL,
            Self::mplsLabelStackLength(_) => IE::mplsLabelStackLength,
            Self::mplsLabelStackDepth(_) => IE::mplsLabelStackDepth,
            Self::mplsTopLabelExp(_) => IE::mplsTopLabelExp,
            Self::ipPayloadLength(_) => IE::ipPayloadLength,
            Self::udpMessageLength(_) => IE::udpMessageLength,
            Self::isMulticast(_) => IE::isMulticast,
            Self::ipv4IHL(_) => IE::ipv4IHL,
            Self::ipv4Options(_) => IE::ipv4Options,
            Self::tcpOptions(_) => IE::tcpOptions,
            Self::paddingOctets(_) => IE::paddingOctets,
            Self::collectorIPv4Address(_) => IE::collectorIPv4Address,
            Self::collectorIPv6Address(_) => IE::collectorIPv6Address,
            Self::exportInterface(_) => IE::exportInterface,
            Self::exportProtocolVersion(_) => IE::exportProtocolVersion,
            Self::exportTransportProtocol(_) => IE::exportTransportProtocol,
            Self::collectorTransportPort(_) => IE::collectorTransportPort,
            Self::exporterTransportPort(_) => IE::exporterTransportPort,
            Self::tcpSynTotalCount(_) => IE::tcpSynTotalCount,
            Self::tcpFinTotalCount(_) => IE::tcpFinTotalCount,
            Self::tcpRstTotalCount(_) => IE::tcpRstTotalCount,
            Self::tcpPshTotalCount(_) => IE::tcpPshTotalCount,
            Self::tcpAckTotalCount(_) => IE::tcpAckTotalCount,
            Self::tcpUrgTotalCount(_) => IE::tcpUrgTotalCount,
            Self::ipTotalLength(_) => IE::ipTotalLength,
            Self::postNATSourceIPv4Address(_) => IE::postNATSourceIPv4Address,
            Self::postNATDestinationIPv4Address(_) => IE::postNATDestinationIPv4Address,
            Self::postNAPTSourceTransportPort(_) => IE::postNAPTSourceTransportPort,
            Self::postNAPTDestinationTransportPort(_) => IE::postNAPTDestinationTransportPort,
            Self::natOriginatingAddressRealm(_) => IE::natOriginatingAddressRealm,
            Self::natEvent(_) => IE::natEvent,
            Self::initiatorOctets(_) => IE::initiatorOctets,
            Self::responderOctets(_) => IE::responderOctets,
            Self::firewallEvent(_) => IE::firewallEvent,
            Self::ingressVRFID(_) => IE::ingressVRFID,
            Self::egressVRFID(_) => IE::egressVRFID,
            Self::VRFname(_) => IE::VRFname,
            Self::postMplsTopLabelExp(_) => IE::postMplsTopLabelExp,
            Self::tcpWindowScale(_) => IE::tcpWindowScale,
            Self::biflowDirection(_) => IE::biflowDirection,
            Self::ethernetHeaderLength(_) => IE::ethernetHeaderLength,
            Self::ethernetPayloadLength(_) => IE::ethernetPayloadLength,
            Self::ethernetTotalLength(_) => IE::ethernetTotalLength,
            Self::dot1qVlanId(_) => IE::dot1qVlanId,
            Self::dot1qPriority(_) => IE::dot1qPriority,
            Self::dot1qCustomerVlanId(_) => IE::dot1qCustomerVlanId,
            Self::dot1qCustomerPriority(_) => IE::dot1qCustomerPriority,
            Self::metroEvcId(_) => IE::metroEvcId,
            Self::metroEvcType(_) => IE::metroEvcType,
            Self::pseudoWireId(_) => IE::pseudoWireId,
            Self::pseudoWireType(_) => IE::pseudoWireType,
            Self::pseudoWireControlWord(_) => IE::pseudoWireControlWord,
            Self::ingressPhysicalInterface(_) => IE::ingressPhysicalInterface,
            Self::egressPhysicalInterface(_) => IE::egressPhysicalInterface,
            Self::postDot1qVlanId(_) => IE::postDot1qVlanId,
            Self::postDot1qCustomerVlanId(_) => IE::postDot1qCustomerVlanId,
            Self::ethernetType(_) => IE::ethernetType,
            Self::postIpPrecedence(_) => IE::postIpPrecedence,
            Self::collectionTimeMilliseconds(_) => IE::collectionTimeMilliseconds,
            Self::exportSctpStreamId(_) => IE::exportSctpStreamId,
            Self::maxExportSeconds(_) => IE::maxExportSeconds,
            Self::maxFlowEndSeconds(_) => IE::maxFlowEndSeconds,
            Self::messageMD5Checksum(_) => IE::messageMD5Checksum,
            Self::messageScope(_) => IE::messageScope,
            Self::minExportSeconds(_) => IE::minExportSeconds,
            Self::minFlowStartSeconds(_) => IE::minFlowStartSeconds,
            Self::opaqueOctets(_) => IE::opaqueOctets,
            Self::sessionScope(_) => IE::sessionScope,
            Self::maxFlowEndMicroseconds(_) => IE::maxFlowEndMicroseconds,
            Self::maxFlowEndMilliseconds(_) => IE::maxFlowEndMilliseconds,
            Self::maxFlowEndNanoseconds(_) => IE::maxFlowEndNanoseconds,
            Self::minFlowStartMicroseconds(_) => IE::minFlowStartMicroseconds,
            Self::minFlowStartMilliseconds(_) => IE::minFlowStartMilliseconds,
            Self::minFlowStartNanoseconds(_) => IE::minFlowStartNanoseconds,
            Self::collectorCertificate(_) => IE::collectorCertificate,
            Self::exporterCertificate(_) => IE::exporterCertificate,
            Self::dataRecordsReliability(_) => IE::dataRecordsReliability,
            Self::observationPointType(_) => IE::observationPointType,
            Self::newConnectionDeltaCount(_) => IE::newConnectionDeltaCount,
            Self::connectionSumDurationSeconds(_) => IE::connectionSumDurationSeconds,
            Self::connectionTransactionId(_) => IE::connectionTransactionId,
            Self::postNATSourceIPv6Address(_) => IE::postNATSourceIPv6Address,
            Self::postNATDestinationIPv6Address(_) => IE::postNATDestinationIPv6Address,
            Self::natPoolId(_) => IE::natPoolId,
            Self::natPoolName(_) => IE::natPoolName,
            Self::anonymizationFlags(_) => IE::anonymizationFlags,
            Self::anonymizationTechnique(_) => IE::anonymizationTechnique,
            Self::informationElementIndex(_) => IE::informationElementIndex,
            Self::p2pTechnology(_) => IE::p2pTechnology,
            Self::tunnelTechnology(_) => IE::tunnelTechnology,
            Self::encryptedTechnology(_) => IE::encryptedTechnology,
            Self::basicList(_) => IE::basicList,
            Self::subTemplateList(_) => IE::subTemplateList,
            Self::subTemplateMultiList(_) => IE::subTemplateMultiList,
            Self::bgpValidityState(_) => IE::bgpValidityState,
            Self::IPSecSPI(_) => IE::IPSecSPI,
            Self::greKey(_) => IE::greKey,
            Self::natType(_) => IE::natType,
            Self::initiatorPackets(_) => IE::initiatorPackets,
            Self::responderPackets(_) => IE::responderPackets,
            Self::observationDomainName(_) => IE::observationDomainName,
            Self::selectionSequenceId(_) => IE::selectionSequenceId,
            Self::selectorId(_) => IE::selectorId,
            Self::informationElementId(_) => IE::informationElementId,
            Self::selectorAlgorithm(_) => IE::selectorAlgorithm,
            Self::samplingPacketInterval(_) => IE::samplingPacketInterval,
            Self::samplingPacketSpace(_) => IE::samplingPacketSpace,
            Self::samplingTimeInterval(_) => IE::samplingTimeInterval,
            Self::samplingTimeSpace(_) => IE::samplingTimeSpace,
            Self::samplingSize(_) => IE::samplingSize,
            Self::samplingPopulation(_) => IE::samplingPopulation,
            Self::samplingProbability(_) => IE::samplingProbability,
            Self::dataLinkFrameSize(_) => IE::dataLinkFrameSize,
            Self::ipHeaderPacketSection(_) => IE::ipHeaderPacketSection,
            Self::ipPayloadPacketSection(_) => IE::ipPayloadPacketSection,
            Self::dataLinkFrameSection(_) => IE::dataLinkFrameSection,
            Self::mplsLabelStackSection(_) => IE::mplsLabelStackSection,
            Self::mplsPayloadPacketSection(_) => IE::mplsPayloadPacketSection,
            Self::selectorIdTotalPktsObserved(_) => IE::selectorIdTotalPktsObserved,
            Self::selectorIdTotalPktsSelected(_) => IE::selectorIdTotalPktsSelected,
            Self::absoluteError(_) => IE::absoluteError,
            Self::relativeError(_) => IE::relativeError,
            Self::observationTimeSeconds(_) => IE::observationTimeSeconds,
            Self::observationTimeMilliseconds(_) => IE::observationTimeMilliseconds,
            Self::observationTimeMicroseconds(_) => IE::observationTimeMicroseconds,
            Self::observationTimeNanoseconds(_) => IE::observationTimeNanoseconds,
            Self::digestHashValue(_) => IE::digestHashValue,
            Self::hashIPPayloadOffset(_) => IE::hashIPPayloadOffset,
            Self::hashIPPayloadSize(_) => IE::hashIPPayloadSize,
            Self::hashOutputRangeMin(_) => IE::hashOutputRangeMin,
            Self::hashOutputRangeMax(_) => IE::hashOutputRangeMax,
            Self::hashSelectedRangeMin(_) => IE::hashSelectedRangeMin,
            Self::hashSelectedRangeMax(_) => IE::hashSelectedRangeMax,
            Self::hashDigestOutput(_) => IE::hashDigestOutput,
            Self::hashInitialiserValue(_) => IE::hashInitialiserValue,
            Self::selectorName(_) => IE::selectorName,
            Self::upperCILimit(_) => IE::upperCILimit,
            Self::lowerCILimit(_) => IE::lowerCILimit,
            Self::confidenceLevel(_) => IE::confidenceLevel,
            Self::informationElementDataType(_) => IE::informationElementDataType,
            Self::informationElementDescription(_) => IE::informationElementDescription,
            Self::informationElementName(_) => IE::informationElementName,
            Self::informationElementRangeBegin(_) => IE::informationElementRangeBegin,
            Self::informationElementRangeEnd(_) => IE::informationElementRangeEnd,
            Self::informationElementSemantics(_) => IE::informationElementSemantics,
            Self::informationElementUnits(_) => IE::informationElementUnits,
            Self::privateEnterpriseNumber(_) => IE::privateEnterpriseNumber,
            Self::virtualStationInterfaceId(_) => IE::virtualStationInterfaceId,
            Self::virtualStationInterfaceName(_) => IE::virtualStationInterfaceName,
            Self::virtualStationUUID(_) => IE::virtualStationUUID,
            Self::virtualStationName(_) => IE::virtualStationName,
            Self::layer2SegmentId(_) => IE::layer2SegmentId,
            Self::layer2OctetDeltaCount(_) => IE::layer2OctetDeltaCount,
            Self::layer2OctetTotalCount(_) => IE::layer2OctetTotalCount,
            Self::ingressUnicastPacketTotalCount(_) => IE::ingressUnicastPacketTotalCount,
            Self::ingressMulticastPacketTotalCount(_) => IE::ingressMulticastPacketTotalCount,
            Self::ingressBroadcastPacketTotalCount(_) => IE::ingressBroadcastPacketTotalCount,
            Self::egressUnicastPacketTotalCount(_) => IE::egressUnicastPacketTotalCount,
            Self::egressBroadcastPacketTotalCount(_) => IE::egressBroadcastPacketTotalCount,
            Self::monitoringIntervalStartMilliSeconds(_) => IE::monitoringIntervalStartMilliSeconds,
            Self::monitoringIntervalEndMilliSeconds(_) => IE::monitoringIntervalEndMilliSeconds,
            Self::portRangeStart(_) => IE::portRangeStart,
            Self::portRangeEnd(_) => IE::portRangeEnd,
            Self::portRangeStepSize(_) => IE::portRangeStepSize,
            Self::portRangeNumPorts(_) => IE::portRangeNumPorts,
            Self::staMacAddress(_) => IE::staMacAddress,
            Self::staIPv4Address(_) => IE::staIPv4Address,
            Self::wtpMacAddress(_) => IE::wtpMacAddress,
            Self::ingressInterfaceType(_) => IE::ingressInterfaceType,
            Self::egressInterfaceType(_) => IE::egressInterfaceType,
            Self::rtpSequenceNumber(_) => IE::rtpSequenceNumber,
            Self::userName(_) => IE::userName,
            Self::applicationCategoryName(_) => IE::applicationCategoryName,
            Self::applicationSubCategoryName(_) => IE::applicationSubCategoryName,
            Self::applicationGroupName(_) => IE::applicationGroupName,
            Self::originalFlowsPresent(_) => IE::originalFlowsPresent,
            Self::originalFlowsInitiated(_) => IE::originalFlowsInitiated,
            Self::originalFlowsCompleted(_) => IE::originalFlowsCompleted,
            Self::distinctCountOfSourceIPAddress(_) => IE::distinctCountOfSourceIPAddress,
            Self::distinctCountOfDestinationIPAddress(_) => IE::distinctCountOfDestinationIPAddress,
            Self::distinctCountOfSourceIPv4Address(_) => IE::distinctCountOfSourceIPv4Address,
            Self::distinctCountOfDestinationIPv4Address(_) => IE::distinctCountOfDestinationIPv4Address,
            Self::distinctCountOfSourceIPv6Address(_) => IE::distinctCountOfSourceIPv6Address,
            Self::distinctCountOfDestinationIPv6Address(_) => IE::distinctCountOfDestinationIPv6Address,
            Self::valueDistributionMethod(_) => IE::valueDistributionMethod,
            Self::rfc3550JitterMilliseconds(_) => IE::rfc3550JitterMilliseconds,
            Self::rfc3550JitterMicroseconds(_) => IE::rfc3550JitterMicroseconds,
            Self::rfc3550JitterNanoseconds(_) => IE::rfc3550JitterNanoseconds,
            Self::dot1qDEI(_) => IE::dot1qDEI,
            Self::dot1qCustomerDEI(_) => IE::dot1qCustomerDEI,
            Self::flowSelectorAlgorithm(_) => IE::flowSelectorAlgorithm,
            Self::flowSelectedOctetDeltaCount(_) => IE::flowSelectedOctetDeltaCount,
            Self::flowSelectedPacketDeltaCount(_) => IE::flowSelectedPacketDeltaCount,
            Self::flowSelectedFlowDeltaCount(_) => IE::flowSelectedFlowDeltaCount,
            Self::selectorIDTotalFlowsObserved(_) => IE::selectorIDTotalFlowsObserved,
            Self::selectorIDTotalFlowsSelected(_) => IE::selectorIDTotalFlowsSelected,
            Self::samplingFlowInterval(_) => IE::samplingFlowInterval,
            Self::samplingFlowSpacing(_) => IE::samplingFlowSpacing,
            Self::flowSamplingTimeInterval(_) => IE::flowSamplingTimeInterval,
            Self::flowSamplingTimeSpacing(_) => IE::flowSamplingTimeSpacing,
            Self::hashFlowDomain(_) => IE::hashFlowDomain,
            Self::transportOctetDeltaCount(_) => IE::transportOctetDeltaCount,
            Self::transportPacketDeltaCount(_) => IE::transportPacketDeltaCount,
            Self::originalExporterIPv4Address(_) => IE::originalExporterIPv4Address,
            Self::originalExporterIPv6Address(_) => IE::originalExporterIPv6Address,
            Self::originalObservationDomainId(_) => IE::originalObservationDomainId,
            Self::intermediateProcessId(_) => IE::intermediateProcessId,
            Self::ignoredDataRecordTotalCount(_) => IE::ignoredDataRecordTotalCount,
            Self::dataLinkFrameType(_) => IE::dataLinkFrameType,
            Self::sectionOffset(_) => IE::sectionOffset,
            Self::sectionExportedOctets(_) => IE::sectionExportedOctets,
            Self::dot1qServiceInstanceTag(_) => IE::dot1qServiceInstanceTag,
            Self::dot1qServiceInstanceId(_) => IE::dot1qServiceInstanceId,
            Self::dot1qServiceInstancePriority(_) => IE::dot1qServiceInstancePriority,
            Self::dot1qCustomerSourceMacAddress(_) => IE::dot1qCustomerSourceMacAddress,
            Self::dot1qCustomerDestinationMacAddress(_) => IE::dot1qCustomerDestinationMacAddress,
            Self::postLayer2OctetDeltaCount(_) => IE::postLayer2OctetDeltaCount,
            Self::postMCastLayer2OctetDeltaCount(_) => IE::postMCastLayer2OctetDeltaCount,
            Self::postLayer2OctetTotalCount(_) => IE::postLayer2OctetTotalCount,
            Self::postMCastLayer2OctetTotalCount(_) => IE::postMCastLayer2OctetTotalCount,
            Self::minimumLayer2TotalLength(_) => IE::minimumLayer2TotalLength,
            Self::maximumLayer2TotalLength(_) => IE::maximumLayer2TotalLength,
            Self::droppedLayer2OctetDeltaCount(_) => IE::droppedLayer2OctetDeltaCount,
            Self::droppedLayer2OctetTotalCount(_) => IE::droppedLayer2OctetTotalCount,
            Self::ignoredLayer2OctetTotalCount(_) => IE::ignoredLayer2OctetTotalCount,
            Self::notSentLayer2OctetTotalCount(_) => IE::notSentLayer2OctetTotalCount,
            Self::layer2OctetDeltaSumOfSquares(_) => IE::layer2OctetDeltaSumOfSquares,
            Self::layer2OctetTotalSumOfSquares(_) => IE::layer2OctetTotalSumOfSquares,
            Self::layer2FrameDeltaCount(_) => IE::layer2FrameDeltaCount,
            Self::layer2FrameTotalCount(_) => IE::layer2FrameTotalCount,
            Self::pseudoWireDestinationIPv4Address(_) => IE::pseudoWireDestinationIPv4Address,
            Self::ignoredLayer2FrameTotalCount(_) => IE::ignoredLayer2FrameTotalCount,
            Self::mibObjectValueInteger(_) => IE::mibObjectValueInteger,
            Self::mibObjectValueOctetString(_) => IE::mibObjectValueOctetString,
            Self::mibObjectValueOID(_) => IE::mibObjectValueOID,
            Self::mibObjectValueBits(_) => IE::mibObjectValueBits,
            Self::mibObjectValueIPAddress(_) => IE::mibObjectValueIPAddress,
            Self::mibObjectValueCounter(_) => IE::mibObjectValueCounter,
            Self::mibObjectValueGauge(_) => IE::mibObjectValueGauge,
            Self::mibObjectValueTimeTicks(_) => IE::mibObjectValueTimeTicks,
            Self::mibObjectValueUnsigned(_) => IE::mibObjectValueUnsigned,
            Self::mibObjectValueTable(_) => IE::mibObjectValueTable,
            Self::mibObjectValueRow(_) => IE::mibObjectValueRow,
            Self::mibObjectIdentifier(_) => IE::mibObjectIdentifier,
            Self::mibSubIdentifier(_) => IE::mibSubIdentifier,
            Self::mibIndexIndicator(_) => IE::mibIndexIndicator,
            Self::mibCaptureTimeSemantics(_) => IE::mibCaptureTimeSemantics,
            Self::mibContextEngineID(_) => IE::mibContextEngineID,
            Self::mibContextName(_) => IE::mibContextName,
            Self::mibObjectName(_) => IE::mibObjectName,
            Self::mibObjectDescription(_) => IE::mibObjectDescription,
            Self::mibObjectSyntax(_) => IE::mibObjectSyntax,
            Self::mibModuleName(_) => IE::mibModuleName,
            Self::mobileIMSI(_) => IE::mobileIMSI,
            Self::mobileMSISDN(_) => IE::mobileMSISDN,
            Self::httpStatusCode(_) => IE::httpStatusCode,
            Self::sourceTransportPortsLimit(_) => IE::sourceTransportPortsLimit,
            Self::httpRequestMethod(_) => IE::httpRequestMethod,
            Self::httpRequestHost(_) => IE::httpRequestHost,
            Self::httpRequestTarget(_) => IE::httpRequestTarget,
            Self::httpMessageVersion(_) => IE::httpMessageVersion,
            Self::natInstanceID(_) => IE::natInstanceID,
            Self::internalAddressRealm(_) => IE::internalAddressRealm,
            Self::externalAddressRealm(_) => IE::externalAddressRealm,
            Self::natQuotaExceededEvent(_) => IE::natQuotaExceededEvent,
            Self::natThresholdEvent(_) => IE::natThresholdEvent,
            Self::httpUserAgent(_) => IE::httpUserAgent,
            Self::httpContentType(_) => IE::httpContentType,
            Self::httpReasonPhrase(_) => IE::httpReasonPhrase,
            Self::maxSessionEntries(_) => IE::maxSessionEntries,
            Self::maxBIBEntries(_) => IE::maxBIBEntries,
            Self::maxEntriesPerUser(_) => IE::maxEntriesPerUser,
            Self::maxSubscribers(_) => IE::maxSubscribers,
            Self::maxFragmentsPendingReassembly(_) => IE::maxFragmentsPendingReassembly,
            Self::addressPoolHighThreshold(_) => IE::addressPoolHighThreshold,
            Self::addressPoolLowThreshold(_) => IE::addressPoolLowThreshold,
            Self::addressPortMappingHighThreshold(_) => IE::addressPortMappingHighThreshold,
            Self::addressPortMappingLowThreshold(_) => IE::addressPortMappingLowThreshold,
            Self::addressPortMappingPerUserHighThreshold(_) => IE::addressPortMappingPerUserHighThreshold,
            Self::globalAddressMappingHighThreshold(_) => IE::globalAddressMappingHighThreshold,
            Self::vpnIdentifier(_) => IE::vpnIdentifier,
            Self::bgpCommunity(_) => IE::bgpCommunity,
            Self::bgpSourceCommunityList(_) => IE::bgpSourceCommunityList,
            Self::bgpDestinationCommunityList(_) => IE::bgpDestinationCommunityList,
            Self::bgpExtendedCommunity(_) => IE::bgpExtendedCommunity,
            Self::bgpSourceExtendedCommunityList(_) => IE::bgpSourceExtendedCommunityList,
            Self::bgpDestinationExtendedCommunityList(_) => IE::bgpDestinationExtendedCommunityList,
            Self::bgpLargeCommunity(_) => IE::bgpLargeCommunity,
            Self::bgpSourceLargeCommunityList(_) => IE::bgpSourceLargeCommunityList,
            Self::bgpDestinationLargeCommunityList(_) => IE::bgpDestinationLargeCommunityList,
            Self::srhFlagsIPv6(_) => IE::srhFlagsIPv6,
            Self::srhTagIPv6(_) => IE::srhTagIPv6,
            Self::srhSegmentIPv6(_) => IE::srhSegmentIPv6,
            Self::srhActiveSegmentIPv6(_) => IE::srhActiveSegmentIPv6,
            Self::srhSegmentIPv6BasicList(_) => IE::srhSegmentIPv6BasicList,
            Self::srhSegmentIPv6ListSection(_) => IE::srhSegmentIPv6ListSection,
            Self::srhSegmentsIPv6Left(_) => IE::srhSegmentsIPv6Left,
            Self::srhIPv6Section(_) => IE::srhIPv6Section,
            Self::srhIPv6ActiveSegmentType(_) => IE::srhIPv6ActiveSegmentType,
            Self::srhSegmentIPv6LocatorLength(_) => IE::srhSegmentIPv6LocatorLength,
            Self::srhSegmentIPv6EndpointBehavior(_) => IE::srhSegmentIPv6EndpointBehavior,
            Self::transportChecksum(_) => IE::transportChecksum,
            Self::icmpHeaderPacketSection(_) => IE::icmpHeaderPacketSection,
            Self::gtpuFlags(_) => IE::gtpuFlags,
            Self::gtpuMsgType(_) => IE::gtpuMsgType,
            Self::gtpuTEid(_) => IE::gtpuTEid,
            Self::gtpuSequenceNum(_) => IE::gtpuSequenceNum,
            Self::gtpuQFI(_) => IE::gtpuQFI,
            Self::gtpuPduType(_) => IE::gtpuPduType,
            Self::bgpSourceAsPathList(_) => IE::bgpSourceAsPathList,
            Self::bgpDestinationAsPathList(_) => IE::bgpDestinationAsPathList,
            Self::ipv6ExtensionHeaderType(_) => IE::ipv6ExtensionHeaderType,
            Self::ipv6ExtensionHeaderCount(_) => IE::ipv6ExtensionHeaderCount,
            Self::ipv6ExtensionHeadersFull(_) => IE::ipv6ExtensionHeadersFull,
            Self::ipv6ExtensionHeaderTypeCountList(_) => IE::ipv6ExtensionHeaderTypeCountList,
            Self::ipv6ExtensionHeadersLimit(_) => IE::ipv6ExtensionHeadersLimit,
            Self::ipv6ExtensionHeadersChainLength(_) => IE::ipv6ExtensionHeadersChainLength,
            Self::ipv6ExtensionHeaderChainLengthList(_) => IE::ipv6ExtensionHeaderChainLengthList,
            Self::tcpOptionsFull(_) => IE::tcpOptionsFull,
            Self::tcpSharedOptionExID16(_) => IE::tcpSharedOptionExID16,
            Self::tcpSharedOptionExID32(_) => IE::tcpSharedOptionExID32,
            Self::tcpSharedOptionExID16List(_) => IE::tcpSharedOptionExID16List,
            Self::tcpSharedOptionExID32List(_) => IE::tcpSharedOptionExID32List,
        }

    }

}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct octetDeltaCount(pub u64);

impl HasIE for octetDeltaCount {
    fn ie(&self) -> IE {
        IE::octetDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct packetDeltaCount(pub u64);

impl HasIE for packetDeltaCount {
    fn ie(&self) -> IE {
        IE::packetDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct deltaFlowCount(pub u64);

impl HasIE for deltaFlowCount {
    fn ie(&self) -> IE {
        IE::deltaFlowCount
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum protocolIdentifier {
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
impl From<protocolIdentifier> for u8 {
    fn from(value: protocolIdentifier) -> Self {
        match value {
            protocolIdentifier::HOPOPT => 0,
            protocolIdentifier::ICMP => 1,
            protocolIdentifier::IGMP => 2,
            protocolIdentifier::GGP => 3,
            protocolIdentifier::IPv4 => 4,
            protocolIdentifier::ST => 5,
            protocolIdentifier::TCP => 6,
            protocolIdentifier::CBT => 7,
            protocolIdentifier::EGP => 8,
            protocolIdentifier::IGP => 9,
            protocolIdentifier::BBNRCCMON => 10,
            protocolIdentifier::NVPII => 11,
            protocolIdentifier::PUP => 12,
            protocolIdentifier::ARGUSdeprecated => 13,
            protocolIdentifier::EMCON => 14,
            protocolIdentifier::XNET => 15,
            protocolIdentifier::CHAOS => 16,
            protocolIdentifier::UDP => 17,
            protocolIdentifier::MUX => 18,
            protocolIdentifier::DCNMEAS => 19,
            protocolIdentifier::HMP => 20,
            protocolIdentifier::PRM => 21,
            protocolIdentifier::XNSIDP => 22,
            protocolIdentifier::TRUNK1 => 23,
            protocolIdentifier::TRUNK2 => 24,
            protocolIdentifier::LEAF1 => 25,
            protocolIdentifier::LEAF2 => 26,
            protocolIdentifier::RDP => 27,
            protocolIdentifier::IRTP => 28,
            protocolIdentifier::ISOTP4 => 29,
            protocolIdentifier::NETBLT => 30,
            protocolIdentifier::MFENSP => 31,
            protocolIdentifier::MERITINP => 32,
            protocolIdentifier::DCCP => 33,
            protocolIdentifier::ThreePC => 34,
            protocolIdentifier::IDPR => 35,
            protocolIdentifier::XTP => 36,
            protocolIdentifier::DDP => 37,
            protocolIdentifier::IDPRCMTP => 38,
            protocolIdentifier::TP => 39,
            protocolIdentifier::IL => 40,
            protocolIdentifier::IPv6 => 41,
            protocolIdentifier::SDRP => 42,
            protocolIdentifier::IPv6Route => 43,
            protocolIdentifier::IPv6Frag => 44,
            protocolIdentifier::IDRP => 45,
            protocolIdentifier::RSVP => 46,
            protocolIdentifier::GRE => 47,
            protocolIdentifier::DSR => 48,
            protocolIdentifier::BNA => 49,
            protocolIdentifier::ESP => 50,
            protocolIdentifier::AH => 51,
            protocolIdentifier::INLSP => 52,
            protocolIdentifier::SWIPEdeprecated => 53,
            protocolIdentifier::NARP => 54,
            protocolIdentifier::MinIPv4 => 55,
            protocolIdentifier::TLSP => 56,
            protocolIdentifier::SKIP => 57,
            protocolIdentifier::IPv6ICMP => 58,
            protocolIdentifier::IPv6NoNxt => 59,
            protocolIdentifier::IPv6Opts => 60,
            protocolIdentifier::anyhostinternalprotocol => 61,
            protocolIdentifier::CFTP => 62,
            protocolIdentifier::anylocalnetwork => 63,
            protocolIdentifier::SATEXPAK => 64,
            protocolIdentifier::KRYPTOLAN => 65,
            protocolIdentifier::RVD => 66,
            protocolIdentifier::IPPC => 67,
            protocolIdentifier::anydistributedfilesystem => 68,
            protocolIdentifier::SATMON => 69,
            protocolIdentifier::VISA => 70,
            protocolIdentifier::IPCV => 71,
            protocolIdentifier::CPNX => 72,
            protocolIdentifier::CPHB => 73,
            protocolIdentifier::WSN => 74,
            protocolIdentifier::PVP => 75,
            protocolIdentifier::BRSATMON => 76,
            protocolIdentifier::SUNND => 77,
            protocolIdentifier::WBMON => 78,
            protocolIdentifier::WBEXPAK => 79,
            protocolIdentifier::ISOIP => 80,
            protocolIdentifier::VMTP => 81,
            protocolIdentifier::SECUREVMTP => 82,
            protocolIdentifier::VINES => 83,
            protocolIdentifier::IPTM => 84,
            protocolIdentifier::NSFNETIGP => 85,
            protocolIdentifier::DGP => 86,
            protocolIdentifier::TCF => 87,
            protocolIdentifier::EIGRP => 88,
            protocolIdentifier::OSPFIGP => 89,
            protocolIdentifier::SpriteRPC => 90,
            protocolIdentifier::LARP => 91,
            protocolIdentifier::MTP => 92,
            protocolIdentifier::AX25 => 93,
            protocolIdentifier::IPIP => 94,
            protocolIdentifier::MICPdeprecated => 95,
            protocolIdentifier::SCCSP => 96,
            protocolIdentifier::ETHERIP => 97,
            protocolIdentifier::ENCAP => 98,
            protocolIdentifier::anyprivateencryptionscheme => 99,
            protocolIdentifier::GMTP => 100,
            protocolIdentifier::IFMP => 101,
            protocolIdentifier::PNNI => 102,
            protocolIdentifier::PIM => 103,
            protocolIdentifier::ARIS => 104,
            protocolIdentifier::SCPS => 105,
            protocolIdentifier::QNX => 106,
            protocolIdentifier::AN => 107,
            protocolIdentifier::IPComp => 108,
            protocolIdentifier::SNP => 109,
            protocolIdentifier::CompaqPeer => 110,
            protocolIdentifier::IPXinIP => 111,
            protocolIdentifier::VRRP => 112,
            protocolIdentifier::PGM => 113,
            protocolIdentifier::any0hopprotocol => 114,
            protocolIdentifier::L2TP => 115,
            protocolIdentifier::DDX => 116,
            protocolIdentifier::IATP => 117,
            protocolIdentifier::STP => 118,
            protocolIdentifier::SRP => 119,
            protocolIdentifier::UTI => 120,
            protocolIdentifier::SMP => 121,
            protocolIdentifier::SMdeprecated => 122,
            protocolIdentifier::PTP => 123,
            protocolIdentifier::ISISoverIPv4 => 124,
            protocolIdentifier::FIRE => 125,
            protocolIdentifier::CRTP => 126,
            protocolIdentifier::CRUDP => 127,
            protocolIdentifier::SSCOPMCE => 128,
            protocolIdentifier::IPLT => 129,
            protocolIdentifier::SPS => 130,
            protocolIdentifier::PIPE => 131,
            protocolIdentifier::SCTP => 132,
            protocolIdentifier::FC => 133,
            protocolIdentifier::RSVPE2EIGNORE => 134,
            protocolIdentifier::MobilityHeader => 135,
            protocolIdentifier::UDPLite => 136,
            protocolIdentifier::MPLSinIP => 137,
            protocolIdentifier::manet => 138,
            protocolIdentifier::HIP => 139,
            protocolIdentifier::Shim6 => 140,
            protocolIdentifier::WESP => 141,
            protocolIdentifier::ROHC => 142,
            protocolIdentifier::Ethernet => 143,
            protocolIdentifier::AGGFRAG => 144,
            protocolIdentifier::NSH => 145,
            protocolIdentifier::Unassigned(x) => x,
        }
    }
}
impl From<u8> for protocolIdentifier {
    fn from(value: u8) -> Self {
        match value {
            0 => protocolIdentifier::HOPOPT,
            1 => protocolIdentifier::ICMP,
            2 => protocolIdentifier::IGMP,
            3 => protocolIdentifier::GGP,
            4 => protocolIdentifier::IPv4,
            5 => protocolIdentifier::ST,
            6 => protocolIdentifier::TCP,
            7 => protocolIdentifier::CBT,
            8 => protocolIdentifier::EGP,
            9 => protocolIdentifier::IGP,
            10 => protocolIdentifier::BBNRCCMON,
            11 => protocolIdentifier::NVPII,
            12 => protocolIdentifier::PUP,
            13 => protocolIdentifier::ARGUSdeprecated,
            14 => protocolIdentifier::EMCON,
            15 => protocolIdentifier::XNET,
            16 => protocolIdentifier::CHAOS,
            17 => protocolIdentifier::UDP,
            18 => protocolIdentifier::MUX,
            19 => protocolIdentifier::DCNMEAS,
            20 => protocolIdentifier::HMP,
            21 => protocolIdentifier::PRM,
            22 => protocolIdentifier::XNSIDP,
            23 => protocolIdentifier::TRUNK1,
            24 => protocolIdentifier::TRUNK2,
            25 => protocolIdentifier::LEAF1,
            26 => protocolIdentifier::LEAF2,
            27 => protocolIdentifier::RDP,
            28 => protocolIdentifier::IRTP,
            29 => protocolIdentifier::ISOTP4,
            30 => protocolIdentifier::NETBLT,
            31 => protocolIdentifier::MFENSP,
            32 => protocolIdentifier::MERITINP,
            33 => protocolIdentifier::DCCP,
            34 => protocolIdentifier::ThreePC,
            35 => protocolIdentifier::IDPR,
            36 => protocolIdentifier::XTP,
            37 => protocolIdentifier::DDP,
            38 => protocolIdentifier::IDPRCMTP,
            39 => protocolIdentifier::TP,
            40 => protocolIdentifier::IL,
            41 => protocolIdentifier::IPv6,
            42 => protocolIdentifier::SDRP,
            43 => protocolIdentifier::IPv6Route,
            44 => protocolIdentifier::IPv6Frag,
            45 => protocolIdentifier::IDRP,
            46 => protocolIdentifier::RSVP,
            47 => protocolIdentifier::GRE,
            48 => protocolIdentifier::DSR,
            49 => protocolIdentifier::BNA,
            50 => protocolIdentifier::ESP,
            51 => protocolIdentifier::AH,
            52 => protocolIdentifier::INLSP,
            53 => protocolIdentifier::SWIPEdeprecated,
            54 => protocolIdentifier::NARP,
            55 => protocolIdentifier::MinIPv4,
            56 => protocolIdentifier::TLSP,
            57 => protocolIdentifier::SKIP,
            58 => protocolIdentifier::IPv6ICMP,
            59 => protocolIdentifier::IPv6NoNxt,
            60 => protocolIdentifier::IPv6Opts,
            61 => protocolIdentifier::anyhostinternalprotocol,
            62 => protocolIdentifier::CFTP,
            63 => protocolIdentifier::anylocalnetwork,
            64 => protocolIdentifier::SATEXPAK,
            65 => protocolIdentifier::KRYPTOLAN,
            66 => protocolIdentifier::RVD,
            67 => protocolIdentifier::IPPC,
            68 => protocolIdentifier::anydistributedfilesystem,
            69 => protocolIdentifier::SATMON,
            70 => protocolIdentifier::VISA,
            71 => protocolIdentifier::IPCV,
            72 => protocolIdentifier::CPNX,
            73 => protocolIdentifier::CPHB,
            74 => protocolIdentifier::WSN,
            75 => protocolIdentifier::PVP,
            76 => protocolIdentifier::BRSATMON,
            77 => protocolIdentifier::SUNND,
            78 => protocolIdentifier::WBMON,
            79 => protocolIdentifier::WBEXPAK,
            80 => protocolIdentifier::ISOIP,
            81 => protocolIdentifier::VMTP,
            82 => protocolIdentifier::SECUREVMTP,
            83 => protocolIdentifier::VINES,
            84 => protocolIdentifier::IPTM,
            85 => protocolIdentifier::NSFNETIGP,
            86 => protocolIdentifier::DGP,
            87 => protocolIdentifier::TCF,
            88 => protocolIdentifier::EIGRP,
            89 => protocolIdentifier::OSPFIGP,
            90 => protocolIdentifier::SpriteRPC,
            91 => protocolIdentifier::LARP,
            92 => protocolIdentifier::MTP,
            93 => protocolIdentifier::AX25,
            94 => protocolIdentifier::IPIP,
            95 => protocolIdentifier::MICPdeprecated,
            96 => protocolIdentifier::SCCSP,
            97 => protocolIdentifier::ETHERIP,
            98 => protocolIdentifier::ENCAP,
            99 => protocolIdentifier::anyprivateencryptionscheme,
            100 => protocolIdentifier::GMTP,
            101 => protocolIdentifier::IFMP,
            102 => protocolIdentifier::PNNI,
            103 => protocolIdentifier::PIM,
            104 => protocolIdentifier::ARIS,
            105 => protocolIdentifier::SCPS,
            106 => protocolIdentifier::QNX,
            107 => protocolIdentifier::AN,
            108 => protocolIdentifier::IPComp,
            109 => protocolIdentifier::SNP,
            110 => protocolIdentifier::CompaqPeer,
            111 => protocolIdentifier::IPXinIP,
            112 => protocolIdentifier::VRRP,
            113 => protocolIdentifier::PGM,
            114 => protocolIdentifier::any0hopprotocol,
            115 => protocolIdentifier::L2TP,
            116 => protocolIdentifier::DDX,
            117 => protocolIdentifier::IATP,
            118 => protocolIdentifier::STP,
            119 => protocolIdentifier::SRP,
            120 => protocolIdentifier::UTI,
            121 => protocolIdentifier::SMP,
            122 => protocolIdentifier::SMdeprecated,
            123 => protocolIdentifier::PTP,
            124 => protocolIdentifier::ISISoverIPv4,
            125 => protocolIdentifier::FIRE,
            126 => protocolIdentifier::CRTP,
            127 => protocolIdentifier::CRUDP,
            128 => protocolIdentifier::SSCOPMCE,
            129 => protocolIdentifier::IPLT,
            130 => protocolIdentifier::SPS,
            131 => protocolIdentifier::PIPE,
            132 => protocolIdentifier::SCTP,
            133 => protocolIdentifier::FC,
            134 => protocolIdentifier::RSVPE2EIGNORE,
            135 => protocolIdentifier::MobilityHeader,
            136 => protocolIdentifier::UDPLite,
            137 => protocolIdentifier::MPLSinIP,
            138 => protocolIdentifier::manet,
            139 => protocolIdentifier::HIP,
            140 => protocolIdentifier::Shim6,
            141 => protocolIdentifier::WESP,
            142 => protocolIdentifier::ROHC,
            143 => protocolIdentifier::Ethernet,
            144 => protocolIdentifier::AGGFRAG,
            145 => protocolIdentifier::NSH,
            x => protocolIdentifier::Unassigned(x),
        }
    }
}

impl HasIE for protocolIdentifier {
    fn ie(&self) -> IE {
        IE::protocolIdentifier
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipClassOfService(pub u8);

impl HasIE for ipClassOfService {
    fn ie(&self) -> IE {
        IE::ipClassOfService
   }
}

impl HasIE for netgauze_iana::tcp::TCPHeaderFlags {
    fn ie(&self) -> IE {
        IE::tcpControlBits
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct sourceTransportPort(pub u16);

impl HasIE for sourceTransportPort {
    fn ie(&self) -> IE {
        IE::sourceTransportPort
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct sourceIPv4Address(pub std::net::Ipv4Addr);

impl HasIE for sourceIPv4Address {
    fn ie(&self) -> IE {
        IE::sourceIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct sourceIPv4PrefixLength(pub u8);

impl HasIE for sourceIPv4PrefixLength {
    fn ie(&self) -> IE {
        IE::sourceIPv4PrefixLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ingressInterface(pub u32);

impl HasIE for ingressInterface {
    fn ie(&self) -> IE {
        IE::ingressInterface
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct destinationTransportPort(pub u16);

impl HasIE for destinationTransportPort {
    fn ie(&self) -> IE {
        IE::destinationTransportPort
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct destinationIPv4Address(pub std::net::Ipv4Addr);

impl HasIE for destinationIPv4Address {
    fn ie(&self) -> IE {
        IE::destinationIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct destinationIPv4PrefixLength(pub u8);

impl HasIE for destinationIPv4PrefixLength {
    fn ie(&self) -> IE {
        IE::destinationIPv4PrefixLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct egressInterface(pub u32);

impl HasIE for egressInterface {
    fn ie(&self) -> IE {
        IE::egressInterface
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipNextHopIPv4Address(pub std::net::Ipv4Addr);

impl HasIE for ipNextHopIPv4Address {
    fn ie(&self) -> IE {
        IE::ipNextHopIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpSourceAsNumber(pub u32);

impl HasIE for bgpSourceAsNumber {
    fn ie(&self) -> IE {
        IE::bgpSourceAsNumber
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpDestinationAsNumber(pub u32);

impl HasIE for bgpDestinationAsNumber {
    fn ie(&self) -> IE {
        IE::bgpDestinationAsNumber
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpNextHopIPv4Address(pub std::net::Ipv4Addr);

impl HasIE for bgpNextHopIPv4Address {
    fn ie(&self) -> IE {
        IE::bgpNextHopIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postMCastPacketDeltaCount(pub u64);

impl HasIE for postMCastPacketDeltaCount {
    fn ie(&self) -> IE {
        IE::postMCastPacketDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postMCastOctetDeltaCount(pub u64);

impl HasIE for postMCastOctetDeltaCount {
    fn ie(&self) -> IE {
        IE::postMCastOctetDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowEndSysUpTime(pub u32);

impl HasIE for flowEndSysUpTime {
    fn ie(&self) -> IE {
        IE::flowEndSysUpTime
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowStartSysUpTime(pub u32);

impl HasIE for flowStartSysUpTime {
    fn ie(&self) -> IE {
        IE::flowStartSysUpTime
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postOctetDeltaCount(pub u64);

impl HasIE for postOctetDeltaCount {
    fn ie(&self) -> IE {
        IE::postOctetDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postPacketDeltaCount(pub u64);

impl HasIE for postPacketDeltaCount {
    fn ie(&self) -> IE {
        IE::postPacketDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct minimumIpTotalLength(pub u64);

impl HasIE for minimumIpTotalLength {
    fn ie(&self) -> IE {
        IE::minimumIpTotalLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maximumIpTotalLength(pub u64);

impl HasIE for maximumIpTotalLength {
    fn ie(&self) -> IE {
        IE::maximumIpTotalLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct sourceIPv6Address(pub std::net::Ipv6Addr);

impl HasIE for sourceIPv6Address {
    fn ie(&self) -> IE {
        IE::sourceIPv6Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct destinationIPv6Address(pub std::net::Ipv6Addr);

impl HasIE for destinationIPv6Address {
    fn ie(&self) -> IE {
        IE::destinationIPv6Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct sourceIPv6PrefixLength(pub u8);

impl HasIE for sourceIPv6PrefixLength {
    fn ie(&self) -> IE {
        IE::sourceIPv6PrefixLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct destinationIPv6PrefixLength(pub u8);

impl HasIE for destinationIPv6PrefixLength {
    fn ie(&self) -> IE {
        IE::destinationIPv6PrefixLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowLabelIPv6(pub u32);

impl HasIE for flowLabelIPv6 {
    fn ie(&self) -> IE {
        IE::flowLabelIPv6
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct icmpTypeCodeIPv4(pub u16);

impl HasIE for icmpTypeCodeIPv4 {
    fn ie(&self) -> IE {
        IE::icmpTypeCodeIPv4
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct igmpType(pub u8);

impl HasIE for igmpType {
    fn ie(&self) -> IE {
        IE::igmpType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplingInterval(pub u32);

impl HasIE for samplingInterval {
    fn ie(&self) -> IE {
        IE::samplingInterval
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplingAlgorithm(pub u8);

impl HasIE for samplingAlgorithm {
    fn ie(&self) -> IE {
        IE::samplingAlgorithm
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowActiveTimeout(pub u16);

impl HasIE for flowActiveTimeout {
    fn ie(&self) -> IE {
        IE::flowActiveTimeout
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowIdleTimeout(pub u16);

impl HasIE for flowIdleTimeout {
    fn ie(&self) -> IE {
        IE::flowIdleTimeout
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct engineType(pub u8);

impl HasIE for engineType {
    fn ie(&self) -> IE {
        IE::engineType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct engineId(pub u8);

impl HasIE for engineId {
    fn ie(&self) -> IE {
        IE::engineId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct exportedOctetTotalCount(pub u64);

impl HasIE for exportedOctetTotalCount {
    fn ie(&self) -> IE {
        IE::exportedOctetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct exportedMessageTotalCount(pub u64);

impl HasIE for exportedMessageTotalCount {
    fn ie(&self) -> IE {
        IE::exportedMessageTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct exportedFlowRecordTotalCount(pub u64);

impl HasIE for exportedFlowRecordTotalCount {
    fn ie(&self) -> IE {
        IE::exportedFlowRecordTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipv4RouterSc(pub std::net::Ipv4Addr);

impl HasIE for ipv4RouterSc {
    fn ie(&self) -> IE {
        IE::ipv4RouterSc
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct sourceIPv4Prefix(pub std::net::Ipv4Addr);

impl HasIE for sourceIPv4Prefix {
    fn ie(&self) -> IE {
        IE::sourceIPv4Prefix
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct destinationIPv4Prefix(pub std::net::Ipv4Addr);

impl HasIE for destinationIPv4Prefix {
    fn ie(&self) -> IE {
        IE::destinationIPv4Prefix
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum mplsTopLabelType {
    /// Unknown: The MPLS label type is not known.
    ///
    /// Reference: [RFC3954](https://datatracker.ietf.org/doc/html/rfc3954)
    Unknown = 0,
    /// TE-MIDPT: Any TE tunnel mid-point or tail label
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    TEMIDPT = 1,
    /// Pseudowire: Any PWE3 or Cisco AToM based label
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    Pseudowire = 2,
    /// VPN: Any label associated with VPN
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC4364](https://datatracker.ietf.org/doc/html/rfc4364)
    VPN = 3,
    /// BGP: Any label associated with BGP or BGP routing
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC4271](https://datatracker.ietf.org/doc/html/rfc4271)
    BGP = 4,
    /// LDP: Any label associated with dynamically assigned labels using LDP
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    /// Reference: [RFC5036](https://datatracker.ietf.org/doc/html/rfc5036)
    LDP = 5,
    /// Path Computation Element
    ///
    /// Reference: [RFC9160](https://datatracker.ietf.org/doc/html/rfc9160)
    /// Reference: [RFC8664](https://datatracker.ietf.org/doc/html/rfc8664)
    PathComputationElement = 6,
    /// OSPFv2 Segment Routing
    ///
    /// Reference: [RFC9160](https://datatracker.ietf.org/doc/html/rfc9160)
    /// Reference: [RFC8665](https://datatracker.ietf.org/doc/html/rfc8665)
    OSPFv2SegmentRouting = 7,
    /// OSPFv3 Segment Routing
    ///
    /// Reference: [RFC9160](https://datatracker.ietf.org/doc/html/rfc9160)
    /// Reference: [RFC8666](https://datatracker.ietf.org/doc/html/rfc8666)
    OSPFv3SegmentRouting = 8,
    /// IS-IS Segment Routing
    ///
    /// Reference: [RFC9160](https://datatracker.ietf.org/doc/html/rfc9160)
    /// Reference: [RFC8667](https://datatracker.ietf.org/doc/html/rfc8667)
    ISISSegmentRouting = 9,
    /// BGP Segment Routing Prefix-SID
    ///
    /// Reference: [RFC9160](https://datatracker.ietf.org/doc/html/rfc9160)
    /// Reference: [RFC8669](https://datatracker.ietf.org/doc/html/rfc8669)
    BGPSegmentRoutingPrefixSID = 10,
    Unassigned(u8),
}
impl From<mplsTopLabelType> for u8 {
    fn from(value: mplsTopLabelType) -> Self {
        match value {
            mplsTopLabelType::Unknown => 0,
            mplsTopLabelType::TEMIDPT => 1,
            mplsTopLabelType::Pseudowire => 2,
            mplsTopLabelType::VPN => 3,
            mplsTopLabelType::BGP => 4,
            mplsTopLabelType::LDP => 5,
            mplsTopLabelType::PathComputationElement => 6,
            mplsTopLabelType::OSPFv2SegmentRouting => 7,
            mplsTopLabelType::OSPFv3SegmentRouting => 8,
            mplsTopLabelType::ISISSegmentRouting => 9,
            mplsTopLabelType::BGPSegmentRoutingPrefixSID => 10,
            mplsTopLabelType::Unassigned(x) => x,
        }
    }
}
impl From<u8> for mplsTopLabelType {
    fn from(value: u8) -> Self {
        match value {
            0 => mplsTopLabelType::Unknown,
            1 => mplsTopLabelType::TEMIDPT,
            2 => mplsTopLabelType::Pseudowire,
            3 => mplsTopLabelType::VPN,
            4 => mplsTopLabelType::BGP,
            5 => mplsTopLabelType::LDP,
            6 => mplsTopLabelType::PathComputationElement,
            7 => mplsTopLabelType::OSPFv2SegmentRouting,
            8 => mplsTopLabelType::OSPFv3SegmentRouting,
            9 => mplsTopLabelType::ISISSegmentRouting,
            10 => mplsTopLabelType::BGPSegmentRoutingPrefixSID,
            x => mplsTopLabelType::Unassigned(x),
        }
    }
}

impl HasIE for mplsTopLabelType {
    fn ie(&self) -> IE {
        IE::mplsTopLabelType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsTopLabelIPv4Address(pub std::net::Ipv4Addr);

impl HasIE for mplsTopLabelIPv4Address {
    fn ie(&self) -> IE {
        IE::mplsTopLabelIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplerId(pub u32);

impl HasIE for samplerId {
    fn ie(&self) -> IE {
        IE::samplerId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplerMode(pub u8);

impl HasIE for samplerMode {
    fn ie(&self) -> IE {
        IE::samplerMode
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplerRandomInterval(pub u32);

impl HasIE for samplerRandomInterval {
    fn ie(&self) -> IE {
        IE::samplerRandomInterval
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct classId(pub u8);

impl HasIE for classId {
    fn ie(&self) -> IE {
        IE::classId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct minimumTTL(pub u8);

impl HasIE for minimumTTL {
    fn ie(&self) -> IE {
        IE::minimumTTL
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maximumTTL(pub u8);

impl HasIE for maximumTTL {
    fn ie(&self) -> IE {
        IE::maximumTTL
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct fragmentIdentification(pub u32);

impl HasIE for fragmentIdentification {
    fn ie(&self) -> IE {
        IE::fragmentIdentification
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postIpClassOfService(pub u8);

impl HasIE for postIpClassOfService {
    fn ie(&self) -> IE {
        IE::postIpClassOfService
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct sourceMacAddress(pub super::MacAddress);

impl HasIE for sourceMacAddress {
    fn ie(&self) -> IE {
        IE::sourceMacAddress
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postDestinationMacAddress(pub super::MacAddress);

impl HasIE for postDestinationMacAddress {
    fn ie(&self) -> IE {
        IE::postDestinationMacAddress
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct vlanId(pub u16);

impl HasIE for vlanId {
    fn ie(&self) -> IE {
        IE::vlanId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postVlanId(pub u16);

impl HasIE for postVlanId {
    fn ie(&self) -> IE {
        IE::postVlanId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipVersion(pub u8);

impl HasIE for ipVersion {
    fn ie(&self) -> IE {
        IE::ipVersion
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
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

impl HasIE for flowDirection {
    fn ie(&self) -> IE {
        IE::flowDirection
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipNextHopIPv6Address(pub std::net::Ipv6Addr);

impl HasIE for ipNextHopIPv6Address {
    fn ie(&self) -> IE {
        IE::ipNextHopIPv6Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpNextHopIPv6Address(pub std::net::Ipv6Addr);

impl HasIE for bgpNextHopIPv6Address {
    fn ie(&self) -> IE {
        IE::bgpNextHopIPv6Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipv6ExtensionHeaders(pub u32);

impl HasIE for ipv6ExtensionHeaders {
    fn ie(&self) -> IE {
        IE::ipv6ExtensionHeaders
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsTopLabelStackSection(pub Vec<u8>);

impl HasIE for mplsTopLabelStackSection {
    fn ie(&self) -> IE {
        IE::mplsTopLabelStackSection
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsLabelStackSection2(pub Vec<u8>);

impl HasIE for mplsLabelStackSection2 {
    fn ie(&self) -> IE {
        IE::mplsLabelStackSection2
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsLabelStackSection3(pub Vec<u8>);

impl HasIE for mplsLabelStackSection3 {
    fn ie(&self) -> IE {
        IE::mplsLabelStackSection3
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsLabelStackSection4(pub Vec<u8>);

impl HasIE for mplsLabelStackSection4 {
    fn ie(&self) -> IE {
        IE::mplsLabelStackSection4
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsLabelStackSection5(pub Vec<u8>);

impl HasIE for mplsLabelStackSection5 {
    fn ie(&self) -> IE {
        IE::mplsLabelStackSection5
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsLabelStackSection6(pub Vec<u8>);

impl HasIE for mplsLabelStackSection6 {
    fn ie(&self) -> IE {
        IE::mplsLabelStackSection6
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsLabelStackSection7(pub Vec<u8>);

impl HasIE for mplsLabelStackSection7 {
    fn ie(&self) -> IE {
        IE::mplsLabelStackSection7
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsLabelStackSection8(pub Vec<u8>);

impl HasIE for mplsLabelStackSection8 {
    fn ie(&self) -> IE {
        IE::mplsLabelStackSection8
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsLabelStackSection9(pub Vec<u8>);

impl HasIE for mplsLabelStackSection9 {
    fn ie(&self) -> IE {
        IE::mplsLabelStackSection9
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsLabelStackSection10(pub Vec<u8>);

impl HasIE for mplsLabelStackSection10 {
    fn ie(&self) -> IE {
        IE::mplsLabelStackSection10
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct destinationMacAddress(pub super::MacAddress);

impl HasIE for destinationMacAddress {
    fn ie(&self) -> IE {
        IE::destinationMacAddress
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postSourceMacAddress(pub super::MacAddress);

impl HasIE for postSourceMacAddress {
    fn ie(&self) -> IE {
        IE::postSourceMacAddress
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct interfaceName(pub String);

impl HasIE for interfaceName {
    fn ie(&self) -> IE {
        IE::interfaceName
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct interfaceDescription(pub String);

impl HasIE for interfaceDescription {
    fn ie(&self) -> IE {
        IE::interfaceDescription
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplerName(pub String);

impl HasIE for samplerName {
    fn ie(&self) -> IE {
        IE::samplerName
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct octetTotalCount(pub u64);

impl HasIE for octetTotalCount {
    fn ie(&self) -> IE {
        IE::octetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct packetTotalCount(pub u64);

impl HasIE for packetTotalCount {
    fn ie(&self) -> IE {
        IE::packetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flagsAndSamplerId(pub u32);

impl HasIE for flagsAndSamplerId {
    fn ie(&self) -> IE {
        IE::flagsAndSamplerId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct fragmentOffset(pub u16);

impl HasIE for fragmentOffset {
    fn ie(&self) -> IE {
        IE::fragmentOffset
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum forwardingStatus {
    /// Unknown
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Unknown(forwardingStatusUnknownReason),
    /// Forwarded
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Forwarded(forwardingStatusForwardedReason),
    /// Dropped
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Dropped(forwardingStatusDroppedReason),
    /// Consumed
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Consumed(forwardingStatusConsumedReason),
    Unassigned(u32),
}
impl From<forwardingStatus> for u32 {
    fn from(value: forwardingStatus) -> Self {
        match value {
            forwardingStatus::Unknown(x) => u32::from(x),
            forwardingStatus::Forwarded(x) => u32::from(x),
            forwardingStatus::Dropped(x) => u32::from(x),
            forwardingStatus::Consumed(x) => u32::from(x),
            forwardingStatus::Unassigned(x) => x,
        }
    }
}
impl From<u32> for forwardingStatus {
    fn from(value: u32) -> Self {
            if (0..=63).contains(&value) {
                forwardingStatus::Unknown(forwardingStatusUnknownReason::from(value))
            }
            else if (64..=127).contains(&value) {
                forwardingStatus::Forwarded(forwardingStatusForwardedReason::from(value))
            }
            else if (128..=191).contains(&value) {
                forwardingStatus::Dropped(forwardingStatusDroppedReason::from(value))
            }
            else if (192..=255).contains(&value) {
                forwardingStatus::Consumed(forwardingStatusConsumedReason::from(value))
            }
            else {
                forwardingStatus::Unassigned(value)
            }
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum forwardingStatusUnknownReason {
    Unassigned(u32),
}
impl From<forwardingStatusUnknownReason> for u32 {
    fn from(value: forwardingStatusUnknownReason) -> Self {
        match value {
            forwardingStatusUnknownReason::Unassigned(x) => x,
        }
    }
}
impl From<u32> for forwardingStatusUnknownReason {
    fn from(value: u32) -> Self {
        let x = value;
        forwardingStatusUnknownReason::Unassigned(x)
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum forwardingStatusForwardedReason {
    /// Unknown
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Unknown = 64,
    /// Fragmented
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Fragmented = 65,
    /// Not Fragmented
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    NotFragmented = 66,
    /// Tunneled
    ///
    Tunneled = 67,
    /// ACL Redirect
    ///
    ACLRedirect = 68,
    Unassigned(u32),
}
impl From<forwardingStatusForwardedReason> for u32 {
    fn from(value: forwardingStatusForwardedReason) -> Self {
        match value {
            forwardingStatusForwardedReason::Unknown => 64,
            forwardingStatusForwardedReason::Fragmented => 65,
            forwardingStatusForwardedReason::NotFragmented => 66,
            forwardingStatusForwardedReason::Tunneled => 67,
            forwardingStatusForwardedReason::ACLRedirect => 68,
            forwardingStatusForwardedReason::Unassigned(x) => x,
        }
    }
}
impl From<u32> for forwardingStatusForwardedReason {
    fn from(value: u32) -> Self {
        match value {
            64 => forwardingStatusForwardedReason::Unknown,
            65 => forwardingStatusForwardedReason::Fragmented,
            66 => forwardingStatusForwardedReason::NotFragmented,
            67 => forwardingStatusForwardedReason::Tunneled,
            68 => forwardingStatusForwardedReason::ACLRedirect,
            x => forwardingStatusForwardedReason::Unassigned(x),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum forwardingStatusDroppedReason {
    /// Unknown
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Unknown = 128,
    /// ACL deny
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    ACLdeny = 129,
    /// ACL drop
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    ACLdrop = 130,
    /// Unroutable
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Unroutable = 131,
    /// Adjacency
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Adjacency = 132,
    /// Fragmentation and DF set
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    FragmentationandDFset = 133,
    /// Bad header checksum
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Badheaderchecksum = 134,
    /// Bad total Length
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    BadtotalLength = 135,
    /// Bad header length
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Badheaderlength = 136,
    /// bad TTL
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    badTTL = 137,
    /// Policer
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Policer = 138,
    /// WRED
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    WRED = 139,
    /// RPF
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    RPF = 140,
    /// For us
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Forus = 141,
    /// Bad output interface
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Badoutputinterface = 142,
    /// Hardware
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Hardware = 143,
    Unassigned(u32),
}
impl From<forwardingStatusDroppedReason> for u32 {
    fn from(value: forwardingStatusDroppedReason) -> Self {
        match value {
            forwardingStatusDroppedReason::Unknown => 128,
            forwardingStatusDroppedReason::ACLdeny => 129,
            forwardingStatusDroppedReason::ACLdrop => 130,
            forwardingStatusDroppedReason::Unroutable => 131,
            forwardingStatusDroppedReason::Adjacency => 132,
            forwardingStatusDroppedReason::FragmentationandDFset => 133,
            forwardingStatusDroppedReason::Badheaderchecksum => 134,
            forwardingStatusDroppedReason::BadtotalLength => 135,
            forwardingStatusDroppedReason::Badheaderlength => 136,
            forwardingStatusDroppedReason::badTTL => 137,
            forwardingStatusDroppedReason::Policer => 138,
            forwardingStatusDroppedReason::WRED => 139,
            forwardingStatusDroppedReason::RPF => 140,
            forwardingStatusDroppedReason::Forus => 141,
            forwardingStatusDroppedReason::Badoutputinterface => 142,
            forwardingStatusDroppedReason::Hardware => 143,
            forwardingStatusDroppedReason::Unassigned(x) => x,
        }
    }
}
impl From<u32> for forwardingStatusDroppedReason {
    fn from(value: u32) -> Self {
        match value {
            128 => forwardingStatusDroppedReason::Unknown,
            129 => forwardingStatusDroppedReason::ACLdeny,
            130 => forwardingStatusDroppedReason::ACLdrop,
            131 => forwardingStatusDroppedReason::Unroutable,
            132 => forwardingStatusDroppedReason::Adjacency,
            133 => forwardingStatusDroppedReason::FragmentationandDFset,
            134 => forwardingStatusDroppedReason::Badheaderchecksum,
            135 => forwardingStatusDroppedReason::BadtotalLength,
            136 => forwardingStatusDroppedReason::Badheaderlength,
            137 => forwardingStatusDroppedReason::badTTL,
            138 => forwardingStatusDroppedReason::Policer,
            139 => forwardingStatusDroppedReason::WRED,
            140 => forwardingStatusDroppedReason::RPF,
            141 => forwardingStatusDroppedReason::Forus,
            142 => forwardingStatusDroppedReason::Badoutputinterface,
            143 => forwardingStatusDroppedReason::Hardware,
            x => forwardingStatusDroppedReason::Unassigned(x),
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum forwardingStatusConsumedReason {
    /// Unknown
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Unknown = 192,
    /// Punt Adjacency
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    PuntAdjacency = 193,
    /// Incomplete Adjacency
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    IncompleteAdjacency = 194,
    /// For us
    ///
    /// Reference: [RFC7270](https://datatracker.ietf.org/doc/html/rfc7270)
    Forus = 195,
    Unassigned(u32),
}
impl From<forwardingStatusConsumedReason> for u32 {
    fn from(value: forwardingStatusConsumedReason) -> Self {
        match value {
            forwardingStatusConsumedReason::Unknown => 192,
            forwardingStatusConsumedReason::PuntAdjacency => 193,
            forwardingStatusConsumedReason::IncompleteAdjacency => 194,
            forwardingStatusConsumedReason::Forus => 195,
            forwardingStatusConsumedReason::Unassigned(x) => x,
        }
    }
}
impl From<u32> for forwardingStatusConsumedReason {
    fn from(value: u32) -> Self {
        match value {
            192 => forwardingStatusConsumedReason::Unknown,
            193 => forwardingStatusConsumedReason::PuntAdjacency,
            194 => forwardingStatusConsumedReason::IncompleteAdjacency,
            195 => forwardingStatusConsumedReason::Forus,
            x => forwardingStatusConsumedReason::Unassigned(x),
        }
    }
}

impl HasIE for forwardingStatus {
    fn ie(&self) -> IE {
        IE::forwardingStatus
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsVpnRouteDistinguisher(pub Vec<u8>);

impl HasIE for mplsVpnRouteDistinguisher {
    fn ie(&self) -> IE {
        IE::mplsVpnRouteDistinguisher
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsTopLabelPrefixLength(pub u8);

impl HasIE for mplsTopLabelPrefixLength {
    fn ie(&self) -> IE {
        IE::mplsTopLabelPrefixLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct srcTrafficIndex(pub u32);

impl HasIE for srcTrafficIndex {
    fn ie(&self) -> IE {
        IE::srcTrafficIndex
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dstTrafficIndex(pub u32);

impl HasIE for dstTrafficIndex {
    fn ie(&self) -> IE {
        IE::dstTrafficIndex
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct applicationDescription(pub String);

impl HasIE for applicationDescription {
    fn ie(&self) -> IE {
        IE::applicationDescription
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct applicationId(pub Vec<u8>);

impl HasIE for applicationId {
    fn ie(&self) -> IE {
        IE::applicationId
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct applicationName(pub String);

impl HasIE for applicationName {
    fn ie(&self) -> IE {
        IE::applicationName
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postIpDiffServCodePoint(pub u8);

impl HasIE for postIpDiffServCodePoint {
    fn ie(&self) -> IE {
        IE::postIpDiffServCodePoint
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct multicastReplicationFactor(pub u32);

impl HasIE for multicastReplicationFactor {
    fn ie(&self) -> IE {
        IE::multicastReplicationFactor
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct className(pub String);

impl HasIE for className {
    fn ie(&self) -> IE {
        IE::className
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum classificationEngineId {
    /// Invalid.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    Invalid = 0,
    /// IANA-L3: The Assigned Internet Protocol Number (layer 3 (L3)) is exported in the Selector ID. See
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    IANAL3 = 1,
    /// PANA-L3: Proprietary layer 3 definition. An enterprise can export its own layer 3 protocol numbers. The Selector ID has a global significance for all devices from the same enterprise.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    PANAL3 = 2,
    /// IANA-L4: The IANA layer 4 (L4) well-known port
    /// number is exported in the Selector ID. See
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    IANAL4 = 3,
    /// PANA-L4: Proprietary layer 4 definition. An
    /// enterprise can export its own layer 4 port
    /// numbers. The Selector ID has global significance
    /// for devices from the same enterprise. Example:
    /// IPFIX had the port 4739 pre-assigned in the IETF
    /// draft for years. While waiting for the RFC and its
    /// associated IANA registration, the Selector ID 4739
    /// was used with this PANA-L4.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    PANAL4 = 4,
    /// Reserved
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    Reserved5 = 5,
    /// USER-Defined: The Selector ID represents
    /// applications defined by the user (using CLI, GUI,
    /// etc.) based on the methods described in section 2.
    /// The Selector ID has a local significance per
    /// device.
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    USERDefined = 6,
    /// Reserved
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    Reserved7 = 7,
    /// Reserved
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    Reserved8 = 8,
    /// Reserved
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    Reserved9 = 9,
    /// Reserved
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    Reserved10 = 10,
    /// Reserved
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    Reserved11 = 11,
    /// PANA-L2: Proprietary layer 2 (L2) definition.  An
    /// enterprise can export its own layer 2 identifiers.
    /// The Selector ID represents the enterprise's unique
    /// global layer 2 applications. The Selector ID has a
    /// global significance for all devices from the same
    /// enterprise. Examples include Cisco Subnetwork
    /// Access Protocol (SNAP).
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    PANAL2 = 12,
    /// PANA-L7: Proprietary layer 7 definition. The
    /// Selector ID represents the enterprise's unique
    /// global ID for the layer 7 applications. The
    /// Selector ID has a global significance for all
    /// devices from the same enterprise. This
    /// Classification Engine Id is used when the
    /// application registry is owned by the Exporter
    /// manufacturer (referred to as the "enterprise" in
    /// this document).
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    PANAL7 = 13,
    /// Reserved
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    Reserved14 = 14,
    /// Reserved
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    Reserved15 = 15,
    /// Reserved
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    Reserved16 = 16,
    /// Reserved
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    Reserved17 = 17,
    /// ETHERTYPE: The Selector ID represents the well-
    /// known Ethertype. See
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    ETHERTYPE = 18,
    /// LLC: The Selector ID represents the well-known
    /// IEEE 802.2 Link Layer Control (LLC) Destination
    /// Service Access Point (DSAP).
    /// See
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    LLC = 19,
    /// PANA-L7-PEN: Proprietary layer 7 definition,
    /// including a Private Enterprise Number (PEN)
    ///
    /// Reference: [RFC6759](https://datatracker.ietf.org/doc/html/rfc6759)
    PANAL7PEN = 20,
    /// The Selector ID contains an application ID from the Qosmos ixEngine.
    ///
    Value21 = 21,
    /// The Selector ID contains a protocol from the ntop nDPI engine.
    ///
    Value22 = 22,
    /// R&S ipoque DPI PACE2 engine
    ///
    RSipoqueDPIPACE2engine = 23,
    /// R&S ipoque DPI vPACE engine
    ///
    RSipoqueDPIvPACEengine = 24,
    Unassigned(u8),
}
impl From<classificationEngineId> for u8 {
    fn from(value: classificationEngineId) -> Self {
        match value {
            classificationEngineId::Invalid => 0,
            classificationEngineId::IANAL3 => 1,
            classificationEngineId::PANAL3 => 2,
            classificationEngineId::IANAL4 => 3,
            classificationEngineId::PANAL4 => 4,
            classificationEngineId::Reserved5 => 5,
            classificationEngineId::USERDefined => 6,
            classificationEngineId::Reserved7 => 7,
            classificationEngineId::Reserved8 => 8,
            classificationEngineId::Reserved9 => 9,
            classificationEngineId::Reserved10 => 10,
            classificationEngineId::Reserved11 => 11,
            classificationEngineId::PANAL2 => 12,
            classificationEngineId::PANAL7 => 13,
            classificationEngineId::Reserved14 => 14,
            classificationEngineId::Reserved15 => 15,
            classificationEngineId::Reserved16 => 16,
            classificationEngineId::Reserved17 => 17,
            classificationEngineId::ETHERTYPE => 18,
            classificationEngineId::LLC => 19,
            classificationEngineId::PANAL7PEN => 20,
            classificationEngineId::Value21 => 21,
            classificationEngineId::Value22 => 22,
            classificationEngineId::RSipoqueDPIPACE2engine => 23,
            classificationEngineId::RSipoqueDPIvPACEengine => 24,
            classificationEngineId::Unassigned(x) => x,
        }
    }
}
impl From<u8> for classificationEngineId {
    fn from(value: u8) -> Self {
        match value {
            0 => classificationEngineId::Invalid,
            1 => classificationEngineId::IANAL3,
            2 => classificationEngineId::PANAL3,
            3 => classificationEngineId::IANAL4,
            4 => classificationEngineId::PANAL4,
            5 => classificationEngineId::Reserved5,
            6 => classificationEngineId::USERDefined,
            7 => classificationEngineId::Reserved7,
            8 => classificationEngineId::Reserved8,
            9 => classificationEngineId::Reserved9,
            10 => classificationEngineId::Reserved10,
            11 => classificationEngineId::Reserved11,
            12 => classificationEngineId::PANAL2,
            13 => classificationEngineId::PANAL7,
            14 => classificationEngineId::Reserved14,
            15 => classificationEngineId::Reserved15,
            16 => classificationEngineId::Reserved16,
            17 => classificationEngineId::Reserved17,
            18 => classificationEngineId::ETHERTYPE,
            19 => classificationEngineId::LLC,
            20 => classificationEngineId::PANAL7PEN,
            21 => classificationEngineId::Value21,
            22 => classificationEngineId::Value22,
            23 => classificationEngineId::RSipoqueDPIPACE2engine,
            24 => classificationEngineId::RSipoqueDPIvPACEengine,
            x => classificationEngineId::Unassigned(x),
        }
    }
}

impl HasIE for classificationEngineId {
    fn ie(&self) -> IE {
        IE::classificationEngineId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct layer2packetSectionOffset(pub u16);

impl HasIE for layer2packetSectionOffset {
    fn ie(&self) -> IE {
        IE::layer2packetSectionOffset
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct layer2packetSectionSize(pub u16);

impl HasIE for layer2packetSectionSize {
    fn ie(&self) -> IE {
        IE::layer2packetSectionSize
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct layer2packetSectionData(pub Vec<u8>);

impl HasIE for layer2packetSectionData {
    fn ie(&self) -> IE {
        IE::layer2packetSectionData
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpNextAdjacentAsNumber(pub u32);

impl HasIE for bgpNextAdjacentAsNumber {
    fn ie(&self) -> IE {
        IE::bgpNextAdjacentAsNumber
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpPrevAdjacentAsNumber(pub u32);

impl HasIE for bgpPrevAdjacentAsNumber {
    fn ie(&self) -> IE {
        IE::bgpPrevAdjacentAsNumber
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct exporterIPv4Address(pub std::net::Ipv4Addr);

impl HasIE for exporterIPv4Address {
    fn ie(&self) -> IE {
        IE::exporterIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct exporterIPv6Address(pub std::net::Ipv6Addr);

impl HasIE for exporterIPv6Address {
    fn ie(&self) -> IE {
        IE::exporterIPv6Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct droppedOctetDeltaCount(pub u64);

impl HasIE for droppedOctetDeltaCount {
    fn ie(&self) -> IE {
        IE::droppedOctetDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct droppedPacketDeltaCount(pub u64);

impl HasIE for droppedPacketDeltaCount {
    fn ie(&self) -> IE {
        IE::droppedPacketDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct droppedOctetTotalCount(pub u64);

impl HasIE for droppedOctetTotalCount {
    fn ie(&self) -> IE {
        IE::droppedOctetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct droppedPacketTotalCount(pub u64);

impl HasIE for droppedPacketTotalCount {
    fn ie(&self) -> IE {
        IE::droppedPacketTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum flowEndReason {
    /// 
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    Reserved0 = 0,
    /// The Flow was terminated because it was considered to be
    /// idle.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    idletimeout = 1,
    /// The Flow was terminated for reporting purposes while it was
    /// still active, for example, after the maximum lifetime of
    /// unreported Flows was reached.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    activetimeout = 2,
    /// The Flow was terminated because the Metering Process
    /// detected signals indicating the end of the Flow,
    /// for example, the TCP FIN flag.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    endofFlowdetected = 3,
    /// The Flow was terminated because of some external event,
    /// for example, a shutdown of the Metering Process initiated
    /// by a network management application.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    forcedend = 4,
    /// The Flow was terminated because of lack of resources
    /// available to the Metering Process and/or the Exporting
    /// Process.
    ///
    /// Reference: [RFC5102](https://datatracker.ietf.org/doc/html/rfc5102)
    lackofresources = 5,
    Unassigned(u8),
}
impl From<flowEndReason> for u8 {
    fn from(value: flowEndReason) -> Self {
        match value {
            flowEndReason::Reserved0 => 0,
            flowEndReason::idletimeout => 1,
            flowEndReason::activetimeout => 2,
            flowEndReason::endofFlowdetected => 3,
            flowEndReason::forcedend => 4,
            flowEndReason::lackofresources => 5,
            flowEndReason::Unassigned(x) => x,
        }
    }
}
impl From<u8> for flowEndReason {
    fn from(value: u8) -> Self {
        match value {
            0 => flowEndReason::Reserved0,
            1 => flowEndReason::idletimeout,
            2 => flowEndReason::activetimeout,
            3 => flowEndReason::endofFlowdetected,
            4 => flowEndReason::forcedend,
            5 => flowEndReason::lackofresources,
            x => flowEndReason::Unassigned(x),
        }
    }
}

impl HasIE for flowEndReason {
    fn ie(&self) -> IE {
        IE::flowEndReason
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct commonPropertiesId(pub u64);

impl HasIE for commonPropertiesId {
    fn ie(&self) -> IE {
        IE::commonPropertiesId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct observationPointId(pub u64);

impl HasIE for observationPointId {
    fn ie(&self) -> IE {
        IE::observationPointId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct icmpTypeCodeIPv6(pub u16);

impl HasIE for icmpTypeCodeIPv6 {
    fn ie(&self) -> IE {
        IE::icmpTypeCodeIPv6
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsTopLabelIPv6Address(pub std::net::Ipv6Addr);

impl HasIE for mplsTopLabelIPv6Address {
    fn ie(&self) -> IE {
        IE::mplsTopLabelIPv6Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct lineCardId(pub u32);

impl HasIE for lineCardId {
    fn ie(&self) -> IE {
        IE::lineCardId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct portId(pub u32);

impl HasIE for portId {
    fn ie(&self) -> IE {
        IE::portId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct meteringProcessId(pub u32);

impl HasIE for meteringProcessId {
    fn ie(&self) -> IE {
        IE::meteringProcessId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct exportingProcessId(pub u32);

impl HasIE for exportingProcessId {
    fn ie(&self) -> IE {
        IE::exportingProcessId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct templateId(pub u16);

impl HasIE for templateId {
    fn ie(&self) -> IE {
        IE::templateId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct wlanChannelId(pub u8);

impl HasIE for wlanChannelId {
    fn ie(&self) -> IE {
        IE::wlanChannelId
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct wlanSSID(pub String);

impl HasIE for wlanSSID {
    fn ie(&self) -> IE {
        IE::wlanSSID
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowId(pub u64);

impl HasIE for flowId {
    fn ie(&self) -> IE {
        IE::flowId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct observationDomainId(pub u32);

impl HasIE for observationDomainId {
    fn ie(&self) -> IE {
        IE::observationDomainId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowStartSeconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for flowStartSeconds {
    fn ie(&self) -> IE {
        IE::flowStartSeconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowEndSeconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for flowEndSeconds {
    fn ie(&self) -> IE {
        IE::flowEndSeconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowStartMilliseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for flowStartMilliseconds {
    fn ie(&self) -> IE {
        IE::flowStartMilliseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowEndMilliseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for flowEndMilliseconds {
    fn ie(&self) -> IE {
        IE::flowEndMilliseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowStartMicroseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for flowStartMicroseconds {
    fn ie(&self) -> IE {
        IE::flowStartMicroseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowEndMicroseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for flowEndMicroseconds {
    fn ie(&self) -> IE {
        IE::flowEndMicroseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowStartNanoseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for flowStartNanoseconds {
    fn ie(&self) -> IE {
        IE::flowStartNanoseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowEndNanoseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for flowEndNanoseconds {
    fn ie(&self) -> IE {
        IE::flowEndNanoseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowStartDeltaMicroseconds(pub u32);

impl HasIE for flowStartDeltaMicroseconds {
    fn ie(&self) -> IE {
        IE::flowStartDeltaMicroseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowEndDeltaMicroseconds(pub u32);

impl HasIE for flowEndDeltaMicroseconds {
    fn ie(&self) -> IE {
        IE::flowEndDeltaMicroseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct systemInitTimeMilliseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for systemInitTimeMilliseconds {
    fn ie(&self) -> IE {
        IE::systemInitTimeMilliseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowDurationMilliseconds(pub u32);

impl HasIE for flowDurationMilliseconds {
    fn ie(&self) -> IE {
        IE::flowDurationMilliseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowDurationMicroseconds(pub u32);

impl HasIE for flowDurationMicroseconds {
    fn ie(&self) -> IE {
        IE::flowDurationMicroseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct observedFlowTotalCount(pub u64);

impl HasIE for observedFlowTotalCount {
    fn ie(&self) -> IE {
        IE::observedFlowTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ignoredPacketTotalCount(pub u64);

impl HasIE for ignoredPacketTotalCount {
    fn ie(&self) -> IE {
        IE::ignoredPacketTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ignoredOctetTotalCount(pub u64);

impl HasIE for ignoredOctetTotalCount {
    fn ie(&self) -> IE {
        IE::ignoredOctetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct notSentFlowTotalCount(pub u64);

impl HasIE for notSentFlowTotalCount {
    fn ie(&self) -> IE {
        IE::notSentFlowTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct notSentPacketTotalCount(pub u64);

impl HasIE for notSentPacketTotalCount {
    fn ie(&self) -> IE {
        IE::notSentPacketTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct notSentOctetTotalCount(pub u64);

impl HasIE for notSentOctetTotalCount {
    fn ie(&self) -> IE {
        IE::notSentOctetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct destinationIPv6Prefix(pub std::net::Ipv6Addr);

impl HasIE for destinationIPv6Prefix {
    fn ie(&self) -> IE {
        IE::destinationIPv6Prefix
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct sourceIPv6Prefix(pub std::net::Ipv6Addr);

impl HasIE for sourceIPv6Prefix {
    fn ie(&self) -> IE {
        IE::sourceIPv6Prefix
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postOctetTotalCount(pub u64);

impl HasIE for postOctetTotalCount {
    fn ie(&self) -> IE {
        IE::postOctetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postPacketTotalCount(pub u64);

impl HasIE for postPacketTotalCount {
    fn ie(&self) -> IE {
        IE::postPacketTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowKeyIndicator(pub u64);

impl HasIE for flowKeyIndicator {
    fn ie(&self) -> IE {
        IE::flowKeyIndicator
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postMCastPacketTotalCount(pub u64);

impl HasIE for postMCastPacketTotalCount {
    fn ie(&self) -> IE {
        IE::postMCastPacketTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postMCastOctetTotalCount(pub u64);

impl HasIE for postMCastOctetTotalCount {
    fn ie(&self) -> IE {
        IE::postMCastOctetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct icmpTypeIPv4(pub u8);

impl HasIE for icmpTypeIPv4 {
    fn ie(&self) -> IE {
        IE::icmpTypeIPv4
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct icmpCodeIPv4(pub u8);

impl HasIE for icmpCodeIPv4 {
    fn ie(&self) -> IE {
        IE::icmpCodeIPv4
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct icmpTypeIPv6(pub u8);

impl HasIE for icmpTypeIPv6 {
    fn ie(&self) -> IE {
        IE::icmpTypeIPv6
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct icmpCodeIPv6(pub u8);

impl HasIE for icmpCodeIPv6 {
    fn ie(&self) -> IE {
        IE::icmpCodeIPv6
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct udpSourcePort(pub u16);

impl HasIE for udpSourcePort {
    fn ie(&self) -> IE {
        IE::udpSourcePort
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct udpDestinationPort(pub u16);

impl HasIE for udpDestinationPort {
    fn ie(&self) -> IE {
        IE::udpDestinationPort
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpSourcePort(pub u16);

impl HasIE for tcpSourcePort {
    fn ie(&self) -> IE {
        IE::tcpSourcePort
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpDestinationPort(pub u16);

impl HasIE for tcpDestinationPort {
    fn ie(&self) -> IE {
        IE::tcpDestinationPort
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpSequenceNumber(pub u32);

impl HasIE for tcpSequenceNumber {
    fn ie(&self) -> IE {
        IE::tcpSequenceNumber
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpAcknowledgementNumber(pub u32);

impl HasIE for tcpAcknowledgementNumber {
    fn ie(&self) -> IE {
        IE::tcpAcknowledgementNumber
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpWindowSize(pub u16);

impl HasIE for tcpWindowSize {
    fn ie(&self) -> IE {
        IE::tcpWindowSize
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpUrgentPointer(pub u16);

impl HasIE for tcpUrgentPointer {
    fn ie(&self) -> IE {
        IE::tcpUrgentPointer
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpHeaderLength(pub u8);

impl HasIE for tcpHeaderLength {
    fn ie(&self) -> IE {
        IE::tcpHeaderLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipHeaderLength(pub u8);

impl HasIE for ipHeaderLength {
    fn ie(&self) -> IE {
        IE::ipHeaderLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct totalLengthIPv4(pub u16);

impl HasIE for totalLengthIPv4 {
    fn ie(&self) -> IE {
        IE::totalLengthIPv4
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct payloadLengthIPv6(pub u16);

impl HasIE for payloadLengthIPv6 {
    fn ie(&self) -> IE {
        IE::payloadLengthIPv6
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipTTL(pub u8);

impl HasIE for ipTTL {
    fn ie(&self) -> IE {
        IE::ipTTL
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct nextHeaderIPv6(pub u8);

impl HasIE for nextHeaderIPv6 {
    fn ie(&self) -> IE {
        IE::nextHeaderIPv6
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsPayloadLength(pub u32);

impl HasIE for mplsPayloadLength {
    fn ie(&self) -> IE {
        IE::mplsPayloadLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipDiffServCodePoint(pub u8);

impl HasIE for ipDiffServCodePoint {
    fn ie(&self) -> IE {
        IE::ipDiffServCodePoint
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipPrecedence(pub u8);

impl HasIE for ipPrecedence {
    fn ie(&self) -> IE {
        IE::ipPrecedence
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct fragmentFlags(pub u8);

impl HasIE for fragmentFlags {
    fn ie(&self) -> IE {
        IE::fragmentFlags
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct octetDeltaSumOfSquares(pub u64);

impl HasIE for octetDeltaSumOfSquares {
    fn ie(&self) -> IE {
        IE::octetDeltaSumOfSquares
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct octetTotalSumOfSquares(pub u64);

impl HasIE for octetTotalSumOfSquares {
    fn ie(&self) -> IE {
        IE::octetTotalSumOfSquares
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsTopLabelTTL(pub u8);

impl HasIE for mplsTopLabelTTL {
    fn ie(&self) -> IE {
        IE::mplsTopLabelTTL
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsLabelStackLength(pub u32);

impl HasIE for mplsLabelStackLength {
    fn ie(&self) -> IE {
        IE::mplsLabelStackLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsLabelStackDepth(pub u32);

impl HasIE for mplsLabelStackDepth {
    fn ie(&self) -> IE {
        IE::mplsLabelStackDepth
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsTopLabelExp(pub u8);

impl HasIE for mplsTopLabelExp {
    fn ie(&self) -> IE {
        IE::mplsTopLabelExp
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipPayloadLength(pub u32);

impl HasIE for ipPayloadLength {
    fn ie(&self) -> IE {
        IE::ipPayloadLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct udpMessageLength(pub u16);

impl HasIE for udpMessageLength {
    fn ie(&self) -> IE {
        IE::udpMessageLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct isMulticast(pub u8);

impl HasIE for isMulticast {
    fn ie(&self) -> IE {
        IE::isMulticast
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipv4IHL(pub u8);

impl HasIE for ipv4IHL {
    fn ie(&self) -> IE {
        IE::ipv4IHL
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipv4Options(pub u32);

impl HasIE for ipv4Options {
    fn ie(&self) -> IE {
        IE::ipv4Options
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpOptions(pub u64);

impl HasIE for tcpOptions {
    fn ie(&self) -> IE {
        IE::tcpOptions
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct paddingOctets(pub Vec<u8>);

impl HasIE for paddingOctets {
    fn ie(&self) -> IE {
        IE::paddingOctets
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct collectorIPv4Address(pub std::net::Ipv4Addr);

impl HasIE for collectorIPv4Address {
    fn ie(&self) -> IE {
        IE::collectorIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct collectorIPv6Address(pub std::net::Ipv6Addr);

impl HasIE for collectorIPv6Address {
    fn ie(&self) -> IE {
        IE::collectorIPv6Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct exportInterface(pub u32);

impl HasIE for exportInterface {
    fn ie(&self) -> IE {
        IE::exportInterface
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct exportProtocolVersion(pub u8);

impl HasIE for exportProtocolVersion {
    fn ie(&self) -> IE {
        IE::exportProtocolVersion
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct exportTransportProtocol(pub u8);

impl HasIE for exportTransportProtocol {
    fn ie(&self) -> IE {
        IE::exportTransportProtocol
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct collectorTransportPort(pub u16);

impl HasIE for collectorTransportPort {
    fn ie(&self) -> IE {
        IE::collectorTransportPort
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct exporterTransportPort(pub u16);

impl HasIE for exporterTransportPort {
    fn ie(&self) -> IE {
        IE::exporterTransportPort
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpSynTotalCount(pub u64);

impl HasIE for tcpSynTotalCount {
    fn ie(&self) -> IE {
        IE::tcpSynTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpFinTotalCount(pub u64);

impl HasIE for tcpFinTotalCount {
    fn ie(&self) -> IE {
        IE::tcpFinTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpRstTotalCount(pub u64);

impl HasIE for tcpRstTotalCount {
    fn ie(&self) -> IE {
        IE::tcpRstTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpPshTotalCount(pub u64);

impl HasIE for tcpPshTotalCount {
    fn ie(&self) -> IE {
        IE::tcpPshTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpAckTotalCount(pub u64);

impl HasIE for tcpAckTotalCount {
    fn ie(&self) -> IE {
        IE::tcpAckTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpUrgTotalCount(pub u64);

impl HasIE for tcpUrgTotalCount {
    fn ie(&self) -> IE {
        IE::tcpUrgTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipTotalLength(pub u64);

impl HasIE for ipTotalLength {
    fn ie(&self) -> IE {
        IE::ipTotalLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postNATSourceIPv4Address(pub std::net::Ipv4Addr);

impl HasIE for postNATSourceIPv4Address {
    fn ie(&self) -> IE {
        IE::postNATSourceIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postNATDestinationIPv4Address(pub std::net::Ipv4Addr);

impl HasIE for postNATDestinationIPv4Address {
    fn ie(&self) -> IE {
        IE::postNATDestinationIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postNAPTSourceTransportPort(pub u16);

impl HasIE for postNAPTSourceTransportPort {
    fn ie(&self) -> IE {
        IE::postNAPTSourceTransportPort
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postNAPTDestinationTransportPort(pub u16);

impl HasIE for postNAPTDestinationTransportPort {
    fn ie(&self) -> IE {
        IE::postNAPTDestinationTransportPort
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum natOriginatingAddressRealm {
    /// Private
    ///
    Private1 = 1,
    /// Private
    ///
    Private2 = 2,
    Unassigned(u8),
}
impl From<natOriginatingAddressRealm> for u8 {
    fn from(value: natOriginatingAddressRealm) -> Self {
        match value {
            natOriginatingAddressRealm::Private1 => 1,
            natOriginatingAddressRealm::Private2 => 2,
            natOriginatingAddressRealm::Unassigned(x) => x,
        }
    }
}
impl From<u8> for natOriginatingAddressRealm {
    fn from(value: u8) -> Self {
        match value {
            1 => natOriginatingAddressRealm::Private1,
            2 => natOriginatingAddressRealm::Private2,
            x => natOriginatingAddressRealm::Unassigned(x),
        }
    }
}

impl HasIE for natOriginatingAddressRealm {
    fn ie(&self) -> IE {
        IE::natOriginatingAddressRealm
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum natEvent {
    /// Reserved
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Reserved0 = 0,
    /// NAT translation create (Historic)
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    NATtranslationcreateHistoric = 1,
    /// NAT translation delete (Historic)
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    NATtranslationdeleteHistoric = 2,
    /// NAT Addresses exhausted
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    NATAddressesexhausted = 3,
    /// NAT44 session create
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    NAT44sessioncreate = 4,
    /// NAT44 session delete
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    NAT44sessiondelete = 5,
    /// NAT64 session create
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    NAT64sessioncreate = 6,
    /// NAT64 session delete
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    NAT64sessiondelete = 7,
    /// NAT44 BIB create
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    NAT44BIBcreate = 8,
    /// NAT44 BIB delete
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    NAT44BIBdelete = 9,
    /// NAT64 BIB create
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    NAT64BIBcreate = 10,
    /// NAT64 BIB delete
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    NAT64BIBdelete = 11,
    /// NAT ports exhausted
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    NATportsexhausted = 12,
    /// Quota Exceeded
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    QuotaExceeded = 13,
    /// Address binding create
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Addressbindingcreate = 14,
    /// Address binding delete
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Addressbindingdelete = 15,
    /// Port block allocation
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Portblockallocation = 16,
    /// Port block de-allocation
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Portblockdeallocation = 17,
    /// Threshold Reached
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    ThresholdReached = 18,
    Unassigned(u8),
}
impl From<natEvent> for u8 {
    fn from(value: natEvent) -> Self {
        match value {
            natEvent::Reserved0 => 0,
            natEvent::NATtranslationcreateHistoric => 1,
            natEvent::NATtranslationdeleteHistoric => 2,
            natEvent::NATAddressesexhausted => 3,
            natEvent::NAT44sessioncreate => 4,
            natEvent::NAT44sessiondelete => 5,
            natEvent::NAT64sessioncreate => 6,
            natEvent::NAT64sessiondelete => 7,
            natEvent::NAT44BIBcreate => 8,
            natEvent::NAT44BIBdelete => 9,
            natEvent::NAT64BIBcreate => 10,
            natEvent::NAT64BIBdelete => 11,
            natEvent::NATportsexhausted => 12,
            natEvent::QuotaExceeded => 13,
            natEvent::Addressbindingcreate => 14,
            natEvent::Addressbindingdelete => 15,
            natEvent::Portblockallocation => 16,
            natEvent::Portblockdeallocation => 17,
            natEvent::ThresholdReached => 18,
            natEvent::Unassigned(x) => x,
        }
    }
}
impl From<u8> for natEvent {
    fn from(value: u8) -> Self {
        match value {
            0 => natEvent::Reserved0,
            1 => natEvent::NATtranslationcreateHistoric,
            2 => natEvent::NATtranslationdeleteHistoric,
            3 => natEvent::NATAddressesexhausted,
            4 => natEvent::NAT44sessioncreate,
            5 => natEvent::NAT44sessiondelete,
            6 => natEvent::NAT64sessioncreate,
            7 => natEvent::NAT64sessiondelete,
            8 => natEvent::NAT44BIBcreate,
            9 => natEvent::NAT44BIBdelete,
            10 => natEvent::NAT64BIBcreate,
            11 => natEvent::NAT64BIBdelete,
            12 => natEvent::NATportsexhausted,
            13 => natEvent::QuotaExceeded,
            14 => natEvent::Addressbindingcreate,
            15 => natEvent::Addressbindingdelete,
            16 => natEvent::Portblockallocation,
            17 => natEvent::Portblockdeallocation,
            18 => natEvent::ThresholdReached,
            x => natEvent::Unassigned(x),
        }
    }
}

impl HasIE for natEvent {
    fn ie(&self) -> IE {
        IE::natEvent
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct initiatorOctets(pub u64);

impl HasIE for initiatorOctets {
    fn ie(&self) -> IE {
        IE::initiatorOctets
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct responderOctets(pub u64);

impl HasIE for responderOctets {
    fn ie(&self) -> IE {
        IE::responderOctets
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum firewallEvent {
    /// Ignore (invalid)
    ///
    Ignoreinvalid = 0,
    /// Flow Created
    ///
    FlowCreated = 1,
    /// Flow Deleted
    ///
    FlowDeleted = 2,
    /// Flow Denied
    ///
    FlowDenied = 3,
    /// Flow Alert
    ///
    FlowAlert = 4,
    /// Flow Update
    ///
    FlowUpdate = 5,
    Unassigned(u8),
}
impl From<firewallEvent> for u8 {
    fn from(value: firewallEvent) -> Self {
        match value {
            firewallEvent::Ignoreinvalid => 0,
            firewallEvent::FlowCreated => 1,
            firewallEvent::FlowDeleted => 2,
            firewallEvent::FlowDenied => 3,
            firewallEvent::FlowAlert => 4,
            firewallEvent::FlowUpdate => 5,
            firewallEvent::Unassigned(x) => x,
        }
    }
}
impl From<u8> for firewallEvent {
    fn from(value: u8) -> Self {
        match value {
            0 => firewallEvent::Ignoreinvalid,
            1 => firewallEvent::FlowCreated,
            2 => firewallEvent::FlowDeleted,
            3 => firewallEvent::FlowDenied,
            4 => firewallEvent::FlowAlert,
            5 => firewallEvent::FlowUpdate,
            x => firewallEvent::Unassigned(x),
        }
    }
}

impl HasIE for firewallEvent {
    fn ie(&self) -> IE {
        IE::firewallEvent
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ingressVRFID(pub u32);

impl HasIE for ingressVRFID {
    fn ie(&self) -> IE {
        IE::ingressVRFID
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct egressVRFID(pub u32);

impl HasIE for egressVRFID {
    fn ie(&self) -> IE {
        IE::egressVRFID
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct VRFname(pub String);

impl HasIE for VRFname {
    fn ie(&self) -> IE {
        IE::VRFname
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postMplsTopLabelExp(pub u8);

impl HasIE for postMplsTopLabelExp {
    fn ie(&self) -> IE {
        IE::postMplsTopLabelExp
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpWindowScale(pub u16);

impl HasIE for tcpWindowScale {
    fn ie(&self) -> IE {
        IE::tcpWindowScale
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum biflowDirection {
    /// Direction was assigned arbitrarily.
    ///
    /// Reference: [RFC5103](https://datatracker.ietf.org/doc/html/rfc5103)
    arbitrary = 0,
    /// The Biflow Source is the flow initiator, as determined by the
    /// Metering Process' best effort to detect the initiator.
    ///
    /// Reference: [RFC5103](https://datatracker.ietf.org/doc/html/rfc5103)
    initiator = 1,
    /// The Biflow Destination is the flow initiator, as determined by the
    /// Metering Process' best effort to detect the initiator.  This value is
    /// provided for the convenience of Exporting Processes to revise an
    /// initiator estimate without re-encoding the Biflow Record.
    ///
    /// Reference: [RFC5103](https://datatracker.ietf.org/doc/html/rfc5103)
    reverseInitiator = 2,
    /// The Biflow Source is the endpoint outside of a defined perimeter.  The
    /// perimeter's definition is implicit in the set of Biflow Source and Biflow
    /// Destination addresses exported in the Biflow Records.
    ///
    /// Reference: [RFC5103](https://datatracker.ietf.org/doc/html/rfc5103)
    perimeter = 3,
    Unassigned(u8),
}
impl From<biflowDirection> for u8 {
    fn from(value: biflowDirection) -> Self {
        match value {
            biflowDirection::arbitrary => 0,
            biflowDirection::initiator => 1,
            biflowDirection::reverseInitiator => 2,
            biflowDirection::perimeter => 3,
            biflowDirection::Unassigned(x) => x,
        }
    }
}
impl From<u8> for biflowDirection {
    fn from(value: u8) -> Self {
        match value {
            0 => biflowDirection::arbitrary,
            1 => biflowDirection::initiator,
            2 => biflowDirection::reverseInitiator,
            3 => biflowDirection::perimeter,
            x => biflowDirection::Unassigned(x),
        }
    }
}

impl HasIE for biflowDirection {
    fn ie(&self) -> IE {
        IE::biflowDirection
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ethernetHeaderLength(pub u8);

impl HasIE for ethernetHeaderLength {
    fn ie(&self) -> IE {
        IE::ethernetHeaderLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ethernetPayloadLength(pub u16);

impl HasIE for ethernetPayloadLength {
    fn ie(&self) -> IE {
        IE::ethernetPayloadLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ethernetTotalLength(pub u16);

impl HasIE for ethernetTotalLength {
    fn ie(&self) -> IE {
        IE::ethernetTotalLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dot1qVlanId(pub u16);

impl HasIE for dot1qVlanId {
    fn ie(&self) -> IE {
        IE::dot1qVlanId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dot1qPriority(pub u8);

impl HasIE for dot1qPriority {
    fn ie(&self) -> IE {
        IE::dot1qPriority
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dot1qCustomerVlanId(pub u16);

impl HasIE for dot1qCustomerVlanId {
    fn ie(&self) -> IE {
        IE::dot1qCustomerVlanId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dot1qCustomerPriority(pub u8);

impl HasIE for dot1qCustomerPriority {
    fn ie(&self) -> IE {
        IE::dot1qCustomerPriority
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct metroEvcId(pub String);

impl HasIE for metroEvcId {
    fn ie(&self) -> IE {
        IE::metroEvcId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct metroEvcType(pub u8);

impl HasIE for metroEvcType {
    fn ie(&self) -> IE {
        IE::metroEvcType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct pseudoWireId(pub u32);

impl HasIE for pseudoWireId {
    fn ie(&self) -> IE {
        IE::pseudoWireId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct pseudoWireType(pub u16);

impl HasIE for pseudoWireType {
    fn ie(&self) -> IE {
        IE::pseudoWireType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct pseudoWireControlWord(pub u32);

impl HasIE for pseudoWireControlWord {
    fn ie(&self) -> IE {
        IE::pseudoWireControlWord
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ingressPhysicalInterface(pub u32);

impl HasIE for ingressPhysicalInterface {
    fn ie(&self) -> IE {
        IE::ingressPhysicalInterface
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct egressPhysicalInterface(pub u32);

impl HasIE for egressPhysicalInterface {
    fn ie(&self) -> IE {
        IE::egressPhysicalInterface
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postDot1qVlanId(pub u16);

impl HasIE for postDot1qVlanId {
    fn ie(&self) -> IE {
        IE::postDot1qVlanId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postDot1qCustomerVlanId(pub u16);

impl HasIE for postDot1qCustomerVlanId {
    fn ie(&self) -> IE {
        IE::postDot1qCustomerVlanId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ethernetType(pub u16);

impl HasIE for ethernetType {
    fn ie(&self) -> IE {
        IE::ethernetType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postIpPrecedence(pub u8);

impl HasIE for postIpPrecedence {
    fn ie(&self) -> IE {
        IE::postIpPrecedence
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct collectionTimeMilliseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for collectionTimeMilliseconds {
    fn ie(&self) -> IE {
        IE::collectionTimeMilliseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct exportSctpStreamId(pub u16);

impl HasIE for exportSctpStreamId {
    fn ie(&self) -> IE {
        IE::exportSctpStreamId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maxExportSeconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for maxExportSeconds {
    fn ie(&self) -> IE {
        IE::maxExportSeconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maxFlowEndSeconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for maxFlowEndSeconds {
    fn ie(&self) -> IE {
        IE::maxFlowEndSeconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct messageMD5Checksum(pub Vec<u8>);

impl HasIE for messageMD5Checksum {
    fn ie(&self) -> IE {
        IE::messageMD5Checksum
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct messageScope(pub u8);

impl HasIE for messageScope {
    fn ie(&self) -> IE {
        IE::messageScope
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct minExportSeconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for minExportSeconds {
    fn ie(&self) -> IE {
        IE::minExportSeconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct minFlowStartSeconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for minFlowStartSeconds {
    fn ie(&self) -> IE {
        IE::minFlowStartSeconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct opaqueOctets(pub Vec<u8>);

impl HasIE for opaqueOctets {
    fn ie(&self) -> IE {
        IE::opaqueOctets
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct sessionScope(pub u8);

impl HasIE for sessionScope {
    fn ie(&self) -> IE {
        IE::sessionScope
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maxFlowEndMicroseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for maxFlowEndMicroseconds {
    fn ie(&self) -> IE {
        IE::maxFlowEndMicroseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maxFlowEndMilliseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for maxFlowEndMilliseconds {
    fn ie(&self) -> IE {
        IE::maxFlowEndMilliseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maxFlowEndNanoseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for maxFlowEndNanoseconds {
    fn ie(&self) -> IE {
        IE::maxFlowEndNanoseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct minFlowStartMicroseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for minFlowStartMicroseconds {
    fn ie(&self) -> IE {
        IE::minFlowStartMicroseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct minFlowStartMilliseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for minFlowStartMilliseconds {
    fn ie(&self) -> IE {
        IE::minFlowStartMilliseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct minFlowStartNanoseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for minFlowStartNanoseconds {
    fn ie(&self) -> IE {
        IE::minFlowStartNanoseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct collectorCertificate(pub Vec<u8>);

impl HasIE for collectorCertificate {
    fn ie(&self) -> IE {
        IE::collectorCertificate
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct exporterCertificate(pub Vec<u8>);

impl HasIE for exporterCertificate {
    fn ie(&self) -> IE {
        IE::exporterCertificate
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dataRecordsReliability(pub bool);

impl HasIE for dataRecordsReliability {
    fn ie(&self) -> IE {
        IE::dataRecordsReliability
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum observationPointType {
    /// Physical port
    ///
    Physicalport = 1,
    /// Port channel
    ///
    Portchannel = 2,
    /// Vlan
    ///
    Vlan = 3,
    Unassigned(u8),
}
impl From<observationPointType> for u8 {
    fn from(value: observationPointType) -> Self {
        match value {
            observationPointType::Physicalport => 1,
            observationPointType::Portchannel => 2,
            observationPointType::Vlan => 3,
            observationPointType::Unassigned(x) => x,
        }
    }
}
impl From<u8> for observationPointType {
    fn from(value: u8) -> Self {
        match value {
            1 => observationPointType::Physicalport,
            2 => observationPointType::Portchannel,
            3 => observationPointType::Vlan,
            x => observationPointType::Unassigned(x),
        }
    }
}

impl HasIE for observationPointType {
    fn ie(&self) -> IE {
        IE::observationPointType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct newConnectionDeltaCount(pub u32);

impl HasIE for newConnectionDeltaCount {
    fn ie(&self) -> IE {
        IE::newConnectionDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct connectionSumDurationSeconds(pub u64);

impl HasIE for connectionSumDurationSeconds {
    fn ie(&self) -> IE {
        IE::connectionSumDurationSeconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct connectionTransactionId(pub u64);

impl HasIE for connectionTransactionId {
    fn ie(&self) -> IE {
        IE::connectionTransactionId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postNATSourceIPv6Address(pub std::net::Ipv6Addr);

impl HasIE for postNATSourceIPv6Address {
    fn ie(&self) -> IE {
        IE::postNATSourceIPv6Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postNATDestinationIPv6Address(pub std::net::Ipv6Addr);

impl HasIE for postNATDestinationIPv6Address {
    fn ie(&self) -> IE {
        IE::postNATDestinationIPv6Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct natPoolId(pub u32);

impl HasIE for natPoolId {
    fn ie(&self) -> IE {
        IE::natPoolId
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct natPoolName(pub String);

impl HasIE for natPoolName {
    fn ie(&self) -> IE {
        IE::natPoolName
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct anonymizationFlags(pub u16);

impl HasIE for anonymizationFlags {
    fn ie(&self) -> IE {
        IE::anonymizationFlags
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum anonymizationTechnique {
    /// The Exporting Process makes no representation as to
    /// whether the defined field is anonymized or not.
    /// While the Collecting Process MAY assume that
    /// the field is not anonymized, it is not
    /// guaranteed not to be. This is the default
    /// anonymization technique.
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    Undefined = 0,
    /// The values exported are real.
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    None = 1,
    /// The values exported are anonymized using simple
    /// precision degradation or truncation.  The new
    /// precision or number of truncated bits is
    /// implicit in the exported data, and can be deduced
    /// by the Collecting Process.
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    PrecisionDegradationTruncation = 2,
    /// The values exported are anonymized into bins.
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    Binning = 3,
    /// The values exported are anonymized by enumeration.
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    Enumeration = 4,
    /// The values exported are anonymized by permutation.
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    Permutation = 5,
    /// The values exported are anonymized by permutation,
    /// preserving bit-level structure as appropriate; this
    /// represents prefix-preserving IP address anonymization or
    /// structured MAC address anonymization.
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    StructuredPermutation = 6,
    /// The values exported are anonymized using reverse
    /// truncation.  The number of truncated bits is implicit in the exported
    /// data, and can be deduced by the Collecting Process.
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    ReverseTruncation = 7,
    /// The values exported are anonymized by adding random
    /// noise to each value.
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    Noise = 8,
    /// The values exported are anonymized by adding a single offset
    /// to all values.
    ///
    /// Reference: [RFC6235](https://datatracker.ietf.org/doc/html/rfc6235)
    Offset = 9,
    Unassigned(u16),
}
impl From<anonymizationTechnique> for u16 {
    fn from(value: anonymizationTechnique) -> Self {
        match value {
            anonymizationTechnique::Undefined => 0,
            anonymizationTechnique::None => 1,
            anonymizationTechnique::PrecisionDegradationTruncation => 2,
            anonymizationTechnique::Binning => 3,
            anonymizationTechnique::Enumeration => 4,
            anonymizationTechnique::Permutation => 5,
            anonymizationTechnique::StructuredPermutation => 6,
            anonymizationTechnique::ReverseTruncation => 7,
            anonymizationTechnique::Noise => 8,
            anonymizationTechnique::Offset => 9,
            anonymizationTechnique::Unassigned(x) => x,
        }
    }
}
impl From<u16> for anonymizationTechnique {
    fn from(value: u16) -> Self {
        match value {
            0 => anonymizationTechnique::Undefined,
            1 => anonymizationTechnique::None,
            2 => anonymizationTechnique::PrecisionDegradationTruncation,
            3 => anonymizationTechnique::Binning,
            4 => anonymizationTechnique::Enumeration,
            5 => anonymizationTechnique::Permutation,
            6 => anonymizationTechnique::StructuredPermutation,
            7 => anonymizationTechnique::ReverseTruncation,
            8 => anonymizationTechnique::Noise,
            9 => anonymizationTechnique::Offset,
            x => anonymizationTechnique::Unassigned(x),
        }
    }
}

impl HasIE for anonymizationTechnique {
    fn ie(&self) -> IE {
        IE::anonymizationTechnique
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct informationElementIndex(pub u16);

impl HasIE for informationElementIndex {
    fn ie(&self) -> IE {
        IE::informationElementIndex
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct p2pTechnology(pub String);

impl HasIE for p2pTechnology {
    fn ie(&self) -> IE {
        IE::p2pTechnology
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tunnelTechnology(pub String);

impl HasIE for tunnelTechnology {
    fn ie(&self) -> IE {
        IE::tunnelTechnology
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct encryptedTechnology(pub String);

impl HasIE for encryptedTechnology {
    fn ie(&self) -> IE {
        IE::encryptedTechnology
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct basicList(pub Vec<u8>);

impl HasIE for basicList {
    fn ie(&self) -> IE {
        IE::basicList
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct subTemplateList(pub Vec<u8>);

impl HasIE for subTemplateList {
    fn ie(&self) -> IE {
        IE::subTemplateList
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct subTemplateMultiList(pub Vec<u8>);

impl HasIE for subTemplateMultiList {
    fn ie(&self) -> IE {
        IE::subTemplateMultiList
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpValidityState(pub u8);

impl HasIE for bgpValidityState {
    fn ie(&self) -> IE {
        IE::bgpValidityState
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct IPSecSPI(pub u32);

impl HasIE for IPSecSPI {
    fn ie(&self) -> IE {
        IE::IPSecSPI
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct greKey(pub u32);

impl HasIE for greKey {
    fn ie(&self) -> IE {
        IE::greKey
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum natType {
    /// unknown
    ///
    unknown = 0,
    /// NAT44 translated
    ///
    NAT44translated = 1,
    /// NAT64 translated
    ///
    NAT64translated = 2,
    /// NAT46 translated
    ///
    NAT46translated = 3,
    /// IPv4-->IPv4 (no NAT)
    ///
    IPv4IPv4noNAT = 4,
    /// NAT66 translated
    ///
    NAT66translated = 5,
    /// IPv6-->IPv6 (no NAT)
    ///
    IPv6IPv6noNAT = 6,
    Unassigned(u8),
}
impl From<natType> for u8 {
    fn from(value: natType) -> Self {
        match value {
            natType::unknown => 0,
            natType::NAT44translated => 1,
            natType::NAT64translated => 2,
            natType::NAT46translated => 3,
            natType::IPv4IPv4noNAT => 4,
            natType::NAT66translated => 5,
            natType::IPv6IPv6noNAT => 6,
            natType::Unassigned(x) => x,
        }
    }
}
impl From<u8> for natType {
    fn from(value: u8) -> Self {
        match value {
            0 => natType::unknown,
            1 => natType::NAT44translated,
            2 => natType::NAT64translated,
            3 => natType::NAT46translated,
            4 => natType::IPv4IPv4noNAT,
            5 => natType::NAT66translated,
            6 => natType::IPv6IPv6noNAT,
            x => natType::Unassigned(x),
        }
    }
}

impl HasIE for natType {
    fn ie(&self) -> IE {
        IE::natType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct initiatorPackets(pub u64);

impl HasIE for initiatorPackets {
    fn ie(&self) -> IE {
        IE::initiatorPackets
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct responderPackets(pub u64);

impl HasIE for responderPackets {
    fn ie(&self) -> IE {
        IE::responderPackets
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct observationDomainName(pub String);

impl HasIE for observationDomainName {
    fn ie(&self) -> IE {
        IE::observationDomainName
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct selectionSequenceId(pub u64);

impl HasIE for selectionSequenceId {
    fn ie(&self) -> IE {
        IE::selectionSequenceId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct selectorId(pub u64);

impl HasIE for selectorId {
    fn ie(&self) -> IE {
        IE::selectorId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct informationElementId(pub u16);

impl HasIE for informationElementId {
    fn ie(&self) -> IE {
        IE::informationElementId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct selectorAlgorithm(pub u16);

impl HasIE for selectorAlgorithm {
    fn ie(&self) -> IE {
        IE::selectorAlgorithm
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplingPacketInterval(pub u32);

impl HasIE for samplingPacketInterval {
    fn ie(&self) -> IE {
        IE::samplingPacketInterval
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplingPacketSpace(pub u32);

impl HasIE for samplingPacketSpace {
    fn ie(&self) -> IE {
        IE::samplingPacketSpace
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplingTimeInterval(pub u32);

impl HasIE for samplingTimeInterval {
    fn ie(&self) -> IE {
        IE::samplingTimeInterval
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplingTimeSpace(pub u32);

impl HasIE for samplingTimeSpace {
    fn ie(&self) -> IE {
        IE::samplingTimeSpace
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplingSize(pub u32);

impl HasIE for samplingSize {
    fn ie(&self) -> IE {
        IE::samplingSize
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplingPopulation(pub u32);

impl HasIE for samplingPopulation {
    fn ie(&self) -> IE {
        IE::samplingPopulation
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplingProbability(pub f64);

impl HasIE for samplingProbability {
    fn ie(&self) -> IE {
        IE::samplingProbability
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dataLinkFrameSize(pub u16);

impl HasIE for dataLinkFrameSize {
    fn ie(&self) -> IE {
        IE::dataLinkFrameSize
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipHeaderPacketSection(pub Vec<u8>);

impl HasIE for ipHeaderPacketSection {
    fn ie(&self) -> IE {
        IE::ipHeaderPacketSection
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipPayloadPacketSection(pub Vec<u8>);

impl HasIE for ipPayloadPacketSection {
    fn ie(&self) -> IE {
        IE::ipPayloadPacketSection
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dataLinkFrameSection(pub Vec<u8>);

impl HasIE for dataLinkFrameSection {
    fn ie(&self) -> IE {
        IE::dataLinkFrameSection
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsLabelStackSection(pub Vec<u8>);

impl HasIE for mplsLabelStackSection {
    fn ie(&self) -> IE {
        IE::mplsLabelStackSection
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mplsPayloadPacketSection(pub Vec<u8>);

impl HasIE for mplsPayloadPacketSection {
    fn ie(&self) -> IE {
        IE::mplsPayloadPacketSection
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct selectorIdTotalPktsObserved(pub u64);

impl HasIE for selectorIdTotalPktsObserved {
    fn ie(&self) -> IE {
        IE::selectorIdTotalPktsObserved
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct selectorIdTotalPktsSelected(pub u64);

impl HasIE for selectorIdTotalPktsSelected {
    fn ie(&self) -> IE {
        IE::selectorIdTotalPktsSelected
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct absoluteError(pub f64);

impl HasIE for absoluteError {
    fn ie(&self) -> IE {
        IE::absoluteError
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct relativeError(pub f64);

impl HasIE for relativeError {
    fn ie(&self) -> IE {
        IE::relativeError
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct observationTimeSeconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for observationTimeSeconds {
    fn ie(&self) -> IE {
        IE::observationTimeSeconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct observationTimeMilliseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for observationTimeMilliseconds {
    fn ie(&self) -> IE {
        IE::observationTimeMilliseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct observationTimeMicroseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for observationTimeMicroseconds {
    fn ie(&self) -> IE {
        IE::observationTimeMicroseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct observationTimeNanoseconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for observationTimeNanoseconds {
    fn ie(&self) -> IE {
        IE::observationTimeNanoseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct digestHashValue(pub u64);

impl HasIE for digestHashValue {
    fn ie(&self) -> IE {
        IE::digestHashValue
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct hashIPPayloadOffset(pub u64);

impl HasIE for hashIPPayloadOffset {
    fn ie(&self) -> IE {
        IE::hashIPPayloadOffset
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct hashIPPayloadSize(pub u64);

impl HasIE for hashIPPayloadSize {
    fn ie(&self) -> IE {
        IE::hashIPPayloadSize
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct hashOutputRangeMin(pub u64);

impl HasIE for hashOutputRangeMin {
    fn ie(&self) -> IE {
        IE::hashOutputRangeMin
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct hashOutputRangeMax(pub u64);

impl HasIE for hashOutputRangeMax {
    fn ie(&self) -> IE {
        IE::hashOutputRangeMax
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct hashSelectedRangeMin(pub u64);

impl HasIE for hashSelectedRangeMin {
    fn ie(&self) -> IE {
        IE::hashSelectedRangeMin
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct hashSelectedRangeMax(pub u64);

impl HasIE for hashSelectedRangeMax {
    fn ie(&self) -> IE {
        IE::hashSelectedRangeMax
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct hashDigestOutput(pub bool);

impl HasIE for hashDigestOutput {
    fn ie(&self) -> IE {
        IE::hashDigestOutput
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct hashInitialiserValue(pub u64);

impl HasIE for hashInitialiserValue {
    fn ie(&self) -> IE {
        IE::hashInitialiserValue
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct selectorName(pub String);

impl HasIE for selectorName {
    fn ie(&self) -> IE {
        IE::selectorName
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct upperCILimit(pub f64);

impl HasIE for upperCILimit {
    fn ie(&self) -> IE {
        IE::upperCILimit
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct lowerCILimit(pub f64);

impl HasIE for lowerCILimit {
    fn ie(&self) -> IE {
        IE::lowerCILimit
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct confidenceLevel(pub f64);

impl HasIE for confidenceLevel {
    fn ie(&self) -> IE {
        IE::confidenceLevel
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct informationElementDataType(pub u8);

impl HasIE for informationElementDataType {
    fn ie(&self) -> IE {
        IE::informationElementDataType
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct informationElementDescription(pub String);

impl HasIE for informationElementDescription {
    fn ie(&self) -> IE {
        IE::informationElementDescription
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct informationElementName(pub String);

impl HasIE for informationElementName {
    fn ie(&self) -> IE {
        IE::informationElementName
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct informationElementRangeBegin(pub u64);

impl HasIE for informationElementRangeBegin {
    fn ie(&self) -> IE {
        IE::informationElementRangeBegin
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct informationElementRangeEnd(pub u64);

impl HasIE for informationElementRangeEnd {
    fn ie(&self) -> IE {
        IE::informationElementRangeEnd
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct informationElementSemantics(pub u8);

impl HasIE for informationElementSemantics {
    fn ie(&self) -> IE {
        IE::informationElementSemantics
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct informationElementUnits(pub u16);

impl HasIE for informationElementUnits {
    fn ie(&self) -> IE {
        IE::informationElementUnits
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct privateEnterpriseNumber(pub u32);

impl HasIE for privateEnterpriseNumber {
    fn ie(&self) -> IE {
        IE::privateEnterpriseNumber
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct virtualStationInterfaceId(pub Vec<u8>);

impl HasIE for virtualStationInterfaceId {
    fn ie(&self) -> IE {
        IE::virtualStationInterfaceId
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct virtualStationInterfaceName(pub String);

impl HasIE for virtualStationInterfaceName {
    fn ie(&self) -> IE {
        IE::virtualStationInterfaceName
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct virtualStationUUID(pub Vec<u8>);

impl HasIE for virtualStationUUID {
    fn ie(&self) -> IE {
        IE::virtualStationUUID
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct virtualStationName(pub String);

impl HasIE for virtualStationName {
    fn ie(&self) -> IE {
        IE::virtualStationName
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct layer2SegmentId(pub u64);

impl HasIE for layer2SegmentId {
    fn ie(&self) -> IE {
        IE::layer2SegmentId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct layer2OctetDeltaCount(pub u64);

impl HasIE for layer2OctetDeltaCount {
    fn ie(&self) -> IE {
        IE::layer2OctetDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct layer2OctetTotalCount(pub u64);

impl HasIE for layer2OctetTotalCount {
    fn ie(&self) -> IE {
        IE::layer2OctetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ingressUnicastPacketTotalCount(pub u64);

impl HasIE for ingressUnicastPacketTotalCount {
    fn ie(&self) -> IE {
        IE::ingressUnicastPacketTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ingressMulticastPacketTotalCount(pub u64);

impl HasIE for ingressMulticastPacketTotalCount {
    fn ie(&self) -> IE {
        IE::ingressMulticastPacketTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ingressBroadcastPacketTotalCount(pub u64);

impl HasIE for ingressBroadcastPacketTotalCount {
    fn ie(&self) -> IE {
        IE::ingressBroadcastPacketTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct egressUnicastPacketTotalCount(pub u64);

impl HasIE for egressUnicastPacketTotalCount {
    fn ie(&self) -> IE {
        IE::egressUnicastPacketTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct egressBroadcastPacketTotalCount(pub u64);

impl HasIE for egressBroadcastPacketTotalCount {
    fn ie(&self) -> IE {
        IE::egressBroadcastPacketTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct monitoringIntervalStartMilliSeconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for monitoringIntervalStartMilliSeconds {
    fn ie(&self) -> IE {
        IE::monitoringIntervalStartMilliSeconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct monitoringIntervalEndMilliSeconds(#[cfg_attr(feature = "fuzz", arbitrary(with = crate::arbitrary_datetime))] pub chrono::DateTime<chrono::Utc>);

impl HasIE for monitoringIntervalEndMilliSeconds {
    fn ie(&self) -> IE {
        IE::monitoringIntervalEndMilliSeconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct portRangeStart(pub u16);

impl HasIE for portRangeStart {
    fn ie(&self) -> IE {
        IE::portRangeStart
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct portRangeEnd(pub u16);

impl HasIE for portRangeEnd {
    fn ie(&self) -> IE {
        IE::portRangeEnd
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct portRangeStepSize(pub u16);

impl HasIE for portRangeStepSize {
    fn ie(&self) -> IE {
        IE::portRangeStepSize
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct portRangeNumPorts(pub u16);

impl HasIE for portRangeNumPorts {
    fn ie(&self) -> IE {
        IE::portRangeNumPorts
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct staMacAddress(pub super::MacAddress);

impl HasIE for staMacAddress {
    fn ie(&self) -> IE {
        IE::staMacAddress
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct staIPv4Address(pub std::net::Ipv4Addr);

impl HasIE for staIPv4Address {
    fn ie(&self) -> IE {
        IE::staIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct wtpMacAddress(pub super::MacAddress);

impl HasIE for wtpMacAddress {
    fn ie(&self) -> IE {
        IE::wtpMacAddress
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ingressInterfaceType(pub u32);

impl HasIE for ingressInterfaceType {
    fn ie(&self) -> IE {
        IE::ingressInterfaceType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct egressInterfaceType(pub u32);

impl HasIE for egressInterfaceType {
    fn ie(&self) -> IE {
        IE::egressInterfaceType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct rtpSequenceNumber(pub u16);

impl HasIE for rtpSequenceNumber {
    fn ie(&self) -> IE {
        IE::rtpSequenceNumber
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct userName(pub String);

impl HasIE for userName {
    fn ie(&self) -> IE {
        IE::userName
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct applicationCategoryName(pub String);

impl HasIE for applicationCategoryName {
    fn ie(&self) -> IE {
        IE::applicationCategoryName
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct applicationSubCategoryName(pub String);

impl HasIE for applicationSubCategoryName {
    fn ie(&self) -> IE {
        IE::applicationSubCategoryName
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct applicationGroupName(pub String);

impl HasIE for applicationGroupName {
    fn ie(&self) -> IE {
        IE::applicationGroupName
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct originalFlowsPresent(pub u64);

impl HasIE for originalFlowsPresent {
    fn ie(&self) -> IE {
        IE::originalFlowsPresent
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct originalFlowsInitiated(pub u64);

impl HasIE for originalFlowsInitiated {
    fn ie(&self) -> IE {
        IE::originalFlowsInitiated
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct originalFlowsCompleted(pub u64);

impl HasIE for originalFlowsCompleted {
    fn ie(&self) -> IE {
        IE::originalFlowsCompleted
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct distinctCountOfSourceIPAddress(pub u64);

impl HasIE for distinctCountOfSourceIPAddress {
    fn ie(&self) -> IE {
        IE::distinctCountOfSourceIPAddress
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct distinctCountOfDestinationIPAddress(pub u64);

impl HasIE for distinctCountOfDestinationIPAddress {
    fn ie(&self) -> IE {
        IE::distinctCountOfDestinationIPAddress
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct distinctCountOfSourceIPv4Address(pub u32);

impl HasIE for distinctCountOfSourceIPv4Address {
    fn ie(&self) -> IE {
        IE::distinctCountOfSourceIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct distinctCountOfDestinationIPv4Address(pub u32);

impl HasIE for distinctCountOfDestinationIPv4Address {
    fn ie(&self) -> IE {
        IE::distinctCountOfDestinationIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct distinctCountOfSourceIPv6Address(pub u64);

impl HasIE for distinctCountOfSourceIPv6Address {
    fn ie(&self) -> IE {
        IE::distinctCountOfSourceIPv6Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct distinctCountOfDestinationIPv6Address(pub u64);

impl HasIE for distinctCountOfDestinationIPv6Address {
    fn ie(&self) -> IE {
        IE::distinctCountOfDestinationIPv6Address
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum valueDistributionMethod {
    /// The counters for an Original Flow are
    /// explicitly not distributed according to any other method
    /// defined for this Information Element; use for arbitrary
    /// distribution, or distribution algorithms not described by
    /// any other codepoint.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    Unspecified = 0,
    /// The counters for an Original Flow are
    /// added to the counters of the appropriate Aggregated
    /// Flow containing the start time of the Original Flow.
    /// This should be assumed the default if value
    /// distribution information is not available at a
    /// Collecting Process for an Aggregated Flow.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    StartInterval = 1,
    /// The counters for an Original Flow are added
    /// to the counters of the appropriate Aggregated Flow
    /// containing the end time of the Original Flow.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    EndInterval = 2,
    /// The counters for an Original Flow are added
    /// to the counters of a single appropriate Aggregated Flow
    /// containing some timestamp between start and end time of
    /// the Original Flow.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    MidInterval = 3,
    /// Each counter for an Original
    /// Flow is divided by the number of time intervals the
    /// Original Flow covers (i.e., of appropriate Aggregated
    /// Flows sharing the same Flow Key), and this number is
    /// added to each corresponding counter in each Aggregated
    /// Flow.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    SimpleUniformDistribution = 4,
    /// Each counter for an
    /// Original Flow is divided by the number of time units the
    /// Original Flow covers, to derive a mean count rate.  This
    /// mean count rate is then multiplied by the number of time
    /// units in the intersection of the duration of the Original
    /// Flow and the time interval of each Aggregated Flow.  This
    /// is like simple uniform distribution, but accounts for the
    /// fractional portions of a time interval covered by an
    /// Original Flow in the first and last time interval.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    ProportionalUniformDistribution = 5,
    /// Each counter of the Original Flow is
    /// distributed among the intervals of the Aggregated Flows
    /// according to some function the Intermediate Aggregation
    /// Process uses based upon properties of Flows presumed to
    /// be like the Original Flow.  This is essentially an
    /// assertion that the Intermediate Aggregation Process has
    /// no direct packet timing information but is nevertheless
    /// not using one of the other simpler distribution methods.
    /// The Intermediate Aggregation Process specifically makes
    /// no assertion as to the correctness of the simulation.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    SimulatedProcess = 6,
    /// The Intermediate Aggregation Process has access
    /// to the original packet timings from the packets making up
    /// the Original Flow, and uses these to distribute or
    /// recalculate the counters.
    ///
    /// Reference: [RFC7015](https://datatracker.ietf.org/doc/html/rfc7015)
    Direct = 7,
    Unassigned(u8),
}
impl From<valueDistributionMethod> for u8 {
    fn from(value: valueDistributionMethod) -> Self {
        match value {
            valueDistributionMethod::Unspecified => 0,
            valueDistributionMethod::StartInterval => 1,
            valueDistributionMethod::EndInterval => 2,
            valueDistributionMethod::MidInterval => 3,
            valueDistributionMethod::SimpleUniformDistribution => 4,
            valueDistributionMethod::ProportionalUniformDistribution => 5,
            valueDistributionMethod::SimulatedProcess => 6,
            valueDistributionMethod::Direct => 7,
            valueDistributionMethod::Unassigned(x) => x,
        }
    }
}
impl From<u8> for valueDistributionMethod {
    fn from(value: u8) -> Self {
        match value {
            0 => valueDistributionMethod::Unspecified,
            1 => valueDistributionMethod::StartInterval,
            2 => valueDistributionMethod::EndInterval,
            3 => valueDistributionMethod::MidInterval,
            4 => valueDistributionMethod::SimpleUniformDistribution,
            5 => valueDistributionMethod::ProportionalUniformDistribution,
            6 => valueDistributionMethod::SimulatedProcess,
            7 => valueDistributionMethod::Direct,
            x => valueDistributionMethod::Unassigned(x),
        }
    }
}

impl HasIE for valueDistributionMethod {
    fn ie(&self) -> IE {
        IE::valueDistributionMethod
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct rfc3550JitterMilliseconds(pub u32);

impl HasIE for rfc3550JitterMilliseconds {
    fn ie(&self) -> IE {
        IE::rfc3550JitterMilliseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct rfc3550JitterMicroseconds(pub u32);

impl HasIE for rfc3550JitterMicroseconds {
    fn ie(&self) -> IE {
        IE::rfc3550JitterMicroseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct rfc3550JitterNanoseconds(pub u32);

impl HasIE for rfc3550JitterNanoseconds {
    fn ie(&self) -> IE {
        IE::rfc3550JitterNanoseconds
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dot1qDEI(pub bool);

impl HasIE for dot1qDEI {
    fn ie(&self) -> IE {
        IE::dot1qDEI
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dot1qCustomerDEI(pub bool);

impl HasIE for dot1qCustomerDEI {
    fn ie(&self) -> IE {
        IE::dot1qCustomerDEI
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum flowSelectorAlgorithm {
    /// Systematic count-based Sampling
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    SystematiccountbasedSampling = 1,
    /// Systematic time-based Sampling
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    SystematictimebasedSampling = 2,
    /// Random n-out-of-N Sampling
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    RandomnoutofNSampling = 3,
    /// Uniform probabilistic Sampling
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    UniformprobabilisticSampling = 4,
    /// Property Match Filtering
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    PropertyMatchFiltering = 5,
    /// Hash-based Filtering using BOB
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    HashbasedFilteringusingBOB = 6,
    /// Hash-based Filtering using IPSX
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    HashbasedFilteringusingIPSX = 7,
    /// Hash-based Filtering using CRC
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    HashbasedFilteringusingCRC = 8,
    /// Flow-state Dependent Intermediate Flow Selection Process
    ///
    /// Reference: [RFC7014](https://datatracker.ietf.org/doc/html/rfc7014)
    FlowstateDependentIntermediateFlowSelectionProcess = 9,
    Unassigned(u16),
}
impl From<flowSelectorAlgorithm> for u16 {
    fn from(value: flowSelectorAlgorithm) -> Self {
        match value {
            flowSelectorAlgorithm::SystematiccountbasedSampling => 1,
            flowSelectorAlgorithm::SystematictimebasedSampling => 2,
            flowSelectorAlgorithm::RandomnoutofNSampling => 3,
            flowSelectorAlgorithm::UniformprobabilisticSampling => 4,
            flowSelectorAlgorithm::PropertyMatchFiltering => 5,
            flowSelectorAlgorithm::HashbasedFilteringusingBOB => 6,
            flowSelectorAlgorithm::HashbasedFilteringusingIPSX => 7,
            flowSelectorAlgorithm::HashbasedFilteringusingCRC => 8,
            flowSelectorAlgorithm::FlowstateDependentIntermediateFlowSelectionProcess => 9,
            flowSelectorAlgorithm::Unassigned(x) => x,
        }
    }
}
impl From<u16> for flowSelectorAlgorithm {
    fn from(value: u16) -> Self {
        match value {
            1 => flowSelectorAlgorithm::SystematiccountbasedSampling,
            2 => flowSelectorAlgorithm::SystematictimebasedSampling,
            3 => flowSelectorAlgorithm::RandomnoutofNSampling,
            4 => flowSelectorAlgorithm::UniformprobabilisticSampling,
            5 => flowSelectorAlgorithm::PropertyMatchFiltering,
            6 => flowSelectorAlgorithm::HashbasedFilteringusingBOB,
            7 => flowSelectorAlgorithm::HashbasedFilteringusingIPSX,
            8 => flowSelectorAlgorithm::HashbasedFilteringusingCRC,
            9 => flowSelectorAlgorithm::FlowstateDependentIntermediateFlowSelectionProcess,
            x => flowSelectorAlgorithm::Unassigned(x),
        }
    }
}

impl HasIE for flowSelectorAlgorithm {
    fn ie(&self) -> IE {
        IE::flowSelectorAlgorithm
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowSelectedOctetDeltaCount(pub u64);

impl HasIE for flowSelectedOctetDeltaCount {
    fn ie(&self) -> IE {
        IE::flowSelectedOctetDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowSelectedPacketDeltaCount(pub u64);

impl HasIE for flowSelectedPacketDeltaCount {
    fn ie(&self) -> IE {
        IE::flowSelectedPacketDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowSelectedFlowDeltaCount(pub u64);

impl HasIE for flowSelectedFlowDeltaCount {
    fn ie(&self) -> IE {
        IE::flowSelectedFlowDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct selectorIDTotalFlowsObserved(pub u64);

impl HasIE for selectorIDTotalFlowsObserved {
    fn ie(&self) -> IE {
        IE::selectorIDTotalFlowsObserved
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct selectorIDTotalFlowsSelected(pub u64);

impl HasIE for selectorIDTotalFlowsSelected {
    fn ie(&self) -> IE {
        IE::selectorIDTotalFlowsSelected
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplingFlowInterval(pub u64);

impl HasIE for samplingFlowInterval {
    fn ie(&self) -> IE {
        IE::samplingFlowInterval
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct samplingFlowSpacing(pub u64);

impl HasIE for samplingFlowSpacing {
    fn ie(&self) -> IE {
        IE::samplingFlowSpacing
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowSamplingTimeInterval(pub u64);

impl HasIE for flowSamplingTimeInterval {
    fn ie(&self) -> IE {
        IE::flowSamplingTimeInterval
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct flowSamplingTimeSpacing(pub u64);

impl HasIE for flowSamplingTimeSpacing {
    fn ie(&self) -> IE {
        IE::flowSamplingTimeSpacing
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct hashFlowDomain(pub u16);

impl HasIE for hashFlowDomain {
    fn ie(&self) -> IE {
        IE::hashFlowDomain
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct transportOctetDeltaCount(pub u64);

impl HasIE for transportOctetDeltaCount {
    fn ie(&self) -> IE {
        IE::transportOctetDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct transportPacketDeltaCount(pub u64);

impl HasIE for transportPacketDeltaCount {
    fn ie(&self) -> IE {
        IE::transportPacketDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct originalExporterIPv4Address(pub std::net::Ipv4Addr);

impl HasIE for originalExporterIPv4Address {
    fn ie(&self) -> IE {
        IE::originalExporterIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct originalExporterIPv6Address(pub std::net::Ipv6Addr);

impl HasIE for originalExporterIPv6Address {
    fn ie(&self) -> IE {
        IE::originalExporterIPv6Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct originalObservationDomainId(pub u32);

impl HasIE for originalObservationDomainId {
    fn ie(&self) -> IE {
        IE::originalObservationDomainId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct intermediateProcessId(pub u32);

impl HasIE for intermediateProcessId {
    fn ie(&self) -> IE {
        IE::intermediateProcessId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ignoredDataRecordTotalCount(pub u64);

impl HasIE for ignoredDataRecordTotalCount {
    fn ie(&self) -> IE {
        IE::ignoredDataRecordTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u16)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum dataLinkFrameType {
    /// IEEE802.3 ETHERNET
    ///
    IEEE8023ETHERNET = 1,
    /// IEEE802.11 MAC Frame format
    ///
    IEEE80211MACFrameformat = 2,
    Unassigned(u16),
}
impl From<dataLinkFrameType> for u16 {
    fn from(value: dataLinkFrameType) -> Self {
        match value {
            dataLinkFrameType::IEEE8023ETHERNET => 1,
            dataLinkFrameType::IEEE80211MACFrameformat => 2,
            dataLinkFrameType::Unassigned(x) => x,
        }
    }
}
impl From<u16> for dataLinkFrameType {
    fn from(value: u16) -> Self {
        match value {
            1 => dataLinkFrameType::IEEE8023ETHERNET,
            2 => dataLinkFrameType::IEEE80211MACFrameformat,
            x => dataLinkFrameType::Unassigned(x),
        }
    }
}

impl HasIE for dataLinkFrameType {
    fn ie(&self) -> IE {
        IE::dataLinkFrameType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct sectionOffset(pub u16);

impl HasIE for sectionOffset {
    fn ie(&self) -> IE {
        IE::sectionOffset
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct sectionExportedOctets(pub u16);

impl HasIE for sectionExportedOctets {
    fn ie(&self) -> IE {
        IE::sectionExportedOctets
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dot1qServiceInstanceTag(pub Vec<u8>);

impl HasIE for dot1qServiceInstanceTag {
    fn ie(&self) -> IE {
        IE::dot1qServiceInstanceTag
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dot1qServiceInstanceId(pub u32);

impl HasIE for dot1qServiceInstanceId {
    fn ie(&self) -> IE {
        IE::dot1qServiceInstanceId
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dot1qServiceInstancePriority(pub u8);

impl HasIE for dot1qServiceInstancePriority {
    fn ie(&self) -> IE {
        IE::dot1qServiceInstancePriority
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dot1qCustomerSourceMacAddress(pub super::MacAddress);

impl HasIE for dot1qCustomerSourceMacAddress {
    fn ie(&self) -> IE {
        IE::dot1qCustomerSourceMacAddress
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct dot1qCustomerDestinationMacAddress(pub super::MacAddress);

impl HasIE for dot1qCustomerDestinationMacAddress {
    fn ie(&self) -> IE {
        IE::dot1qCustomerDestinationMacAddress
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postLayer2OctetDeltaCount(pub u64);

impl HasIE for postLayer2OctetDeltaCount {
    fn ie(&self) -> IE {
        IE::postLayer2OctetDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postMCastLayer2OctetDeltaCount(pub u64);

impl HasIE for postMCastLayer2OctetDeltaCount {
    fn ie(&self) -> IE {
        IE::postMCastLayer2OctetDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postLayer2OctetTotalCount(pub u64);

impl HasIE for postLayer2OctetTotalCount {
    fn ie(&self) -> IE {
        IE::postLayer2OctetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct postMCastLayer2OctetTotalCount(pub u64);

impl HasIE for postMCastLayer2OctetTotalCount {
    fn ie(&self) -> IE {
        IE::postMCastLayer2OctetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct minimumLayer2TotalLength(pub u64);

impl HasIE for minimumLayer2TotalLength {
    fn ie(&self) -> IE {
        IE::minimumLayer2TotalLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maximumLayer2TotalLength(pub u64);

impl HasIE for maximumLayer2TotalLength {
    fn ie(&self) -> IE {
        IE::maximumLayer2TotalLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct droppedLayer2OctetDeltaCount(pub u64);

impl HasIE for droppedLayer2OctetDeltaCount {
    fn ie(&self) -> IE {
        IE::droppedLayer2OctetDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct droppedLayer2OctetTotalCount(pub u64);

impl HasIE for droppedLayer2OctetTotalCount {
    fn ie(&self) -> IE {
        IE::droppedLayer2OctetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ignoredLayer2OctetTotalCount(pub u64);

impl HasIE for ignoredLayer2OctetTotalCount {
    fn ie(&self) -> IE {
        IE::ignoredLayer2OctetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct notSentLayer2OctetTotalCount(pub u64);

impl HasIE for notSentLayer2OctetTotalCount {
    fn ie(&self) -> IE {
        IE::notSentLayer2OctetTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct layer2OctetDeltaSumOfSquares(pub u64);

impl HasIE for layer2OctetDeltaSumOfSquares {
    fn ie(&self) -> IE {
        IE::layer2OctetDeltaSumOfSquares
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct layer2OctetTotalSumOfSquares(pub u64);

impl HasIE for layer2OctetTotalSumOfSquares {
    fn ie(&self) -> IE {
        IE::layer2OctetTotalSumOfSquares
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct layer2FrameDeltaCount(pub u64);

impl HasIE for layer2FrameDeltaCount {
    fn ie(&self) -> IE {
        IE::layer2FrameDeltaCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct layer2FrameTotalCount(pub u64);

impl HasIE for layer2FrameTotalCount {
    fn ie(&self) -> IE {
        IE::layer2FrameTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct pseudoWireDestinationIPv4Address(pub std::net::Ipv4Addr);

impl HasIE for pseudoWireDestinationIPv4Address {
    fn ie(&self) -> IE {
        IE::pseudoWireDestinationIPv4Address
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ignoredLayer2FrameTotalCount(pub u64);

impl HasIE for ignoredLayer2FrameTotalCount {
    fn ie(&self) -> IE {
        IE::ignoredLayer2FrameTotalCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectValueInteger(pub i32);

impl HasIE for mibObjectValueInteger {
    fn ie(&self) -> IE {
        IE::mibObjectValueInteger
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectValueOctetString(pub Vec<u8>);

impl HasIE for mibObjectValueOctetString {
    fn ie(&self) -> IE {
        IE::mibObjectValueOctetString
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectValueOID(pub Vec<u8>);

impl HasIE for mibObjectValueOID {
    fn ie(&self) -> IE {
        IE::mibObjectValueOID
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectValueBits(pub Vec<u8>);

impl HasIE for mibObjectValueBits {
    fn ie(&self) -> IE {
        IE::mibObjectValueBits
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectValueIPAddress(pub std::net::Ipv4Addr);

impl HasIE for mibObjectValueIPAddress {
    fn ie(&self) -> IE {
        IE::mibObjectValueIPAddress
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectValueCounter(pub u64);

impl HasIE for mibObjectValueCounter {
    fn ie(&self) -> IE {
        IE::mibObjectValueCounter
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectValueGauge(pub u32);

impl HasIE for mibObjectValueGauge {
    fn ie(&self) -> IE {
        IE::mibObjectValueGauge
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectValueTimeTicks(pub u32);

impl HasIE for mibObjectValueTimeTicks {
    fn ie(&self) -> IE {
        IE::mibObjectValueTimeTicks
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectValueUnsigned(pub u32);

impl HasIE for mibObjectValueUnsigned {
    fn ie(&self) -> IE {
        IE::mibObjectValueUnsigned
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectValueTable(pub Vec<u8>);

impl HasIE for mibObjectValueTable {
    fn ie(&self) -> IE {
        IE::mibObjectValueTable
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectValueRow(pub Vec<u8>);

impl HasIE for mibObjectValueRow {
    fn ie(&self) -> IE {
        IE::mibObjectValueRow
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectIdentifier(pub Vec<u8>);

impl HasIE for mibObjectIdentifier {
    fn ie(&self) -> IE {
        IE::mibObjectIdentifier
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibSubIdentifier(pub u32);

impl HasIE for mibSubIdentifier {
    fn ie(&self) -> IE {
        IE::mibSubIdentifier
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibIndexIndicator(pub u64);

impl HasIE for mibIndexIndicator {
    fn ie(&self) -> IE {
        IE::mibIndexIndicator
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum mibCaptureTimeSemantics {
    /// 
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    undefined = 0,
    /// The value for the MIB object is captured
    /// from the MIB when the Flow is first observed
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    begin = 1,
    /// The value for the MIB object is captured
    /// from the MIB when the Flow ends
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    end = 2,
    /// The value for the MIB object is captured
    /// from the MIB at export time
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    export = 3,
    /// The value for the MIB object is an average
    /// of multiple captures from the MIB over the observed
    /// life of the Flow
    ///
    /// Reference: [RFC8038](https://datatracker.ietf.org/doc/html/rfc8038)
    average = 4,
    Unassigned(u8),
}
impl From<mibCaptureTimeSemantics> for u8 {
    fn from(value: mibCaptureTimeSemantics) -> Self {
        match value {
            mibCaptureTimeSemantics::undefined => 0,
            mibCaptureTimeSemantics::begin => 1,
            mibCaptureTimeSemantics::end => 2,
            mibCaptureTimeSemantics::export => 3,
            mibCaptureTimeSemantics::average => 4,
            mibCaptureTimeSemantics::Unassigned(x) => x,
        }
    }
}
impl From<u8> for mibCaptureTimeSemantics {
    fn from(value: u8) -> Self {
        match value {
            0 => mibCaptureTimeSemantics::undefined,
            1 => mibCaptureTimeSemantics::begin,
            2 => mibCaptureTimeSemantics::end,
            3 => mibCaptureTimeSemantics::export,
            4 => mibCaptureTimeSemantics::average,
            x => mibCaptureTimeSemantics::Unassigned(x),
        }
    }
}

impl HasIE for mibCaptureTimeSemantics {
    fn ie(&self) -> IE {
        IE::mibCaptureTimeSemantics
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibContextEngineID(pub Vec<u8>);

impl HasIE for mibContextEngineID {
    fn ie(&self) -> IE {
        IE::mibContextEngineID
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibContextName(pub String);

impl HasIE for mibContextName {
    fn ie(&self) -> IE {
        IE::mibContextName
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectName(pub String);

impl HasIE for mibObjectName {
    fn ie(&self) -> IE {
        IE::mibObjectName
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectDescription(pub String);

impl HasIE for mibObjectDescription {
    fn ie(&self) -> IE {
        IE::mibObjectDescription
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibObjectSyntax(pub String);

impl HasIE for mibObjectSyntax {
    fn ie(&self) -> IE {
        IE::mibObjectSyntax
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mibModuleName(pub String);

impl HasIE for mibModuleName {
    fn ie(&self) -> IE {
        IE::mibModuleName
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mobileIMSI(pub String);

impl HasIE for mobileIMSI {
    fn ie(&self) -> IE {
        IE::mobileIMSI
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct mobileMSISDN(pub String);

impl HasIE for mobileMSISDN {
    fn ie(&self) -> IE {
        IE::mobileMSISDN
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct httpStatusCode(pub u16);

impl HasIE for httpStatusCode {
    fn ie(&self) -> IE {
        IE::httpStatusCode
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct sourceTransportPortsLimit(pub u16);

impl HasIE for sourceTransportPortsLimit {
    fn ie(&self) -> IE {
        IE::sourceTransportPortsLimit
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct httpRequestMethod(pub String);

impl HasIE for httpRequestMethod {
    fn ie(&self) -> IE {
        IE::httpRequestMethod
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct httpRequestHost(pub String);

impl HasIE for httpRequestHost {
    fn ie(&self) -> IE {
        IE::httpRequestHost
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct httpRequestTarget(pub String);

impl HasIE for httpRequestTarget {
    fn ie(&self) -> IE {
        IE::httpRequestTarget
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct httpMessageVersion(pub String);

impl HasIE for httpMessageVersion {
    fn ie(&self) -> IE {
        IE::httpMessageVersion
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct natInstanceID(pub u32);

impl HasIE for natInstanceID {
    fn ie(&self) -> IE {
        IE::natInstanceID
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct internalAddressRealm(pub Vec<u8>);

impl HasIE for internalAddressRealm {
    fn ie(&self) -> IE {
        IE::internalAddressRealm
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct externalAddressRealm(pub Vec<u8>);

impl HasIE for externalAddressRealm {
    fn ie(&self) -> IE {
        IE::externalAddressRealm
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum natQuotaExceededEvent {
    /// Reserved
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Reserved0 = 0,
    /// Maximum session entries
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Maximumsessionentries = 1,
    /// Maximum BIB entries
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    MaximumBIBentries = 2,
    /// Maximum entries per user
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Maximumentriesperuser = 3,
    /// Maximum active hosts or subscribers
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Maximumactivehostsorsubscribers = 4,
    /// Maximum fragments pending reassembly
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Maximumfragmentspendingreassembly = 5,
    Unassigned(u32),
}
impl From<natQuotaExceededEvent> for u32 {
    fn from(value: natQuotaExceededEvent) -> Self {
        match value {
            natQuotaExceededEvent::Reserved0 => 0,
            natQuotaExceededEvent::Maximumsessionentries => 1,
            natQuotaExceededEvent::MaximumBIBentries => 2,
            natQuotaExceededEvent::Maximumentriesperuser => 3,
            natQuotaExceededEvent::Maximumactivehostsorsubscribers => 4,
            natQuotaExceededEvent::Maximumfragmentspendingreassembly => 5,
            natQuotaExceededEvent::Unassigned(x) => x,
        }
    }
}
impl From<u32> for natQuotaExceededEvent {
    fn from(value: u32) -> Self {
        match value {
            0 => natQuotaExceededEvent::Reserved0,
            1 => natQuotaExceededEvent::Maximumsessionentries,
            2 => natQuotaExceededEvent::MaximumBIBentries,
            3 => natQuotaExceededEvent::Maximumentriesperuser,
            4 => natQuotaExceededEvent::Maximumactivehostsorsubscribers,
            5 => natQuotaExceededEvent::Maximumfragmentspendingreassembly,
            x => natQuotaExceededEvent::Unassigned(x),
        }
    }
}

impl HasIE for natQuotaExceededEvent {
    fn ie(&self) -> IE {
        IE::natQuotaExceededEvent
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u32)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum natThresholdEvent {
    /// Reserved
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Reserved0 = 0,
    /// Address pool high threshold event
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Addresspoolhighthresholdevent = 1,
    /// Address pool low threshold event
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Addresspoollowthresholdevent = 2,
    /// Address and port mapping high threshold event
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Addressandportmappinghighthresholdevent = 3,
    /// Address and port mapping per user high threshold event
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    Addressandportmappingperuserhighthresholdevent = 4,
    /// Global Address mapping high threshold event
    ///
    /// Reference: [RFC8158](https://datatracker.ietf.org/doc/html/rfc8158)
    GlobalAddressmappinghighthresholdevent = 5,
    Unassigned(u32),
}
impl From<natThresholdEvent> for u32 {
    fn from(value: natThresholdEvent) -> Self {
        match value {
            natThresholdEvent::Reserved0 => 0,
            natThresholdEvent::Addresspoolhighthresholdevent => 1,
            natThresholdEvent::Addresspoollowthresholdevent => 2,
            natThresholdEvent::Addressandportmappinghighthresholdevent => 3,
            natThresholdEvent::Addressandportmappingperuserhighthresholdevent => 4,
            natThresholdEvent::GlobalAddressmappinghighthresholdevent => 5,
            natThresholdEvent::Unassigned(x) => x,
        }
    }
}
impl From<u32> for natThresholdEvent {
    fn from(value: u32) -> Self {
        match value {
            0 => natThresholdEvent::Reserved0,
            1 => natThresholdEvent::Addresspoolhighthresholdevent,
            2 => natThresholdEvent::Addresspoollowthresholdevent,
            3 => natThresholdEvent::Addressandportmappinghighthresholdevent,
            4 => natThresholdEvent::Addressandportmappingperuserhighthresholdevent,
            5 => natThresholdEvent::GlobalAddressmappinghighthresholdevent,
            x => natThresholdEvent::Unassigned(x),
        }
    }
}

impl HasIE for natThresholdEvent {
    fn ie(&self) -> IE {
        IE::natThresholdEvent
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct httpUserAgent(pub String);

impl HasIE for httpUserAgent {
    fn ie(&self) -> IE {
        IE::httpUserAgent
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct httpContentType(pub String);

impl HasIE for httpContentType {
    fn ie(&self) -> IE {
        IE::httpContentType
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct httpReasonPhrase(pub String);

impl HasIE for httpReasonPhrase {
    fn ie(&self) -> IE {
        IE::httpReasonPhrase
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maxSessionEntries(pub u32);

impl HasIE for maxSessionEntries {
    fn ie(&self) -> IE {
        IE::maxSessionEntries
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maxBIBEntries(pub u32);

impl HasIE for maxBIBEntries {
    fn ie(&self) -> IE {
        IE::maxBIBEntries
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maxEntriesPerUser(pub u32);

impl HasIE for maxEntriesPerUser {
    fn ie(&self) -> IE {
        IE::maxEntriesPerUser
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maxSubscribers(pub u32);

impl HasIE for maxSubscribers {
    fn ie(&self) -> IE {
        IE::maxSubscribers
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct maxFragmentsPendingReassembly(pub u32);

impl HasIE for maxFragmentsPendingReassembly {
    fn ie(&self) -> IE {
        IE::maxFragmentsPendingReassembly
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct addressPoolHighThreshold(pub u32);

impl HasIE for addressPoolHighThreshold {
    fn ie(&self) -> IE {
        IE::addressPoolHighThreshold
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct addressPoolLowThreshold(pub u32);

impl HasIE for addressPoolLowThreshold {
    fn ie(&self) -> IE {
        IE::addressPoolLowThreshold
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct addressPortMappingHighThreshold(pub u32);

impl HasIE for addressPortMappingHighThreshold {
    fn ie(&self) -> IE {
        IE::addressPortMappingHighThreshold
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct addressPortMappingLowThreshold(pub u32);

impl HasIE for addressPortMappingLowThreshold {
    fn ie(&self) -> IE {
        IE::addressPortMappingLowThreshold
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct addressPortMappingPerUserHighThreshold(pub u32);

impl HasIE for addressPortMappingPerUserHighThreshold {
    fn ie(&self) -> IE {
        IE::addressPortMappingPerUserHighThreshold
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct globalAddressMappingHighThreshold(pub u32);

impl HasIE for globalAddressMappingHighThreshold {
    fn ie(&self) -> IE {
        IE::globalAddressMappingHighThreshold
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct vpnIdentifier(pub Vec<u8>);

impl HasIE for vpnIdentifier {
    fn ie(&self) -> IE {
        IE::vpnIdentifier
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpCommunity(pub u32);

impl HasIE for bgpCommunity {
    fn ie(&self) -> IE {
        IE::bgpCommunity
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpSourceCommunityList(pub Vec<u8>);

impl HasIE for bgpSourceCommunityList {
    fn ie(&self) -> IE {
        IE::bgpSourceCommunityList
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpDestinationCommunityList(pub Vec<u8>);

impl HasIE for bgpDestinationCommunityList {
    fn ie(&self) -> IE {
        IE::bgpDestinationCommunityList
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpExtendedCommunity(pub Vec<u8>);

impl HasIE for bgpExtendedCommunity {
    fn ie(&self) -> IE {
        IE::bgpExtendedCommunity
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpSourceExtendedCommunityList(pub Vec<u8>);

impl HasIE for bgpSourceExtendedCommunityList {
    fn ie(&self) -> IE {
        IE::bgpSourceExtendedCommunityList
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpDestinationExtendedCommunityList(pub Vec<u8>);

impl HasIE for bgpDestinationExtendedCommunityList {
    fn ie(&self) -> IE {
        IE::bgpDestinationExtendedCommunityList
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpLargeCommunity(pub Vec<u8>);

impl HasIE for bgpLargeCommunity {
    fn ie(&self) -> IE {
        IE::bgpLargeCommunity
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpSourceLargeCommunityList(pub Vec<u8>);

impl HasIE for bgpSourceLargeCommunityList {
    fn ie(&self) -> IE {
        IE::bgpSourceLargeCommunityList
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpDestinationLargeCommunityList(pub Vec<u8>);

impl HasIE for bgpDestinationLargeCommunityList {
    fn ie(&self) -> IE {
        IE::bgpDestinationLargeCommunityList
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct srhFlagsIPv6(pub u8);

impl HasIE for srhFlagsIPv6 {
    fn ie(&self) -> IE {
        IE::srhFlagsIPv6
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct srhTagIPv6(pub u16);

impl HasIE for srhTagIPv6 {
    fn ie(&self) -> IE {
        IE::srhTagIPv6
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct srhSegmentIPv6(pub std::net::Ipv6Addr);

impl HasIE for srhSegmentIPv6 {
    fn ie(&self) -> IE {
        IE::srhSegmentIPv6
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct srhActiveSegmentIPv6(pub std::net::Ipv6Addr);

impl HasIE for srhActiveSegmentIPv6 {
    fn ie(&self) -> IE {
        IE::srhActiveSegmentIPv6
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct srhSegmentIPv6BasicList(pub Vec<u8>);

impl HasIE for srhSegmentIPv6BasicList {
    fn ie(&self) -> IE {
        IE::srhSegmentIPv6BasicList
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct srhSegmentIPv6ListSection(pub Vec<u8>);

impl HasIE for srhSegmentIPv6ListSection {
    fn ie(&self) -> IE {
        IE::srhSegmentIPv6ListSection
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct srhSegmentsIPv6Left(pub u8);

impl HasIE for srhSegmentsIPv6Left {
    fn ie(&self) -> IE {
        IE::srhSegmentsIPv6Left
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct srhIPv6Section(pub Vec<u8>);

impl HasIE for srhIPv6Section {
    fn ie(&self) -> IE {
        IE::srhIPv6Section
   }
}

#[allow(non_camel_case_types)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum srhIPv6ActiveSegmentType {
    /// Unknown
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    Unknown = 0,
    /// Segment Routing Policy
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    /// Reference: [RFC9256](https://datatracker.ietf.org/doc/html/rfc9256)
    SegmentRoutingPolicy = 1,
    /// Path Computation Element
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    /// Reference: [RFC Draft RFC-IETF-PCE-SEGMENT-ROUTING-IPV6-25](https://datatracker.ietf.org/doc/html/RFC-ietf-pce-segment-routing-ipv6-25)
    PathComputationElement = 2,
    /// OSPFv3 Segment Routing
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    /// Reference: [RFC9513](https://datatracker.ietf.org/doc/html/rfc9513)
    OSPFv3SegmentRouting = 3,
    /// IS-IS Segment Routing
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    /// Reference: [RFC9352](https://datatracker.ietf.org/doc/html/rfc9352)
    ISISSegmentRouting = 4,
    /// BGP Segment Routing Prefix-SID
    ///
    /// Reference: [RFC9487](https://datatracker.ietf.org/doc/html/rfc9487)
    /// Reference: [RFC8669](https://datatracker.ietf.org/doc/html/rfc8669)
    BGPSegmentRoutingPrefixSID = 5,
    Unassigned(u8),
}
impl From<srhIPv6ActiveSegmentType> for u8 {
    fn from(value: srhIPv6ActiveSegmentType) -> Self {
        match value {
            srhIPv6ActiveSegmentType::Unknown => 0,
            srhIPv6ActiveSegmentType::SegmentRoutingPolicy => 1,
            srhIPv6ActiveSegmentType::PathComputationElement => 2,
            srhIPv6ActiveSegmentType::OSPFv3SegmentRouting => 3,
            srhIPv6ActiveSegmentType::ISISSegmentRouting => 4,
            srhIPv6ActiveSegmentType::BGPSegmentRoutingPrefixSID => 5,
            srhIPv6ActiveSegmentType::Unassigned(x) => x,
        }
    }
}
impl From<u8> for srhIPv6ActiveSegmentType {
    fn from(value: u8) -> Self {
        match value {
            0 => srhIPv6ActiveSegmentType::Unknown,
            1 => srhIPv6ActiveSegmentType::SegmentRoutingPolicy,
            2 => srhIPv6ActiveSegmentType::PathComputationElement,
            3 => srhIPv6ActiveSegmentType::OSPFv3SegmentRouting,
            4 => srhIPv6ActiveSegmentType::ISISSegmentRouting,
            5 => srhIPv6ActiveSegmentType::BGPSegmentRoutingPrefixSID,
            x => srhIPv6ActiveSegmentType::Unassigned(x),
        }
    }
}

impl HasIE for srhIPv6ActiveSegmentType {
    fn ie(&self) -> IE {
        IE::srhIPv6ActiveSegmentType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct srhSegmentIPv6LocatorLength(pub u8);

impl HasIE for srhSegmentIPv6LocatorLength {
    fn ie(&self) -> IE {
        IE::srhSegmentIPv6LocatorLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct srhSegmentIPv6EndpointBehavior(pub u16);

impl HasIE for srhSegmentIPv6EndpointBehavior {
    fn ie(&self) -> IE {
        IE::srhSegmentIPv6EndpointBehavior
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct transportChecksum(pub u16);

impl HasIE for transportChecksum {
    fn ie(&self) -> IE {
        IE::transportChecksum
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct icmpHeaderPacketSection(pub Vec<u8>);

impl HasIE for icmpHeaderPacketSection {
    fn ie(&self) -> IE {
        IE::icmpHeaderPacketSection
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct gtpuFlags(pub u8);

impl HasIE for gtpuFlags {
    fn ie(&self) -> IE {
        IE::gtpuFlags
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct gtpuMsgType(pub u8);

impl HasIE for gtpuMsgType {
    fn ie(&self) -> IE {
        IE::gtpuMsgType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct gtpuTEid(pub u32);

impl HasIE for gtpuTEid {
    fn ie(&self) -> IE {
        IE::gtpuTEid
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct gtpuSequenceNum(pub u16);

impl HasIE for gtpuSequenceNum {
    fn ie(&self) -> IE {
        IE::gtpuSequenceNum
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct gtpuQFI(pub u8);

impl HasIE for gtpuQFI {
    fn ie(&self) -> IE {
        IE::gtpuQFI
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct gtpuPduType(pub u8);

impl HasIE for gtpuPduType {
    fn ie(&self) -> IE {
        IE::gtpuPduType
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpSourceAsPathList(pub Vec<u8>);

impl HasIE for bgpSourceAsPathList {
    fn ie(&self) -> IE {
        IE::bgpSourceAsPathList
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct bgpDestinationAsPathList(pub Vec<u8>);

impl HasIE for bgpDestinationAsPathList {
    fn ie(&self) -> IE {
        IE::bgpDestinationAsPathList
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipv6ExtensionHeaderType(pub u8);

impl HasIE for ipv6ExtensionHeaderType {
    fn ie(&self) -> IE {
        IE::ipv6ExtensionHeaderType
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipv6ExtensionHeaderCount(pub u8);

impl HasIE for ipv6ExtensionHeaderCount {
    fn ie(&self) -> IE {
        IE::ipv6ExtensionHeaderCount
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipv6ExtensionHeadersFull(pub [u8; 32]);

impl HasIE for ipv6ExtensionHeadersFull {
    fn ie(&self) -> IE {
        IE::ipv6ExtensionHeadersFull
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipv6ExtensionHeaderTypeCountList(pub Vec<u8>);

impl HasIE for ipv6ExtensionHeaderTypeCountList {
    fn ie(&self) -> IE {
        IE::ipv6ExtensionHeaderTypeCountList
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipv6ExtensionHeadersLimit(pub bool);

impl HasIE for ipv6ExtensionHeadersLimit {
    fn ie(&self) -> IE {
        IE::ipv6ExtensionHeadersLimit
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipv6ExtensionHeadersChainLength(pub u32);

impl HasIE for ipv6ExtensionHeadersChainLength {
    fn ie(&self) -> IE {
        IE::ipv6ExtensionHeadersChainLength
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct ipv6ExtensionHeaderChainLengthList(pub Vec<u8>);

impl HasIE for ipv6ExtensionHeaderChainLengthList {
    fn ie(&self) -> IE {
        IE::ipv6ExtensionHeaderChainLengthList
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpOptionsFull(pub [u8; 32]);

impl HasIE for tcpOptionsFull {
    fn ie(&self) -> IE {
        IE::tcpOptionsFull
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpSharedOptionExID16(pub u16);

impl HasIE for tcpSharedOptionExID16 {
    fn ie(&self) -> IE {
        IE::tcpSharedOptionExID16
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpSharedOptionExID32(pub u32);

impl HasIE for tcpSharedOptionExID32 {
    fn ie(&self) -> IE {
        IE::tcpSharedOptionExID32
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpSharedOptionExID16List(pub Vec<u8>);

impl HasIE for tcpSharedOptionExID16List {
    fn ie(&self) -> IE {
        IE::tcpSharedOptionExID16List
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct tcpSharedOptionExID32List(pub Vec<u8>);

impl HasIE for tcpSharedOptionExID32List {
    fn ie(&self) -> IE {
        IE::tcpSharedOptionExID32List
   }
}

pub mod nokia {include!(concat!(env!("OUT_DIR"), "/nokia_generated.rs"));}

pub mod netgauze {include!(concat!(env!("OUT_DIR"), "/netgauze_generated.rs"));}

pub mod cisco {include!(concat!(env!("OUT_DIR"), "/cisco_generated.rs"));}

pub mod vmware {include!(concat!(env!("OUT_DIR"), "/vmware_generated.rs"));}

