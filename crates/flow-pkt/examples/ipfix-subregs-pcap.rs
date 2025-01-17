use std::{collections::HashMap, io::Cursor, net::Ipv4Addr};

use chrono::{TimeZone, Utc};

use netgauze_flow_pkt::{ie, ipfix::*, DataSetId, FieldSpecifier};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePduWithOneInput};

use netgauze_flow_pkt::pcap::save_buf_in_pcap;

fn main() {
    // Cache to share the templates for decoding data packets
    let mut templates_map = HashMap::new();

    // IPFIX template packet
    let ipfix_template = IpfixPacket::new(
        Utc.with_ymd_and_hms(2024, 7, 08, 10, 0, 0).unwrap(),
        0,
        0,
        vec![Set::Template(vec![TemplateRecord::new(
            400,
            vec![
                FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::sourceTransportPort, 2).unwrap(),
                FieldSpecifier::new(ie::IE::destinationTransportPort, 2).unwrap(),
                FieldSpecifier::new(ie::IE::flowId, 8).unwrap(),
                FieldSpecifier::new(ie::IE::protocolIdentifier, 1).unwrap(),
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::packetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::mplsTopLabelType, 1).unwrap(),
                FieldSpecifier::new(ie::IE::forwardingStatus, 4).unwrap(),
                FieldSpecifier::new(ie::IE::classificationEngineId, 1).unwrap(),
                FieldSpecifier::new(ie::IE::flowEndReason, 1).unwrap(),
                FieldSpecifier::new(ie::IE::natOriginatingAddressRealm, 1).unwrap(),
                FieldSpecifier::new(ie::IE::firewallEvent, 1).unwrap(),
                FieldSpecifier::new(ie::IE::biflowDirection, 1).unwrap(),
                FieldSpecifier::new(ie::IE::observationPointType, 1).unwrap(),
                FieldSpecifier::new(ie::IE::anonymizationTechnique, 2).unwrap(),
                FieldSpecifier::new(ie::IE::natType, 1).unwrap(),
                FieldSpecifier::new(ie::IE::valueDistributionMethod, 1).unwrap(),
                FieldSpecifier::new(ie::IE::flowSelectorAlgorithm, 2).unwrap(),
                FieldSpecifier::new(ie::IE::dataLinkFrameType, 2).unwrap(),
                FieldSpecifier::new(ie::IE::mibCaptureTimeSemantics, 1).unwrap(),
                FieldSpecifier::new(ie::IE::natQuotaExceededEvent, 1).unwrap(),
                FieldSpecifier::new(ie::IE::natThresholdEvent, 1).unwrap(),
                FieldSpecifier::new(ie::IE::srhIPv6ActiveSegmentType, 1).unwrap(),
            ],
        )])],
    );

    println!(
        "JSON representation of IPFIX Template packet: {}",
        serde_json::to_string(&ipfix_template).unwrap()
    );
    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    ipfix_template.write(&mut cursor, None).unwrap();

    let buf_str = buf
        .iter()
        .map(|&byte| byte.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    dbg!(format!("[{}]", buf_str));

    // Deserialize the message from binary format (this will also add the Template
    // to templates_map, otherwise the packet will be generated with all the
    // default lengths)
    IpfixPacket::from_wire(Span::new(&buf), &mut templates_map).unwrap();

    let mut ipfix_packets = vec![];
    ipfix_packets.push(buf.clone());

    // IPFIX data packet
    let ipfix_data = IpfixPacket::new(
        Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap(),
        0,
        0,
        vec![Set::Data {
            id: DataSetId::new(400).unwrap(),
            records: vec![DataRecord::new(
                vec![],
                vec![
                    ie::Field::sourceIPv4Address(ie::sourceIPv4Address(Ipv4Addr::new(
                        10, 100, 0, 1,
                    ))),
                    ie::Field::destinationIPv4Address(ie::destinationIPv4Address(Ipv4Addr::new(
                        10, 100, 0, 151,
                    ))),
                    ie::Field::sourceTransportPort(ie::sourceTransportPort(10004)),
                    ie::Field::destinationTransportPort(ie::destinationTransportPort(1)),
                    ie::Field::flowId(ie::flowId(10101010)),
                    ie::Field::protocolIdentifier(ie::protocolIdentifier::UDPLite),
                    ie::Field::octetDeltaCount(ie::octetDeltaCount(1200)),
                    ie::Field::packetDeltaCount(ie::packetDeltaCount(1)),
                    ie::Field::mplsTopLabelType(ie::mplsTopLabelType::Unknown),
                    ie::Field::forwardingStatus(ie::forwardingStatus::Dropped(
                        ie::forwardingStatusDroppedReason::Badheaderchecksum,
                    )),
                    ie::Field::classificationEngineId(ie::classificationEngineId::ETHERTYPE),
                    ie::Field::flowEndReason(ie::flowEndReason::lackofresources),
                    ie::Field::natOriginatingAddressRealm(
                        ie::natOriginatingAddressRealm::Unassigned(15),
                    ),
                    ie::Field::firewallEvent(ie::firewallEvent::FlowDeleted),
                    ie::Field::biflowDirection(ie::biflowDirection::perimeter),
                    ie::Field::observationPointType(ie::observationPointType::Physicalport),
                    ie::Field::anonymizationTechnique(
                        ie::anonymizationTechnique::StructuredPermutation,
                    ),
                    ie::Field::natType(ie::natType::NAT66translated),
                    ie::Field::valueDistributionMethod(
                        ie::valueDistributionMethod::SimpleUniformDistribution,
                    ),
                    ie::Field::flowSelectorAlgorithm(
                        ie::flowSelectorAlgorithm::UniformprobabilisticSampling,
                    ),
                    ie::Field::dataLinkFrameType(ie::dataLinkFrameType::Unassigned(10)),
                    ie::Field::mibCaptureTimeSemantics(ie::mibCaptureTimeSemantics::average),
                    ie::Field::natQuotaExceededEvent(
                        ie::natQuotaExceededEvent::Maximumactivehostsorsubscribers,
                    ),
                    ie::Field::natThresholdEvent(
                        ie::natThresholdEvent::Addresspoolhighthresholdevent,
                    ),
                    ie::Field::srhIPv6ActiveSegmentType(
                        ie::srhIPv6ActiveSegmentType::BGPSegmentRoutingPrefixSID,
                    ),
                ],
            )],
        }],
    );

    println!(
        "JSON representation of IPFIX Data packet: {}",
        serde_json::to_string(&ipfix_data).unwrap()
    );

    let mut buf: Vec<u8> = vec![];
    let mut cursor = Cursor::new(&mut buf);
    ipfix_data
        .write(&mut cursor, Some(&templates_map))
        .unwrap();

    let buf_str = buf
        .iter()
        .map(|&byte| byte.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    dbg!(format!("[{}]", buf_str));

    ipfix_packets.push(buf.clone());
    save_buf_in_pcap("flow-subregs-test.pcap", &ipfix_packets);
}
