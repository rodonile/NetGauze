use std::{collections::HashMap, io::Cursor, net::Ipv4Addr};

use chrono::{TimeZone, Utc};

use netgauze_flow_pkt::{ie, ie::*, ipfix::*, DataSetId, FieldSpecifier};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePduWithOneInput};

use netgauze_flow_pkt::pcap::save_buf_in_pcap;

fn main() {
    // Cache to share the templates for decoding data packets
    let mut templates_map = HashMap::new();

    // IPFIX template packet
    let ipfix_template = IpfixPacket::new(
        Utc.with_ymd_and_hms(2024, 6, 20, 14, 0, 0).unwrap(),
        0,
        0,
        vec![Set::Template(vec![TemplateRecord::new(
            400,
            vec![
                FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::sourceTransportPort, 2).unwrap(),
                FieldSpecifier::new(ie::IE::destinationTransportPort, 2).unwrap(),
                FieldSpecifier::new(ie::IE::postNATSourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::postNAPTSourceTransportPort, 2).unwrap(),
                FieldSpecifier::new(ie::IE::flowId, 8).unwrap(),
                FieldSpecifier::new(ie::IE::protocolIdentifier, 1).unwrap(),
                FieldSpecifier::new(ie::IE::engineType, 1).unwrap(),
                FieldSpecifier::new(ie::IE::Nokia(nokia::IE::aluInsideServiceId), 2).unwrap(),
                FieldSpecifier::new(ie::IE::Nokia(nokia::IE::aluOutsideServiceId), 2).unwrap(),
                FieldSpecifier::new(ie::IE::Nokia(nokia::IE::aluNatSubString), 65535).unwrap(),
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::packetDeltaCount, 4).unwrap(),
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

    // Deserialize the message from binary format (to add the Template to
    // templates_map) Otherwise the packet will be serialized with all the
    // default lengths (when .write is called on an IPFIX data packet),
    // which could be fine as well but we need to be aware about it!!
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
                    ie::Field::postNATSourceIPv4Address(ie::postNATSourceIPv4Address(
                        Ipv4Addr::new(8, 8, 8, 8),
                    )),
                    ie::Field::postNAPTSourceTransportPort(ie::postNAPTSourceTransportPort(8881)),
                    ie::Field::flowId(ie::flowId(10101010)),
                    ie::Field::protocolIdentifier(ie::protocolIdentifier::ICMP),
                    ie::Field::engineType(ie::engineType(0)),
                    ie::Field::Nokia(nokia::Field::aluInsideServiceId(nokia::aluInsideServiceId(
                        1,
                    ))),
                    ie::Field::Nokia(nokia::Field::aluOutsideServiceId(
                        nokia::aluOutsideServiceId(15),
                    )),
                    ie::Field::Nokia(nokia::Field::aluNatSubString(nokia::aluNatSubString(
                        String::from("LSN-Host@10.10.10.101"),
                    ))),
                    ie::Field::octetDeltaCount(ie::octetDeltaCount(1200)),
                    ie::Field::packetDeltaCount(ie::packetDeltaCount(1)),
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
        .write(&mut cursor, Some(&templates_map)) // IMPORTANT: if templates_map empty, we can still write a packet, just will assume default
        // length for all fields!
        .unwrap();

    let buf_str = buf
        .iter()
        .map(|&byte| byte.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    dbg!(format!("[{}]", buf_str));

    ipfix_packets.push(buf.clone());
    save_buf_in_pcap("flow-nokia-test.pcap", &ipfix_packets);
}
