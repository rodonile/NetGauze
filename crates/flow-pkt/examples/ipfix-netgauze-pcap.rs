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
        Utc.with_ymd_and_hms(2023, 3, 4, 12, 0, 0).unwrap(),
        3812,
        0,
        vec![Set::Template(vec![TemplateRecord::new(
            307,
            vec![
                FieldSpecifier::new(ie::IE::sourceIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::destinationIPv4Address, 4).unwrap(),
                FieldSpecifier::new(ie::IE::octetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::packetDeltaCount, 4).unwrap(),
                FieldSpecifier::new(ie::IE::NetGauze(netgauze::IE::peerIPv4Address), 4).unwrap(),
                FieldSpecifier::new(ie::IE::NetGauze(netgauze::IE::collectorHostname), 65535).unwrap(),
                FieldSpecifier::new(ie::IE::NetGauze(netgauze::IE::collectorLocation), 65535)
                    .unwrap(),
                FieldSpecifier::new(ie::IE::NetGauze(netgauze::IE::isRenormalized), 1).unwrap(),
                FieldSpecifier::new(ie::IE::NetGauze(netgauze::IE::samplingInfoOrigin), 65535)
                    .unwrap(),
                FieldSpecifier::new(ie::IE::Cisco(cisco::IE::connectionId), 4).unwrap(),
                FieldSpecifier::new(ie::IE::Cisco(cisco::IE::applicationHttpUriStatistics), 65535)
                    .unwrap(),
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

    println!("ipfix template: {:?}", buf);

    let mut ipfix_packets = vec![];
    ipfix_packets.push(buf.clone());

    // Deserialize the message from binary format
    let (_, msg_back) = IpfixPacket::from_wire(
        Span::new(&buf),
        &mut templates_map
    ).unwrap();
    assert_eq!(ipfix_template, msg_back);

// IPFIX data packet
let ipfix_data = IpfixPacket::new(
        Utc.with_ymd_and_hms(2023, 3, 4, 12, 0, 1).unwrap(),
        3812,
        0,
        vec![Set::Data {
                id: DataSetId::new(307).unwrap(),
                records: vec![DataRecord::new(
                        vec![],
                        vec![
                                ie::Field::sourceIPv4Address(ie::sourceIPv4Address(Ipv4Addr::new(70, 1, 115, 1))),
                                ie::Field::destinationIPv4Address(ie::destinationIPv4Address(Ipv4Addr::new(50, 0, 71, 1))),
                                ie::Field::octetDeltaCount(ie::octetDeltaCount(1312)),
                                ie::Field::packetDeltaCount(ie::packetDeltaCount(9)),
                                ie::Field::NetGauze(netgauze::Field::peerIPv4Address(
                                        netgauze::peerIPv4Address(Ipv4Addr::new(100, 105, 31, 1)),
                                )),
                                ie::Field::NetGauze(netgauze::Field::collectorHostname(
                                        netgauze::collectorHostname(String::from("Leonardo")),
                                )),
                                ie::Field::NetGauze(netgauze::Field::collectorLocation(
                                        netgauze::collectorLocation(String::from("taarole8-rocky8 VM")),
                                )),
                                ie::Field::NetGauze(netgauze::Field::isRenormalized(
                                        netgauze::isRenormalized(true),
                                )),
                                ie::Field::NetGauze(netgauze::Field::samplingInfoOrigin(
                                        netgauze::samplingInfoOrigin(String::from("flow_option")),
                                )),
                                ie::Field::Cisco(cisco::Field::connectionId(cisco::connectionId(123456789))),
                                ie::Field::Cisco(cisco::Field::applicationHttpUriStatistics(
                                        cisco::applicationHttpUriStatistics(String::from("http://www.example.com")),
                                )),
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

    println!("ipfix data: {:?}", buf);

    ipfix_packets.push(buf.clone());
    save_buf_in_pcap("internals-flow-test.pcap", &ipfix_packets);

    // Deserialize the message from binary format
    let (_, msg_back) = IpfixPacket::from_wire(Span::new(&buf), &mut templates_map).unwrap();
    assert_eq!(ipfix_data, msg_back);
}
