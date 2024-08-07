use std::{cell::RefCell, collections::HashMap, io::Cursor, net::Ipv4Addr, rc::Rc};

use chrono::{TimeZone, Utc};

use netgauze_flow_pkt::{ie, ie::*, ipfix::*, DataSetId, FieldSpecifier};
use netgauze_parse_utils::{ReadablePduWithOneInput, Span, WritablePduWithOneInput};

use netgauze_flow_pkt::pcap::save_buf_in_pcap;

fn main() {
    // Cache to share the templates for decoding data packets
    let templates_map = Rc::new(RefCell::new(HashMap::new()));

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
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::ingressInterfaceAttr), 2).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::egressInterfaceAttr), 2).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::vxlanExportRole), 1).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::tenantSourceIPv4), 4).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::tenantDestIPv4), 4).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::tenantSourcePort), 2).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::tenantDestPort), 2).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::tenantProtocol), 1).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::flowDirection), 1).unwrap(),
                FieldSpecifier::new(ie::IE::VMWare(vmware::IE::virtualObsID), 65535).unwrap(),
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
    IpfixPacket::from_wire(Span::new(&buf), Rc::clone(&templates_map)).unwrap();

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
                    ie::Field::protocolIdentifier(ie::protocolIdentifier::ICMP),
                    ie::Field::octetDeltaCount(ie::octetDeltaCount(1200)),
                    ie::Field::packetDeltaCount(ie::packetDeltaCount(1)),
                    ie::Field::VMWare(vmware::Field::ingressInterfaceAttr(
                        vmware::ingressInterfaceAttr(10),
                    )),
                    ie::Field::VMWare(vmware::Field::egressInterfaceAttr(
                        vmware::egressInterfaceAttr(12),
                    )),
                    ie::Field::VMWare(vmware::Field::vxlanExportRole(vmware::vxlanExportRole(0))),
                    ie::Field::VMWare(vmware::Field::tenantSourceIPv4(vmware::tenantSourceIPv4(
                        Ipv4Addr::new(192, 168, 140, 6),
                    ))),
                    ie::Field::VMWare(vmware::Field::tenantDestIPv4(vmware::tenantDestIPv4(
                        Ipv4Addr::new(192, 168, 140, 68),
                    ))),
                    ie::Field::VMWare(vmware::Field::tenantSourcePort(vmware::tenantSourcePort(
                        20023,
                    ))),
                    ie::Field::VMWare(vmware::Field::tenantDestPort(vmware::tenantDestPort(443))),
                    ie::Field::VMWare(vmware::Field::tenantProtocol(vmware::tenantProtocol::TCP)),
                    ie::Field::VMWare(vmware::Field::flowDirection(vmware::flowDirection::ingress)),
                    ie::Field::VMWare(vmware::Field::virtualObsID(vmware::virtualObsID(
                        String::from("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
                    ))),
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
        .write(&mut cursor, Some(Rc::clone(&templates_map)))
        .unwrap();

    let buf_str = buf
        .iter()
        .map(|&byte| byte.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    dbg!(format!("[{}]", buf_str));

    ipfix_packets.push(buf.clone());
    save_buf_in_pcap("flow-vmware-test.pcap", &ipfix_packets);
}
