use std::{
    borrow::Cow,
    fs::File,
    net::Ipv4Addr,
    time::{Duration, SystemTime},
};

use pcap_file::pcap::PcapWriter;
use pnet::{
    datalink::MacAddr,
    packet::{
        ethernet::{EtherTypes, MutableEthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::{checksum, MutableIpv4Packet},
        udp::MutableUdpPacket,
        Packet,
    },
};

pub fn save_buf_in_pcap(pcap_file_path: &str, buf_vec: &[Vec<u8>]) {
    // Pcap Writer
    let pcap_file = File::create(pcap_file_path).expect("Failed to create pcap file");
    let mut writer = PcapWriter::new(pcap_file).unwrap();

    for buf in buf_vec {
        // UDP
        let mut udp_buffer =
            vec![0u8; MutableUdpPacket::minimum_packet_size() + buf.len()].into_boxed_slice();
        let mut udp_packet = MutableUdpPacket::new(&mut udp_buffer).unwrap();
        udp_packet.set_source(12345);
        udp_packet.set_destination(9992);
        udp_packet.set_length((MutableUdpPacket::minimum_packet_size() + buf.len()) as u16);
        udp_packet.set_payload(&buf);

        // IPv4
        let mut ipv4_buffer =
            vec![0u8; MutableIpv4Packet::minimum_packet_size() + udp_buffer.len()]
                .into_boxed_slice();
        let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buffer).unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet
            .set_total_length((MutableIpv4Packet::minimum_packet_size() + udp_buffer.len()) as u16);
        ipv4_packet.set_ttl(64);
        ipv4_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
        ipv4_packet.set_source(Ipv4Addr::new(192, 168, 100, 1));
        ipv4_packet.set_destination(Ipv4Addr::new(192, 168, 100, 100));
        ipv4_packet.set_payload(&udp_buffer);
        ipv4_packet.set_checksum(checksum(&ipv4_packet.to_immutable()));

        // Ethernet
        let mut ethernet_buffer =
            vec![0u8; MutableEthernetPacket::minimum_packet_size() + ipv4_buffer.len()]
                .into_boxed_slice();
        let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        ethernet_packet.set_source(MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff));
        ethernet_packet.set_destination(MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66));
        ethernet_packet.set_ethertype(EtherTypes::Ipv4);
        ethernet_packet.set_payload(&ipv4_buffer);

        // PcapPacket
        let duration = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(duration) => duration,
            Err(_) => Duration::new(0, 0),
        };
        let pcap_packet = pcap_file::pcap::PcapPacket {
            timestamp: duration,
            orig_len: ethernet_packet.packet().len() as u32,
            data: Cow::Borrowed(ethernet_packet.packet()),
        };

        writer.write_packet(&pcap_packet).unwrap();
    }
}
