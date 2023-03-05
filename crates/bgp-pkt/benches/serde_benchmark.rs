use criterion::{criterion_group, criterion_main, Criterion};
use netgauze_bgp_pkt::BgpMessage;
use netgauze_parse_utils::{ReadablePduWithOneInput, Span};

const OPEN_COMPLEX_NO_PARAMS: [u8; 29] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x1d, 0x01, 0x04, 0xfe, 0x09, 0x00, 0xb4, 0xc0, 0xa8, 0x00, 0x0f, 0x00,
];

const OPEN_COMPLEX_RAW: [u8; 123] = [
    // BGP Marker
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // Message Length
    0x00, 0x7b, // Message type
    0x01, // Version
    0x04, // My As number
    0x00, 0x64, // Hold Time
    0x00, 0xb4, // BGP ID
    0x0a, 0x12, 0xa0, 0x7a, // Opt Param Len
    0x5e, // First and only parameter
    0x02, // Param length
    0x5c, // Capability: Support for 4-octet AS number
    0x41, // Capability 1: length
    0x04, // Capability 1: As number
    0x00, 0x00, 0x00, 0x64, // Capability 2: BGP Extended Message
    0x06, 0x00, // Capability 3: Route Refresh
    0x02, 0x00, // Capability 4: add path
    0x45, // Capability4 : length
    0x08, // Capability 4: AFI Ipv4
    0x00, 0x01, // Capability 4: SAFI Unicast
    0x01, // Send/Receive
    0x03, // Capability 4: Afi IPv6
    0x00, 0x02, // Capability 4: unicast
    0x01, // Capability 4: send recevie
    0x03, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x01, 0x04, 0x00, 0x02, 0x00, 0x01, 0x01, 0x04, 0x40,
    0x04, 0x00, 0x47, 0x01, 0x04, 0x00, 0x01, 0x00, 0x85, 0x01, 0x04, 0x00, 0x02, 0x00, 0x85, 0x01,
    0x04, 0x00, 0x01, 0x00, 0x86, 0x01, 0x04, 0x00, 0x02, 0x00, 0x86, 0x01, 0x04, 0x00, 0x01, 0x00,
    0x04, 0x01, 0x04, 0x00, 0x02, 0x00, 0x04, 0x01, 0x04, 0x00, 0x01, 0x00, 0x80, 0x01, 0x04, 0x00,
    0x02, 0x00, 0x80, 0x01, 0x04, 0x00, 0x19, 0x00, 0x46,
];

pub fn test_open_message_no_params(span: Span) {
    let x = BgpMessage::from_wire(span, true);
    x.unwrap();
}
pub fn test_complex_open_message(span: Span) {
    let x = BgpMessage::from_wire(span, true);
    x.unwrap();
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let no_params_span = Span::new(&OPEN_COMPLEX_NO_PARAMS);
    let complex_span = Span::new(&OPEN_COMPLEX_RAW);
    c.bench_function("open no params", |b| {
        b.iter(|| test_open_message_no_params(no_params_span))
    });
    c.bench_function("open complex", |b| {
        b.iter(|| test_complex_open_message(complex_span))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);