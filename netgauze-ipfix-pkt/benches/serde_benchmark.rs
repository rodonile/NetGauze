use std::{cell::RefCell, collections::HashMap, rc::Rc};

use criterion::{criterion_group, criterion_main, Criterion};

use netgauze_ipfix_pkt::{FieldSpecifier, IpfixPacket};
use netgauze_parse_utils::{ReadablePDUWithOneInput, Span};

const IPFIX_PKT_TEMPLATE_RAW: &[u8] = &[
    0x00, 0x0a, // Version
    0x00, 0x60, // Length
    0x58, 0x3d, 0xe0, 0x59, // Export time
    0x00, 0x00, 0x0e, 0xe4, // Seq number
    0x00, 0x00, 0x00, 0x00, // Observation domain
    0x00, 0x02, 0x00, 0x64, 0x01, 0x33, 0x00, 0x17, 0x00, 0x08, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x04,
    0x00, 0x05, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x07, 0x00, 0x02, 0x00, 0x0b, 0x00, 0x02,
    0x00, 0x20, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x10, 0x00, 0x04, 0x00, 0x11, 0x00, 0x04,
    0x00, 0x12, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04,
    0x00, 0x16, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x0f, 0x00, 0x04, 0x00, 0x09, 0x00, 0x01,
    0x00, 0x0d, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x3c, 0x00, 0x01, 0x00, 0x98, 0x00, 0x08,
    0x00, 0x99, 0x00, 0x08,
];

const IPFIX_PKT_OPTIONS_TEMPLATE_RAW: &[u8] = &[
    0x00, 0x0a, 0x00, 0x28, 0x58, 0x3d, 0xe0, 0x57, 0x00, 0x00, 0x0e, 0xcf, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x03, 0x00, 0x18, 0x01, 0x34, 0x00, 0x03, 0x00, 0x01, 0x00, 0x05, 0x00, 0x01, 0x00, 0x24,
    0x00, 0x02, 0x00, 0x25, 0x00, 0x02, 0x00, 0x00,
];

#[rustfmt::skip]
const IPFIX_PKT_MIXED: &[u8] = &[
    0x00, 0x0a, 0x02, 0x24, 0x63, 0x4a, 0xe2, 0x9d, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02, 0x00, 0x40, 0x04, 0x00, 0x00, 0x0e, 0x00, 0x08, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x04,
    0x00, 0x16, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04,
    0x00, 0x0a, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x04, 0x00, 0x07, 0x00, 0x02, 0x00, 0x0b, 0x00, 0x02,
    0x00, 0x04, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x3c, 0x00, 0x01, 0x00, 0x05, 0x00, 0x01,
    0x00, 0x02, 0x00, 0x34, 0x04, 0x01, 0x00, 0x0b, 0x00, 0x08, 0x00, 0x04, 0x00, 0x0c, 0x00, 0x04,
    0x00, 0x16, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04, 0x00, 0x02, 0x00, 0x04,
    0x00, 0x0a, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x04, 0x00, 0x20, 0x00, 0x02, 0x00, 0x3c, 0x00, 0x01,
    0x00, 0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x40, 0x08, 0x00, 0x00, 0x0e, 0x00, 0x1b, 0x00, 0x10,
    0x00, 0x1c, 0x00, 0x10, 0x00, 0x16, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04,
    0x00, 0x02, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x04, 0x00, 0x07, 0x00, 0x02,
    0x00, 0x0b, 0x00, 0x02, 0x00, 0x04, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x3c, 0x00, 0x01,
    0x00, 0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x34, 0x08, 0x01, 0x00, 0x0b, 0x00, 0x1b, 0x00, 0x10,
    0x00, 0x1c, 0x00, 0x10, 0x00, 0x16, 0x00, 0x04, 0x00, 0x15, 0x00, 0x04, 0x00, 0x01, 0x00, 0x04,
    0x00, 0x02, 0x00, 0x04, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x0e, 0x00, 0x04, 0x00, 0x8b, 0x00, 0x02,
    0x00, 0x3c, 0x00, 0x01, 0x00, 0x05, 0x00, 0x01, 0x00, 0x03, 0x00, 0x1e, 0x01, 0x00, 0x00, 0x05,
    0x00, 0x01, 0x00, 0x8f, 0x00, 0x04, 0x00, 0xa0, 0x00, 0x08, 0x01, 0x31, 0x00, 0x04, 0x01, 0x32,
    0x00, 0x04, 0x01, 0x30, 0x00, 0x02, 0x01, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x04, 0xbc, 0x00, 0x00,
    0x01, 0x83, 0xdc, 0x83, 0x41, 0x87, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x04, 0x00, 0x00, 0xf4, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x06, 0x9f,
    0x00, 0x00, 0x06, 0x9f, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xdd, 0xe4, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x06, 0x9f, 0x00, 0x00, 0x06, 0x9f, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0xe4, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x12, 0xa2,
    0x00, 0x00, 0x12, 0xa2, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xdd, 0xf0, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x12, 0xa2, 0x00, 0x00, 0x12, 0xa2, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0xf0, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x1e, 0x7b,
    0x00, 0x00, 0x1e, 0x7b, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xdd, 0xfc, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x1e, 0x7b, 0x00, 0x00, 0x1e, 0x7b, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xdd, 0xfc, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00,
];

#[rustfmt::skip]
const IPFIX_PKT_DATA_PKT_ONLY: &[u8] = &[
    0x00, 0x0a, 0x05, 0x64, 0x63, 0x4a, 0xe2, 0xd9, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x05, 0x54, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x2a, 0x36,
    0x00, 0x00, 0x2a, 0x36, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xde, 0x04, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x2a, 0x36, 0x00, 0x00, 0x2a, 0x36, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xde, 0x04, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x36, 0x00,
    0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0x90, 0x7a, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x7a, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x41, 0xb9,
    0x00, 0x00, 0x41, 0xb9, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0x90, 0x7e, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x41, 0xb9, 0x00, 0x00, 0x41, 0xb9, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x7e, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x4d, 0x74,
    0x00, 0x00, 0x4d, 0x74, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0x90, 0x8c, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x4d, 0x74, 0x00, 0x00, 0x4d, 0x74, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x8c, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x59, 0x2f,
    0x00, 0x00, 0x59, 0x2f, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xd6, 0xf2, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x59, 0x2f, 0x00, 0x00, 0x59, 0x2f, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd6, 0xf2, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x64, 0xe9,
    0x00, 0x00, 0x64, 0xe9, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xd6, 0xf6, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x64, 0xe9, 0x00, 0x00, 0x64, 0xe9, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd6, 0xf6, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x70, 0xa3,
    0x00, 0x00, 0x70, 0xa3, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xd6, 0xfe, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x70, 0xa3, 0x00, 0x00, 0x70, 0xa3, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd6, 0xfe, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x7c, 0x5c,
    0x00, 0x00, 0x7c, 0x5c, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xd6, 0x68, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x7c, 0x5c, 0x00, 0x00, 0x7c, 0x5c, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd6, 0x68, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x88, 0x17,
    0x00, 0x00, 0x88, 0x18, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xd6, 0x74, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x88, 0x17, 0x00, 0x00, 0x88, 0x18, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd6, 0x74, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x93, 0xd0,
    0x00, 0x00, 0x93, 0xd0, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xd6, 0x76, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x93, 0xd0, 0x00, 0x00, 0x93, 0xd0, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd6, 0x76, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0x9f, 0x8b,
    0x00, 0x00, 0x9f, 0x8c, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xd6, 0x7c, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0x9f, 0x8b, 0x00, 0x00, 0x9f, 0x8c, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd6, 0x7c, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0xab, 0x46,
    0x00, 0x00, 0xab, 0x46, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0x87, 0xd0, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0xab, 0x46, 0x00, 0x00, 0xab, 0x46, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0xd0, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0xb6, 0xfe,
    0x00, 0x00, 0xb7, 0x01, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0x87, 0xde, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0xb6, 0xfe, 0x00, 0x00, 0xb7, 0x01, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0xde, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0xc3, 0x96,
    0x00, 0x00, 0xc3, 0x97, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0x87, 0xec, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0xc3, 0x96, 0x00, 0x00, 0xc3, 0x97, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87, 0xec, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0xcf, 0x4f,
    0x00, 0x00, 0xcf, 0x4f, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xc3, 0xb8, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0xcf, 0x4f, 0x00, 0x00, 0xcf, 0x4f, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3, 0xb8, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0xdb, 0x09,
    0x00, 0x00, 0xdb, 0x0a, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xc3, 0xbe, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0xdb, 0x09, 0x00, 0x00, 0xdb, 0x0a, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3, 0xbe, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x01, 0xc0, 0xa8, 0x38, 0x0a, 0x00, 0x00, 0xe6, 0xc5,
    0x00, 0x00, 0xe6, 0xc5, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x80, 0xe8, 0xc3, 0xc8, 0x06, 0x14, 0x04, 0x00, 0xc0, 0xa8, 0x38, 0x0a,
    0xc0, 0xa8, 0x38, 0x01, 0x00, 0x00, 0xe6, 0xc5, 0x00, 0x00, 0xe6, 0xc5, 0x00, 0x00, 0x00, 0x3c,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc3, 0xc8, 0x80, 0xe8,
    0x06, 0x02, 0x04, 0x00
];

pub fn test_parse(span: Span, templates_map: Rc<RefCell<HashMap<u16, Rc<Vec<FieldSpecifier>>>>>) {
    let x = IpfixPacket::from_wire(span, templates_map);
    x.unwrap();
}

pub fn criterion_benchmark(c: &mut Criterion) {
    let template_span = Span::new(&IPFIX_PKT_TEMPLATE_RAW);
    let options_template_span = Span::new(&IPFIX_PKT_OPTIONS_TEMPLATE_RAW);
    let mixed_span = Span::new(&IPFIX_PKT_MIXED);
    let data_span = Span::new(&IPFIX_PKT_DATA_PKT_ONLY);

    let templates_map = Rc::new(RefCell::new(HashMap::new()));
    c.bench_function("IPFIX pkt with template only pkt", |b| {
        b.iter(|| test_parse(template_span, templates_map.clone()))
    });

    let templates_map = Rc::new(RefCell::new(HashMap::new()));
    c.bench_function("IPFIX with options template only pkt", |b| {
        b.iter(|| test_parse(options_template_span, templates_map.clone()))
    });

    let templates_map = Rc::new(RefCell::new(HashMap::new()));
    c.bench_function("IPFIX mixed with all set types", |b| {
        b.iter(|| test_parse(mixed_span, templates_map.clone()))
    });

    // Initialize the templates
    let templates_map = Rc::new(RefCell::new(HashMap::new()));
    IpfixPacket::from_wire(mixed_span, templates_map.clone()).unwrap();
    c.bench_function("IPFIX mixed with data only", |b| {
        b.iter(|| test_parse(data_span, templates_map.clone()))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
