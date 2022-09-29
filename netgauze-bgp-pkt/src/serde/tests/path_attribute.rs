// Copyright (C) 2022-present The NetGauze Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::{
    path_attribute::{
        AS4Path, ASPath, Aggregator, As2Aggregator, As2PathSegment, As4Aggregator, As4PathSegment,
        AsPathSegmentType, AtomicAggregate, Communities, Community, LocalPreference,
        MultiExitDiscriminator, NextHop, Origin, PathAttribute, PathAttributeLength,
        UndefinedAsPathSegmentType, UndefinedOrigin, UnknownAttribute,
    },
    serde::{
        deserializer::path_attribute::{
            AggregatorParsingError, AsPathParsingError, AtomicAggregateParsingError,
            CommunitiesParsingError, LocalPreferenceParsingError, LocatedAggregatorParsingError,
            LocatedAsPathParsingError, LocatedAtomicAggregateParsingError,
            LocatedCommunitiesParsingError, LocatedLocalPreferenceParsingError,
            LocatedMultiExitDiscriminatorParsingError, LocatedNextHopParsingError,
            LocatedOriginParsingError, LocatedPathAttributeParsingError,
            MultiExitDiscriminatorParsingError, NextHopParsingError, OriginParsingError,
            PathAttributeParsingError, UnknownAttributeParsingError,
        },
        serializer::path_attribute::{
            AggregatorWritingError, AsPathWritingError, AtomicAggregateWritingError,
            CommunitiesWritingError, LocalPreferenceWritingError,
            MultiExitDiscriminatorWritingError, NextHopWritingError, OriginWritingError,
            PathAttributeWritingError, UnknownAttributeWritingError,
        },
    },
};

use crate::{
    nlri::{
        InvalidIpv6MulticastNetwork, InvalidIpv6UnicastNetwork, Ipv4Multicast, Ipv4Unicast,
        Ipv6Multicast, Ipv6Unicast,
    },
    path_attribute::{MpReach, MpUnreach},
    serde::{
        deserializer::{
            nlri::{
                Ipv4MulticastParsingError, Ipv4UnicastParsingError, Ipv6MulticastParsingError,
                Ipv6UnicastParsingError,
            },
            path_attribute::{
                LocatedMpReachParsingError, MpReachParsingError, MpUnreachParsingError,
            },
            Ipv4PrefixParsingError,
        },
        serializer::path_attribute::MpReachWritingError,
    },
};
use ipnet::{Ipv4Net, Ipv6Net};
use netgauze_iana::address_family::{
    AddressFamily, InvalidAddressType, SubsequentAddressFamily, UndefinedAddressFamily,
    UndefinedSubsequentAddressFamily,
};
use netgauze_parse_utils::{
    test_helpers::{
        test_parse_error, test_parse_error_with_one_input, test_parse_error_with_two_inputs,
        test_parsed_completely, test_parsed_completely_with_one_input,
        test_parsed_completely_with_three_inputs, test_parsed_completely_with_two_inputs,
        test_write, test_write_with_one_input,
    },
    Span,
};
use nom::error::ErrorKind;
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

#[test]
fn test_origin_value() -> Result<(), OriginWritingError> {
    let good_igp_wire = [0x01, 0x00];
    let good_egp_wire = [0x01, 0x01];
    let good_incomplete_wire = [0x01, 0x02];
    let bad_zero_length_wire = [0x0, 0x02];
    let bad_long_length_wire = [0x2, 0x02];
    let bad_invalid_code_wire = [0x1, 0x03];

    let igp = Origin::IGP;
    let egp = Origin::EGP;
    let incomplete = Origin::Incomplete;
    let bad_zero_length = LocatedOriginParsingError::new(
        Span::new(&bad_zero_length_wire),
        OriginParsingError::InvalidOriginLength(PathAttributeLength::U8(0)),
    );

    let bad_long_length = LocatedOriginParsingError::new(
        Span::new(&bad_long_length_wire),
        OriginParsingError::InvalidOriginLength(PathAttributeLength::U8(2)),
    );

    let bad_invalid_code = LocatedOriginParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_invalid_code_wire[1..]) },
        OriginParsingError::UndefinedOrigin(UndefinedOrigin(3)),
    );

    test_parsed_completely_with_one_input(&good_igp_wire, false, &igp);
    test_parsed_completely_with_one_input(&good_egp_wire, false, &egp);
    test_parsed_completely_with_one_input(&good_incomplete_wire, false, &incomplete);
    test_parse_error_with_one_input::<'_, Origin, bool, LocatedOriginParsingError<'_>>(
        &bad_zero_length_wire,
        false,
        &bad_zero_length,
    );
    test_parse_error_with_one_input::<'_, Origin, bool, LocatedOriginParsingError<'_>>(
        &bad_long_length_wire,
        false,
        &bad_long_length,
    );
    test_parse_error_with_one_input::<'_, Origin, bool, LocatedOriginParsingError<'_>>(
        &bad_invalid_code_wire,
        false,
        &bad_invalid_code,
    );

    test_write_with_one_input(&igp, false, &good_igp_wire)?;
    test_write_with_one_input(&egp, false, &good_egp_wire)?;
    test_write_with_one_input(&incomplete, false, &good_incomplete_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_origin() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x40, 0x01, 0x01, 0x00];
    let good_extended_wire = [0x50, 0x01, 0x00, 0x01, 0x00];
    let bad_extended_wire = [0x50, 0x01, 0x00, 0x01, 0x03];
    let bad_incomplete_wire = [0x40, 0x01, 0x01];

    let good = PathAttribute::Origin {
        extended_length: false,
        value: Origin::IGP,
    };
    let good_extended = PathAttribute::Origin {
        extended_length: true,
        value: Origin::IGP,
    };

    let bad_extended = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(4, &bad_extended_wire[4..]) },
        PathAttributeParsingError::OriginError(OriginParsingError::UndefinedOrigin(
            UndefinedOrigin(3),
        )),
    );

    let bad_incomplete = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(3, &bad_incomplete_wire[3..]) },
        PathAttributeParsingError::OriginError(OriginParsingError::NomError(ErrorKind::Eof)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, false, &good_extended);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &bad_extended_wire,
        false,
        &bad_extended,
    );
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &bad_incomplete_wire,
        false,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_as2_path_segment() -> Result<(), AsPathWritingError> {
    let good_set_wire = [0x01, 0x01, 0x00, 0x01];
    let good_seq_wire = [0x02, 0x01, 0x00, 0x01];
    let good_empty_wire = [0x01, 0x00];
    let bad_undefined_segment_type_wire = [0x00, 0x01, 0x00, 0x01];
    let bad_incomplete_wire = [0x01, 0x01, 0x00];

    let set = As2PathSegment::new(AsPathSegmentType::AsSet, vec![1]);
    let seq = As2PathSegment::new(AsPathSegmentType::AsSequence, vec![1]);
    let empty = As2PathSegment::new(AsPathSegmentType::AsSet, vec![]);

    let bad_undefined_segment_type = LocatedAsPathParsingError::new(
        Span::new(&bad_undefined_segment_type_wire),
        AsPathParsingError::UndefinedAsPathSegmentType(UndefinedAsPathSegmentType(0x00)),
    );
    let bad_incomplete = LocatedAsPathParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_incomplete_wire[2..]) },
        AsPathParsingError::NomError(ErrorKind::Eof),
    );

    test_parsed_completely(&good_set_wire, &set);
    test_parsed_completely(&good_seq_wire, &seq);
    test_parsed_completely(&good_empty_wire, &empty);
    test_parse_error::<As2PathSegment, LocatedAsPathParsingError<'_>>(
        &bad_undefined_segment_type_wire,
        &bad_undefined_segment_type,
    );
    test_parse_error::<As2PathSegment, LocatedAsPathParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&set, &good_set_wire)?;
    test_write(&seq, &good_seq_wire)?;
    test_write(&empty, &good_empty_wire)?;
    Ok(())
}

#[test]
fn test_as4_path_segment() -> Result<(), AsPathWritingError> {
    let good_set_wire = [0x01, 0x01, 0x00, 0x00, 0x00, 0x01];
    let good_seq_wire = [0x02, 0x01, 0x00, 0x00, 0x00, 0x01];
    let good_empty_wire = [0x01, 0x00];
    let undefined_segment_type_wire = [0x00, 0x01, 0x00, 0x00, 0x00, 0x01];

    let set = As4PathSegment::new(AsPathSegmentType::AsSet, vec![1]);
    let seq = As4PathSegment::new(AsPathSegmentType::AsSequence, vec![1]);
    let empty = As4PathSegment::new(AsPathSegmentType::AsSet, vec![]);

    let undefined_segment_type = LocatedAsPathParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &undefined_segment_type_wire) },
        AsPathParsingError::UndefinedAsPathSegmentType(UndefinedAsPathSegmentType(0x00)),
    );

    test_parsed_completely(&good_set_wire, &set);
    test_parsed_completely(&good_seq_wire, &seq);
    test_parsed_completely(&good_empty_wire, &empty);
    test_parse_error::<As4PathSegment, LocatedAsPathParsingError<'_>>(
        &undefined_segment_type_wire,
        &undefined_segment_type,
    );

    test_write(&set, &good_set_wire)?;
    test_write(&seq, &good_seq_wire)?;
    test_write(&empty, &good_empty_wire)?;
    Ok(())
}

#[test]
fn test_as2_path_segments() -> Result<(), AsPathWritingError> {
    let good_wire = [0x08, 0x01, 0x01, 0x00, 0x01, 0x02, 0x01, 0x00, 0x01];
    let good_extended_wire = [0x00, 0x08, 0x01, 0x01, 0x00, 0x01, 0x02, 0x01, 0x00, 0x01];
    let good_empty_wire = [0x00];
    let bad_underflow_wire = [0x08, 0x01, 0x01, 0x00, 0x01];
    let bad_overflow_wire = [0x08, 0x01, 0x02, 0x00, 0x01, 0x00, 0x02];

    let good = ASPath::As2PathSegments(vec![
        As2PathSegment::new(AsPathSegmentType::AsSet, vec![1]),
        As2PathSegment::new(AsPathSegmentType::AsSequence, vec![1]),
    ]);
    let good_extended = ASPath::As2PathSegments(vec![
        As2PathSegment::new(AsPathSegmentType::AsSet, vec![1]),
        As2PathSegment::new(AsPathSegmentType::AsSequence, vec![1]),
    ]);
    let good_empty = ASPath::As2PathSegments(vec![]);
    let bad_underflow = nom::Err::Incomplete(nom::Needed::new(4));
    let bad_overflow = nom::Err::Incomplete(nom::Needed::new(2));

    test_parsed_completely_with_two_inputs(&good_wire, false, false, &good);
    test_parsed_completely_with_two_inputs(&good_empty_wire, false, false, &good_empty);
    test_parsed_completely_with_two_inputs(&good_extended_wire, true, false, &good_extended);
    test_parse_error_with_two_inputs::<ASPath, bool, bool, LocatedAsPathParsingError<'_>>(
        &bad_underflow_wire,
        false,
        false,
        bad_underflow,
    );
    test_parse_error_with_two_inputs::<ASPath, bool, bool, LocatedAsPathParsingError<'_>>(
        &bad_overflow_wire,
        false,
        false,
        bad_overflow,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    test_write_with_one_input(&good_empty, false, &good_empty_wire)?;
    Ok(())
}

#[test]
fn test_as4_path_segments() -> Result<(), AsPathWritingError> {
    let good_empty_wire = [0x00, 0x00];
    let good_one_wire = [0x00, 0x06, 0x02, 0x01, 0x00, 0x00, 0x00, 0x01];
    let good_two_wire = [
        0x00, 0x0c, 0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x01,
    ];
    let bad_underflow_wire = [0x00, 0x08, 0x01, 0x01, 0x00, 0x01];
    let bad_overflow_wire = [0x00, 0x08, 0x01, 0x02, 0x00, 0x01, 0x00, 0x02];

    let good_empty = ASPath::As4PathSegments(vec![]);
    let good_one = ASPath::As4PathSegments(vec![As4PathSegment::new(
        AsPathSegmentType::AsSequence,
        vec![1],
    )]);
    let good_two = ASPath::As4PathSegments(vec![
        As4PathSegment::new(AsPathSegmentType::AsSet, vec![1]),
        As4PathSegment::new(AsPathSegmentType::AsSequence, vec![1]),
    ]);

    let bad_underflow = nom::Err::Incomplete(nom::Needed::new(4));
    let bad_overflow = nom::Err::Incomplete(nom::Needed::new(2));

    test_parsed_completely_with_two_inputs(&good_empty_wire, true, true, &good_empty);
    test_parsed_completely_with_two_inputs(&good_one_wire, true, true, &good_one);
    test_parsed_completely_with_two_inputs(&good_two_wire, true, true, &good_two);

    test_parse_error_with_two_inputs::<ASPath, bool, bool, LocatedAsPathParsingError<'_>>(
        &bad_underflow_wire,
        true,
        true,
        bad_underflow,
    );
    test_parse_error_with_two_inputs::<ASPath, bool, bool, LocatedAsPathParsingError<'_>>(
        &bad_overflow_wire,
        true,
        true,
        bad_overflow,
    );

    test_write_with_one_input(&good_empty, true, &good_empty_wire)?;
    test_write_with_one_input(&good_one, true, &good_one_wire)?;
    test_write_with_one_input(&good_two, true, &good_two_wire)?;

    Ok(())
}

#[test]
fn test_path_attribute_as2_path() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x40, 0x02, 0x06, 0x02, 0x02, 0x00, 0x64, 0x01, 0x2c];
    let good_wire_extended = [0x50, 0x02, 0x00, 0x06, 0x02, 0x02, 0x00, 0x64, 0x01, 0x2c];
    let undefined_segment_type_wire = [0x50, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x64, 0x01, 0x2c];

    let good = PathAttribute::ASPath {
        extended_length: false,
        value: ASPath::As2PathSegments(vec![As2PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };
    let good_extended = PathAttribute::ASPath {
        extended_length: true,
        value: ASPath::As2PathSegments(vec![As2PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };

    let undefined_segment_type = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(4, &undefined_segment_type_wire[4..]) },
        PathAttributeParsingError::AsPathError(AsPathParsingError::UndefinedAsPathSegmentType(
            UndefinedAsPathSegmentType(0),
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_wire_extended, false, &good_extended);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &undefined_segment_type_wire,
        false,
        &undefined_segment_type,
    );
    test_write(&good_extended, &good_wire_extended)?;
    Ok(())
}

#[test]
fn test_path_attribute_as4_path() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x40, 0x02, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];
    let good_wire_extended = [
        0x50, 0x02, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];

    let good = PathAttribute::ASPath {
        extended_length: false,
        value: ASPath::As4PathSegments(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };
    let good_extended = PathAttribute::ASPath {
        extended_length: true,
        value: ASPath::As4PathSegments(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };

    test_parsed_completely_with_one_input(&good_wire, true, &good);
    test_parsed_completely_with_one_input(&good_wire_extended, true, &good_extended);
    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_wire_extended)?;
    Ok(())
}

#[test]
fn test_path_attribute_as4_path_transitional() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0xc0, 0x11, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];
    let good_wire_extended = [
        0xd0, 0x11, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];
    let good_wire_partial = [
        0xf0, 0x11, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x01, 0x2c,
    ];

    let good = PathAttribute::AS4Path {
        partial: false,
        extended_length: false,
        value: AS4Path::new(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };
    let good_extended = PathAttribute::AS4Path {
        partial: false,
        extended_length: true,
        value: AS4Path::new(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };
    let good_partial = PathAttribute::AS4Path {
        partial: true,
        extended_length: true,
        value: AS4Path::new(vec![As4PathSegment::new(
            AsPathSegmentType::AsSequence,
            vec![100, 300],
        )]),
    };

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_wire_extended, true, &good_extended);
    test_parsed_completely_with_one_input(&good_wire_partial, true, &good_partial);

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_wire_extended)?;
    test_write(&good_partial, &good_wire_partial)?;
    Ok(())
}

#[test]
fn test_next_hop() -> Result<(), NextHopWritingError> {
    let good_wire = [0x04, 0xac, 0x10, 0x03, 0x02];
    let bad_wire = [0x05, 0xac, 0x10, 0x03, 0x02];

    let good = NextHop::new(Ipv4Addr::new(172, 16, 3, 2));
    let bad = LocatedNextHopParsingError::new(
        unsafe { Span::new_from_raw_offset(0, &bad_wire) },
        NextHopParsingError::InvalidNextHopLength(PathAttributeLength::U8(5)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parse_error_with_one_input::<NextHop, bool, LocatedNextHopParsingError<'_>>(
        &bad_wire, false, &bad,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_next_hop() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x40, 0x03, 0x04, 0xac, 0x10, 0x03, 0x01];
    let good_wire_extended = [0x50, 0x03, 0x00, 0x04, 0xac, 0x10, 0x03, 0x01];
    let bad_wire = [0x50, 0x03, 0x00, 0x03, 0xac, 0x10, 0x03, 0x01];

    let good = PathAttribute::NextHop {
        extended_length: false,
        value: NextHop::new(Ipv4Addr::new(172, 16, 3, 1)),
    };
    let good_extended = PathAttribute::NextHop {
        extended_length: true,
        value: NextHop::new(Ipv4Addr::new(172, 16, 3, 1)),
    };
    let bad = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_wire[2..]) },
        PathAttributeParsingError::NextHopError(NextHopParsingError::InvalidNextHopLength(
            PathAttributeLength::U16(3),
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_wire_extended, true, &good_extended);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &bad_wire, false, &bad,
    );
    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_wire_extended)?;
    Ok(())
}

#[test]
fn test_multi_exit_discriminator() -> Result<(), MultiExitDiscriminatorWritingError> {
    let good_wire = [0x04, 0x00, 0x00, 0x00, 0x01];
    let good_extended_wire = [0x00, 0x04, 0x00, 0x00, 0x00, 0x01];
    let bad_wire = [0x03, 0x00, 0x00, 0x00, 0x01];

    let good = MultiExitDiscriminator::new(1);
    let good_extended = MultiExitDiscriminator::new(1);
    let bad = LocatedMultiExitDiscriminatorParsingError::new(
        Span::new(&bad_wire),
        MultiExitDiscriminatorParsingError::InvalidLength(PathAttributeLength::U8(3)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parse_error_with_one_input::<
        MultiExitDiscriminator,
        bool,
        LocatedMultiExitDiscriminatorParsingError<'_>,
    >(&bad_wire, false, &bad);

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_multi_exit_discriminator() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x80, 0x04, 0x04, 0x00, 0x00, 0x00, 0x01];
    let good_wire_extended = [0x90, 0x04, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01];
    let bad_eof_wire = [0x80, 0x04, 0x04, 0x00, 0x00, 0x00];

    let good = PathAttribute::MultiExitDiscriminator {
        extended_length: false,
        value: MultiExitDiscriminator::new(1),
    };
    let good_extended = PathAttribute::MultiExitDiscriminator {
        extended_length: true,
        value: MultiExitDiscriminator::new(1),
    };
    let bad_eof = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(3, &bad_eof_wire[3..]) },
        PathAttributeParsingError::MultiExitDiscriminatorError(
            MultiExitDiscriminatorParsingError::NomError(ErrorKind::Eof),
        ),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_wire_extended, true, &good_extended);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &bad_eof_wire,
        false,
        &bad_eof,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_wire_extended)?;
    Ok(())
}

#[test]
fn test_local_preference() -> Result<(), LocalPreferenceWritingError> {
    let good_wire = [0x04, 0x00, 0x00, 0x00, 0x01];
    let good_extended_wire = [0x00, 0x04, 0x00, 0x00, 0x00, 0x01];
    let bad_underflow_wire = [0x04, 0x00, 0x00, 0x01];
    let bad_length_wire = [0x03, 0x00, 0x00, 0x01];

    let good = LocalPreference::new(1);
    let good_extended = LocalPreference::new(1);
    let bad_underflow = LocatedLocalPreferenceParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &bad_underflow_wire[1..]) },
        LocalPreferenceParsingError::NomError(ErrorKind::Eof),
    );
    let bad_length = LocatedLocalPreferenceParsingError::new(
        Span::new(&bad_length_wire),
        LocalPreferenceParsingError::InvalidLength(PathAttributeLength::U8(3)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parse_error_with_one_input::<LocalPreference, bool, LocatedLocalPreferenceParsingError<'_>>(
        &bad_underflow_wire,
        false,
        &bad_underflow,
    );
    test_parse_error_with_one_input::<LocalPreference, bool, LocatedLocalPreferenceParsingError<'_>>(
        &bad_length_wire,
        false,
        &bad_length,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_local_preference() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0x40, 0x05, 0x04, 0x00, 0x00, 0x00, 0x64];
    let good_extended_wire = [0x50, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64];

    let good = PathAttribute::LocalPreference {
        extended_length: false,
        value: LocalPreference::new(100),
    };
    let good_extended = PathAttribute::LocalPreference {
        extended_length: true,
        value: LocalPreference::new(100),
    };

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_atomic_aggregate() -> Result<(), AtomicAggregateWritingError> {
    let good_wire = [0x00];
    let good_extended_wire = [0x00, 0x00];
    let bad_length_wire = [0x01];
    let bad_extended_length_wire = [0x00, 0x01];

    let good = AtomicAggregate;
    let good_extended = AtomicAggregate;
    let bad_length = LocatedAtomicAggregateParsingError::new(
        Span::new(&bad_length_wire),
        AtomicAggregateParsingError::InvalidLength(PathAttributeLength::U8(1)),
    );
    let bad_extended_length = LocatedAtomicAggregateParsingError::new(
        Span::new(&bad_extended_length_wire),
        AtomicAggregateParsingError::InvalidLength(PathAttributeLength::U16(1)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parse_error_with_one_input::<AtomicAggregate, bool, LocatedAtomicAggregateParsingError<'_>>(
        &bad_length_wire,
        false,
        &bad_length,
    );
    test_parse_error_with_one_input::<AtomicAggregate, bool, LocatedAtomicAggregateParsingError<'_>>(
        &bad_extended_length_wire,
        true,
        &bad_extended_length,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_atomic_aggregate() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0xc0, 0x06, 0x00];
    let good_extended_wire = [0xd0, 0x06, 0x00, 0x00];
    let bad_length_wire = [0xc0, 0x06, 0x01];
    let bad_extended_length_wire = [0xd0, 0x06, 0x00, 0x01];

    let good = PathAttribute::AtomicAggregate {
        extended_length: false,
        value: AtomicAggregate,
    };
    let good_extended = PathAttribute::AtomicAggregate {
        extended_length: true,
        value: AtomicAggregate,
    };
    let bad_length = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_length_wire[2..]) },
        PathAttributeParsingError::AtomicAggregateError(
            AtomicAggregateParsingError::InvalidLength(PathAttributeLength::U8(1)),
        ),
    );
    let bad_extended_length = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_extended_length_wire[2..]) },
        PathAttributeParsingError::AtomicAggregateError(
            AtomicAggregateParsingError::InvalidLength(PathAttributeLength::U16(1)),
        ),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &bad_length_wire,
        false,
        &bad_length,
    );
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &bad_extended_length_wire,
        true,
        &bad_extended_length,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_as2_aggregator() -> Result<(), AggregatorWritingError> {
    let good_wire = [0x06, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let bad_length_wire = [0x05, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let good_extended_wire = [0x00, 0x06, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let bad_extended_length_wire = [0x00, 0x07, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];

    let good = As2Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10));
    let good_extended = As2Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10));

    let bad_length = LocatedAggregatorParsingError::new(
        Span::new(&bad_length_wire),
        AggregatorParsingError::InvalidLength(PathAttributeLength::U8(5)),
    );

    let bad_extended_length = LocatedAggregatorParsingError::new(
        Span::new(&bad_extended_length_wire),
        AggregatorParsingError::InvalidLength(PathAttributeLength::U16(7)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parse_error_with_one_input::<As2Aggregator, bool, LocatedAggregatorParsingError<'_>>(
        &bad_length_wire,
        false,
        &bad_length,
    );
    test_parse_error_with_one_input::<As2Aggregator, bool, LocatedAggregatorParsingError<'_>>(
        &bad_extended_length_wire,
        true,
        &bad_extended_length,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_as4_aggregator() -> Result<(), AggregatorWritingError> {
    let good_wire = [0x08, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let bad_length_wire = [0x09, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let good_extended_wire = [0x00, 0x08, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let bad_extended_length_wire = [0x00, 0x07, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];

    let good = As4Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10));
    let good_extended = As4Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10));

    let bad_length = LocatedAggregatorParsingError::new(
        Span::new(&bad_length_wire),
        AggregatorParsingError::InvalidLength(PathAttributeLength::U8(9)),
    );

    let bad_extended_length = LocatedAggregatorParsingError::new(
        Span::new(&bad_extended_length_wire),
        AggregatorParsingError::InvalidLength(PathAttributeLength::U16(7)),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parse_error_with_one_input::<As4Aggregator, bool, LocatedAggregatorParsingError<'_>>(
        &bad_length_wire,
        false,
        &bad_length,
    );
    test_parse_error_with_one_input::<As4Aggregator, bool, LocatedAggregatorParsingError<'_>>(
        &bad_extended_length_wire,
        true,
        &bad_extended_length,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good_extended, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_as2_aggregator() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0xc0, 0x07, 0x06, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let good_partial_wire = [0xe0, 0x07, 0x06, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let good_extended_wire = [0xd0, 0x07, 0x00, 0x06, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let good_partial_extended_wire = [0xf0, 0x07, 0x00, 0x06, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let bad_length_wire = [0xc0, 0x07, 0x08, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a];
    let bad_incomplete_wire = [0xc0, 0x07, 0x06, 0x00, 0x64, 0xac, 0x10, 0x00];

    let good = PathAttribute::Aggregator {
        partial: false,
        extended_length: false,
        value: Aggregator::As2Aggregator(As2Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10))),
    };
    let good_partial = PathAttribute::Aggregator {
        partial: true,
        extended_length: false,
        value: Aggregator::As2Aggregator(As2Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10))),
    };

    let good_extended = PathAttribute::Aggregator {
        partial: false,
        extended_length: true,
        value: Aggregator::As2Aggregator(As2Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10))),
    };
    let good_partial_extended = PathAttribute::Aggregator {
        partial: true,
        extended_length: true,
        value: Aggregator::As2Aggregator(As2Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10))),
    };
    let bad_length = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(2, &bad_length_wire[2..]) },
        PathAttributeParsingError::AggregatorError(AggregatorParsingError::InvalidLength(
            PathAttributeLength::U8(8),
        )),
    );

    let bad_incomplete = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(5, &bad_incomplete_wire[5..]) },
        PathAttributeParsingError::AggregatorError(AggregatorParsingError::NomError(
            ErrorKind::Eof,
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_partial_wire, false, &good_partial);
    test_parsed_completely_with_one_input(&good_extended_wire, false, &good_extended);
    test_parsed_completely_with_one_input(
        &good_partial_extended_wire,
        false,
        &good_partial_extended,
    );
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &bad_length_wire,
        false,
        &bad_length,
    );
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &bad_incomplete_wire,
        false,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_partial, &good_partial_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    test_write(&good_partial_extended, &good_partial_extended_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_as4_aggregator() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0xc0, 0x07, 0x08, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a,
    ];
    let good_partial_wire = [
        0xe0, 0x07, 0x08, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a,
    ];
    let good_extended_wire = [
        0xd0, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a,
    ];
    let good_partial_extended_wire = [
        0xf0, 0x07, 0x00, 0x08, 0x00, 0x00, 0x00, 0x64, 0xac, 0x10, 0x00, 0x0a,
    ];

    let good = PathAttribute::Aggregator {
        partial: false,
        extended_length: false,
        value: Aggregator::As4Aggregator(As4Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10))),
    };
    let good_partial = PathAttribute::Aggregator {
        partial: true,
        extended_length: false,
        value: Aggregator::As4Aggregator(As4Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10))),
    };

    let good_extended = PathAttribute::Aggregator {
        partial: false,
        extended_length: true,
        value: Aggregator::As4Aggregator(As4Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10))),
    };
    let good_partial_extended = PathAttribute::Aggregator {
        partial: true,
        extended_length: true,
        value: Aggregator::As4Aggregator(As4Aggregator::new(100, Ipv4Addr::new(172, 16, 0, 10))),
    };

    test_parsed_completely_with_one_input(&good_wire, true, &good);
    test_parsed_completely_with_one_input(&good_partial_wire, true, &good_partial);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parsed_completely_with_one_input(
        &good_partial_extended_wire,
        true,
        &good_partial_extended,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_partial, &good_partial_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    test_write(&good_partial_extended, &good_partial_extended_wire)?;
    Ok(())
}

#[test]
fn test_community() -> Result<(), CommunitiesWritingError> {
    let good_wire = [0x00, 0xef, 0x00, 0x20];
    let bad_incomplete_wire = [0x00];

    let good = Community::new(0x00ef0020);
    let bad_incomplete = LocatedCommunitiesParsingError::new(
        Span::new(&bad_incomplete_wire),
        CommunitiesParsingError::NomError(ErrorKind::Eof),
    );

    test_parsed_completely(&good_wire, &good);
    test_parse_error::<Community, LocatedCommunitiesParsingError<'_>>(
        &bad_incomplete_wire,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_communities() -> Result<(), PathAttributeWritingError> {
    let good_zero_wire = [0xc0, 0x08, 0x00];
    let good_one_wire = [0xc0, 0x08, 0x04, 0x00, 0x00, 0x00, 0x01];
    let good_two_wire = [
        0xc0, 0x08, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
    ];
    let good_two_wire_extended = [
        0xd0, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02,
    ];

    let good_zero = PathAttribute::Communities {
        partial: false,
        extended_length: false,
        value: Communities::new(vec![]),
    };

    let good_one = PathAttribute::Communities {
        partial: false,
        extended_length: false,
        value: Communities::new(vec![Community::new(1)]),
    };

    let good_two = PathAttribute::Communities {
        partial: false,
        extended_length: false,
        value: Communities::new(vec![Community::new(1), Community::new(2)]),
    };

    let good_two_extended = PathAttribute::Communities {
        partial: false,
        extended_length: true,
        value: Communities::new(vec![Community::new(1), Community::new(2)]),
    };

    test_parsed_completely_with_one_input(&good_zero_wire, false, &good_zero);
    test_parsed_completely_with_one_input(&good_one_wire, false, &good_one);
    test_parsed_completely_with_one_input(&good_two_wire, false, &good_two);
    test_parsed_completely_with_one_input(&good_two_wire_extended, true, &good_two_extended);
    test_write(&good_zero, &good_zero_wire)?;
    test_write(&good_one, &good_one_wire)?;
    test_write(&good_two, &good_two_wire)?;
    test_write(&good_two_extended, &good_two_wire_extended)?;
    Ok(())
}

#[test]
fn test_mp_reach_nlri_ipv6() -> Result<(), MpReachWritingError> {
    let good_wire = [
        0x40, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x000,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
        0x001, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01,
        0x00, 0x002, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20, 0x01, 0x0d,
        0xb8, 0x00, 0x001, 0x00, 0x00,
    ];

    let good_extended_wire = [
        0x00, 0x40, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xc0, 0x001, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00,
        0x01, 0x00, 0x002, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20, 0x01,
        0x0d, 0xb8, 0x00, 0x001, 0x00, 0x00,
    ];

    let invalid_afi_wire = [
        0x40, 0x00, 0xff, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x000,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
        0x001, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01,
        0x00, 0x002, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20, 0x01, 0x0d,
        0xb8, 0x00, 0x001, 0x00, 0x00,
    ];

    let invalid_safi_wire = [
        0x40, 0x00, 0x02, 0xff, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x000,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
        0x001, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01,
        0x00, 0x002, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20, 0x01, 0x0d,
        0xb8, 0x00, 0x001, 0x00, 0x00,
    ];
    let invalid_address_type_wire = [
        0x40, 0x00, 0x0c, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x000,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0,
        0x001, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01,
        0x00, 0x002, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20, 0x01, 0x0d,
        0xb8, 0x00, 0x001, 0x00, 0x00,
    ];

    let good = MpReach::Ipv6Unicast {
        next_hop_global: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x1),
        next_hop_local: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xc001, 0xbff, 0xfe7e, 0)),
        nlri: vec![
            Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8:1:2::/64").unwrap()).unwrap(),
            Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8:1:1::/64").unwrap()).unwrap(),
            Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8:1::/64").unwrap()).unwrap(),
        ],
    };

    let invalid_afi = LocatedMpReachParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &invalid_afi_wire[1..]) },
        MpReachParsingError::UndefinedAddressFamily(UndefinedAddressFamily(0xff)),
    );

    let invalid_safi = LocatedMpReachParsingError::new(
        unsafe { Span::new_from_raw_offset(3, &invalid_safi_wire[3..]) },
        MpReachParsingError::UndefinedSubsequentAddressFamily(UndefinedSubsequentAddressFamily(
            0xff,
        )),
    );

    let invalid_address_type = LocatedMpReachParsingError::new(
        unsafe { Span::new_from_raw_offset(1, &invalid_address_type_wire[1..]) },
        MpReachParsingError::InvalidAddressType(InvalidAddressType::new(
            AddressFamily::AppleTalk,
            SubsequentAddressFamily::Unicast,
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good);

    test_parse_error_with_one_input::<MpReach, bool, LocatedMpReachParsingError<'_>>(
        &invalid_afi_wire,
        false,
        &invalid_afi,
    );
    test_parse_error_with_one_input::<MpReach, bool, LocatedMpReachParsingError<'_>>(
        &invalid_safi_wire,
        false,
        &invalid_safi,
    );
    test_parse_error_with_one_input::<MpReach, bool, LocatedMpReachParsingError<'_>>(
        &invalid_address_type_wire,
        false,
        &invalid_address_type,
    );

    test_write_with_one_input(&good, false, &good_wire)?;
    test_write_with_one_input(&good, true, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_mp_reach_nlri_ipv4_unicast() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x90, 0x0e, 0x00, 0x0c, 0x00, 0x01, 0x01, 0x04, 0xac, 0x10, 0x00, 0x14, 0x00, 0x10, 0xc0,
        0xa8,
    ];
    let invalid_wire = [
        0x90, 0x0e, 0x00, 0x0c, 0x00, 0x01, 0x01, 0x04, 0xac, 0x10, 0x00, 0x14, 0x00, 0x30, 0xe0,
        0x00,
    ];

    let good = PathAttribute::MpReach {
        extended_length: true,
        value: MpReach::Ipv4Unicast {
            next_hop: Ipv4Addr::new(172, 16, 0, 20),
            nlri: vec![
                Ipv4Unicast::from_net(Ipv4Net::from_str("192.168.0.0/16").unwrap()).unwrap(),
            ],
        },
    };

    let invalid = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(14, &invalid_wire[14..]) },
        PathAttributeParsingError::MpReachErrorError(MpReachParsingError::Ipv4UnicastError(
            Ipv4UnicastParsingError::Ipv4PrefixError(Ipv4PrefixParsingError::NomError(
                ErrorKind::Eof,
            )),
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &invalid_wire,
        false,
        &invalid,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_mp_reach_nlri_ipv4_multicast() -> Result<(), PathAttributeWritingError>
{
    let good_wire = [
        0x90, 0x0e, 0x00, 0x0c, 0x00, 0x01, 0x02, 0x04, 0xac, 0x10, 0x00, 0x14, 0x00, 0x10, 0xe0,
        0x00,
    ];
    let invalid_wire = [
        0x90, 0x0e, 0x00, 0x0c, 0x00, 0x01, 0x02, 0x04, 0xac, 0x10, 0x00, 0x14, 0x00, 0x30, 0xe0,
        0x00,
    ];

    let good = PathAttribute::MpReach {
        extended_length: true,
        value: MpReach::Ipv4Multicast {
            next_hop: Ipv4Addr::new(172, 16, 0, 20),
            nlri: vec![
                Ipv4Multicast::from_net(Ipv4Net::from_str("224.0.0.0/16").unwrap()).unwrap(),
            ],
        },
    };

    let invalid = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(14, &invalid_wire[14..]) },
        PathAttributeParsingError::MpReachErrorError(MpReachParsingError::Ipv4MulticastError(
            Ipv4MulticastParsingError::Ipv4PrefixError(Ipv4PrefixParsingError::NomError(
                ErrorKind::Eof,
            )),
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &invalid_wire,
        false,
        &invalid,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_mp_reach_nlri_ipv6_unicast() -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x80, 0x0e, 0x40, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc0, 0x001, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x01, 0x00, 0x002, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20,
        0x01, 0x0d, 0xb8, 0x00, 0x001, 0x00, 0x00,
    ];
    let invalid_addr_wire: [u8; 67] = [
        0x80, 0x0e, 0x40, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc0, 0x001, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0xff, 0x01, 0x0d, 0xb8,
        0x00, 0x01, 0x00, 0x002, 0x40, 0xff, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0xff,
        0x01, 0x0d, 0xb8, 0x00, 0x001, 0x00, 0x00,
    ];

    let good = PathAttribute::MpReach {
        extended_length: false,
        value: MpReach::Ipv6Unicast {
            next_hop_global: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x1),
            next_hop_local: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xc001, 0xbff, 0xfe7e, 0)),
            nlri: vec![
                Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8:1:2::/64").unwrap()).unwrap(),
                Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8:1:1::/64").unwrap()).unwrap(),
                Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8:1::/64").unwrap()).unwrap(),
            ],
        },
    };

    let invalid = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(40, &invalid_addr_wire[40..]) },
        PathAttributeParsingError::MpReachErrorError(MpReachParsingError::Ipv6UnicastError(
            Ipv6UnicastParsingError::InvalidUnicastNetwork(InvalidIpv6UnicastNetwork(
                Ipv6Net::from_str("ff01:db8:1:2::/64").unwrap(),
            )),
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &invalid_addr_wire,
        false,
        &invalid,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_mp_reach_nlri_ipv6_multicast() -> Result<(), PathAttributeWritingError>
{
    let good_wire = [
        0x80, 0x0e, 0x40, 0x00, 0x02, 0x02, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc0, 0x001, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0xff, 0x01, 0x0d, 0xb8,
        0x00, 0x01, 0x00, 0x002, 0x40, 0xff, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0xff,
        0x01, 0x0d, 0xb8, 0x00, 0x001, 0x00, 0x00,
    ];

    let invalid_addr_wire = [
        0x80, 0x0e, 0x40, 0x00, 0x02, 0x02, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xc0, 0x001, 0x0b, 0xff, 0xfe, 0x7e, 0x00, 0x00, 0x00, 0x40, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x01, 0x00, 0x002, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x01, 0x40, 0x20,
        0x01, 0x0d, 0xb8, 0x00, 0x001, 0x00, 0x00,
    ];

    let good = PathAttribute::MpReach {
        extended_length: false,
        value: MpReach::Ipv6Multicast {
            next_hop_global: Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x1),
            next_hop_local: Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0xc001, 0xbff, 0xfe7e, 0)),
            nlri: vec![
                Ipv6Multicast::from_net(Ipv6Net::from_str("ff01:db8:1:2::/64").unwrap()).unwrap(),
                Ipv6Multicast::from_net(Ipv6Net::from_str("ff01:db8:1:1::/64").unwrap()).unwrap(),
                Ipv6Multicast::from_net(Ipv6Net::from_str("ff01:db8:1::/64").unwrap()).unwrap(),
            ],
        },
    };

    let invalid = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(40, &invalid_addr_wire[40..]) },
        PathAttributeParsingError::MpReachErrorError(MpReachParsingError::Ipv6MulticastError(
            Ipv6MulticastParsingError::InvalidMulticastNetwork(InvalidIpv6MulticastNetwork(
                Ipv6Net::from_str("2001:db8:1:2::/64").unwrap(),
            )),
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &invalid_addr_wire,
        false,
        &invalid,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_mp_unreach_nlri_ipv6_unicast() -> Result<(), PathAttributeWritingError>
{
    let good_wire = [
        0x90, 0x0f, 0x00, 0x11, 0x00, 0x02, 0x01, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x40, 0xfd, 0xfd,
        0x00, 0x00, 0x00, 0x00, 0x8b, 0xea,
    ];
    let invalid_afi_wire = [
        0x90, 0x0f, 0x00, 0x11, 0x00, 0x02, 0x01, 0x20, 0xff, 0x01, 0x0d, 0xb8, 0x40, 0xfd, 0xfd,
        0x00, 0x00, 0x00, 0x00, 0x8b, 0xea,
    ];

    let good = PathAttribute::MpUnreach {
        extended_length: true,
        value: MpUnreach::Ipv6Unicast {
            nlri: vec![
                Ipv6Unicast::from_net(Ipv6Net::from_str("2001:db8::/32").unwrap()).unwrap(),
                Ipv6Unicast::from_net(Ipv6Net::from_str("fdfd:0:0:8bea::/64").unwrap()).unwrap(),
            ],
        },
    };

    let invalid_afi = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(7, &invalid_afi_wire[7..]) },
        PathAttributeParsingError::MpUnreachErrorError(MpUnreachParsingError::Ipv6UnicastError(
            Ipv6UnicastParsingError::InvalidUnicastNetwork(InvalidIpv6UnicastNetwork(
                Ipv6Net::from_str("ff01:db8::/32").unwrap(),
            )),
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &invalid_afi_wire,
        false,
        &invalid_afi,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_parse_path_attribute_mp_unreach_nlri_ipv6_multicast(
) -> Result<(), PathAttributeWritingError> {
    let good_wire = [
        0x90, 0x0f, 0x00, 0x11, 0x00, 0x02, 0x02, 0x20, 0xff, 0x01, 0x0d, 0xb8, 0x40, 0xff, 0xfd,
        0x00, 0x00, 0x00, 0x00, 0x8b, 0xea,
    ];
    let invalid_afi_wire = [
        0x90, 0x0f, 0x00, 0x11, 0x00, 0x02, 0x02, 0x20, 0x20, 0x01, 0x0d, 0xb8, 0x40, 0xff, 0xfd,
        0x00, 0x00, 0x00, 0x00, 0x8b, 0xea,
    ];

    let good = PathAttribute::MpUnreach {
        extended_length: true,
        value: MpUnreach::Ipv6Multicast {
            nlri: vec![
                Ipv6Multicast::from_net(Ipv6Net::from_str("ff01:db8::/32").unwrap()).unwrap(),
                Ipv6Multicast::from_net(Ipv6Net::from_str("fffd:0:0:8bea::/64").unwrap()).unwrap(),
            ],
        },
    };

    let invalid_afi = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(7, &invalid_afi_wire[7..]) },
        PathAttributeParsingError::MpUnreachErrorError(MpUnreachParsingError::Ipv6MulticastError(
            Ipv6MulticastParsingError::InvalidMulticastNetwork(InvalidIpv6MulticastNetwork(
                Ipv6Net::from_str("2001:db8::/32").unwrap(),
            )),
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, false, &good);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &invalid_afi_wire,
        false,
        &invalid_afi,
    );

    test_write(&good, &good_wire)?;
    Ok(())
}

#[test]
fn test_unknown_attribute() -> Result<(), UnknownAttributeWritingError> {
    let good_wire = [0x00, 0x04, 0xac, 0x10, 0x03, 0x02];
    let good_extended_wire = [0x00, 0x00, 0x04, 0xac, 0x10, 0x03, 0x02];

    let good = UnknownAttribute::new(
        true,
        false,
        0,
        PathAttributeLength::U8(4),
        vec![0xac, 0x10, 0x03, 0x02],
    );
    let good_extended = UnknownAttribute::new(
        true,
        false,
        0,
        PathAttributeLength::U16(4),
        vec![0xac, 0x10, 0x03, 0x02],
    );

    test_parsed_completely_with_three_inputs(&good_wire, true, false, false, &good);
    test_parsed_completely_with_three_inputs(
        &good_extended_wire,
        true,
        false,
        true,
        &good_extended,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    Ok(())
}

#[test]
fn test_path_attribute_unknown_attribute() -> Result<(), PathAttributeWritingError> {
    let good_wire = [0xc0, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64];
    let good_extended_wire = [0xd0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64];
    let bad_incomplete_wire = [0xc0, 0x00, 0x04, 0x00, 0x00, 0x00];

    let good = PathAttribute::UnknownAttribute {
        partial: false,
        value: UnknownAttribute::new(
            true,
            true,
            0,
            PathAttributeLength::U8(4),
            good_wire[3..].into(),
        ),
    };
    let good_extended = PathAttribute::UnknownAttribute {
        partial: false,
        value: UnknownAttribute::new(
            true,
            true,
            0,
            PathAttributeLength::U16(4),
            good_wire[3..].into(),
        ),
    };
    let bad_incomplete = LocatedPathAttributeParsingError::new(
        unsafe { Span::new_from_raw_offset(3, &bad_incomplete_wire[3..]) },
        PathAttributeParsingError::UnknownAttributeError(UnknownAttributeParsingError::NomError(
            ErrorKind::Eof,
        )),
    );

    test_parsed_completely_with_one_input(&good_wire, true, &good);
    test_parsed_completely_with_one_input(&good_extended_wire, true, &good_extended);
    test_parse_error_with_one_input::<PathAttribute, bool, LocatedPathAttributeParsingError<'_>>(
        &bad_incomplete_wire,
        false,
        &bad_incomplete,
    );

    test_write(&good, &good_wire)?;
    test_write(&good_extended, &good_extended_wire)?;
    Ok(())
}
