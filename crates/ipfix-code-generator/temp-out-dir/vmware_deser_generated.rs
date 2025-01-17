use nom::{InputIter, InputLength, Slice};
use crate::ie::vmware::*;

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum tenantProtocolParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantProtocolParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for tenantProtocolParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedtenantProtocolParsingError<'a>> for tenantProtocol {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedtenantProtocolParsingError<'a>> {
        let (buf, value) = match length {
            1 => nom::number::complete::be_u8(buf)?,
            _ => return Err(nom::Err::Error(LocatedtenantProtocolParsingError::new(buf, tenantProtocolParsingError::InvalidLength(length))))
        };
        let enum_val = tenantProtocol::from(value);
        Ok((buf, enum_val))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum tenantSourceIPv4ParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantSourceIPv4ParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for tenantSourceIPv4ParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedtenantSourceIPv4ParsingError<'a>> for tenantSourceIPv4 {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedtenantSourceIPv4ParsingError<'a>> {
        if length != 4 {
            return Err(nom::Err::Error(LocatedtenantSourceIPv4ParsingError::new(buf, tenantSourceIPv4ParsingError::InvalidLength(length))));
        };
        let (buf, ip) = nom::number::complete::be_u32(buf)?;
        let value = std::net::Ipv4Addr::from(ip);
        Ok((buf, tenantSourceIPv4(value)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum tenantDestIPv4ParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantDestIPv4ParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for tenantDestIPv4ParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedtenantDestIPv4ParsingError<'a>> for tenantDestIPv4 {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedtenantDestIPv4ParsingError<'a>> {
        if length != 4 {
            return Err(nom::Err::Error(LocatedtenantDestIPv4ParsingError::new(buf, tenantDestIPv4ParsingError::InvalidLength(length))));
        };
        let (buf, ip) = nom::number::complete::be_u32(buf)?;
        let value = std::net::Ipv4Addr::from(ip);
        Ok((buf, tenantDestIPv4(value)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum tenantSourceIPv6ParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantSourceIPv6ParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for tenantSourceIPv6ParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedtenantSourceIPv6ParsingError<'a>> for tenantSourceIPv6 {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedtenantSourceIPv6ParsingError<'a>> {
        if length != 16 {
            return Err(nom::Err::Error(LocatedtenantSourceIPv6ParsingError::new(buf, tenantSourceIPv6ParsingError::InvalidLength(length))));
        };
        let (buf, ip) = nom::number::complete::be_u128(buf)?;
        let value = std::net::Ipv6Addr::from(ip);
        Ok((buf, tenantSourceIPv6(value)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum tenantDestIPv6ParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantDestIPv6ParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for tenantDestIPv6ParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedtenantDestIPv6ParsingError<'a>> for tenantDestIPv6 {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedtenantDestIPv6ParsingError<'a>> {
        if length != 16 {
            return Err(nom::Err::Error(LocatedtenantDestIPv6ParsingError::new(buf, tenantDestIPv6ParsingError::InvalidLength(length))));
        };
        let (buf, ip) = nom::number::complete::be_u128(buf)?;
        let value = std::net::Ipv6Addr::from(ip);
        Ok((buf, tenantDestIPv6(value)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum tenantSourcePortParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantSourcePortParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for tenantSourcePortParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedtenantSourcePortParsingError<'a>> for tenantSourcePort {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedtenantSourcePortParsingError<'a>> {
        let (buf, value) = match length {
            1 => {
                let (buf, value) = nom::number::complete::be_u8(buf)?;
                (buf, value as u16)
            }
            2 => nom::number::complete::be_u16(buf)?,
            _ => return Err(nom::Err::Error(LocatedtenantSourcePortParsingError::new(buf, tenantSourcePortParsingError::InvalidLength(length))))
        };
        Ok((buf, tenantSourcePort(value)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum tenantDestPortParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantDestPortParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for tenantDestPortParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedtenantDestPortParsingError<'a>> for tenantDestPort {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedtenantDestPortParsingError<'a>> {
        let (buf, value) = match length {
            1 => {
                let (buf, value) = nom::number::complete::be_u8(buf)?;
                (buf, value as u16)
            }
            2 => nom::number::complete::be_u16(buf)?,
            _ => return Err(nom::Err::Error(LocatedtenantDestPortParsingError::new(buf, tenantDestPortParsingError::InvalidLength(length))))
        };
        Ok((buf, tenantDestPort(value)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum egressInterfaceAttrParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for egressInterfaceAttrParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for egressInterfaceAttrParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedegressInterfaceAttrParsingError<'a>> for egressInterfaceAttr {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedegressInterfaceAttrParsingError<'a>> {
        let (buf, value) = match length {
            1 => {
                let (buf, value) = nom::number::complete::be_u8(buf)?;
                (buf, value as u16)
            }
            2 => nom::number::complete::be_u16(buf)?,
            _ => return Err(nom::Err::Error(LocatedegressInterfaceAttrParsingError::new(buf, egressInterfaceAttrParsingError::InvalidLength(length))))
        };
        Ok((buf, egressInterfaceAttr(value)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum vxlanExportRoleParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for vxlanExportRoleParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for vxlanExportRoleParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedvxlanExportRoleParsingError<'a>> for vxlanExportRole {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedvxlanExportRoleParsingError<'a>> {
        let (buf, value) = match length {
            1 => nom::number::complete::be_u8(buf)?,
            _ => return Err(nom::Err::Error(LocatedvxlanExportRoleParsingError::new(buf, vxlanExportRoleParsingError::InvalidLength(length))))
        };
        Ok((buf, vxlanExportRole(value)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ingressInterfaceAttrParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for ingressInterfaceAttrParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for ingressInterfaceAttrParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedingressInterfaceAttrParsingError<'a>> for ingressInterfaceAttr {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedingressInterfaceAttrParsingError<'a>> {
        let (buf, value) = match length {
            1 => {
                let (buf, value) = nom::number::complete::be_u8(buf)?;
                (buf, value as u16)
            }
            2 => nom::number::complete::be_u16(buf)?,
            _ => return Err(nom::Err::Error(LocatedingressInterfaceAttrParsingError::new(buf, ingressInterfaceAttrParsingError::InvalidLength(length))))
        };
        Ok((buf, ingressInterfaceAttr(value)))
    }
}

impl std::fmt::Display for virtualObsIDParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::Utf8Error(val) => write!(f, "utf8 error {val}"),
        }
    }
}

impl std::error::Error for virtualObsIDParsingError {}
#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum virtualObsIDParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    Utf8Error(String),
}

impl<'a> nom::error::FromExternalError<netgauze_parse_utils::Span<'a>, std::str::Utf8Error>
for LocatedvirtualObsIDParsingError<'a>
{
    fn from_external_error(input: netgauze_parse_utils::Span<'a>, _kind: nom::error::ErrorKind, error: std::str::Utf8Error) -> Self {
        LocatedvirtualObsIDParsingError::new(
            input,
            virtualObsIDParsingError::Utf8Error(error.to_string()),
        )
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedvirtualObsIDParsingError<'a>> for virtualObsID {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedvirtualObsIDParsingError<'a>> {
        if length == u16::MAX {
            let (buf, short_length) = nom::number::complete::be_u8(buf)?;
            let (buf, variable_length) = if short_length == u8::MAX {
                let mut variable_length: u32= 0;
                let (buf, part1) = nom::number::complete::be_u8(buf)?;
                let (buf, part2) = nom::number::complete::be_u8(buf)?;
                let (buf, part3) = nom::number::complete::be_u8(buf)?;
                variable_length = (variable_length << 8) + part1  as u32;
                variable_length = (variable_length << 8) + part2  as u32;
                variable_length = (variable_length << 8) + part3  as u32;
                (buf, variable_length)
            } else {
                (buf, short_length as u32)
            };
            let (buf, value) = nom::combinator::map_res(nom::bytes::complete::take(variable_length), |str_buf: netgauze_parse_utils::Span<'_>| {
                let result = ::std::str::from_utf8(&str_buf);
                result.map(|x| x.to_string())
            })(buf)?;
            Ok((buf,  virtualObsID(value.to_string())))
        } else {
            let (buf, value) =
                nom::combinator::map_res(nom::bytes::complete::take(length), |str_buf: netgauze_parse_utils::Span<'_>| {
                    let nul_range_end = str_buf
                        .iter()
                        .position(|&c| c == b' ')
                        .unwrap_or(str_buf.len());
                    let result = ::std::str::from_utf8(&str_buf[..nul_range_end]);
                    result.map(|x| x.to_string())
                })(buf)?;
            Ok((buf,  virtualObsID(value)))
        }
    }
}
#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum ruleIdParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for ruleIdParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for ruleIdParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedruleIdParsingError<'a>> for ruleId {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedruleIdParsingError<'a>> {
        let len = length as usize;
        if length > 4 || buf.input_len() < len {
            return Err(nom::Err::Error(LocatedruleIdParsingError::new(buf, ruleIdParsingError::InvalidLength(length))))
        }
        let mut res = 0u32;
        for byte in buf.iter_elements().take(len) {
            res = (res << 8) + byte as u32;
        }
        Ok((buf.slice(len..), ruleId(res)))
    }
}

impl std::fmt::Display for vmUuidParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::Utf8Error(val) => write!(f, "utf8 error {val}"),
        }
    }
}

impl std::error::Error for vmUuidParsingError {}
#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum vmUuidParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    Utf8Error(String),
}

impl<'a> nom::error::FromExternalError<netgauze_parse_utils::Span<'a>, std::str::Utf8Error>
for LocatedvmUuidParsingError<'a>
{
    fn from_external_error(input: netgauze_parse_utils::Span<'a>, _kind: nom::error::ErrorKind, error: std::str::Utf8Error) -> Self {
        LocatedvmUuidParsingError::new(
            input,
            vmUuidParsingError::Utf8Error(error.to_string()),
        )
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedvmUuidParsingError<'a>> for vmUuid {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedvmUuidParsingError<'a>> {
        if length == u16::MAX {
            let (buf, short_length) = nom::number::complete::be_u8(buf)?;
            let (buf, variable_length) = if short_length == u8::MAX {
                let mut variable_length: u32= 0;
                let (buf, part1) = nom::number::complete::be_u8(buf)?;
                let (buf, part2) = nom::number::complete::be_u8(buf)?;
                let (buf, part3) = nom::number::complete::be_u8(buf)?;
                variable_length = (variable_length << 8) + part1  as u32;
                variable_length = (variable_length << 8) + part2  as u32;
                variable_length = (variable_length << 8) + part3  as u32;
                (buf, variable_length)
            } else {
                (buf, short_length as u32)
            };
            let (buf, value) = nom::combinator::map_res(nom::bytes::complete::take(variable_length), |str_buf: netgauze_parse_utils::Span<'_>| {
                let result = ::std::str::from_utf8(&str_buf);
                result.map(|x| x.to_string())
            })(buf)?;
            Ok((buf,  vmUuid(value.to_string())))
        } else {
            let (buf, value) =
                nom::combinator::map_res(nom::bytes::complete::take(length), |str_buf: netgauze_parse_utils::Span<'_>| {
                    let nul_range_end = str_buf
                        .iter()
                        .position(|&c| c == b' ')
                        .unwrap_or(str_buf.len());
                    let result = ::std::str::from_utf8(&str_buf[..nul_range_end]);
                    result.map(|x| x.to_string())
                })(buf)?;
            Ok((buf,  vmUuid(value)))
        }
    }
}
#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum vnicIndexParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for vnicIndexParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for vnicIndexParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedvnicIndexParsingError<'a>> for vnicIndex {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedvnicIndexParsingError<'a>> {
        let len = length as usize;
        if length > 4 || buf.input_len() < len {
            return Err(nom::Err::Error(LocatedvnicIndexParsingError::new(buf, vnicIndexParsingError::InvalidLength(length))))
        }
        let mut res = 0u32;
        for byte in buf.iter_elements().take(len) {
            res = (res << 8) + byte as u32;
        }
        Ok((buf.slice(len..), vnicIndex(res)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum sessionFlagsParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for sessionFlagsParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for sessionFlagsParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedsessionFlagsParsingError<'a>> for sessionFlags {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedsessionFlagsParsingError<'a>> {
        let (buf, value) = match length {
            1 => nom::number::complete::be_u8(buf)?,
            _ => return Err(nom::Err::Error(LocatedsessionFlagsParsingError::new(buf, sessionFlagsParsingError::InvalidLength(length))))
        };
        Ok((buf, sessionFlags(value)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum flowDirectionParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for flowDirectionParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for flowDirectionParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedflowDirectionParsingError<'a>> for flowDirection {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedflowDirectionParsingError<'a>> {
        let (buf, value) = match length {
            1 => nom::number::complete::be_u8(buf)?,
            _ => return Err(nom::Err::Error(LocatedflowDirectionParsingError::new(buf, flowDirectionParsingError::InvalidLength(length))))
        };
        let enum_val = flowDirection::from(value);
        Ok((buf, enum_val))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum algControlFlowIdParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for algControlFlowIdParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for algControlFlowIdParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedalgControlFlowIdParsingError<'a>> for algControlFlowId {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedalgControlFlowIdParsingError<'a>> {
        let len = length as usize;
        if length > 8 || buf.input_len() < len {
            return Err(nom::Err::Error(LocatedalgControlFlowIdParsingError::new(buf, algControlFlowIdParsingError::InvalidLength(length))))
        }
        let mut res = 0u64;
        for byte in buf.iter_elements().take(len) {
            res = (res << 8) + byte as u64;
        }
        Ok((buf.slice(len..), algControlFlowId(res)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum algTypeParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for algTypeParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for algTypeParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedalgTypeParsingError<'a>> for algType {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedalgTypeParsingError<'a>> {
        let (buf, value) = match length {
            1 => nom::number::complete::be_u8(buf)?,
            _ => return Err(nom::Err::Error(LocatedalgTypeParsingError::new(buf, algTypeParsingError::InvalidLength(length))))
        };
        Ok((buf, algType(value)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum algFlowTypeParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for algFlowTypeParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for algFlowTypeParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedalgFlowTypeParsingError<'a>> for algFlowType {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedalgFlowTypeParsingError<'a>> {
        let (buf, value) = match length {
            1 => nom::number::complete::be_u8(buf)?,
            _ => return Err(nom::Err::Error(LocatedalgFlowTypeParsingError::new(buf, algFlowTypeParsingError::InvalidLength(length))))
        };
        Ok((buf, algFlowType(value)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum averageLatencyParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for averageLatencyParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for averageLatencyParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedaverageLatencyParsingError<'a>> for averageLatency {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedaverageLatencyParsingError<'a>> {
        let len = length as usize;
        if length > 4 || buf.input_len() < len {
            return Err(nom::Err::Error(LocatedaverageLatencyParsingError::new(buf, averageLatencyParsingError::InvalidLength(length))))
        }
        let mut res = 0u32;
        for byte in buf.iter_elements().take(len) {
            res = (res << 8) + byte as u32;
        }
        Ok((buf.slice(len..), averageLatency(res)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum retransmissionCountParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for retransmissionCountParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for retransmissionCountParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedretransmissionCountParsingError<'a>> for retransmissionCount {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedretransmissionCountParsingError<'a>> {
        let len = length as usize;
        if length > 4 || buf.input_len() < len {
            return Err(nom::Err::Error(LocatedretransmissionCountParsingError::new(buf, retransmissionCountParsingError::InvalidLength(length))))
        }
        let mut res = 0u32;
        for byte in buf.iter_elements().take(len) {
            res = (res << 8) + byte as u32;
        }
        Ok((buf.slice(len..), retransmissionCount(res)))
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum vifUuidParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    InvalidLength(u16),
}

impl std::fmt::Display for vifUuidParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::InvalidLength(len) => write!(f, "invalid field length {len}"),
        }
    }
}

impl std::error::Error for vifUuidParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::InvalidLength(_len) => None,
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedvifUuidParsingError<'a>> for vifUuid {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedvifUuidParsingError<'a>> {
        let (buf, value) = nom::multi::count(nom::number::complete::be_u8, length as usize)(buf)?;
        Ok((buf, vifUuid(value)))
    }
}

impl std::fmt::Display for vifIdParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::Utf8Error(val) => write!(f, "utf8 error {val}"),
        }
    }
}

impl std::error::Error for vifIdParsingError {}
#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum vifIdParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    Utf8Error(String),
}

impl<'a> nom::error::FromExternalError<netgauze_parse_utils::Span<'a>, std::str::Utf8Error>
for LocatedvifIdParsingError<'a>
{
    fn from_external_error(input: netgauze_parse_utils::Span<'a>, _kind: nom::error::ErrorKind, error: std::str::Utf8Error) -> Self {
        LocatedvifIdParsingError::new(
            input,
            vifIdParsingError::Utf8Error(error.to_string()),
        )
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithOneInput<'a, u16, LocatedvifIdParsingError<'a>> for vifId {
    #[inline]
    fn from_wire(buf: netgauze_parse_utils::Span<'a>, length: u16) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedvifIdParsingError<'a>> {
        if length == u16::MAX {
            let (buf, short_length) = nom::number::complete::be_u8(buf)?;
            let (buf, variable_length) = if short_length == u8::MAX {
                let mut variable_length: u32= 0;
                let (buf, part1) = nom::number::complete::be_u8(buf)?;
                let (buf, part2) = nom::number::complete::be_u8(buf)?;
                let (buf, part3) = nom::number::complete::be_u8(buf)?;
                variable_length = (variable_length << 8) + part1  as u32;
                variable_length = (variable_length << 8) + part2  as u32;
                variable_length = (variable_length << 8) + part3  as u32;
                (buf, variable_length)
            } else {
                (buf, short_length as u32)
            };
            let (buf, value) = nom::combinator::map_res(nom::bytes::complete::take(variable_length), |str_buf: netgauze_parse_utils::Span<'_>| {
                let result = ::std::str::from_utf8(&str_buf);
                result.map(|x| x.to_string())
            })(buf)?;
            Ok((buf,  vifId(value.to_string())))
        } else {
            let (buf, value) =
                nom::combinator::map_res(nom::bytes::complete::take(length), |str_buf: netgauze_parse_utils::Span<'_>| {
                    let nul_range_end = str_buf
                        .iter()
                        .position(|&c| c == b' ')
                        .unwrap_or(str_buf.len());
                    let result = ::std::str::from_utf8(&str_buf[..nul_range_end]);
                    result.map(|x| x.to_string())
                })(buf)?;
            Ok((buf,  vifId(value)))
        }
    }
}
#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::LocatedError, Eq, PartialEq, Clone, Debug, serde::Serialize, serde::Deserialize)]
pub enum FieldParsingError {
    #[serde(with = "netgauze_parse_utils::ErrorKindSerdeDeref")]
    NomError(#[from_nom] nom::error::ErrorKind),
    tenantProtocolError(#[from_located(module = "self")] tenantProtocolParsingError),
    tenantSourceIPv4Error(#[from_located(module = "self")] tenantSourceIPv4ParsingError),
    tenantDestIPv4Error(#[from_located(module = "self")] tenantDestIPv4ParsingError),
    tenantSourceIPv6Error(#[from_located(module = "self")] tenantSourceIPv6ParsingError),
    tenantDestIPv6Error(#[from_located(module = "self")] tenantDestIPv6ParsingError),
    tenantSourcePortError(#[from_located(module = "self")] tenantSourcePortParsingError),
    tenantDestPortError(#[from_located(module = "self")] tenantDestPortParsingError),
    egressInterfaceAttrError(#[from_located(module = "self")] egressInterfaceAttrParsingError),
    vxlanExportRoleError(#[from_located(module = "self")] vxlanExportRoleParsingError),
    ingressInterfaceAttrError(#[from_located(module = "self")] ingressInterfaceAttrParsingError),
    virtualObsIDError(#[from_located(module = "self")] virtualObsIDParsingError),
    ruleIdError(#[from_located(module = "self")] ruleIdParsingError),
    vmUuidError(#[from_located(module = "self")] vmUuidParsingError),
    vnicIndexError(#[from_located(module = "self")] vnicIndexParsingError),
    sessionFlagsError(#[from_located(module = "self")] sessionFlagsParsingError),
    flowDirectionError(#[from_located(module = "self")] flowDirectionParsingError),
    algControlFlowIdError(#[from_located(module = "self")] algControlFlowIdParsingError),
    algTypeError(#[from_located(module = "self")] algTypeParsingError),
    algFlowTypeError(#[from_located(module = "self")] algFlowTypeParsingError),
    averageLatencyError(#[from_located(module = "self")] averageLatencyParsingError),
    retransmissionCountError(#[from_located(module = "self")] retransmissionCountParsingError),
    vifUuidError(#[from_located(module = "self")] vifUuidParsingError),
    vifIdError(#[from_located(module = "self")] vifIdParsingError),
}


impl std::fmt::Display for FieldParsingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
           Self::NomError(err) => write!(f, "Nom error {}", nom::Err::Error(err)),
           Self::tenantProtocolError(err) => write!(f, "{err}"),
           Self::tenantSourceIPv4Error(err) => write!(f, "{err}"),
           Self::tenantDestIPv4Error(err) => write!(f, "{err}"),
           Self::tenantSourceIPv6Error(err) => write!(f, "{err}"),
           Self::tenantDestIPv6Error(err) => write!(f, "{err}"),
           Self::tenantSourcePortError(err) => write!(f, "{err}"),
           Self::tenantDestPortError(err) => write!(f, "{err}"),
           Self::egressInterfaceAttrError(err) => write!(f, "{err}"),
           Self::vxlanExportRoleError(err) => write!(f, "{err}"),
           Self::ingressInterfaceAttrError(err) => write!(f, "{err}"),
           Self::virtualObsIDError(err) => write!(f, "{err}"),
           Self::ruleIdError(err) => write!(f, "{err}"),
           Self::vmUuidError(err) => write!(f, "{err}"),
           Self::vnicIndexError(err) => write!(f, "{err}"),
           Self::sessionFlagsError(err) => write!(f, "{err}"),
           Self::flowDirectionError(err) => write!(f, "{err}"),
           Self::algControlFlowIdError(err) => write!(f, "{err}"),
           Self::algTypeError(err) => write!(f, "{err}"),
           Self::algFlowTypeError(err) => write!(f, "{err}"),
           Self::averageLatencyError(err) => write!(f, "{err}"),
           Self::retransmissionCountError(err) => write!(f, "{err}"),
           Self::vifUuidError(err) => write!(f, "{err}"),
           Self::vifIdError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for FieldParsingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
           Self::NomError(_err) => None,
           Self::tenantProtocolError(err) => Some(err),
           Self::tenantSourceIPv4Error(err) => Some(err),
           Self::tenantDestIPv4Error(err) => Some(err),
           Self::tenantSourceIPv6Error(err) => Some(err),
           Self::tenantDestIPv6Error(err) => Some(err),
           Self::tenantSourcePortError(err) => Some(err),
           Self::tenantDestPortError(err) => Some(err),
           Self::egressInterfaceAttrError(err) => Some(err),
           Self::vxlanExportRoleError(err) => Some(err),
           Self::ingressInterfaceAttrError(err) => Some(err),
           Self::virtualObsIDError(err) => Some(err),
           Self::ruleIdError(err) => Some(err),
           Self::vmUuidError(err) => Some(err),
           Self::vnicIndexError(err) => Some(err),
           Self::sessionFlagsError(err) => Some(err),
           Self::flowDirectionError(err) => Some(err),
           Self::algControlFlowIdError(err) => Some(err),
           Self::algTypeError(err) => Some(err),
           Self::algFlowTypeError(err) => Some(err),
           Self::averageLatencyError(err) => Some(err),
           Self::retransmissionCountError(err) => Some(err),
           Self::vifUuidError(err) => Some(err),
           Self::vifIdError(err) => Some(err),
        }
    }
}

impl<'a> netgauze_parse_utils::ReadablePduWithTwoInputs<'a, &IE, u16, LocatedFieldParsingError<'a>>
for Field {
    #[inline]
    fn from_wire(
        buf: netgauze_parse_utils::Span<'a>,
        ie: &IE,
        length: u16,
    ) -> nom::IResult<netgauze_parse_utils::Span<'a>, Self, LocatedFieldParsingError<'a>> {
        let (buf, value) = match ie {
            IE::tenantProtocol => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedtenantProtocolParsingError<'_>, LocatedFieldParsingError<'_>, tenantProtocol>(buf, length)?;
                (buf, Field::tenantProtocol(value))
            }
            IE::tenantSourceIPv4 => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedtenantSourceIPv4ParsingError<'_>, LocatedFieldParsingError<'_>, tenantSourceIPv4>(buf, length)?;
                (buf, Field::tenantSourceIPv4(value))
            }
            IE::tenantDestIPv4 => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedtenantDestIPv4ParsingError<'_>, LocatedFieldParsingError<'_>, tenantDestIPv4>(buf, length)?;
                (buf, Field::tenantDestIPv4(value))
            }
            IE::tenantSourceIPv6 => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedtenantSourceIPv6ParsingError<'_>, LocatedFieldParsingError<'_>, tenantSourceIPv6>(buf, length)?;
                (buf, Field::tenantSourceIPv6(value))
            }
            IE::tenantDestIPv6 => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedtenantDestIPv6ParsingError<'_>, LocatedFieldParsingError<'_>, tenantDestIPv6>(buf, length)?;
                (buf, Field::tenantDestIPv6(value))
            }
            IE::tenantSourcePort => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedtenantSourcePortParsingError<'_>, LocatedFieldParsingError<'_>, tenantSourcePort>(buf, length)?;
                (buf, Field::tenantSourcePort(value))
            }
            IE::tenantDestPort => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedtenantDestPortParsingError<'_>, LocatedFieldParsingError<'_>, tenantDestPort>(buf, length)?;
                (buf, Field::tenantDestPort(value))
            }
            IE::egressInterfaceAttr => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedegressInterfaceAttrParsingError<'_>, LocatedFieldParsingError<'_>, egressInterfaceAttr>(buf, length)?;
                (buf, Field::egressInterfaceAttr(value))
            }
            IE::vxlanExportRole => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedvxlanExportRoleParsingError<'_>, LocatedFieldParsingError<'_>, vxlanExportRole>(buf, length)?;
                (buf, Field::vxlanExportRole(value))
            }
            IE::ingressInterfaceAttr => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedingressInterfaceAttrParsingError<'_>, LocatedFieldParsingError<'_>, ingressInterfaceAttr>(buf, length)?;
                (buf, Field::ingressInterfaceAttr(value))
            }
            IE::virtualObsID => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedvirtualObsIDParsingError<'_>, LocatedFieldParsingError<'_>, virtualObsID>(buf, length)?;
                (buf, Field::virtualObsID(value))
            }
            IE::ruleId => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedruleIdParsingError<'_>, LocatedFieldParsingError<'_>, ruleId>(buf, length)?;
                (buf, Field::ruleId(value))
            }
            IE::vmUuid => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedvmUuidParsingError<'_>, LocatedFieldParsingError<'_>, vmUuid>(buf, length)?;
                (buf, Field::vmUuid(value))
            }
            IE::vnicIndex => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedvnicIndexParsingError<'_>, LocatedFieldParsingError<'_>, vnicIndex>(buf, length)?;
                (buf, Field::vnicIndex(value))
            }
            IE::sessionFlags => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedsessionFlagsParsingError<'_>, LocatedFieldParsingError<'_>, sessionFlags>(buf, length)?;
                (buf, Field::sessionFlags(value))
            }
            IE::flowDirection => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedflowDirectionParsingError<'_>, LocatedFieldParsingError<'_>, flowDirection>(buf, length)?;
                (buf, Field::flowDirection(value))
            }
            IE::algControlFlowId => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedalgControlFlowIdParsingError<'_>, LocatedFieldParsingError<'_>, algControlFlowId>(buf, length)?;
                (buf, Field::algControlFlowId(value))
            }
            IE::algType => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedalgTypeParsingError<'_>, LocatedFieldParsingError<'_>, algType>(buf, length)?;
                (buf, Field::algType(value))
            }
            IE::algFlowType => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedalgFlowTypeParsingError<'_>, LocatedFieldParsingError<'_>, algFlowType>(buf, length)?;
                (buf, Field::algFlowType(value))
            }
            IE::averageLatency => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedaverageLatencyParsingError<'_>, LocatedFieldParsingError<'_>, averageLatency>(buf, length)?;
                (buf, Field::averageLatency(value))
            }
            IE::retransmissionCount => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedretransmissionCountParsingError<'_>, LocatedFieldParsingError<'_>, retransmissionCount>(buf, length)?;
                (buf, Field::retransmissionCount(value))
            }
            IE::vifUuid => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedvifUuidParsingError<'_>, LocatedFieldParsingError<'_>, vifUuid>(buf, length)?;
                (buf, Field::vifUuid(value))
            }
            IE::vifId => {
                let (buf, value) = netgauze_parse_utils::parse_into_located_one_input::<'_, u16, LocatedvifIdParsingError<'_>, LocatedFieldParsingError<'_>, vifId>(buf, length)?;
                (buf, Field::vifId(value))
            }
        };
       Ok((buf, value))
    }
}
