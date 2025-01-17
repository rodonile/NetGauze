use byteorder::WriteBytesExt;
use crate::ie::vmware::*;

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tenantProtocolWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantProtocolWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for tenantProtocolWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tenantProtocolWritingError> for tenantProtocol {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), tenantProtocolWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tenantSourceIPv4WritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantSourceIPv4WritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for tenantSourceIPv4WritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tenantSourceIPv4WritingError> for tenantSourceIPv4 {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), tenantSourceIPv4WritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tenantDestIPv4WritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantDestIPv4WritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for tenantDestIPv4WritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tenantDestIPv4WritingError> for tenantDestIPv4 {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), tenantDestIPv4WritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tenantSourceIPv6WritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantSourceIPv6WritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for tenantSourceIPv6WritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tenantSourceIPv6WritingError> for tenantSourceIPv6 {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), tenantSourceIPv6WritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tenantDestIPv6WritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantDestIPv6WritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for tenantDestIPv6WritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tenantDestIPv6WritingError> for tenantDestIPv6 {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), tenantDestIPv6WritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tenantSourcePortWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantSourcePortWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for tenantSourcePortWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tenantSourcePortWritingError> for tenantSourcePort {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tenantSourcePortWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 if usize::from(len) > be_bytes.len() {
                     return Err(tenantSourcePortWritingError::InvalidLength(len));
                 }
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tenantDestPortWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for tenantDestPortWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for tenantDestPortWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tenantDestPortWritingError> for tenantDestPort {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tenantDestPortWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 if usize::from(len) > be_bytes.len() {
                     return Err(tenantDestPortWritingError::InvalidLength(len));
                 }
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum egressInterfaceAttrWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for egressInterfaceAttrWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for egressInterfaceAttrWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, egressInterfaceAttrWritingError> for egressInterfaceAttr {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), egressInterfaceAttrWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 if usize::from(len) > be_bytes.len() {
                     return Err(egressInterfaceAttrWritingError::InvalidLength(len));
                 }
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum vxlanExportRoleWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for vxlanExportRoleWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for vxlanExportRoleWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, vxlanExportRoleWritingError> for vxlanExportRole {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), vxlanExportRoleWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ingressInterfaceAttrWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for ingressInterfaceAttrWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for ingressInterfaceAttrWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ingressInterfaceAttrWritingError> for ingressInterfaceAttr {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ingressInterfaceAttrWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 if usize::from(len) > be_bytes.len() {
                     return Err(ingressInterfaceAttrWritingError::InvalidLength(len));
                 }
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum virtualObsIDWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for virtualObsIDWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for virtualObsIDWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, virtualObsIDWritingError> for virtualObsID {
    const BASE_LENGTH: usize = 0;

    fn len(&self, length: Option<u16>) -> usize {
        match length {
            None => self.0.len(),
            Some(len) => if len == u16::MAX {
                if self.0.len() < u8::MAX as usize {
                    // One octet for the length field
                    self.0.len() + 1
                } else {
                    // 4 octets for the length field, first is 255 and other three carries the len
                    self.0.len() + 4
                }
            } else {
                len as usize
            },
        }
    }

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), virtualObsIDWritingError> {
        match length {
            Some(u16::MAX) | None => {
                let bytes = self.0.as_bytes();
                if bytes.len() < u8::MAX as usize {
                    writer.write_u8(bytes.len() as u8)?;
                } else {
                    writer.write_u8(u8::MAX)?;
                    writer.write_all(&bytes.len().to_be_bytes()[1..])?;
                }
                writer.write_all(self.0.as_bytes())?;
            }
            Some(len) => {
                writer.write_all(self.0.as_bytes())?;
                // fill the rest with zeros
                for _ in self.0.as_bytes().len()..(len as usize) {
                    writer.write_u8(0)?
                }
            }
        }
        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ruleIdWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for ruleIdWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for ruleIdWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ruleIdWritingError> for ruleId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ruleIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 if usize::from(len) > be_bytes.len() {
                     return Err(ruleIdWritingError::InvalidLength(len));
                 }
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum vmUuidWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for vmUuidWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for vmUuidWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, vmUuidWritingError> for vmUuid {
    const BASE_LENGTH: usize = 0;

    fn len(&self, length: Option<u16>) -> usize {
        match length {
            None => self.0.len(),
            Some(len) => if len == u16::MAX {
                if self.0.len() < u8::MAX as usize {
                    // One octet for the length field
                    self.0.len() + 1
                } else {
                    // 4 octets for the length field, first is 255 and other three carries the len
                    self.0.len() + 4
                }
            } else {
                len as usize
            },
        }
    }

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), vmUuidWritingError> {
        match length {
            Some(u16::MAX) | None => {
                let bytes = self.0.as_bytes();
                if bytes.len() < u8::MAX as usize {
                    writer.write_u8(bytes.len() as u8)?;
                } else {
                    writer.write_u8(u8::MAX)?;
                    writer.write_all(&bytes.len().to_be_bytes()[1..])?;
                }
                writer.write_all(self.0.as_bytes())?;
            }
            Some(len) => {
                writer.write_all(self.0.as_bytes())?;
                // fill the rest with zeros
                for _ in self.0.as_bytes().len()..(len as usize) {
                    writer.write_u8(0)?
                }
            }
        }
        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum vnicIndexWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for vnicIndexWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for vnicIndexWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, vnicIndexWritingError> for vnicIndex {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), vnicIndexWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 if usize::from(len) > be_bytes.len() {
                     return Err(vnicIndexWritingError::InvalidLength(len));
                 }
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sessionFlagsWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for sessionFlagsWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for sessionFlagsWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sessionFlagsWritingError> for sessionFlags {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), sessionFlagsWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowDirectionWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for flowDirectionWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for flowDirectionWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowDirectionWritingError> for flowDirection {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), flowDirectionWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum algControlFlowIdWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for algControlFlowIdWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for algControlFlowIdWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, algControlFlowIdWritingError> for algControlFlowId {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), algControlFlowIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 if usize::from(len) > be_bytes.len() {
                     return Err(algControlFlowIdWritingError::InvalidLength(len));
                 }
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum algTypeWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for algTypeWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for algTypeWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, algTypeWritingError> for algType {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), algTypeWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum algFlowTypeWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for algFlowTypeWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for algFlowTypeWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, algFlowTypeWritingError> for algFlowType {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), algFlowTypeWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum averageLatencyWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for averageLatencyWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for averageLatencyWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, averageLatencyWritingError> for averageLatency {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), averageLatencyWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 if usize::from(len) > be_bytes.len() {
                     return Err(averageLatencyWritingError::InvalidLength(len));
                 }
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum retransmissionCountWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for retransmissionCountWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for retransmissionCountWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, retransmissionCountWritingError> for retransmissionCount {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), retransmissionCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 if usize::from(len) > be_bytes.len() {
                     return Err(retransmissionCountWritingError::InvalidLength(len));
                 }
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum vifUuidWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for vifUuidWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for vifUuidWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, vifUuidWritingError> for vifUuid {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), vifUuidWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum vifIdWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for vifIdWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for vifIdWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, vifIdWritingError> for vifId {
    const BASE_LENGTH: usize = 0;

    fn len(&self, length: Option<u16>) -> usize {
        match length {
            None => self.0.len(),
            Some(len) => if len == u16::MAX {
                if self.0.len() < u8::MAX as usize {
                    // One octet for the length field
                    self.0.len() + 1
                } else {
                    // 4 octets for the length field, first is 255 and other three carries the len
                    self.0.len() + 4
                }
            } else {
                len as usize
            },
        }
    }

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), vifIdWritingError> {
        match length {
            Some(u16::MAX) | None => {
                let bytes = self.0.as_bytes();
                if bytes.len() < u8::MAX as usize {
                    writer.write_u8(bytes.len() as u8)?;
                } else {
                    writer.write_u8(u8::MAX)?;
                    writer.write_all(&bytes.len().to_be_bytes()[1..])?;
                }
                writer.write_all(self.0.as_bytes())?;
            }
            Some(len) => {
                writer.write_all(self.0.as_bytes())?;
                // fill the rest with zeros
                for _ in self.0.as_bytes().len()..(len as usize) {
                    writer.write_u8(0)?
                }
            }
        }
        Ok(())
    }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum FieldWritingError {
    StdIOError(#[from_std_io_error] String),
    tenantProtocolError(#[from] tenantProtocolWritingError),
    tenantSourceIPv4Error(#[from] tenantSourceIPv4WritingError),
    tenantDestIPv4Error(#[from] tenantDestIPv4WritingError),
    tenantSourceIPv6Error(#[from] tenantSourceIPv6WritingError),
    tenantDestIPv6Error(#[from] tenantDestIPv6WritingError),
    tenantSourcePortError(#[from] tenantSourcePortWritingError),
    tenantDestPortError(#[from] tenantDestPortWritingError),
    egressInterfaceAttrError(#[from] egressInterfaceAttrWritingError),
    vxlanExportRoleError(#[from] vxlanExportRoleWritingError),
    ingressInterfaceAttrError(#[from] ingressInterfaceAttrWritingError),
    virtualObsIDError(#[from] virtualObsIDWritingError),
    ruleIdError(#[from] ruleIdWritingError),
    vmUuidError(#[from] vmUuidWritingError),
    vnicIndexError(#[from] vnicIndexWritingError),
    sessionFlagsError(#[from] sessionFlagsWritingError),
    flowDirectionError(#[from] flowDirectionWritingError),
    algControlFlowIdError(#[from] algControlFlowIdWritingError),
    algTypeError(#[from] algTypeWritingError),
    algFlowTypeError(#[from] algFlowTypeWritingError),
    averageLatencyError(#[from] averageLatencyWritingError),
    retransmissionCountError(#[from] retransmissionCountWritingError),
    vifUuidError(#[from] vifUuidWritingError),
    vifIdError(#[from] vifIdWritingError),
}

impl std::fmt::Display for FieldWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
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

impl std::error::Error for FieldWritingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StdIOError(_) => None,
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
        }    }}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, FieldWritingError> for Field {
    const BASE_LENGTH: usize = 0;

    fn len(&self, length: Option<u16>) -> usize {
        match self {
            Self::tenantProtocol(value) => value.len(length),
            Self::tenantSourceIPv4(value) => value.len(length),
            Self::tenantDestIPv4(value) => value.len(length),
            Self::tenantSourceIPv6(value) => value.len(length),
            Self::tenantDestIPv6(value) => value.len(length),
            Self::tenantSourcePort(value) => value.len(length),
            Self::tenantDestPort(value) => value.len(length),
            Self::egressInterfaceAttr(value) => value.len(length),
            Self::vxlanExportRole(value) => value.len(length),
            Self::ingressInterfaceAttr(value) => value.len(length),
            Self::virtualObsID(value) => value.len(length),
            Self::ruleId(value) => value.len(length),
            Self::vmUuid(value) => value.len(length),
            Self::vnicIndex(value) => value.len(length),
            Self::sessionFlags(value) => value.len(length),
            Self::flowDirection(value) => value.len(length),
            Self::algControlFlowId(value) => value.len(length),
            Self::algType(value) => value.len(length),
            Self::algFlowType(value) => value.len(length),
            Self::averageLatency(value) => value.len(length),
            Self::retransmissionCount(value) => value.len(length),
            Self::vifUuid(value) => value.len(length),
            Self::vifId(value) => value.len(length),
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), FieldWritingError> {
        match self {
           Self::tenantProtocol(value) => value.write(writer, length)?,
           Self::tenantSourceIPv4(value) => value.write(writer, length)?,
           Self::tenantDestIPv4(value) => value.write(writer, length)?,
           Self::tenantSourceIPv6(value) => value.write(writer, length)?,
           Self::tenantDestIPv6(value) => value.write(writer, length)?,
           Self::tenantSourcePort(value) => value.write(writer, length)?,
           Self::tenantDestPort(value) => value.write(writer, length)?,
           Self::egressInterfaceAttr(value) => value.write(writer, length)?,
           Self::vxlanExportRole(value) => value.write(writer, length)?,
           Self::ingressInterfaceAttr(value) => value.write(writer, length)?,
           Self::virtualObsID(value) => value.write(writer, length)?,
           Self::ruleId(value) => value.write(writer, length)?,
           Self::vmUuid(value) => value.write(writer, length)?,
           Self::vnicIndex(value) => value.write(writer, length)?,
           Self::sessionFlags(value) => value.write(writer, length)?,
           Self::flowDirection(value) => value.write(writer, length)?,
           Self::algControlFlowId(value) => value.write(writer, length)?,
           Self::algType(value) => value.write(writer, length)?,
           Self::algFlowType(value) => value.write(writer, length)?,
           Self::averageLatency(value) => value.write(writer, length)?,
           Self::retransmissionCount(value) => value.write(writer, length)?,
           Self::vifUuid(value) => value.write(writer, length)?,
           Self::vifId(value) => value.write(writer, length)?,
        }
        Ok(())
    }
}

