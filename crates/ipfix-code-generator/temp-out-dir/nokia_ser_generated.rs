use byteorder::WriteBytesExt;
use crate::ie::nokia::*;

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum aluInsideServiceIdWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for aluInsideServiceIdWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for aluInsideServiceIdWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, aluInsideServiceIdWritingError> for aluInsideServiceId {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), aluInsideServiceIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 if usize::from(len) > be_bytes.len() {
                     return Err(aluInsideServiceIdWritingError::InvalidLength(len));
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
pub enum aluOutsideServiceIdWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for aluOutsideServiceIdWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for aluOutsideServiceIdWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, aluOutsideServiceIdWritingError> for aluOutsideServiceId {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), aluOutsideServiceIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 if usize::from(len) > be_bytes.len() {
                     return Err(aluOutsideServiceIdWritingError::InvalidLength(len));
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
pub enum aluNatSubStringWritingError {
    StdIOError(#[from_std_io_error] String),
    InvalidLength(u16),
}

impl std::fmt::Display for aluNatSubStringWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::InvalidLength(len) => write!(f, "invalid length {len}"),
        }
    }
}

impl std::error::Error for aluNatSubStringWritingError {}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, aluNatSubStringWritingError> for aluNatSubString {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), aluNatSubStringWritingError> {
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
    aluInsideServiceIdError(#[from] aluInsideServiceIdWritingError),
    aluOutsideServiceIdError(#[from] aluOutsideServiceIdWritingError),
    aluNatSubStringError(#[from] aluNatSubStringWritingError),
}

impl std::fmt::Display for FieldWritingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StdIOError(err) => write!(f, "{err}"),
            Self::aluInsideServiceIdError(err) => write!(f, "{err}"),
            Self::aluOutsideServiceIdError(err) => write!(f, "{err}"),
            Self::aluNatSubStringError(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for FieldWritingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StdIOError(_) => None,
            Self::aluInsideServiceIdError(err) => Some(err),
            Self::aluOutsideServiceIdError(err) => Some(err),
            Self::aluNatSubStringError(err) => Some(err),
        }    }}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, FieldWritingError> for Field {
    const BASE_LENGTH: usize = 0;

    fn len(&self, length: Option<u16>) -> usize {
        match self {
            Self::aluInsideServiceId(value) => value.len(length),
            Self::aluOutsideServiceId(value) => value.len(length),
            Self::aluNatSubString(value) => value.len(length),
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), FieldWritingError> {
        match self {
           Self::aluInsideServiceId(value) => value.write(writer, length)?,
           Self::aluOutsideServiceId(value) => value.write(writer, length)?,
           Self::aluNatSubString(value) => value.write(writer, length)?,
        }
        Ok(())
    }
}

