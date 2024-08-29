use crate::ie::*;

pub mod nokia {include!(concat!(env!("OUT_DIR"), "/nokia_ser_generated.rs"));}

pub mod netgauze {include!(concat!(env!("OUT_DIR"), "/netgauze_ser_generated.rs"));}

pub mod cisco {include!(concat!(env!("OUT_DIR"), "/cisco_ser_generated.rs"));}

pub mod vmware {include!(concat!(env!("OUT_DIR"), "/vmware_ser_generated.rs"));}

use byteorder::WriteBytesExt;


#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum octetDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, octetDeltaCountWritingError> for octetDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), octetDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum packetDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, packetDeltaCountWritingError> for packetDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), packetDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum deltaFlowCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, deltaFlowCountWritingError> for deltaFlowCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), deltaFlowCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum protocolIdentifierWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, protocolIdentifierWritingError> for protocolIdentifier {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), protocolIdentifierWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipClassOfServiceWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipClassOfServiceWritingError> for ipClassOfService {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ipClassOfServiceWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpControlBitsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpControlBitsWritingError> for netgauze_iana::tcp::TCPHeaderFlags {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpControlBitsWritingError> {
         let num_val = u16::from(*self);
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sourceTransportPortWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sourceTransportPortWritingError> for sourceTransportPort {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), sourceTransportPortWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sourceIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sourceIPv4AddressWritingError> for sourceIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), sourceIPv4AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sourceIPv4PrefixLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sourceIPv4PrefixLengthWritingError> for sourceIPv4PrefixLength {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), sourceIPv4PrefixLengthWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ingressInterfaceWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ingressInterfaceWritingError> for ingressInterface {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ingressInterfaceWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum destinationTransportPortWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, destinationTransportPortWritingError> for destinationTransportPort {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), destinationTransportPortWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum destinationIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, destinationIPv4AddressWritingError> for destinationIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), destinationIPv4AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum destinationIPv4PrefixLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, destinationIPv4PrefixLengthWritingError> for destinationIPv4PrefixLength {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), destinationIPv4PrefixLengthWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum egressInterfaceWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, egressInterfaceWritingError> for egressInterface {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), egressInterfaceWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipNextHopIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipNextHopIPv4AddressWritingError> for ipNextHopIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ipNextHopIPv4AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpSourceAsNumberWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpSourceAsNumberWritingError> for bgpSourceAsNumber {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), bgpSourceAsNumberWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpDestinationAsNumberWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpDestinationAsNumberWritingError> for bgpDestinationAsNumber {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), bgpDestinationAsNumberWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpNextHopIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpNextHopIPv4AddressWritingError> for bgpNextHopIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpNextHopIPv4AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postMCastPacketDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postMCastPacketDeltaCountWritingError> for postMCastPacketDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postMCastPacketDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postMCastOctetDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postMCastOctetDeltaCountWritingError> for postMCastOctetDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postMCastOctetDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowEndSysUpTimeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowEndSysUpTimeWritingError> for flowEndSysUpTime {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowEndSysUpTimeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowStartSysUpTimeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowStartSysUpTimeWritingError> for flowStartSysUpTime {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowStartSysUpTimeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postOctetDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postOctetDeltaCountWritingError> for postOctetDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postOctetDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postPacketDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postPacketDeltaCountWritingError> for postPacketDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postPacketDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum minimumIpTotalLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, minimumIpTotalLengthWritingError> for minimumIpTotalLength {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), minimumIpTotalLengthWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum maximumIpTotalLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maximumIpTotalLengthWritingError> for maximumIpTotalLength {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), maximumIpTotalLengthWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sourceIPv6AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sourceIPv6AddressWritingError> for sourceIPv6Address {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), sourceIPv6AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum destinationIPv6AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, destinationIPv6AddressWritingError> for destinationIPv6Address {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), destinationIPv6AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sourceIPv6PrefixLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sourceIPv6PrefixLengthWritingError> for sourceIPv6PrefixLength {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), sourceIPv6PrefixLengthWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum destinationIPv6PrefixLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, destinationIPv6PrefixLengthWritingError> for destinationIPv6PrefixLength {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), destinationIPv6PrefixLengthWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowLabelIPv6WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowLabelIPv6WritingError> for flowLabelIPv6 {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowLabelIPv6WritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum icmpTypeCodeIPv4WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, icmpTypeCodeIPv4WritingError> for icmpTypeCodeIPv4 {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), icmpTypeCodeIPv4WritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum igmpTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, igmpTypeWritingError> for igmpType {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), igmpTypeWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplingIntervalWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplingIntervalWritingError> for samplingInterval {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplingIntervalWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplingAlgorithmWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplingAlgorithmWritingError> for samplingAlgorithm {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), samplingAlgorithmWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowActiveTimeoutWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowActiveTimeoutWritingError> for flowActiveTimeout {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowActiveTimeoutWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowIdleTimeoutWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowIdleTimeoutWritingError> for flowIdleTimeout {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowIdleTimeoutWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum engineTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, engineTypeWritingError> for engineType {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), engineTypeWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum engineIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, engineIdWritingError> for engineId {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), engineIdWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum exportedOctetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, exportedOctetTotalCountWritingError> for exportedOctetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), exportedOctetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum exportedMessageTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, exportedMessageTotalCountWritingError> for exportedMessageTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), exportedMessageTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum exportedFlowRecordTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, exportedFlowRecordTotalCountWritingError> for exportedFlowRecordTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), exportedFlowRecordTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipv4RouterScWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipv4RouterScWritingError> for ipv4RouterSc {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ipv4RouterScWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sourceIPv4PrefixWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sourceIPv4PrefixWritingError> for sourceIPv4Prefix {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), sourceIPv4PrefixWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum destinationIPv4PrefixWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, destinationIPv4PrefixWritingError> for destinationIPv4Prefix {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), destinationIPv4PrefixWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsTopLabelTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsTopLabelTypeWritingError> for mplsTopLabelType {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsTopLabelTypeWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsTopLabelIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsTopLabelIPv4AddressWritingError> for mplsTopLabelIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsTopLabelIPv4AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplerIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplerIdWritingError> for samplerId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplerIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplerModeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplerModeWritingError> for samplerMode {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), samplerModeWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplerRandomIntervalWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplerRandomIntervalWritingError> for samplerRandomInterval {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplerRandomIntervalWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum classIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, classIdWritingError> for classId {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), classIdWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum minimumTTLWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, minimumTTLWritingError> for minimumTTL {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), minimumTTLWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum maximumTTLWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maximumTTLWritingError> for maximumTTL {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), maximumTTLWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum fragmentIdentificationWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, fragmentIdentificationWritingError> for fragmentIdentification {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), fragmentIdentificationWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postIpClassOfServiceWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postIpClassOfServiceWritingError> for postIpClassOfService {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), postIpClassOfServiceWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sourceMacAddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sourceMacAddressWritingError> for sourceMacAddress {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), sourceMacAddressWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postDestinationMacAddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postDestinationMacAddressWritingError> for postDestinationMacAddress {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), postDestinationMacAddressWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum vlanIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, vlanIdWritingError> for vlanId {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), vlanIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postVlanIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postVlanIdWritingError> for postVlanId {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postVlanIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipVersionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipVersionWritingError> for ipVersion {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ipVersionWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowDirectionWritingError {
    StdIOError(#[from_std_io_error] String),
}

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
pub enum ipNextHopIPv6AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipNextHopIPv6AddressWritingError> for ipNextHopIPv6Address {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ipNextHopIPv6AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpNextHopIPv6AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpNextHopIPv6AddressWritingError> for bgpNextHopIPv6Address {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpNextHopIPv6AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipv6ExtensionHeadersWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipv6ExtensionHeadersWritingError> for ipv6ExtensionHeaders {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ipv6ExtensionHeadersWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsTopLabelStackSectionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsTopLabelStackSectionWritingError> for mplsTopLabelStackSection {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsTopLabelStackSectionWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsLabelStackSection2WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsLabelStackSection2WritingError> for mplsLabelStackSection2 {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsLabelStackSection2WritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsLabelStackSection3WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsLabelStackSection3WritingError> for mplsLabelStackSection3 {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsLabelStackSection3WritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsLabelStackSection4WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsLabelStackSection4WritingError> for mplsLabelStackSection4 {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsLabelStackSection4WritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsLabelStackSection5WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsLabelStackSection5WritingError> for mplsLabelStackSection5 {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsLabelStackSection5WritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsLabelStackSection6WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsLabelStackSection6WritingError> for mplsLabelStackSection6 {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsLabelStackSection6WritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsLabelStackSection7WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsLabelStackSection7WritingError> for mplsLabelStackSection7 {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsLabelStackSection7WritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsLabelStackSection8WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsLabelStackSection8WritingError> for mplsLabelStackSection8 {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsLabelStackSection8WritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsLabelStackSection9WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsLabelStackSection9WritingError> for mplsLabelStackSection9 {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsLabelStackSection9WritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsLabelStackSection10WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsLabelStackSection10WritingError> for mplsLabelStackSection10 {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsLabelStackSection10WritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum destinationMacAddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, destinationMacAddressWritingError> for destinationMacAddress {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), destinationMacAddressWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postSourceMacAddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postSourceMacAddressWritingError> for postSourceMacAddress {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), postSourceMacAddressWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum interfaceNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, interfaceNameWritingError> for interfaceName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), interfaceNameWritingError> {
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
pub enum interfaceDescriptionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, interfaceDescriptionWritingError> for interfaceDescription {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), interfaceDescriptionWritingError> {
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
pub enum samplerNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplerNameWritingError> for samplerName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplerNameWritingError> {
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
pub enum octetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, octetTotalCountWritingError> for octetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), octetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum packetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, packetTotalCountWritingError> for packetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), packetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flagsAndSamplerIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flagsAndSamplerIdWritingError> for flagsAndSamplerId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flagsAndSamplerIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum fragmentOffsetWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, fragmentOffsetWritingError> for fragmentOffset {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), fragmentOffsetWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum forwardingStatusWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, forwardingStatusWritingError> for forwardingStatus {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), forwardingStatusWritingError> {
         let num_val = u32::from(*self);
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsVpnRouteDistinguisherWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsVpnRouteDistinguisherWritingError> for mplsVpnRouteDistinguisher {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsVpnRouteDistinguisherWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsTopLabelPrefixLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsTopLabelPrefixLengthWritingError> for mplsTopLabelPrefixLength {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsTopLabelPrefixLengthWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum srcTrafficIndexWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, srcTrafficIndexWritingError> for srcTrafficIndex {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), srcTrafficIndexWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dstTrafficIndexWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dstTrafficIndexWritingError> for dstTrafficIndex {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), dstTrafficIndexWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum applicationDescriptionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, applicationDescriptionWritingError> for applicationDescription {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), applicationDescriptionWritingError> {
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
pub enum applicationIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, applicationIdWritingError> for applicationId {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), applicationIdWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum applicationNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, applicationNameWritingError> for applicationName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), applicationNameWritingError> {
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
pub enum postIpDiffServCodePointWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postIpDiffServCodePointWritingError> for postIpDiffServCodePoint {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), postIpDiffServCodePointWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum multicastReplicationFactorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, multicastReplicationFactorWritingError> for multicastReplicationFactor {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), multicastReplicationFactorWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum classNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, classNameWritingError> for className {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), classNameWritingError> {
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
pub enum classificationEngineIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, classificationEngineIdWritingError> for classificationEngineId {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), classificationEngineIdWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum layer2packetSectionOffsetWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, layer2packetSectionOffsetWritingError> for layer2packetSectionOffset {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), layer2packetSectionOffsetWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum layer2packetSectionSizeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, layer2packetSectionSizeWritingError> for layer2packetSectionSize {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), layer2packetSectionSizeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum layer2packetSectionDataWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, layer2packetSectionDataWritingError> for layer2packetSectionData {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), layer2packetSectionDataWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpNextAdjacentAsNumberWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpNextAdjacentAsNumberWritingError> for bgpNextAdjacentAsNumber {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), bgpNextAdjacentAsNumberWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpPrevAdjacentAsNumberWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpPrevAdjacentAsNumberWritingError> for bgpPrevAdjacentAsNumber {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), bgpPrevAdjacentAsNumberWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum exporterIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, exporterIPv4AddressWritingError> for exporterIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), exporterIPv4AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum exporterIPv6AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, exporterIPv6AddressWritingError> for exporterIPv6Address {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), exporterIPv6AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum droppedOctetDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, droppedOctetDeltaCountWritingError> for droppedOctetDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), droppedOctetDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum droppedPacketDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, droppedPacketDeltaCountWritingError> for droppedPacketDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), droppedPacketDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum droppedOctetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, droppedOctetTotalCountWritingError> for droppedOctetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), droppedOctetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum droppedPacketTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, droppedPacketTotalCountWritingError> for droppedPacketTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), droppedPacketTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowEndReasonWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowEndReasonWritingError> for flowEndReason {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), flowEndReasonWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum commonPropertiesIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, commonPropertiesIdWritingError> for commonPropertiesId {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), commonPropertiesIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum observationPointIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, observationPointIdWritingError> for observationPointId {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), observationPointIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum icmpTypeCodeIPv6WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, icmpTypeCodeIPv6WritingError> for icmpTypeCodeIPv6 {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), icmpTypeCodeIPv6WritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsTopLabelIPv6AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsTopLabelIPv6AddressWritingError> for mplsTopLabelIPv6Address {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsTopLabelIPv6AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum lineCardIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, lineCardIdWritingError> for lineCardId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), lineCardIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum portIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, portIdWritingError> for portId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), portIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum meteringProcessIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, meteringProcessIdWritingError> for meteringProcessId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), meteringProcessIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum exportingProcessIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, exportingProcessIdWritingError> for exportingProcessId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), exportingProcessIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum templateIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, templateIdWritingError> for templateId {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), templateIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum wlanChannelIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, wlanChannelIdWritingError> for wlanChannelId {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), wlanChannelIdWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum wlanSSIDWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, wlanSSIDWritingError> for wlanSSID {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), wlanSSIDWritingError> {
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
pub enum flowIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowIdWritingError> for flowId {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum observationDomainIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, observationDomainIdWritingError> for observationDomainId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), observationDomainIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowStartSecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowStartSecondsWritingError> for flowStartSeconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), flowStartSecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowEndSecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowEndSecondsWritingError> for flowEndSeconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), flowEndSecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowStartMillisecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowStartMillisecondsWritingError> for flowStartMilliseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), flowStartMillisecondsWritingError> {
         writer.write_u64::<byteorder::NetworkEndian>(self.0.timestamp_millis() as u64)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowEndMillisecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowEndMillisecondsWritingError> for flowEndMilliseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), flowEndMillisecondsWritingError> {
         writer.write_u64::<byteorder::NetworkEndian>(self.0.timestamp_millis() as u64)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowStartMicrosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowStartMicrosecondsWritingError> for flowStartMicroseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), flowStartMicrosecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         let nanos = self.0.timestamp_subsec_nanos();
         // Convert 1/2**32 of a second to a fraction of a nano second
         let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;
         writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowEndMicrosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowEndMicrosecondsWritingError> for flowEndMicroseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), flowEndMicrosecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         let nanos = self.0.timestamp_subsec_nanos();
         // Convert 1/2**32 of a second to a fraction of a nano second
         let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;
         writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowStartNanosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowStartNanosecondsWritingError> for flowStartNanoseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), flowStartNanosecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         let nanos = self.0.timestamp_subsec_nanos();
         // Convert 1/2**32 of a second to a fraction of a nano second
         let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;
         writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowEndNanosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowEndNanosecondsWritingError> for flowEndNanoseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), flowEndNanosecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         let nanos = self.0.timestamp_subsec_nanos();
         // Convert 1/2**32 of a second to a fraction of a nano second
         let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;
         writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowStartDeltaMicrosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowStartDeltaMicrosecondsWritingError> for flowStartDeltaMicroseconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowStartDeltaMicrosecondsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowEndDeltaMicrosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowEndDeltaMicrosecondsWritingError> for flowEndDeltaMicroseconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowEndDeltaMicrosecondsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum systemInitTimeMillisecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, systemInitTimeMillisecondsWritingError> for systemInitTimeMilliseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), systemInitTimeMillisecondsWritingError> {
         writer.write_u64::<byteorder::NetworkEndian>(self.0.timestamp_millis() as u64)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowDurationMillisecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowDurationMillisecondsWritingError> for flowDurationMilliseconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowDurationMillisecondsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowDurationMicrosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowDurationMicrosecondsWritingError> for flowDurationMicroseconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowDurationMicrosecondsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum observedFlowTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, observedFlowTotalCountWritingError> for observedFlowTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), observedFlowTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ignoredPacketTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ignoredPacketTotalCountWritingError> for ignoredPacketTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ignoredPacketTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ignoredOctetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ignoredOctetTotalCountWritingError> for ignoredOctetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ignoredOctetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum notSentFlowTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, notSentFlowTotalCountWritingError> for notSentFlowTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), notSentFlowTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum notSentPacketTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, notSentPacketTotalCountWritingError> for notSentPacketTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), notSentPacketTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum notSentOctetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, notSentOctetTotalCountWritingError> for notSentOctetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), notSentOctetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum destinationIPv6PrefixWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, destinationIPv6PrefixWritingError> for destinationIPv6Prefix {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), destinationIPv6PrefixWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sourceIPv6PrefixWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sourceIPv6PrefixWritingError> for sourceIPv6Prefix {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), sourceIPv6PrefixWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postOctetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postOctetTotalCountWritingError> for postOctetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postOctetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postPacketTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postPacketTotalCountWritingError> for postPacketTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postPacketTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowKeyIndicatorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowKeyIndicatorWritingError> for flowKeyIndicator {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowKeyIndicatorWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postMCastPacketTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postMCastPacketTotalCountWritingError> for postMCastPacketTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postMCastPacketTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postMCastOctetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postMCastOctetTotalCountWritingError> for postMCastOctetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postMCastOctetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum icmpTypeIPv4WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, icmpTypeIPv4WritingError> for icmpTypeIPv4 {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), icmpTypeIPv4WritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum icmpCodeIPv4WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, icmpCodeIPv4WritingError> for icmpCodeIPv4 {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), icmpCodeIPv4WritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum icmpTypeIPv6WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, icmpTypeIPv6WritingError> for icmpTypeIPv6 {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), icmpTypeIPv6WritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum icmpCodeIPv6WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, icmpCodeIPv6WritingError> for icmpCodeIPv6 {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), icmpCodeIPv6WritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum udpSourcePortWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, udpSourcePortWritingError> for udpSourcePort {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), udpSourcePortWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum udpDestinationPortWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, udpDestinationPortWritingError> for udpDestinationPort {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), udpDestinationPortWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpSourcePortWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpSourcePortWritingError> for tcpSourcePort {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpSourcePortWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpDestinationPortWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpDestinationPortWritingError> for tcpDestinationPort {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpDestinationPortWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpSequenceNumberWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpSequenceNumberWritingError> for tcpSequenceNumber {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpSequenceNumberWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpAcknowledgementNumberWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpAcknowledgementNumberWritingError> for tcpAcknowledgementNumber {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpAcknowledgementNumberWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpWindowSizeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpWindowSizeWritingError> for tcpWindowSize {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpWindowSizeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpUrgentPointerWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpUrgentPointerWritingError> for tcpUrgentPointer {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpUrgentPointerWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpHeaderLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpHeaderLengthWritingError> for tcpHeaderLength {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), tcpHeaderLengthWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipHeaderLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipHeaderLengthWritingError> for ipHeaderLength {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ipHeaderLengthWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum totalLengthIPv4WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, totalLengthIPv4WritingError> for totalLengthIPv4 {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), totalLengthIPv4WritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum payloadLengthIPv6WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, payloadLengthIPv6WritingError> for payloadLengthIPv6 {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), payloadLengthIPv6WritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipTTLWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipTTLWritingError> for ipTTL {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ipTTLWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum nextHeaderIPv6WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, nextHeaderIPv6WritingError> for nextHeaderIPv6 {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), nextHeaderIPv6WritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsPayloadLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsPayloadLengthWritingError> for mplsPayloadLength {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mplsPayloadLengthWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipDiffServCodePointWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipDiffServCodePointWritingError> for ipDiffServCodePoint {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ipDiffServCodePointWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipPrecedenceWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipPrecedenceWritingError> for ipPrecedence {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ipPrecedenceWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum fragmentFlagsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, fragmentFlagsWritingError> for fragmentFlags {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), fragmentFlagsWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum octetDeltaSumOfSquaresWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, octetDeltaSumOfSquaresWritingError> for octetDeltaSumOfSquares {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), octetDeltaSumOfSquaresWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum octetTotalSumOfSquaresWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, octetTotalSumOfSquaresWritingError> for octetTotalSumOfSquares {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), octetTotalSumOfSquaresWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsTopLabelTTLWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsTopLabelTTLWritingError> for mplsTopLabelTTL {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsTopLabelTTLWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsLabelStackLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsLabelStackLengthWritingError> for mplsLabelStackLength {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mplsLabelStackLengthWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsLabelStackDepthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsLabelStackDepthWritingError> for mplsLabelStackDepth {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mplsLabelStackDepthWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsTopLabelExpWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsTopLabelExpWritingError> for mplsTopLabelExp {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsTopLabelExpWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipPayloadLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipPayloadLengthWritingError> for ipPayloadLength {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ipPayloadLengthWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum udpMessageLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, udpMessageLengthWritingError> for udpMessageLength {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), udpMessageLengthWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum isMulticastWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, isMulticastWritingError> for isMulticast {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), isMulticastWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipv4IHLWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipv4IHLWritingError> for ipv4IHL {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ipv4IHLWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipv4OptionsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipv4OptionsWritingError> for ipv4Options {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ipv4OptionsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpOptionsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpOptionsWritingError> for tcpOptions {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpOptionsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum paddingOctetsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, paddingOctetsWritingError> for paddingOctets {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), paddingOctetsWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum collectorIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, collectorIPv4AddressWritingError> for collectorIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), collectorIPv4AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum collectorIPv6AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, collectorIPv6AddressWritingError> for collectorIPv6Address {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), collectorIPv6AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum exportInterfaceWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, exportInterfaceWritingError> for exportInterface {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), exportInterfaceWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum exportProtocolVersionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, exportProtocolVersionWritingError> for exportProtocolVersion {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), exportProtocolVersionWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum exportTransportProtocolWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, exportTransportProtocolWritingError> for exportTransportProtocol {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), exportTransportProtocolWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum collectorTransportPortWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, collectorTransportPortWritingError> for collectorTransportPort {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), collectorTransportPortWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum exporterTransportPortWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, exporterTransportPortWritingError> for exporterTransportPort {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), exporterTransportPortWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpSynTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpSynTotalCountWritingError> for tcpSynTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpSynTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpFinTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpFinTotalCountWritingError> for tcpFinTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpFinTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpRstTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpRstTotalCountWritingError> for tcpRstTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpRstTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpPshTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpPshTotalCountWritingError> for tcpPshTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpPshTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpAckTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpAckTotalCountWritingError> for tcpAckTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpAckTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpUrgTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpUrgTotalCountWritingError> for tcpUrgTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpUrgTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipTotalLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipTotalLengthWritingError> for ipTotalLength {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ipTotalLengthWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postNATSourceIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postNATSourceIPv4AddressWritingError> for postNATSourceIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), postNATSourceIPv4AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postNATDestinationIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postNATDestinationIPv4AddressWritingError> for postNATDestinationIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), postNATDestinationIPv4AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postNAPTSourceTransportPortWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postNAPTSourceTransportPortWritingError> for postNAPTSourceTransportPort {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postNAPTSourceTransportPortWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postNAPTDestinationTransportPortWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postNAPTDestinationTransportPortWritingError> for postNAPTDestinationTransportPort {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postNAPTDestinationTransportPortWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum natOriginatingAddressRealmWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, natOriginatingAddressRealmWritingError> for natOriginatingAddressRealm {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), natOriginatingAddressRealmWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum natEventWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, natEventWritingError> for natEvent {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), natEventWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum initiatorOctetsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, initiatorOctetsWritingError> for initiatorOctets {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), initiatorOctetsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum responderOctetsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, responderOctetsWritingError> for responderOctets {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), responderOctetsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum firewallEventWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, firewallEventWritingError> for firewallEvent {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), firewallEventWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ingressVRFIDWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ingressVRFIDWritingError> for ingressVRFID {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ingressVRFIDWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum egressVRFIDWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, egressVRFIDWritingError> for egressVRFID {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), egressVRFIDWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum VRFnameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, VRFnameWritingError> for VRFname {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), VRFnameWritingError> {
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
pub enum postMplsTopLabelExpWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postMplsTopLabelExpWritingError> for postMplsTopLabelExp {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), postMplsTopLabelExpWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum tcpWindowScaleWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tcpWindowScaleWritingError> for tcpWindowScale {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tcpWindowScaleWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum biflowDirectionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, biflowDirectionWritingError> for biflowDirection {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), biflowDirectionWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ethernetHeaderLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ethernetHeaderLengthWritingError> for ethernetHeaderLength {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ethernetHeaderLengthWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ethernetPayloadLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ethernetPayloadLengthWritingError> for ethernetPayloadLength {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ethernetPayloadLengthWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ethernetTotalLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ethernetTotalLengthWritingError> for ethernetTotalLength {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ethernetTotalLengthWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dot1qVlanIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dot1qVlanIdWritingError> for dot1qVlanId {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), dot1qVlanIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dot1qPriorityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dot1qPriorityWritingError> for dot1qPriority {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), dot1qPriorityWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dot1qCustomerVlanIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dot1qCustomerVlanIdWritingError> for dot1qCustomerVlanId {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), dot1qCustomerVlanIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dot1qCustomerPriorityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dot1qCustomerPriorityWritingError> for dot1qCustomerPriority {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), dot1qCustomerPriorityWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum metroEvcIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, metroEvcIdWritingError> for metroEvcId {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), metroEvcIdWritingError> {
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
pub enum metroEvcTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, metroEvcTypeWritingError> for metroEvcType {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), metroEvcTypeWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum pseudoWireIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, pseudoWireIdWritingError> for pseudoWireId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), pseudoWireIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum pseudoWireTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, pseudoWireTypeWritingError> for pseudoWireType {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), pseudoWireTypeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum pseudoWireControlWordWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, pseudoWireControlWordWritingError> for pseudoWireControlWord {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), pseudoWireControlWordWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ingressPhysicalInterfaceWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ingressPhysicalInterfaceWritingError> for ingressPhysicalInterface {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ingressPhysicalInterfaceWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum egressPhysicalInterfaceWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, egressPhysicalInterfaceWritingError> for egressPhysicalInterface {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), egressPhysicalInterfaceWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postDot1qVlanIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postDot1qVlanIdWritingError> for postDot1qVlanId {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postDot1qVlanIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postDot1qCustomerVlanIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postDot1qCustomerVlanIdWritingError> for postDot1qCustomerVlanId {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postDot1qCustomerVlanIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ethernetTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ethernetTypeWritingError> for ethernetType {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ethernetTypeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postIpPrecedenceWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postIpPrecedenceWritingError> for postIpPrecedence {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), postIpPrecedenceWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum collectionTimeMillisecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, collectionTimeMillisecondsWritingError> for collectionTimeMilliseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), collectionTimeMillisecondsWritingError> {
         writer.write_u64::<byteorder::NetworkEndian>(self.0.timestamp_millis() as u64)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum exportSctpStreamIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, exportSctpStreamIdWritingError> for exportSctpStreamId {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), exportSctpStreamIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum maxExportSecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maxExportSecondsWritingError> for maxExportSeconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), maxExportSecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum maxFlowEndSecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maxFlowEndSecondsWritingError> for maxFlowEndSeconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), maxFlowEndSecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum messageMD5ChecksumWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, messageMD5ChecksumWritingError> for messageMD5Checksum {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), messageMD5ChecksumWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum messageScopeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, messageScopeWritingError> for messageScope {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), messageScopeWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum minExportSecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, minExportSecondsWritingError> for minExportSeconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), minExportSecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum minFlowStartSecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, minFlowStartSecondsWritingError> for minFlowStartSeconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), minFlowStartSecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum opaqueOctetsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, opaqueOctetsWritingError> for opaqueOctets {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), opaqueOctetsWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sessionScopeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sessionScopeWritingError> for sessionScope {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), sessionScopeWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum maxFlowEndMicrosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maxFlowEndMicrosecondsWritingError> for maxFlowEndMicroseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), maxFlowEndMicrosecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         let nanos = self.0.timestamp_subsec_nanos();
         // Convert 1/2**32 of a second to a fraction of a nano second
         let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;
         writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum maxFlowEndMillisecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maxFlowEndMillisecondsWritingError> for maxFlowEndMilliseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), maxFlowEndMillisecondsWritingError> {
         writer.write_u64::<byteorder::NetworkEndian>(self.0.timestamp_millis() as u64)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum maxFlowEndNanosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maxFlowEndNanosecondsWritingError> for maxFlowEndNanoseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), maxFlowEndNanosecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         let nanos = self.0.timestamp_subsec_nanos();
         // Convert 1/2**32 of a second to a fraction of a nano second
         let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;
         writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum minFlowStartMicrosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, minFlowStartMicrosecondsWritingError> for minFlowStartMicroseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), minFlowStartMicrosecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         let nanos = self.0.timestamp_subsec_nanos();
         // Convert 1/2**32 of a second to a fraction of a nano second
         let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;
         writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum minFlowStartMillisecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, minFlowStartMillisecondsWritingError> for minFlowStartMilliseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), minFlowStartMillisecondsWritingError> {
         writer.write_u64::<byteorder::NetworkEndian>(self.0.timestamp_millis() as u64)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum minFlowStartNanosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, minFlowStartNanosecondsWritingError> for minFlowStartNanoseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), minFlowStartNanosecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         let nanos = self.0.timestamp_subsec_nanos();
         // Convert 1/2**32 of a second to a fraction of a nano second
         let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;
         writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum collectorCertificateWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, collectorCertificateWritingError> for collectorCertificate {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), collectorCertificateWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum exporterCertificateWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, exporterCertificateWritingError> for exporterCertificate {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), exporterCertificateWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dataRecordsReliabilityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dataRecordsReliabilityWritingError> for dataRecordsReliability {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), dataRecordsReliabilityWritingError> {
         writer.write_u8(self.0.into())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum observationPointTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, observationPointTypeWritingError> for observationPointType {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), observationPointTypeWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum newConnectionDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, newConnectionDeltaCountWritingError> for newConnectionDeltaCount {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), newConnectionDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum connectionSumDurationSecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, connectionSumDurationSecondsWritingError> for connectionSumDurationSeconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), connectionSumDurationSecondsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum connectionTransactionIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, connectionTransactionIdWritingError> for connectionTransactionId {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), connectionTransactionIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postNATSourceIPv6AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postNATSourceIPv6AddressWritingError> for postNATSourceIPv6Address {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), postNATSourceIPv6AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postNATDestinationIPv6AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postNATDestinationIPv6AddressWritingError> for postNATDestinationIPv6Address {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), postNATDestinationIPv6AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum natPoolIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, natPoolIdWritingError> for natPoolId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), natPoolIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum natPoolNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, natPoolNameWritingError> for natPoolName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), natPoolNameWritingError> {
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
pub enum anonymizationFlagsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, anonymizationFlagsWritingError> for anonymizationFlags {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), anonymizationFlagsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum anonymizationTechniqueWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, anonymizationTechniqueWritingError> for anonymizationTechnique {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), anonymizationTechniqueWritingError> {
         let num_val = u16::from(*self);
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum informationElementIndexWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, informationElementIndexWritingError> for informationElementIndex {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), informationElementIndexWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum p2pTechnologyWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, p2pTechnologyWritingError> for p2pTechnology {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), p2pTechnologyWritingError> {
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
pub enum tunnelTechnologyWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, tunnelTechnologyWritingError> for tunnelTechnology {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), tunnelTechnologyWritingError> {
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
pub enum encryptedTechnologyWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, encryptedTechnologyWritingError> for encryptedTechnology {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), encryptedTechnologyWritingError> {
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
pub enum basicListWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, basicListWritingError> for basicList {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), basicListWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum subTemplateListWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, subTemplateListWritingError> for subTemplateList {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), subTemplateListWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum subTemplateMultiListWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, subTemplateMultiListWritingError> for subTemplateMultiList {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), subTemplateMultiListWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpValidityStateWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpValidityStateWritingError> for bgpValidityState {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpValidityStateWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum IPSecSPIWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, IPSecSPIWritingError> for IPSecSPI {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), IPSecSPIWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum greKeyWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, greKeyWritingError> for greKey {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), greKeyWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum natTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, natTypeWritingError> for natType {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), natTypeWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum initiatorPacketsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, initiatorPacketsWritingError> for initiatorPackets {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), initiatorPacketsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum responderPacketsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, responderPacketsWritingError> for responderPackets {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), responderPacketsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum observationDomainNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, observationDomainNameWritingError> for observationDomainName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), observationDomainNameWritingError> {
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
pub enum selectionSequenceIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, selectionSequenceIdWritingError> for selectionSequenceId {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), selectionSequenceIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum selectorIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, selectorIdWritingError> for selectorId {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), selectorIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum informationElementIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, informationElementIdWritingError> for informationElementId {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), informationElementIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum selectorAlgorithmWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, selectorAlgorithmWritingError> for selectorAlgorithm {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), selectorAlgorithmWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplingPacketIntervalWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplingPacketIntervalWritingError> for samplingPacketInterval {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplingPacketIntervalWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplingPacketSpaceWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplingPacketSpaceWritingError> for samplingPacketSpace {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplingPacketSpaceWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplingTimeIntervalWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplingTimeIntervalWritingError> for samplingTimeInterval {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplingTimeIntervalWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplingTimeSpaceWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplingTimeSpaceWritingError> for samplingTimeSpace {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplingTimeSpaceWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplingSizeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplingSizeWritingError> for samplingSize {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplingSizeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplingPopulationWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplingPopulationWritingError> for samplingPopulation {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplingPopulationWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplingProbabilityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplingProbabilityWritingError> for samplingProbability {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplingProbabilityWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_f64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dataLinkFrameSizeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dataLinkFrameSizeWritingError> for dataLinkFrameSize {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), dataLinkFrameSizeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipHeaderPacketSectionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipHeaderPacketSectionWritingError> for ipHeaderPacketSection {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ipHeaderPacketSectionWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ipPayloadPacketSectionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ipPayloadPacketSectionWritingError> for ipPayloadPacketSection {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), ipPayloadPacketSectionWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dataLinkFrameSectionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dataLinkFrameSectionWritingError> for dataLinkFrameSection {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), dataLinkFrameSectionWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsLabelStackSectionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsLabelStackSectionWritingError> for mplsLabelStackSection {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsLabelStackSectionWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mplsPayloadPacketSectionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mplsPayloadPacketSectionWritingError> for mplsPayloadPacketSection {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mplsPayloadPacketSectionWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum selectorIdTotalPktsObservedWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, selectorIdTotalPktsObservedWritingError> for selectorIdTotalPktsObserved {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), selectorIdTotalPktsObservedWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum selectorIdTotalPktsSelectedWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, selectorIdTotalPktsSelectedWritingError> for selectorIdTotalPktsSelected {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), selectorIdTotalPktsSelectedWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum absoluteErrorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, absoluteErrorWritingError> for absoluteError {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), absoluteErrorWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_f64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum relativeErrorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, relativeErrorWritingError> for relativeError {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), relativeErrorWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_f64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum observationTimeSecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, observationTimeSecondsWritingError> for observationTimeSeconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), observationTimeSecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum observationTimeMillisecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, observationTimeMillisecondsWritingError> for observationTimeMilliseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), observationTimeMillisecondsWritingError> {
         writer.write_u64::<byteorder::NetworkEndian>(self.0.timestamp_millis() as u64)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum observationTimeMicrosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, observationTimeMicrosecondsWritingError> for observationTimeMicroseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), observationTimeMicrosecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         let nanos = self.0.timestamp_subsec_nanos();
         // Convert 1/2**32 of a second to a fraction of a nano second
         let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;
         writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum observationTimeNanosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, observationTimeNanosecondsWritingError> for observationTimeNanoseconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), observationTimeNanosecondsWritingError> {
         writer.write_u32::<byteorder::NetworkEndian>(self.0.timestamp() as u32)?;
         let nanos = self.0.timestamp_subsec_nanos();
         // Convert 1/2**32 of a second to a fraction of a nano second
         let fraction = (nanos as u64 * u32::MAX as u64) / 1_000_000_000;
         writer.write_u32::<byteorder::NetworkEndian>(fraction as u32)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum digestHashValueWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, digestHashValueWritingError> for digestHashValue {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), digestHashValueWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum hashIPPayloadOffsetWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, hashIPPayloadOffsetWritingError> for hashIPPayloadOffset {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), hashIPPayloadOffsetWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum hashIPPayloadSizeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, hashIPPayloadSizeWritingError> for hashIPPayloadSize {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), hashIPPayloadSizeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum hashOutputRangeMinWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, hashOutputRangeMinWritingError> for hashOutputRangeMin {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), hashOutputRangeMinWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum hashOutputRangeMaxWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, hashOutputRangeMaxWritingError> for hashOutputRangeMax {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), hashOutputRangeMaxWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum hashSelectedRangeMinWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, hashSelectedRangeMinWritingError> for hashSelectedRangeMin {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), hashSelectedRangeMinWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum hashSelectedRangeMaxWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, hashSelectedRangeMaxWritingError> for hashSelectedRangeMax {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), hashSelectedRangeMaxWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum hashDigestOutputWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, hashDigestOutputWritingError> for hashDigestOutput {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), hashDigestOutputWritingError> {
         writer.write_u8(self.0.into())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum hashInitialiserValueWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, hashInitialiserValueWritingError> for hashInitialiserValue {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), hashInitialiserValueWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum selectorNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, selectorNameWritingError> for selectorName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), selectorNameWritingError> {
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
pub enum upperCILimitWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, upperCILimitWritingError> for upperCILimit {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), upperCILimitWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_f64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum lowerCILimitWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, lowerCILimitWritingError> for lowerCILimit {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), lowerCILimitWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_f64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum confidenceLevelWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, confidenceLevelWritingError> for confidenceLevel {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), confidenceLevelWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_f64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum informationElementDataTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, informationElementDataTypeWritingError> for informationElementDataType {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), informationElementDataTypeWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum informationElementDescriptionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, informationElementDescriptionWritingError> for informationElementDescription {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), informationElementDescriptionWritingError> {
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
pub enum informationElementNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, informationElementNameWritingError> for informationElementName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), informationElementNameWritingError> {
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
pub enum informationElementRangeBeginWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, informationElementRangeBeginWritingError> for informationElementRangeBegin {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), informationElementRangeBeginWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum informationElementRangeEndWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, informationElementRangeEndWritingError> for informationElementRangeEnd {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), informationElementRangeEndWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum informationElementSemanticsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, informationElementSemanticsWritingError> for informationElementSemantics {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), informationElementSemanticsWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum informationElementUnitsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, informationElementUnitsWritingError> for informationElementUnits {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), informationElementUnitsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum privateEnterpriseNumberWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, privateEnterpriseNumberWritingError> for privateEnterpriseNumber {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), privateEnterpriseNumberWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum virtualStationInterfaceIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, virtualStationInterfaceIdWritingError> for virtualStationInterfaceId {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), virtualStationInterfaceIdWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum virtualStationInterfaceNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, virtualStationInterfaceNameWritingError> for virtualStationInterfaceName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), virtualStationInterfaceNameWritingError> {
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
pub enum virtualStationUUIDWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, virtualStationUUIDWritingError> for virtualStationUUID {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), virtualStationUUIDWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum virtualStationNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, virtualStationNameWritingError> for virtualStationName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), virtualStationNameWritingError> {
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
pub enum layer2SegmentIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, layer2SegmentIdWritingError> for layer2SegmentId {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), layer2SegmentIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum layer2OctetDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, layer2OctetDeltaCountWritingError> for layer2OctetDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), layer2OctetDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum layer2OctetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, layer2OctetTotalCountWritingError> for layer2OctetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), layer2OctetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ingressUnicastPacketTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ingressUnicastPacketTotalCountWritingError> for ingressUnicastPacketTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ingressUnicastPacketTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ingressMulticastPacketTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ingressMulticastPacketTotalCountWritingError> for ingressMulticastPacketTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ingressMulticastPacketTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ingressBroadcastPacketTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ingressBroadcastPacketTotalCountWritingError> for ingressBroadcastPacketTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ingressBroadcastPacketTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum egressUnicastPacketTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, egressUnicastPacketTotalCountWritingError> for egressUnicastPacketTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), egressUnicastPacketTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum egressBroadcastPacketTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, egressBroadcastPacketTotalCountWritingError> for egressBroadcastPacketTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), egressBroadcastPacketTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum monitoringIntervalStartMilliSecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, monitoringIntervalStartMilliSecondsWritingError> for monitoringIntervalStartMilliSeconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), monitoringIntervalStartMilliSecondsWritingError> {
         writer.write_u64::<byteorder::NetworkEndian>(self.0.timestamp_millis() as u64)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum monitoringIntervalEndMilliSecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, monitoringIntervalEndMilliSecondsWritingError> for monitoringIntervalEndMilliSeconds {
    const BASE_LENGTH: usize = 8;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), monitoringIntervalEndMilliSecondsWritingError> {
         writer.write_u64::<byteorder::NetworkEndian>(self.0.timestamp_millis() as u64)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum portRangeStartWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, portRangeStartWritingError> for portRangeStart {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), portRangeStartWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum portRangeEndWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, portRangeEndWritingError> for portRangeEnd {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), portRangeEndWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum portRangeStepSizeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, portRangeStepSizeWritingError> for portRangeStepSize {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), portRangeStepSizeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum portRangeNumPortsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, portRangeNumPortsWritingError> for portRangeNumPorts {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), portRangeNumPortsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum staMacAddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, staMacAddressWritingError> for staMacAddress {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), staMacAddressWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum staIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, staIPv4AddressWritingError> for staIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), staIPv4AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum wtpMacAddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, wtpMacAddressWritingError> for wtpMacAddress {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), wtpMacAddressWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ingressInterfaceTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ingressInterfaceTypeWritingError> for ingressInterfaceType {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ingressInterfaceTypeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum egressInterfaceTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, egressInterfaceTypeWritingError> for egressInterfaceType {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), egressInterfaceTypeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum rtpSequenceNumberWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, rtpSequenceNumberWritingError> for rtpSequenceNumber {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), rtpSequenceNumberWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum userNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, userNameWritingError> for userName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), userNameWritingError> {
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
pub enum applicationCategoryNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, applicationCategoryNameWritingError> for applicationCategoryName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), applicationCategoryNameWritingError> {
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
pub enum applicationSubCategoryNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, applicationSubCategoryNameWritingError> for applicationSubCategoryName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), applicationSubCategoryNameWritingError> {
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
pub enum applicationGroupNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, applicationGroupNameWritingError> for applicationGroupName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), applicationGroupNameWritingError> {
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
pub enum originalFlowsPresentWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, originalFlowsPresentWritingError> for originalFlowsPresent {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), originalFlowsPresentWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum originalFlowsInitiatedWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, originalFlowsInitiatedWritingError> for originalFlowsInitiated {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), originalFlowsInitiatedWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum originalFlowsCompletedWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, originalFlowsCompletedWritingError> for originalFlowsCompleted {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), originalFlowsCompletedWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum distinctCountOfSourceIPAddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, distinctCountOfSourceIPAddressWritingError> for distinctCountOfSourceIPAddress {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), distinctCountOfSourceIPAddressWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum distinctCountOfDestinationIPAddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, distinctCountOfDestinationIPAddressWritingError> for distinctCountOfDestinationIPAddress {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), distinctCountOfDestinationIPAddressWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum distinctCountOfSourceIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, distinctCountOfSourceIPv4AddressWritingError> for distinctCountOfSourceIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), distinctCountOfSourceIPv4AddressWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum distinctCountOfDestinationIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, distinctCountOfDestinationIPv4AddressWritingError> for distinctCountOfDestinationIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), distinctCountOfDestinationIPv4AddressWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum distinctCountOfSourceIPv6AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, distinctCountOfSourceIPv6AddressWritingError> for distinctCountOfSourceIPv6Address {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), distinctCountOfSourceIPv6AddressWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum distinctCountOfDestinationIPv6AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, distinctCountOfDestinationIPv6AddressWritingError> for distinctCountOfDestinationIPv6Address {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), distinctCountOfDestinationIPv6AddressWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum valueDistributionMethodWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, valueDistributionMethodWritingError> for valueDistributionMethod {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), valueDistributionMethodWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum rfc3550JitterMillisecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, rfc3550JitterMillisecondsWritingError> for rfc3550JitterMilliseconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), rfc3550JitterMillisecondsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum rfc3550JitterMicrosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, rfc3550JitterMicrosecondsWritingError> for rfc3550JitterMicroseconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), rfc3550JitterMicrosecondsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum rfc3550JitterNanosecondsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, rfc3550JitterNanosecondsWritingError> for rfc3550JitterNanoseconds {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), rfc3550JitterNanosecondsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dot1qDEIWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dot1qDEIWritingError> for dot1qDEI {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), dot1qDEIWritingError> {
         writer.write_u8(self.0.into())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dot1qCustomerDEIWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dot1qCustomerDEIWritingError> for dot1qCustomerDEI {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), dot1qCustomerDEIWritingError> {
         writer.write_u8(self.0.into())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowSelectorAlgorithmWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowSelectorAlgorithmWritingError> for flowSelectorAlgorithm {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowSelectorAlgorithmWritingError> {
         let num_val = u16::from(*self);
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowSelectedOctetDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowSelectedOctetDeltaCountWritingError> for flowSelectedOctetDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowSelectedOctetDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowSelectedPacketDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowSelectedPacketDeltaCountWritingError> for flowSelectedPacketDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowSelectedPacketDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowSelectedFlowDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowSelectedFlowDeltaCountWritingError> for flowSelectedFlowDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowSelectedFlowDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum selectorIDTotalFlowsObservedWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, selectorIDTotalFlowsObservedWritingError> for selectorIDTotalFlowsObserved {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), selectorIDTotalFlowsObservedWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum selectorIDTotalFlowsSelectedWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, selectorIDTotalFlowsSelectedWritingError> for selectorIDTotalFlowsSelected {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), selectorIDTotalFlowsSelectedWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplingFlowIntervalWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplingFlowIntervalWritingError> for samplingFlowInterval {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplingFlowIntervalWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum samplingFlowSpacingWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, samplingFlowSpacingWritingError> for samplingFlowSpacing {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), samplingFlowSpacingWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowSamplingTimeIntervalWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowSamplingTimeIntervalWritingError> for flowSamplingTimeInterval {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowSamplingTimeIntervalWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum flowSamplingTimeSpacingWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, flowSamplingTimeSpacingWritingError> for flowSamplingTimeSpacing {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), flowSamplingTimeSpacingWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum hashFlowDomainWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, hashFlowDomainWritingError> for hashFlowDomain {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), hashFlowDomainWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum transportOctetDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, transportOctetDeltaCountWritingError> for transportOctetDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), transportOctetDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum transportPacketDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, transportPacketDeltaCountWritingError> for transportPacketDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), transportPacketDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum originalExporterIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, originalExporterIPv4AddressWritingError> for originalExporterIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), originalExporterIPv4AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum originalExporterIPv6AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, originalExporterIPv6AddressWritingError> for originalExporterIPv6Address {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), originalExporterIPv6AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum originalObservationDomainIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, originalObservationDomainIdWritingError> for originalObservationDomainId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), originalObservationDomainIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum intermediateProcessIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, intermediateProcessIdWritingError> for intermediateProcessId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), intermediateProcessIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ignoredDataRecordTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ignoredDataRecordTotalCountWritingError> for ignoredDataRecordTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ignoredDataRecordTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dataLinkFrameTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dataLinkFrameTypeWritingError> for dataLinkFrameType {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), dataLinkFrameTypeWritingError> {
         let num_val = u16::from(*self);
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sectionOffsetWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sectionOffsetWritingError> for sectionOffset {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), sectionOffsetWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sectionExportedOctetsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sectionExportedOctetsWritingError> for sectionExportedOctets {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), sectionExportedOctetsWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dot1qServiceInstanceTagWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dot1qServiceInstanceTagWritingError> for dot1qServiceInstanceTag {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), dot1qServiceInstanceTagWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dot1qServiceInstanceIdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dot1qServiceInstanceIdWritingError> for dot1qServiceInstanceId {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), dot1qServiceInstanceIdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dot1qServiceInstancePriorityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dot1qServiceInstancePriorityWritingError> for dot1qServiceInstancePriority {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), dot1qServiceInstancePriorityWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dot1qCustomerSourceMacAddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dot1qCustomerSourceMacAddressWritingError> for dot1qCustomerSourceMacAddress {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), dot1qCustomerSourceMacAddressWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum dot1qCustomerDestinationMacAddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, dot1qCustomerDestinationMacAddressWritingError> for dot1qCustomerDestinationMacAddress {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), dot1qCustomerDestinationMacAddressWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postLayer2OctetDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postLayer2OctetDeltaCountWritingError> for postLayer2OctetDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postLayer2OctetDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postMCastLayer2OctetDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postMCastLayer2OctetDeltaCountWritingError> for postMCastLayer2OctetDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postMCastLayer2OctetDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postLayer2OctetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postLayer2OctetTotalCountWritingError> for postLayer2OctetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postLayer2OctetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum postMCastLayer2OctetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, postMCastLayer2OctetTotalCountWritingError> for postMCastLayer2OctetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), postMCastLayer2OctetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum minimumLayer2TotalLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, minimumLayer2TotalLengthWritingError> for minimumLayer2TotalLength {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), minimumLayer2TotalLengthWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum maximumLayer2TotalLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maximumLayer2TotalLengthWritingError> for maximumLayer2TotalLength {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), maximumLayer2TotalLengthWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum droppedLayer2OctetDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, droppedLayer2OctetDeltaCountWritingError> for droppedLayer2OctetDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), droppedLayer2OctetDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum droppedLayer2OctetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, droppedLayer2OctetTotalCountWritingError> for droppedLayer2OctetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), droppedLayer2OctetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ignoredLayer2OctetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ignoredLayer2OctetTotalCountWritingError> for ignoredLayer2OctetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ignoredLayer2OctetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum notSentLayer2OctetTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, notSentLayer2OctetTotalCountWritingError> for notSentLayer2OctetTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), notSentLayer2OctetTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum layer2OctetDeltaSumOfSquaresWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, layer2OctetDeltaSumOfSquaresWritingError> for layer2OctetDeltaSumOfSquares {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), layer2OctetDeltaSumOfSquaresWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum layer2OctetTotalSumOfSquaresWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, layer2OctetTotalSumOfSquaresWritingError> for layer2OctetTotalSumOfSquares {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), layer2OctetTotalSumOfSquaresWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum layer2FrameDeltaCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, layer2FrameDeltaCountWritingError> for layer2FrameDeltaCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), layer2FrameDeltaCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum layer2FrameTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, layer2FrameTotalCountWritingError> for layer2FrameTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), layer2FrameTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum pseudoWireDestinationIPv4AddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, pseudoWireDestinationIPv4AddressWritingError> for pseudoWireDestinationIPv4Address {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), pseudoWireDestinationIPv4AddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum ignoredLayer2FrameTotalCountWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, ignoredLayer2FrameTotalCountWritingError> for ignoredLayer2FrameTotalCount {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), ignoredLayer2FrameTotalCountWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibObjectValueIntegerWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectValueIntegerWritingError> for mibObjectValueInteger {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mibObjectValueIntegerWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_i32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibObjectValueOctetStringWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectValueOctetStringWritingError> for mibObjectValueOctetString {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mibObjectValueOctetStringWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibObjectValueOIDWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectValueOIDWritingError> for mibObjectValueOID {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mibObjectValueOIDWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibObjectValueBitsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectValueBitsWritingError> for mibObjectValueBits {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mibObjectValueBitsWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibObjectValueIPAddressWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectValueIPAddressWritingError> for mibObjectValueIPAddress {
    const BASE_LENGTH: usize = 4;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mibObjectValueIPAddressWritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibObjectValueCounterWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectValueCounterWritingError> for mibObjectValueCounter {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mibObjectValueCounterWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibObjectValueGaugeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectValueGaugeWritingError> for mibObjectValueGauge {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mibObjectValueGaugeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibObjectValueTimeTicksWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectValueTimeTicksWritingError> for mibObjectValueTimeTicks {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mibObjectValueTimeTicksWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibObjectValueUnsignedWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectValueUnsignedWritingError> for mibObjectValueUnsigned {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mibObjectValueUnsignedWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibObjectValueTableWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectValueTableWritingError> for mibObjectValueTable {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mibObjectValueTableWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibObjectValueRowWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectValueRowWritingError> for mibObjectValueRow {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mibObjectValueRowWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibObjectIdentifierWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectIdentifierWritingError> for mibObjectIdentifier {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mibObjectIdentifierWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibSubIdentifierWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibSubIdentifierWritingError> for mibSubIdentifier {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mibSubIdentifierWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibIndexIndicatorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibIndexIndicatorWritingError> for mibIndexIndicator {
    const BASE_LENGTH: usize = 8;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mibIndexIndicatorWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u64::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibCaptureTimeSemanticsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibCaptureTimeSemanticsWritingError> for mibCaptureTimeSemantics {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mibCaptureTimeSemanticsWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibContextEngineIDWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibContextEngineIDWritingError> for mibContextEngineID {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), mibContextEngineIDWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum mibContextNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibContextNameWritingError> for mibContextName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mibContextNameWritingError> {
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
pub enum mibObjectNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectNameWritingError> for mibObjectName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mibObjectNameWritingError> {
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
pub enum mibObjectDescriptionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectDescriptionWritingError> for mibObjectDescription {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mibObjectDescriptionWritingError> {
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
pub enum mibObjectSyntaxWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibObjectSyntaxWritingError> for mibObjectSyntax {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mibObjectSyntaxWritingError> {
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
pub enum mibModuleNameWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mibModuleNameWritingError> for mibModuleName {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mibModuleNameWritingError> {
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
pub enum mobileIMSIWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mobileIMSIWritingError> for mobileIMSI {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mobileIMSIWritingError> {
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
pub enum mobileMSISDNWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, mobileMSISDNWritingError> for mobileMSISDN {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), mobileMSISDNWritingError> {
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
pub enum httpStatusCodeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, httpStatusCodeWritingError> for httpStatusCode {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), httpStatusCodeWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum sourceTransportPortsLimitWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, sourceTransportPortsLimitWritingError> for sourceTransportPortsLimit {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), sourceTransportPortsLimitWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum httpRequestMethodWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, httpRequestMethodWritingError> for httpRequestMethod {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), httpRequestMethodWritingError> {
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
pub enum httpRequestHostWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, httpRequestHostWritingError> for httpRequestHost {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), httpRequestHostWritingError> {
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
pub enum httpRequestTargetWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, httpRequestTargetWritingError> for httpRequestTarget {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), httpRequestTargetWritingError> {
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
pub enum httpMessageVersionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, httpMessageVersionWritingError> for httpMessageVersion {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), httpMessageVersionWritingError> {
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
pub enum natInstanceIDWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, natInstanceIDWritingError> for natInstanceID {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), natInstanceIDWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum internalAddressRealmWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, internalAddressRealmWritingError> for internalAddressRealm {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), internalAddressRealmWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum externalAddressRealmWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, externalAddressRealmWritingError> for externalAddressRealm {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), externalAddressRealmWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum natQuotaExceededEventWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, natQuotaExceededEventWritingError> for natQuotaExceededEvent {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), natQuotaExceededEventWritingError> {
         let num_val = u32::from(*self);
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum natThresholdEventWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, natThresholdEventWritingError> for natThresholdEvent {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), natThresholdEventWritingError> {
         let num_val = u32::from(*self);
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum httpUserAgentWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, httpUserAgentWritingError> for httpUserAgent {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), httpUserAgentWritingError> {
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
pub enum httpContentTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, httpContentTypeWritingError> for httpContentType {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), httpContentTypeWritingError> {
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
pub enum httpReasonPhraseWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, httpReasonPhraseWritingError> for httpReasonPhrase {
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

    fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), httpReasonPhraseWritingError> {
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
pub enum maxSessionEntriesWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maxSessionEntriesWritingError> for maxSessionEntries {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), maxSessionEntriesWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum maxBIBEntriesWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maxBIBEntriesWritingError> for maxBIBEntries {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), maxBIBEntriesWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum maxEntriesPerUserWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maxEntriesPerUserWritingError> for maxEntriesPerUser {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), maxEntriesPerUserWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum maxSubscribersWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maxSubscribersWritingError> for maxSubscribers {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), maxSubscribersWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum maxFragmentsPendingReassemblyWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, maxFragmentsPendingReassemblyWritingError> for maxFragmentsPendingReassembly {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), maxFragmentsPendingReassemblyWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum addressPoolHighThresholdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, addressPoolHighThresholdWritingError> for addressPoolHighThreshold {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), addressPoolHighThresholdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum addressPoolLowThresholdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, addressPoolLowThresholdWritingError> for addressPoolLowThreshold {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), addressPoolLowThresholdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum addressPortMappingHighThresholdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, addressPortMappingHighThresholdWritingError> for addressPortMappingHighThreshold {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), addressPortMappingHighThresholdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum addressPortMappingLowThresholdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, addressPortMappingLowThresholdWritingError> for addressPortMappingLowThreshold {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), addressPortMappingLowThresholdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum addressPortMappingPerUserHighThresholdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, addressPortMappingPerUserHighThresholdWritingError> for addressPortMappingPerUserHighThreshold {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), addressPortMappingPerUserHighThresholdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum globalAddressMappingHighThresholdWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, globalAddressMappingHighThresholdWritingError> for globalAddressMappingHighThreshold {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), globalAddressMappingHighThresholdWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum vpnIdentifierWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, vpnIdentifierWritingError> for vpnIdentifier {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), vpnIdentifierWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpCommunityWritingError> for bgpCommunity {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), bgpCommunityWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpSourceCommunityListWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpSourceCommunityListWritingError> for bgpSourceCommunityList {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpSourceCommunityListWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpDestinationCommunityListWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpDestinationCommunityListWritingError> for bgpDestinationCommunityList {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpDestinationCommunityListWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpExtendedCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpExtendedCommunityWritingError> for bgpExtendedCommunity {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpExtendedCommunityWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpSourceExtendedCommunityListWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpSourceExtendedCommunityListWritingError> for bgpSourceExtendedCommunityList {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpSourceExtendedCommunityListWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpDestinationExtendedCommunityListWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpDestinationExtendedCommunityListWritingError> for bgpDestinationExtendedCommunityList {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpDestinationExtendedCommunityListWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpLargeCommunityWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpLargeCommunityWritingError> for bgpLargeCommunity {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpLargeCommunityWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpSourceLargeCommunityListWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpSourceLargeCommunityListWritingError> for bgpSourceLargeCommunityList {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpSourceLargeCommunityListWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpDestinationLargeCommunityListWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpDestinationLargeCommunityListWritingError> for bgpDestinationLargeCommunityList {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpDestinationLargeCommunityListWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum srhFlagsIPv6WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, srhFlagsIPv6WritingError> for srhFlagsIPv6 {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), srhFlagsIPv6WritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum srhTagIPv6WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, srhTagIPv6WritingError> for srhTagIPv6 {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), srhTagIPv6WritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum srhSegmentIPv6WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, srhSegmentIPv6WritingError> for srhSegmentIPv6 {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), srhSegmentIPv6WritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum srhActiveSegmentIPv6WritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, srhActiveSegmentIPv6WritingError> for srhActiveSegmentIPv6 {
    const BASE_LENGTH: usize = 16;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), srhActiveSegmentIPv6WritingError> {
         writer.write_all(&self.0.octets())?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum srhSegmentIPv6BasicListWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, srhSegmentIPv6BasicListWritingError> for srhSegmentIPv6BasicList {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), srhSegmentIPv6BasicListWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum srhSegmentIPv6ListSectionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, srhSegmentIPv6ListSectionWritingError> for srhSegmentIPv6ListSection {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), srhSegmentIPv6ListSectionWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum srhSegmentsIPv6LeftWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, srhSegmentsIPv6LeftWritingError> for srhSegmentsIPv6Left {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), srhSegmentsIPv6LeftWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum srhIPv6SectionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, srhIPv6SectionWritingError> for srhIPv6Section {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), srhIPv6SectionWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum srhIPv6ActiveSegmentTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, srhIPv6ActiveSegmentTypeWritingError> for srhIPv6ActiveSegmentType {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), srhIPv6ActiveSegmentTypeWritingError> {
         let num_val = u8::from(*self);
         writer.write_u8(num_val)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum srhSegmentIPv6LocatorLengthWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, srhSegmentIPv6LocatorLengthWritingError> for srhSegmentIPv6LocatorLength {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), srhSegmentIPv6LocatorLengthWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum srhSegmentIPv6EndpointBehaviorWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, srhSegmentIPv6EndpointBehaviorWritingError> for srhSegmentIPv6EndpointBehavior {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), srhSegmentIPv6EndpointBehaviorWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum transportChecksumWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, transportChecksumWritingError> for transportChecksum {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), transportChecksumWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum icmpHeaderPacketSectionWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, icmpHeaderPacketSectionWritingError> for icmpHeaderPacketSection {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), icmpHeaderPacketSectionWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum gtpuFlagsWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, gtpuFlagsWritingError> for gtpuFlags {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), gtpuFlagsWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum gtpuMsgTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, gtpuMsgTypeWritingError> for gtpuMsgType {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), gtpuMsgTypeWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum gtpuTEidWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, gtpuTEidWritingError> for gtpuTEid {
    const BASE_LENGTH: usize = 4;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), gtpuTEidWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u32::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum gtpuSequenceNumWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, gtpuSequenceNumWritingError> for gtpuSequenceNum {
    const BASE_LENGTH: usize = 2;

     fn len(&self, length: Option<u16>) -> usize {
         match length {
             None => Self::BASE_LENGTH,
             Some(len) => len as usize,
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), gtpuSequenceNumWritingError> {
         let num_val = self.0;
         match length {
             None => writer.write_u16::<byteorder::NetworkEndian>(num_val)?,
             Some(len) => {
                 let be_bytes = num_val.to_be_bytes();
                 let begin_offset = be_bytes.len() - len as usize;
                 writer.write_all(&be_bytes[begin_offset..])?;
             }
         }
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum gtpuQFIWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, gtpuQFIWritingError> for gtpuQFI {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), gtpuQFIWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum gtpuPduTypeWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, gtpuPduTypeWritingError> for gtpuPduType {
    const BASE_LENGTH: usize = 1;

     fn len(&self, _length: Option<u16>) -> usize {
         Self::BASE_LENGTH
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), gtpuPduTypeWritingError> {
         writer.write_u8(self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpSourceAsPathListWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpSourceAsPathListWritingError> for bgpSourceAsPathList {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpSourceAsPathListWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum bgpDestinationAsPathListWritingError {
    StdIOError(#[from_std_io_error] String),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, bgpDestinationAsPathListWritingError> for bgpDestinationAsPathList {
    const BASE_LENGTH: usize = 0;

     fn len(&self, _length: Option<u16>) -> usize {
         self.0.len()
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, _length: Option<u16>) -> Result<(), bgpDestinationAsPathListWritingError> {
         writer.write_all(&self.0)?;
         Ok(())
     }
}

#[allow(non_camel_case_types)]
#[derive(netgauze_serde_macros::WritingError, Eq, PartialEq, Clone, Debug)]
pub enum FieldWritingError {
    StdIOError(#[from_std_io_error] String),
    NokiaError(#[from] nokia::FieldWritingError),
    NetGauzeError(#[from] netgauze::FieldWritingError),
    CiscoError(#[from] cisco::FieldWritingError),
    VMWareError(#[from] vmware::FieldWritingError),
    octetDeltaCountError(#[from] octetDeltaCountWritingError),
    packetDeltaCountError(#[from] packetDeltaCountWritingError),
    deltaFlowCountError(#[from] deltaFlowCountWritingError),
    protocolIdentifierError(#[from] protocolIdentifierWritingError),
    ipClassOfServiceError(#[from] ipClassOfServiceWritingError),
    tcpControlBitsError(#[from] tcpControlBitsWritingError),
    sourceTransportPortError(#[from] sourceTransportPortWritingError),
    sourceIPv4AddressError(#[from] sourceIPv4AddressWritingError),
    sourceIPv4PrefixLengthError(#[from] sourceIPv4PrefixLengthWritingError),
    ingressInterfaceError(#[from] ingressInterfaceWritingError),
    destinationTransportPortError(#[from] destinationTransportPortWritingError),
    destinationIPv4AddressError(#[from] destinationIPv4AddressWritingError),
    destinationIPv4PrefixLengthError(#[from] destinationIPv4PrefixLengthWritingError),
    egressInterfaceError(#[from] egressInterfaceWritingError),
    ipNextHopIPv4AddressError(#[from] ipNextHopIPv4AddressWritingError),
    bgpSourceAsNumberError(#[from] bgpSourceAsNumberWritingError),
    bgpDestinationAsNumberError(#[from] bgpDestinationAsNumberWritingError),
    bgpNextHopIPv4AddressError(#[from] bgpNextHopIPv4AddressWritingError),
    postMCastPacketDeltaCountError(#[from] postMCastPacketDeltaCountWritingError),
    postMCastOctetDeltaCountError(#[from] postMCastOctetDeltaCountWritingError),
    flowEndSysUpTimeError(#[from] flowEndSysUpTimeWritingError),
    flowStartSysUpTimeError(#[from] flowStartSysUpTimeWritingError),
    postOctetDeltaCountError(#[from] postOctetDeltaCountWritingError),
    postPacketDeltaCountError(#[from] postPacketDeltaCountWritingError),
    minimumIpTotalLengthError(#[from] minimumIpTotalLengthWritingError),
    maximumIpTotalLengthError(#[from] maximumIpTotalLengthWritingError),
    sourceIPv6AddressError(#[from] sourceIPv6AddressWritingError),
    destinationIPv6AddressError(#[from] destinationIPv6AddressWritingError),
    sourceIPv6PrefixLengthError(#[from] sourceIPv6PrefixLengthWritingError),
    destinationIPv6PrefixLengthError(#[from] destinationIPv6PrefixLengthWritingError),
    flowLabelIPv6Error(#[from] flowLabelIPv6WritingError),
    icmpTypeCodeIPv4Error(#[from] icmpTypeCodeIPv4WritingError),
    igmpTypeError(#[from] igmpTypeWritingError),
    samplingIntervalError(#[from] samplingIntervalWritingError),
    samplingAlgorithmError(#[from] samplingAlgorithmWritingError),
    flowActiveTimeoutError(#[from] flowActiveTimeoutWritingError),
    flowIdleTimeoutError(#[from] flowIdleTimeoutWritingError),
    engineTypeError(#[from] engineTypeWritingError),
    engineIdError(#[from] engineIdWritingError),
    exportedOctetTotalCountError(#[from] exportedOctetTotalCountWritingError),
    exportedMessageTotalCountError(#[from] exportedMessageTotalCountWritingError),
    exportedFlowRecordTotalCountError(#[from] exportedFlowRecordTotalCountWritingError),
    ipv4RouterScError(#[from] ipv4RouterScWritingError),
    sourceIPv4PrefixError(#[from] sourceIPv4PrefixWritingError),
    destinationIPv4PrefixError(#[from] destinationIPv4PrefixWritingError),
    mplsTopLabelTypeError(#[from] mplsTopLabelTypeWritingError),
    mplsTopLabelIPv4AddressError(#[from] mplsTopLabelIPv4AddressWritingError),
    samplerIdError(#[from] samplerIdWritingError),
    samplerModeError(#[from] samplerModeWritingError),
    samplerRandomIntervalError(#[from] samplerRandomIntervalWritingError),
    classIdError(#[from] classIdWritingError),
    minimumTTLError(#[from] minimumTTLWritingError),
    maximumTTLError(#[from] maximumTTLWritingError),
    fragmentIdentificationError(#[from] fragmentIdentificationWritingError),
    postIpClassOfServiceError(#[from] postIpClassOfServiceWritingError),
    sourceMacAddressError(#[from] sourceMacAddressWritingError),
    postDestinationMacAddressError(#[from] postDestinationMacAddressWritingError),
    vlanIdError(#[from] vlanIdWritingError),
    postVlanIdError(#[from] postVlanIdWritingError),
    ipVersionError(#[from] ipVersionWritingError),
    flowDirectionError(#[from] flowDirectionWritingError),
    ipNextHopIPv6AddressError(#[from] ipNextHopIPv6AddressWritingError),
    bgpNextHopIPv6AddressError(#[from] bgpNextHopIPv6AddressWritingError),
    ipv6ExtensionHeadersError(#[from] ipv6ExtensionHeadersWritingError),
    mplsTopLabelStackSectionError(#[from] mplsTopLabelStackSectionWritingError),
    mplsLabelStackSection2Error(#[from] mplsLabelStackSection2WritingError),
    mplsLabelStackSection3Error(#[from] mplsLabelStackSection3WritingError),
    mplsLabelStackSection4Error(#[from] mplsLabelStackSection4WritingError),
    mplsLabelStackSection5Error(#[from] mplsLabelStackSection5WritingError),
    mplsLabelStackSection6Error(#[from] mplsLabelStackSection6WritingError),
    mplsLabelStackSection7Error(#[from] mplsLabelStackSection7WritingError),
    mplsLabelStackSection8Error(#[from] mplsLabelStackSection8WritingError),
    mplsLabelStackSection9Error(#[from] mplsLabelStackSection9WritingError),
    mplsLabelStackSection10Error(#[from] mplsLabelStackSection10WritingError),
    destinationMacAddressError(#[from] destinationMacAddressWritingError),
    postSourceMacAddressError(#[from] postSourceMacAddressWritingError),
    interfaceNameError(#[from] interfaceNameWritingError),
    interfaceDescriptionError(#[from] interfaceDescriptionWritingError),
    samplerNameError(#[from] samplerNameWritingError),
    octetTotalCountError(#[from] octetTotalCountWritingError),
    packetTotalCountError(#[from] packetTotalCountWritingError),
    flagsAndSamplerIdError(#[from] flagsAndSamplerIdWritingError),
    fragmentOffsetError(#[from] fragmentOffsetWritingError),
    forwardingStatusError(#[from] forwardingStatusWritingError),
    mplsVpnRouteDistinguisherError(#[from] mplsVpnRouteDistinguisherWritingError),
    mplsTopLabelPrefixLengthError(#[from] mplsTopLabelPrefixLengthWritingError),
    srcTrafficIndexError(#[from] srcTrafficIndexWritingError),
    dstTrafficIndexError(#[from] dstTrafficIndexWritingError),
    applicationDescriptionError(#[from] applicationDescriptionWritingError),
    applicationIdError(#[from] applicationIdWritingError),
    applicationNameError(#[from] applicationNameWritingError),
    postIpDiffServCodePointError(#[from] postIpDiffServCodePointWritingError),
    multicastReplicationFactorError(#[from] multicastReplicationFactorWritingError),
    classNameError(#[from] classNameWritingError),
    classificationEngineIdError(#[from] classificationEngineIdWritingError),
    layer2packetSectionOffsetError(#[from] layer2packetSectionOffsetWritingError),
    layer2packetSectionSizeError(#[from] layer2packetSectionSizeWritingError),
    layer2packetSectionDataError(#[from] layer2packetSectionDataWritingError),
    bgpNextAdjacentAsNumberError(#[from] bgpNextAdjacentAsNumberWritingError),
    bgpPrevAdjacentAsNumberError(#[from] bgpPrevAdjacentAsNumberWritingError),
    exporterIPv4AddressError(#[from] exporterIPv4AddressWritingError),
    exporterIPv6AddressError(#[from] exporterIPv6AddressWritingError),
    droppedOctetDeltaCountError(#[from] droppedOctetDeltaCountWritingError),
    droppedPacketDeltaCountError(#[from] droppedPacketDeltaCountWritingError),
    droppedOctetTotalCountError(#[from] droppedOctetTotalCountWritingError),
    droppedPacketTotalCountError(#[from] droppedPacketTotalCountWritingError),
    flowEndReasonError(#[from] flowEndReasonWritingError),
    commonPropertiesIdError(#[from] commonPropertiesIdWritingError),
    observationPointIdError(#[from] observationPointIdWritingError),
    icmpTypeCodeIPv6Error(#[from] icmpTypeCodeIPv6WritingError),
    mplsTopLabelIPv6AddressError(#[from] mplsTopLabelIPv6AddressWritingError),
    lineCardIdError(#[from] lineCardIdWritingError),
    portIdError(#[from] portIdWritingError),
    meteringProcessIdError(#[from] meteringProcessIdWritingError),
    exportingProcessIdError(#[from] exportingProcessIdWritingError),
    templateIdError(#[from] templateIdWritingError),
    wlanChannelIdError(#[from] wlanChannelIdWritingError),
    wlanSSIDError(#[from] wlanSSIDWritingError),
    flowIdError(#[from] flowIdWritingError),
    observationDomainIdError(#[from] observationDomainIdWritingError),
    flowStartSecondsError(#[from] flowStartSecondsWritingError),
    flowEndSecondsError(#[from] flowEndSecondsWritingError),
    flowStartMillisecondsError(#[from] flowStartMillisecondsWritingError),
    flowEndMillisecondsError(#[from] flowEndMillisecondsWritingError),
    flowStartMicrosecondsError(#[from] flowStartMicrosecondsWritingError),
    flowEndMicrosecondsError(#[from] flowEndMicrosecondsWritingError),
    flowStartNanosecondsError(#[from] flowStartNanosecondsWritingError),
    flowEndNanosecondsError(#[from] flowEndNanosecondsWritingError),
    flowStartDeltaMicrosecondsError(#[from] flowStartDeltaMicrosecondsWritingError),
    flowEndDeltaMicrosecondsError(#[from] flowEndDeltaMicrosecondsWritingError),
    systemInitTimeMillisecondsError(#[from] systemInitTimeMillisecondsWritingError),
    flowDurationMillisecondsError(#[from] flowDurationMillisecondsWritingError),
    flowDurationMicrosecondsError(#[from] flowDurationMicrosecondsWritingError),
    observedFlowTotalCountError(#[from] observedFlowTotalCountWritingError),
    ignoredPacketTotalCountError(#[from] ignoredPacketTotalCountWritingError),
    ignoredOctetTotalCountError(#[from] ignoredOctetTotalCountWritingError),
    notSentFlowTotalCountError(#[from] notSentFlowTotalCountWritingError),
    notSentPacketTotalCountError(#[from] notSentPacketTotalCountWritingError),
    notSentOctetTotalCountError(#[from] notSentOctetTotalCountWritingError),
    destinationIPv6PrefixError(#[from] destinationIPv6PrefixWritingError),
    sourceIPv6PrefixError(#[from] sourceIPv6PrefixWritingError),
    postOctetTotalCountError(#[from] postOctetTotalCountWritingError),
    postPacketTotalCountError(#[from] postPacketTotalCountWritingError),
    flowKeyIndicatorError(#[from] flowKeyIndicatorWritingError),
    postMCastPacketTotalCountError(#[from] postMCastPacketTotalCountWritingError),
    postMCastOctetTotalCountError(#[from] postMCastOctetTotalCountWritingError),
    icmpTypeIPv4Error(#[from] icmpTypeIPv4WritingError),
    icmpCodeIPv4Error(#[from] icmpCodeIPv4WritingError),
    icmpTypeIPv6Error(#[from] icmpTypeIPv6WritingError),
    icmpCodeIPv6Error(#[from] icmpCodeIPv6WritingError),
    udpSourcePortError(#[from] udpSourcePortWritingError),
    udpDestinationPortError(#[from] udpDestinationPortWritingError),
    tcpSourcePortError(#[from] tcpSourcePortWritingError),
    tcpDestinationPortError(#[from] tcpDestinationPortWritingError),
    tcpSequenceNumberError(#[from] tcpSequenceNumberWritingError),
    tcpAcknowledgementNumberError(#[from] tcpAcknowledgementNumberWritingError),
    tcpWindowSizeError(#[from] tcpWindowSizeWritingError),
    tcpUrgentPointerError(#[from] tcpUrgentPointerWritingError),
    tcpHeaderLengthError(#[from] tcpHeaderLengthWritingError),
    ipHeaderLengthError(#[from] ipHeaderLengthWritingError),
    totalLengthIPv4Error(#[from] totalLengthIPv4WritingError),
    payloadLengthIPv6Error(#[from] payloadLengthIPv6WritingError),
    ipTTLError(#[from] ipTTLWritingError),
    nextHeaderIPv6Error(#[from] nextHeaderIPv6WritingError),
    mplsPayloadLengthError(#[from] mplsPayloadLengthWritingError),
    ipDiffServCodePointError(#[from] ipDiffServCodePointWritingError),
    ipPrecedenceError(#[from] ipPrecedenceWritingError),
    fragmentFlagsError(#[from] fragmentFlagsWritingError),
    octetDeltaSumOfSquaresError(#[from] octetDeltaSumOfSquaresWritingError),
    octetTotalSumOfSquaresError(#[from] octetTotalSumOfSquaresWritingError),
    mplsTopLabelTTLError(#[from] mplsTopLabelTTLWritingError),
    mplsLabelStackLengthError(#[from] mplsLabelStackLengthWritingError),
    mplsLabelStackDepthError(#[from] mplsLabelStackDepthWritingError),
    mplsTopLabelExpError(#[from] mplsTopLabelExpWritingError),
    ipPayloadLengthError(#[from] ipPayloadLengthWritingError),
    udpMessageLengthError(#[from] udpMessageLengthWritingError),
    isMulticastError(#[from] isMulticastWritingError),
    ipv4IHLError(#[from] ipv4IHLWritingError),
    ipv4OptionsError(#[from] ipv4OptionsWritingError),
    tcpOptionsError(#[from] tcpOptionsWritingError),
    paddingOctetsError(#[from] paddingOctetsWritingError),
    collectorIPv4AddressError(#[from] collectorIPv4AddressWritingError),
    collectorIPv6AddressError(#[from] collectorIPv6AddressWritingError),
    exportInterfaceError(#[from] exportInterfaceWritingError),
    exportProtocolVersionError(#[from] exportProtocolVersionWritingError),
    exportTransportProtocolError(#[from] exportTransportProtocolWritingError),
    collectorTransportPortError(#[from] collectorTransportPortWritingError),
    exporterTransportPortError(#[from] exporterTransportPortWritingError),
    tcpSynTotalCountError(#[from] tcpSynTotalCountWritingError),
    tcpFinTotalCountError(#[from] tcpFinTotalCountWritingError),
    tcpRstTotalCountError(#[from] tcpRstTotalCountWritingError),
    tcpPshTotalCountError(#[from] tcpPshTotalCountWritingError),
    tcpAckTotalCountError(#[from] tcpAckTotalCountWritingError),
    tcpUrgTotalCountError(#[from] tcpUrgTotalCountWritingError),
    ipTotalLengthError(#[from] ipTotalLengthWritingError),
    postNATSourceIPv4AddressError(#[from] postNATSourceIPv4AddressWritingError),
    postNATDestinationIPv4AddressError(#[from] postNATDestinationIPv4AddressWritingError),
    postNAPTSourceTransportPortError(#[from] postNAPTSourceTransportPortWritingError),
    postNAPTDestinationTransportPortError(#[from] postNAPTDestinationTransportPortWritingError),
    natOriginatingAddressRealmError(#[from] natOriginatingAddressRealmWritingError),
    natEventError(#[from] natEventWritingError),
    initiatorOctetsError(#[from] initiatorOctetsWritingError),
    responderOctetsError(#[from] responderOctetsWritingError),
    firewallEventError(#[from] firewallEventWritingError),
    ingressVRFIDError(#[from] ingressVRFIDWritingError),
    egressVRFIDError(#[from] egressVRFIDWritingError),
    VRFnameError(#[from] VRFnameWritingError),
    postMplsTopLabelExpError(#[from] postMplsTopLabelExpWritingError),
    tcpWindowScaleError(#[from] tcpWindowScaleWritingError),
    biflowDirectionError(#[from] biflowDirectionWritingError),
    ethernetHeaderLengthError(#[from] ethernetHeaderLengthWritingError),
    ethernetPayloadLengthError(#[from] ethernetPayloadLengthWritingError),
    ethernetTotalLengthError(#[from] ethernetTotalLengthWritingError),
    dot1qVlanIdError(#[from] dot1qVlanIdWritingError),
    dot1qPriorityError(#[from] dot1qPriorityWritingError),
    dot1qCustomerVlanIdError(#[from] dot1qCustomerVlanIdWritingError),
    dot1qCustomerPriorityError(#[from] dot1qCustomerPriorityWritingError),
    metroEvcIdError(#[from] metroEvcIdWritingError),
    metroEvcTypeError(#[from] metroEvcTypeWritingError),
    pseudoWireIdError(#[from] pseudoWireIdWritingError),
    pseudoWireTypeError(#[from] pseudoWireTypeWritingError),
    pseudoWireControlWordError(#[from] pseudoWireControlWordWritingError),
    ingressPhysicalInterfaceError(#[from] ingressPhysicalInterfaceWritingError),
    egressPhysicalInterfaceError(#[from] egressPhysicalInterfaceWritingError),
    postDot1qVlanIdError(#[from] postDot1qVlanIdWritingError),
    postDot1qCustomerVlanIdError(#[from] postDot1qCustomerVlanIdWritingError),
    ethernetTypeError(#[from] ethernetTypeWritingError),
    postIpPrecedenceError(#[from] postIpPrecedenceWritingError),
    collectionTimeMillisecondsError(#[from] collectionTimeMillisecondsWritingError),
    exportSctpStreamIdError(#[from] exportSctpStreamIdWritingError),
    maxExportSecondsError(#[from] maxExportSecondsWritingError),
    maxFlowEndSecondsError(#[from] maxFlowEndSecondsWritingError),
    messageMD5ChecksumError(#[from] messageMD5ChecksumWritingError),
    messageScopeError(#[from] messageScopeWritingError),
    minExportSecondsError(#[from] minExportSecondsWritingError),
    minFlowStartSecondsError(#[from] minFlowStartSecondsWritingError),
    opaqueOctetsError(#[from] opaqueOctetsWritingError),
    sessionScopeError(#[from] sessionScopeWritingError),
    maxFlowEndMicrosecondsError(#[from] maxFlowEndMicrosecondsWritingError),
    maxFlowEndMillisecondsError(#[from] maxFlowEndMillisecondsWritingError),
    maxFlowEndNanosecondsError(#[from] maxFlowEndNanosecondsWritingError),
    minFlowStartMicrosecondsError(#[from] minFlowStartMicrosecondsWritingError),
    minFlowStartMillisecondsError(#[from] minFlowStartMillisecondsWritingError),
    minFlowStartNanosecondsError(#[from] minFlowStartNanosecondsWritingError),
    collectorCertificateError(#[from] collectorCertificateWritingError),
    exporterCertificateError(#[from] exporterCertificateWritingError),
    dataRecordsReliabilityError(#[from] dataRecordsReliabilityWritingError),
    observationPointTypeError(#[from] observationPointTypeWritingError),
    newConnectionDeltaCountError(#[from] newConnectionDeltaCountWritingError),
    connectionSumDurationSecondsError(#[from] connectionSumDurationSecondsWritingError),
    connectionTransactionIdError(#[from] connectionTransactionIdWritingError),
    postNATSourceIPv6AddressError(#[from] postNATSourceIPv6AddressWritingError),
    postNATDestinationIPv6AddressError(#[from] postNATDestinationIPv6AddressWritingError),
    natPoolIdError(#[from] natPoolIdWritingError),
    natPoolNameError(#[from] natPoolNameWritingError),
    anonymizationFlagsError(#[from] anonymizationFlagsWritingError),
    anonymizationTechniqueError(#[from] anonymizationTechniqueWritingError),
    informationElementIndexError(#[from] informationElementIndexWritingError),
    p2pTechnologyError(#[from] p2pTechnologyWritingError),
    tunnelTechnologyError(#[from] tunnelTechnologyWritingError),
    encryptedTechnologyError(#[from] encryptedTechnologyWritingError),
    basicListError(#[from] basicListWritingError),
    subTemplateListError(#[from] subTemplateListWritingError),
    subTemplateMultiListError(#[from] subTemplateMultiListWritingError),
    bgpValidityStateError(#[from] bgpValidityStateWritingError),
    IPSecSPIError(#[from] IPSecSPIWritingError),
    greKeyError(#[from] greKeyWritingError),
    natTypeError(#[from] natTypeWritingError),
    initiatorPacketsError(#[from] initiatorPacketsWritingError),
    responderPacketsError(#[from] responderPacketsWritingError),
    observationDomainNameError(#[from] observationDomainNameWritingError),
    selectionSequenceIdError(#[from] selectionSequenceIdWritingError),
    selectorIdError(#[from] selectorIdWritingError),
    informationElementIdError(#[from] informationElementIdWritingError),
    selectorAlgorithmError(#[from] selectorAlgorithmWritingError),
    samplingPacketIntervalError(#[from] samplingPacketIntervalWritingError),
    samplingPacketSpaceError(#[from] samplingPacketSpaceWritingError),
    samplingTimeIntervalError(#[from] samplingTimeIntervalWritingError),
    samplingTimeSpaceError(#[from] samplingTimeSpaceWritingError),
    samplingSizeError(#[from] samplingSizeWritingError),
    samplingPopulationError(#[from] samplingPopulationWritingError),
    samplingProbabilityError(#[from] samplingProbabilityWritingError),
    dataLinkFrameSizeError(#[from] dataLinkFrameSizeWritingError),
    ipHeaderPacketSectionError(#[from] ipHeaderPacketSectionWritingError),
    ipPayloadPacketSectionError(#[from] ipPayloadPacketSectionWritingError),
    dataLinkFrameSectionError(#[from] dataLinkFrameSectionWritingError),
    mplsLabelStackSectionError(#[from] mplsLabelStackSectionWritingError),
    mplsPayloadPacketSectionError(#[from] mplsPayloadPacketSectionWritingError),
    selectorIdTotalPktsObservedError(#[from] selectorIdTotalPktsObservedWritingError),
    selectorIdTotalPktsSelectedError(#[from] selectorIdTotalPktsSelectedWritingError),
    absoluteErrorError(#[from] absoluteErrorWritingError),
    relativeErrorError(#[from] relativeErrorWritingError),
    observationTimeSecondsError(#[from] observationTimeSecondsWritingError),
    observationTimeMillisecondsError(#[from] observationTimeMillisecondsWritingError),
    observationTimeMicrosecondsError(#[from] observationTimeMicrosecondsWritingError),
    observationTimeNanosecondsError(#[from] observationTimeNanosecondsWritingError),
    digestHashValueError(#[from] digestHashValueWritingError),
    hashIPPayloadOffsetError(#[from] hashIPPayloadOffsetWritingError),
    hashIPPayloadSizeError(#[from] hashIPPayloadSizeWritingError),
    hashOutputRangeMinError(#[from] hashOutputRangeMinWritingError),
    hashOutputRangeMaxError(#[from] hashOutputRangeMaxWritingError),
    hashSelectedRangeMinError(#[from] hashSelectedRangeMinWritingError),
    hashSelectedRangeMaxError(#[from] hashSelectedRangeMaxWritingError),
    hashDigestOutputError(#[from] hashDigestOutputWritingError),
    hashInitialiserValueError(#[from] hashInitialiserValueWritingError),
    selectorNameError(#[from] selectorNameWritingError),
    upperCILimitError(#[from] upperCILimitWritingError),
    lowerCILimitError(#[from] lowerCILimitWritingError),
    confidenceLevelError(#[from] confidenceLevelWritingError),
    informationElementDataTypeError(#[from] informationElementDataTypeWritingError),
    informationElementDescriptionError(#[from] informationElementDescriptionWritingError),
    informationElementNameError(#[from] informationElementNameWritingError),
    informationElementRangeBeginError(#[from] informationElementRangeBeginWritingError),
    informationElementRangeEndError(#[from] informationElementRangeEndWritingError),
    informationElementSemanticsError(#[from] informationElementSemanticsWritingError),
    informationElementUnitsError(#[from] informationElementUnitsWritingError),
    privateEnterpriseNumberError(#[from] privateEnterpriseNumberWritingError),
    virtualStationInterfaceIdError(#[from] virtualStationInterfaceIdWritingError),
    virtualStationInterfaceNameError(#[from] virtualStationInterfaceNameWritingError),
    virtualStationUUIDError(#[from] virtualStationUUIDWritingError),
    virtualStationNameError(#[from] virtualStationNameWritingError),
    layer2SegmentIdError(#[from] layer2SegmentIdWritingError),
    layer2OctetDeltaCountError(#[from] layer2OctetDeltaCountWritingError),
    layer2OctetTotalCountError(#[from] layer2OctetTotalCountWritingError),
    ingressUnicastPacketTotalCountError(#[from] ingressUnicastPacketTotalCountWritingError),
    ingressMulticastPacketTotalCountError(#[from] ingressMulticastPacketTotalCountWritingError),
    ingressBroadcastPacketTotalCountError(#[from] ingressBroadcastPacketTotalCountWritingError),
    egressUnicastPacketTotalCountError(#[from] egressUnicastPacketTotalCountWritingError),
    egressBroadcastPacketTotalCountError(#[from] egressBroadcastPacketTotalCountWritingError),
    monitoringIntervalStartMilliSecondsError(#[from] monitoringIntervalStartMilliSecondsWritingError),
    monitoringIntervalEndMilliSecondsError(#[from] monitoringIntervalEndMilliSecondsWritingError),
    portRangeStartError(#[from] portRangeStartWritingError),
    portRangeEndError(#[from] portRangeEndWritingError),
    portRangeStepSizeError(#[from] portRangeStepSizeWritingError),
    portRangeNumPortsError(#[from] portRangeNumPortsWritingError),
    staMacAddressError(#[from] staMacAddressWritingError),
    staIPv4AddressError(#[from] staIPv4AddressWritingError),
    wtpMacAddressError(#[from] wtpMacAddressWritingError),
    ingressInterfaceTypeError(#[from] ingressInterfaceTypeWritingError),
    egressInterfaceTypeError(#[from] egressInterfaceTypeWritingError),
    rtpSequenceNumberError(#[from] rtpSequenceNumberWritingError),
    userNameError(#[from] userNameWritingError),
    applicationCategoryNameError(#[from] applicationCategoryNameWritingError),
    applicationSubCategoryNameError(#[from] applicationSubCategoryNameWritingError),
    applicationGroupNameError(#[from] applicationGroupNameWritingError),
    originalFlowsPresentError(#[from] originalFlowsPresentWritingError),
    originalFlowsInitiatedError(#[from] originalFlowsInitiatedWritingError),
    originalFlowsCompletedError(#[from] originalFlowsCompletedWritingError),
    distinctCountOfSourceIPAddressError(#[from] distinctCountOfSourceIPAddressWritingError),
    distinctCountOfDestinationIPAddressError(#[from] distinctCountOfDestinationIPAddressWritingError),
    distinctCountOfSourceIPv4AddressError(#[from] distinctCountOfSourceIPv4AddressWritingError),
    distinctCountOfDestinationIPv4AddressError(#[from] distinctCountOfDestinationIPv4AddressWritingError),
    distinctCountOfSourceIPv6AddressError(#[from] distinctCountOfSourceIPv6AddressWritingError),
    distinctCountOfDestinationIPv6AddressError(#[from] distinctCountOfDestinationIPv6AddressWritingError),
    valueDistributionMethodError(#[from] valueDistributionMethodWritingError),
    rfc3550JitterMillisecondsError(#[from] rfc3550JitterMillisecondsWritingError),
    rfc3550JitterMicrosecondsError(#[from] rfc3550JitterMicrosecondsWritingError),
    rfc3550JitterNanosecondsError(#[from] rfc3550JitterNanosecondsWritingError),
    dot1qDEIError(#[from] dot1qDEIWritingError),
    dot1qCustomerDEIError(#[from] dot1qCustomerDEIWritingError),
    flowSelectorAlgorithmError(#[from] flowSelectorAlgorithmWritingError),
    flowSelectedOctetDeltaCountError(#[from] flowSelectedOctetDeltaCountWritingError),
    flowSelectedPacketDeltaCountError(#[from] flowSelectedPacketDeltaCountWritingError),
    flowSelectedFlowDeltaCountError(#[from] flowSelectedFlowDeltaCountWritingError),
    selectorIDTotalFlowsObservedError(#[from] selectorIDTotalFlowsObservedWritingError),
    selectorIDTotalFlowsSelectedError(#[from] selectorIDTotalFlowsSelectedWritingError),
    samplingFlowIntervalError(#[from] samplingFlowIntervalWritingError),
    samplingFlowSpacingError(#[from] samplingFlowSpacingWritingError),
    flowSamplingTimeIntervalError(#[from] flowSamplingTimeIntervalWritingError),
    flowSamplingTimeSpacingError(#[from] flowSamplingTimeSpacingWritingError),
    hashFlowDomainError(#[from] hashFlowDomainWritingError),
    transportOctetDeltaCountError(#[from] transportOctetDeltaCountWritingError),
    transportPacketDeltaCountError(#[from] transportPacketDeltaCountWritingError),
    originalExporterIPv4AddressError(#[from] originalExporterIPv4AddressWritingError),
    originalExporterIPv6AddressError(#[from] originalExporterIPv6AddressWritingError),
    originalObservationDomainIdError(#[from] originalObservationDomainIdWritingError),
    intermediateProcessIdError(#[from] intermediateProcessIdWritingError),
    ignoredDataRecordTotalCountError(#[from] ignoredDataRecordTotalCountWritingError),
    dataLinkFrameTypeError(#[from] dataLinkFrameTypeWritingError),
    sectionOffsetError(#[from] sectionOffsetWritingError),
    sectionExportedOctetsError(#[from] sectionExportedOctetsWritingError),
    dot1qServiceInstanceTagError(#[from] dot1qServiceInstanceTagWritingError),
    dot1qServiceInstanceIdError(#[from] dot1qServiceInstanceIdWritingError),
    dot1qServiceInstancePriorityError(#[from] dot1qServiceInstancePriorityWritingError),
    dot1qCustomerSourceMacAddressError(#[from] dot1qCustomerSourceMacAddressWritingError),
    dot1qCustomerDestinationMacAddressError(#[from] dot1qCustomerDestinationMacAddressWritingError),
    postLayer2OctetDeltaCountError(#[from] postLayer2OctetDeltaCountWritingError),
    postMCastLayer2OctetDeltaCountError(#[from] postMCastLayer2OctetDeltaCountWritingError),
    postLayer2OctetTotalCountError(#[from] postLayer2OctetTotalCountWritingError),
    postMCastLayer2OctetTotalCountError(#[from] postMCastLayer2OctetTotalCountWritingError),
    minimumLayer2TotalLengthError(#[from] minimumLayer2TotalLengthWritingError),
    maximumLayer2TotalLengthError(#[from] maximumLayer2TotalLengthWritingError),
    droppedLayer2OctetDeltaCountError(#[from] droppedLayer2OctetDeltaCountWritingError),
    droppedLayer2OctetTotalCountError(#[from] droppedLayer2OctetTotalCountWritingError),
    ignoredLayer2OctetTotalCountError(#[from] ignoredLayer2OctetTotalCountWritingError),
    notSentLayer2OctetTotalCountError(#[from] notSentLayer2OctetTotalCountWritingError),
    layer2OctetDeltaSumOfSquaresError(#[from] layer2OctetDeltaSumOfSquaresWritingError),
    layer2OctetTotalSumOfSquaresError(#[from] layer2OctetTotalSumOfSquaresWritingError),
    layer2FrameDeltaCountError(#[from] layer2FrameDeltaCountWritingError),
    layer2FrameTotalCountError(#[from] layer2FrameTotalCountWritingError),
    pseudoWireDestinationIPv4AddressError(#[from] pseudoWireDestinationIPv4AddressWritingError),
    ignoredLayer2FrameTotalCountError(#[from] ignoredLayer2FrameTotalCountWritingError),
    mibObjectValueIntegerError(#[from] mibObjectValueIntegerWritingError),
    mibObjectValueOctetStringError(#[from] mibObjectValueOctetStringWritingError),
    mibObjectValueOIDError(#[from] mibObjectValueOIDWritingError),
    mibObjectValueBitsError(#[from] mibObjectValueBitsWritingError),
    mibObjectValueIPAddressError(#[from] mibObjectValueIPAddressWritingError),
    mibObjectValueCounterError(#[from] mibObjectValueCounterWritingError),
    mibObjectValueGaugeError(#[from] mibObjectValueGaugeWritingError),
    mibObjectValueTimeTicksError(#[from] mibObjectValueTimeTicksWritingError),
    mibObjectValueUnsignedError(#[from] mibObjectValueUnsignedWritingError),
    mibObjectValueTableError(#[from] mibObjectValueTableWritingError),
    mibObjectValueRowError(#[from] mibObjectValueRowWritingError),
    mibObjectIdentifierError(#[from] mibObjectIdentifierWritingError),
    mibSubIdentifierError(#[from] mibSubIdentifierWritingError),
    mibIndexIndicatorError(#[from] mibIndexIndicatorWritingError),
    mibCaptureTimeSemanticsError(#[from] mibCaptureTimeSemanticsWritingError),
    mibContextEngineIDError(#[from] mibContextEngineIDWritingError),
    mibContextNameError(#[from] mibContextNameWritingError),
    mibObjectNameError(#[from] mibObjectNameWritingError),
    mibObjectDescriptionError(#[from] mibObjectDescriptionWritingError),
    mibObjectSyntaxError(#[from] mibObjectSyntaxWritingError),
    mibModuleNameError(#[from] mibModuleNameWritingError),
    mobileIMSIError(#[from] mobileIMSIWritingError),
    mobileMSISDNError(#[from] mobileMSISDNWritingError),
    httpStatusCodeError(#[from] httpStatusCodeWritingError),
    sourceTransportPortsLimitError(#[from] sourceTransportPortsLimitWritingError),
    httpRequestMethodError(#[from] httpRequestMethodWritingError),
    httpRequestHostError(#[from] httpRequestHostWritingError),
    httpRequestTargetError(#[from] httpRequestTargetWritingError),
    httpMessageVersionError(#[from] httpMessageVersionWritingError),
    natInstanceIDError(#[from] natInstanceIDWritingError),
    internalAddressRealmError(#[from] internalAddressRealmWritingError),
    externalAddressRealmError(#[from] externalAddressRealmWritingError),
    natQuotaExceededEventError(#[from] natQuotaExceededEventWritingError),
    natThresholdEventError(#[from] natThresholdEventWritingError),
    httpUserAgentError(#[from] httpUserAgentWritingError),
    httpContentTypeError(#[from] httpContentTypeWritingError),
    httpReasonPhraseError(#[from] httpReasonPhraseWritingError),
    maxSessionEntriesError(#[from] maxSessionEntriesWritingError),
    maxBIBEntriesError(#[from] maxBIBEntriesWritingError),
    maxEntriesPerUserError(#[from] maxEntriesPerUserWritingError),
    maxSubscribersError(#[from] maxSubscribersWritingError),
    maxFragmentsPendingReassemblyError(#[from] maxFragmentsPendingReassemblyWritingError),
    addressPoolHighThresholdError(#[from] addressPoolHighThresholdWritingError),
    addressPoolLowThresholdError(#[from] addressPoolLowThresholdWritingError),
    addressPortMappingHighThresholdError(#[from] addressPortMappingHighThresholdWritingError),
    addressPortMappingLowThresholdError(#[from] addressPortMappingLowThresholdWritingError),
    addressPortMappingPerUserHighThresholdError(#[from] addressPortMappingPerUserHighThresholdWritingError),
    globalAddressMappingHighThresholdError(#[from] globalAddressMappingHighThresholdWritingError),
    vpnIdentifierError(#[from] vpnIdentifierWritingError),
    bgpCommunityError(#[from] bgpCommunityWritingError),
    bgpSourceCommunityListError(#[from] bgpSourceCommunityListWritingError),
    bgpDestinationCommunityListError(#[from] bgpDestinationCommunityListWritingError),
    bgpExtendedCommunityError(#[from] bgpExtendedCommunityWritingError),
    bgpSourceExtendedCommunityListError(#[from] bgpSourceExtendedCommunityListWritingError),
    bgpDestinationExtendedCommunityListError(#[from] bgpDestinationExtendedCommunityListWritingError),
    bgpLargeCommunityError(#[from] bgpLargeCommunityWritingError),
    bgpSourceLargeCommunityListError(#[from] bgpSourceLargeCommunityListWritingError),
    bgpDestinationLargeCommunityListError(#[from] bgpDestinationLargeCommunityListWritingError),
    srhFlagsIPv6Error(#[from] srhFlagsIPv6WritingError),
    srhTagIPv6Error(#[from] srhTagIPv6WritingError),
    srhSegmentIPv6Error(#[from] srhSegmentIPv6WritingError),
    srhActiveSegmentIPv6Error(#[from] srhActiveSegmentIPv6WritingError),
    srhSegmentIPv6BasicListError(#[from] srhSegmentIPv6BasicListWritingError),
    srhSegmentIPv6ListSectionError(#[from] srhSegmentIPv6ListSectionWritingError),
    srhSegmentsIPv6LeftError(#[from] srhSegmentsIPv6LeftWritingError),
    srhIPv6SectionError(#[from] srhIPv6SectionWritingError),
    srhIPv6ActiveSegmentTypeError(#[from] srhIPv6ActiveSegmentTypeWritingError),
    srhSegmentIPv6LocatorLengthError(#[from] srhSegmentIPv6LocatorLengthWritingError),
    srhSegmentIPv6EndpointBehaviorError(#[from] srhSegmentIPv6EndpointBehaviorWritingError),
    transportChecksumError(#[from] transportChecksumWritingError),
    icmpHeaderPacketSectionError(#[from] icmpHeaderPacketSectionWritingError),
    gtpuFlagsError(#[from] gtpuFlagsWritingError),
    gtpuMsgTypeError(#[from] gtpuMsgTypeWritingError),
    gtpuTEidError(#[from] gtpuTEidWritingError),
    gtpuSequenceNumError(#[from] gtpuSequenceNumWritingError),
    gtpuQFIError(#[from] gtpuQFIWritingError),
    gtpuPduTypeError(#[from] gtpuPduTypeWritingError),
    bgpSourceAsPathListError(#[from] bgpSourceAsPathListWritingError),
    bgpDestinationAsPathListError(#[from] bgpDestinationAsPathListWritingError),
}

impl netgauze_parse_utils::WritablePduWithOneInput<Option<u16>, FieldWritingError> for Field {
    const BASE_LENGTH: usize = 0;

    fn len(&self, length: Option<u16>) -> usize {
        match self {
            Self::Unknown(value) => value.len(),
            Self::Nokia(value) => value.len(length),
            Self::NetGauze(value) => value.len(length),
            Self::Cisco(value) => value.len(length),
            Self::VMWare(value) => value.len(length),
            Self::octetDeltaCount(value) => value.len(length),
            Self::packetDeltaCount(value) => value.len(length),
            Self::deltaFlowCount(value) => value.len(length),
            Self::protocolIdentifier(value) => value.len(length),
            Self::ipClassOfService(value) => value.len(length),
            Self::tcpControlBits(value) => value.len(length),
            Self::sourceTransportPort(value) => value.len(length),
            Self::sourceIPv4Address(value) => value.len(length),
            Self::sourceIPv4PrefixLength(value) => value.len(length),
            Self::ingressInterface(value) => value.len(length),
            Self::destinationTransportPort(value) => value.len(length),
            Self::destinationIPv4Address(value) => value.len(length),
            Self::destinationIPv4PrefixLength(value) => value.len(length),
            Self::egressInterface(value) => value.len(length),
            Self::ipNextHopIPv4Address(value) => value.len(length),
            Self::bgpSourceAsNumber(value) => value.len(length),
            Self::bgpDestinationAsNumber(value) => value.len(length),
            Self::bgpNextHopIPv4Address(value) => value.len(length),
            Self::postMCastPacketDeltaCount(value) => value.len(length),
            Self::postMCastOctetDeltaCount(value) => value.len(length),
            Self::flowEndSysUpTime(value) => value.len(length),
            Self::flowStartSysUpTime(value) => value.len(length),
            Self::postOctetDeltaCount(value) => value.len(length),
            Self::postPacketDeltaCount(value) => value.len(length),
            Self::minimumIpTotalLength(value) => value.len(length),
            Self::maximumIpTotalLength(value) => value.len(length),
            Self::sourceIPv6Address(value) => value.len(length),
            Self::destinationIPv6Address(value) => value.len(length),
            Self::sourceIPv6PrefixLength(value) => value.len(length),
            Self::destinationIPv6PrefixLength(value) => value.len(length),
            Self::flowLabelIPv6(value) => value.len(length),
            Self::icmpTypeCodeIPv4(value) => value.len(length),
            Self::igmpType(value) => value.len(length),
            Self::samplingInterval(value) => value.len(length),
            Self::samplingAlgorithm(value) => value.len(length),
            Self::flowActiveTimeout(value) => value.len(length),
            Self::flowIdleTimeout(value) => value.len(length),
            Self::engineType(value) => value.len(length),
            Self::engineId(value) => value.len(length),
            Self::exportedOctetTotalCount(value) => value.len(length),
            Self::exportedMessageTotalCount(value) => value.len(length),
            Self::exportedFlowRecordTotalCount(value) => value.len(length),
            Self::ipv4RouterSc(value) => value.len(length),
            Self::sourceIPv4Prefix(value) => value.len(length),
            Self::destinationIPv4Prefix(value) => value.len(length),
            Self::mplsTopLabelType(value) => value.len(length),
            Self::mplsTopLabelIPv4Address(value) => value.len(length),
            Self::samplerId(value) => value.len(length),
            Self::samplerMode(value) => value.len(length),
            Self::samplerRandomInterval(value) => value.len(length),
            Self::classId(value) => value.len(length),
            Self::minimumTTL(value) => value.len(length),
            Self::maximumTTL(value) => value.len(length),
            Self::fragmentIdentification(value) => value.len(length),
            Self::postIpClassOfService(value) => value.len(length),
            Self::sourceMacAddress(value) => value.len(length),
            Self::postDestinationMacAddress(value) => value.len(length),
            Self::vlanId(value) => value.len(length),
            Self::postVlanId(value) => value.len(length),
            Self::ipVersion(value) => value.len(length),
            Self::flowDirection(value) => value.len(length),
            Self::ipNextHopIPv6Address(value) => value.len(length),
            Self::bgpNextHopIPv6Address(value) => value.len(length),
            Self::ipv6ExtensionHeaders(value) => value.len(length),
            Self::mplsTopLabelStackSection(value) => value.len(length),
            Self::mplsLabelStackSection2(value) => value.len(length),
            Self::mplsLabelStackSection3(value) => value.len(length),
            Self::mplsLabelStackSection4(value) => value.len(length),
            Self::mplsLabelStackSection5(value) => value.len(length),
            Self::mplsLabelStackSection6(value) => value.len(length),
            Self::mplsLabelStackSection7(value) => value.len(length),
            Self::mplsLabelStackSection8(value) => value.len(length),
            Self::mplsLabelStackSection9(value) => value.len(length),
            Self::mplsLabelStackSection10(value) => value.len(length),
            Self::destinationMacAddress(value) => value.len(length),
            Self::postSourceMacAddress(value) => value.len(length),
            Self::interfaceName(value) => value.len(length),
            Self::interfaceDescription(value) => value.len(length),
            Self::samplerName(value) => value.len(length),
            Self::octetTotalCount(value) => value.len(length),
            Self::packetTotalCount(value) => value.len(length),
            Self::flagsAndSamplerId(value) => value.len(length),
            Self::fragmentOffset(value) => value.len(length),
            Self::forwardingStatus(value) => value.len(length),
            Self::mplsVpnRouteDistinguisher(value) => value.len(length),
            Self::mplsTopLabelPrefixLength(value) => value.len(length),
            Self::srcTrafficIndex(value) => value.len(length),
            Self::dstTrafficIndex(value) => value.len(length),
            Self::applicationDescription(value) => value.len(length),
            Self::applicationId(value) => value.len(length),
            Self::applicationName(value) => value.len(length),
            Self::postIpDiffServCodePoint(value) => value.len(length),
            Self::multicastReplicationFactor(value) => value.len(length),
            Self::className(value) => value.len(length),
            Self::classificationEngineId(value) => value.len(length),
            Self::layer2packetSectionOffset(value) => value.len(length),
            Self::layer2packetSectionSize(value) => value.len(length),
            Self::layer2packetSectionData(value) => value.len(length),
            Self::bgpNextAdjacentAsNumber(value) => value.len(length),
            Self::bgpPrevAdjacentAsNumber(value) => value.len(length),
            Self::exporterIPv4Address(value) => value.len(length),
            Self::exporterIPv6Address(value) => value.len(length),
            Self::droppedOctetDeltaCount(value) => value.len(length),
            Self::droppedPacketDeltaCount(value) => value.len(length),
            Self::droppedOctetTotalCount(value) => value.len(length),
            Self::droppedPacketTotalCount(value) => value.len(length),
            Self::flowEndReason(value) => value.len(length),
            Self::commonPropertiesId(value) => value.len(length),
            Self::observationPointId(value) => value.len(length),
            Self::icmpTypeCodeIPv6(value) => value.len(length),
            Self::mplsTopLabelIPv6Address(value) => value.len(length),
            Self::lineCardId(value) => value.len(length),
            Self::portId(value) => value.len(length),
            Self::meteringProcessId(value) => value.len(length),
            Self::exportingProcessId(value) => value.len(length),
            Self::templateId(value) => value.len(length),
            Self::wlanChannelId(value) => value.len(length),
            Self::wlanSSID(value) => value.len(length),
            Self::flowId(value) => value.len(length),
            Self::observationDomainId(value) => value.len(length),
            Self::flowStartSeconds(value) => value.len(length),
            Self::flowEndSeconds(value) => value.len(length),
            Self::flowStartMilliseconds(value) => value.len(length),
            Self::flowEndMilliseconds(value) => value.len(length),
            Self::flowStartMicroseconds(value) => value.len(length),
            Self::flowEndMicroseconds(value) => value.len(length),
            Self::flowStartNanoseconds(value) => value.len(length),
            Self::flowEndNanoseconds(value) => value.len(length),
            Self::flowStartDeltaMicroseconds(value) => value.len(length),
            Self::flowEndDeltaMicroseconds(value) => value.len(length),
            Self::systemInitTimeMilliseconds(value) => value.len(length),
            Self::flowDurationMilliseconds(value) => value.len(length),
            Self::flowDurationMicroseconds(value) => value.len(length),
            Self::observedFlowTotalCount(value) => value.len(length),
            Self::ignoredPacketTotalCount(value) => value.len(length),
            Self::ignoredOctetTotalCount(value) => value.len(length),
            Self::notSentFlowTotalCount(value) => value.len(length),
            Self::notSentPacketTotalCount(value) => value.len(length),
            Self::notSentOctetTotalCount(value) => value.len(length),
            Self::destinationIPv6Prefix(value) => value.len(length),
            Self::sourceIPv6Prefix(value) => value.len(length),
            Self::postOctetTotalCount(value) => value.len(length),
            Self::postPacketTotalCount(value) => value.len(length),
            Self::flowKeyIndicator(value) => value.len(length),
            Self::postMCastPacketTotalCount(value) => value.len(length),
            Self::postMCastOctetTotalCount(value) => value.len(length),
            Self::icmpTypeIPv4(value) => value.len(length),
            Self::icmpCodeIPv4(value) => value.len(length),
            Self::icmpTypeIPv6(value) => value.len(length),
            Self::icmpCodeIPv6(value) => value.len(length),
            Self::udpSourcePort(value) => value.len(length),
            Self::udpDestinationPort(value) => value.len(length),
            Self::tcpSourcePort(value) => value.len(length),
            Self::tcpDestinationPort(value) => value.len(length),
            Self::tcpSequenceNumber(value) => value.len(length),
            Self::tcpAcknowledgementNumber(value) => value.len(length),
            Self::tcpWindowSize(value) => value.len(length),
            Self::tcpUrgentPointer(value) => value.len(length),
            Self::tcpHeaderLength(value) => value.len(length),
            Self::ipHeaderLength(value) => value.len(length),
            Self::totalLengthIPv4(value) => value.len(length),
            Self::payloadLengthIPv6(value) => value.len(length),
            Self::ipTTL(value) => value.len(length),
            Self::nextHeaderIPv6(value) => value.len(length),
            Self::mplsPayloadLength(value) => value.len(length),
            Self::ipDiffServCodePoint(value) => value.len(length),
            Self::ipPrecedence(value) => value.len(length),
            Self::fragmentFlags(value) => value.len(length),
            Self::octetDeltaSumOfSquares(value) => value.len(length),
            Self::octetTotalSumOfSquares(value) => value.len(length),
            Self::mplsTopLabelTTL(value) => value.len(length),
            Self::mplsLabelStackLength(value) => value.len(length),
            Self::mplsLabelStackDepth(value) => value.len(length),
            Self::mplsTopLabelExp(value) => value.len(length),
            Self::ipPayloadLength(value) => value.len(length),
            Self::udpMessageLength(value) => value.len(length),
            Self::isMulticast(value) => value.len(length),
            Self::ipv4IHL(value) => value.len(length),
            Self::ipv4Options(value) => value.len(length),
            Self::tcpOptions(value) => value.len(length),
            Self::paddingOctets(value) => value.len(length),
            Self::collectorIPv4Address(value) => value.len(length),
            Self::collectorIPv6Address(value) => value.len(length),
            Self::exportInterface(value) => value.len(length),
            Self::exportProtocolVersion(value) => value.len(length),
            Self::exportTransportProtocol(value) => value.len(length),
            Self::collectorTransportPort(value) => value.len(length),
            Self::exporterTransportPort(value) => value.len(length),
            Self::tcpSynTotalCount(value) => value.len(length),
            Self::tcpFinTotalCount(value) => value.len(length),
            Self::tcpRstTotalCount(value) => value.len(length),
            Self::tcpPshTotalCount(value) => value.len(length),
            Self::tcpAckTotalCount(value) => value.len(length),
            Self::tcpUrgTotalCount(value) => value.len(length),
            Self::ipTotalLength(value) => value.len(length),
            Self::postNATSourceIPv4Address(value) => value.len(length),
            Self::postNATDestinationIPv4Address(value) => value.len(length),
            Self::postNAPTSourceTransportPort(value) => value.len(length),
            Self::postNAPTDestinationTransportPort(value) => value.len(length),
            Self::natOriginatingAddressRealm(value) => value.len(length),
            Self::natEvent(value) => value.len(length),
            Self::initiatorOctets(value) => value.len(length),
            Self::responderOctets(value) => value.len(length),
            Self::firewallEvent(value) => value.len(length),
            Self::ingressVRFID(value) => value.len(length),
            Self::egressVRFID(value) => value.len(length),
            Self::VRFname(value) => value.len(length),
            Self::postMplsTopLabelExp(value) => value.len(length),
            Self::tcpWindowScale(value) => value.len(length),
            Self::biflowDirection(value) => value.len(length),
            Self::ethernetHeaderLength(value) => value.len(length),
            Self::ethernetPayloadLength(value) => value.len(length),
            Self::ethernetTotalLength(value) => value.len(length),
            Self::dot1qVlanId(value) => value.len(length),
            Self::dot1qPriority(value) => value.len(length),
            Self::dot1qCustomerVlanId(value) => value.len(length),
            Self::dot1qCustomerPriority(value) => value.len(length),
            Self::metroEvcId(value) => value.len(length),
            Self::metroEvcType(value) => value.len(length),
            Self::pseudoWireId(value) => value.len(length),
            Self::pseudoWireType(value) => value.len(length),
            Self::pseudoWireControlWord(value) => value.len(length),
            Self::ingressPhysicalInterface(value) => value.len(length),
            Self::egressPhysicalInterface(value) => value.len(length),
            Self::postDot1qVlanId(value) => value.len(length),
            Self::postDot1qCustomerVlanId(value) => value.len(length),
            Self::ethernetType(value) => value.len(length),
            Self::postIpPrecedence(value) => value.len(length),
            Self::collectionTimeMilliseconds(value) => value.len(length),
            Self::exportSctpStreamId(value) => value.len(length),
            Self::maxExportSeconds(value) => value.len(length),
            Self::maxFlowEndSeconds(value) => value.len(length),
            Self::messageMD5Checksum(value) => value.len(length),
            Self::messageScope(value) => value.len(length),
            Self::minExportSeconds(value) => value.len(length),
            Self::minFlowStartSeconds(value) => value.len(length),
            Self::opaqueOctets(value) => value.len(length),
            Self::sessionScope(value) => value.len(length),
            Self::maxFlowEndMicroseconds(value) => value.len(length),
            Self::maxFlowEndMilliseconds(value) => value.len(length),
            Self::maxFlowEndNanoseconds(value) => value.len(length),
            Self::minFlowStartMicroseconds(value) => value.len(length),
            Self::minFlowStartMilliseconds(value) => value.len(length),
            Self::minFlowStartNanoseconds(value) => value.len(length),
            Self::collectorCertificate(value) => value.len(length),
            Self::exporterCertificate(value) => value.len(length),
            Self::dataRecordsReliability(value) => value.len(length),
            Self::observationPointType(value) => value.len(length),
            Self::newConnectionDeltaCount(value) => value.len(length),
            Self::connectionSumDurationSeconds(value) => value.len(length),
            Self::connectionTransactionId(value) => value.len(length),
            Self::postNATSourceIPv6Address(value) => value.len(length),
            Self::postNATDestinationIPv6Address(value) => value.len(length),
            Self::natPoolId(value) => value.len(length),
            Self::natPoolName(value) => value.len(length),
            Self::anonymizationFlags(value) => value.len(length),
            Self::anonymizationTechnique(value) => value.len(length),
            Self::informationElementIndex(value) => value.len(length),
            Self::p2pTechnology(value) => value.len(length),
            Self::tunnelTechnology(value) => value.len(length),
            Self::encryptedTechnology(value) => value.len(length),
            Self::basicList(value) => value.len(length),
            Self::subTemplateList(value) => value.len(length),
            Self::subTemplateMultiList(value) => value.len(length),
            Self::bgpValidityState(value) => value.len(length),
            Self::IPSecSPI(value) => value.len(length),
            Self::greKey(value) => value.len(length),
            Self::natType(value) => value.len(length),
            Self::initiatorPackets(value) => value.len(length),
            Self::responderPackets(value) => value.len(length),
            Self::observationDomainName(value) => value.len(length),
            Self::selectionSequenceId(value) => value.len(length),
            Self::selectorId(value) => value.len(length),
            Self::informationElementId(value) => value.len(length),
            Self::selectorAlgorithm(value) => value.len(length),
            Self::samplingPacketInterval(value) => value.len(length),
            Self::samplingPacketSpace(value) => value.len(length),
            Self::samplingTimeInterval(value) => value.len(length),
            Self::samplingTimeSpace(value) => value.len(length),
            Self::samplingSize(value) => value.len(length),
            Self::samplingPopulation(value) => value.len(length),
            Self::samplingProbability(value) => value.len(length),
            Self::dataLinkFrameSize(value) => value.len(length),
            Self::ipHeaderPacketSection(value) => value.len(length),
            Self::ipPayloadPacketSection(value) => value.len(length),
            Self::dataLinkFrameSection(value) => value.len(length),
            Self::mplsLabelStackSection(value) => value.len(length),
            Self::mplsPayloadPacketSection(value) => value.len(length),
            Self::selectorIdTotalPktsObserved(value) => value.len(length),
            Self::selectorIdTotalPktsSelected(value) => value.len(length),
            Self::absoluteError(value) => value.len(length),
            Self::relativeError(value) => value.len(length),
            Self::observationTimeSeconds(value) => value.len(length),
            Self::observationTimeMilliseconds(value) => value.len(length),
            Self::observationTimeMicroseconds(value) => value.len(length),
            Self::observationTimeNanoseconds(value) => value.len(length),
            Self::digestHashValue(value) => value.len(length),
            Self::hashIPPayloadOffset(value) => value.len(length),
            Self::hashIPPayloadSize(value) => value.len(length),
            Self::hashOutputRangeMin(value) => value.len(length),
            Self::hashOutputRangeMax(value) => value.len(length),
            Self::hashSelectedRangeMin(value) => value.len(length),
            Self::hashSelectedRangeMax(value) => value.len(length),
            Self::hashDigestOutput(value) => value.len(length),
            Self::hashInitialiserValue(value) => value.len(length),
            Self::selectorName(value) => value.len(length),
            Self::upperCILimit(value) => value.len(length),
            Self::lowerCILimit(value) => value.len(length),
            Self::confidenceLevel(value) => value.len(length),
            Self::informationElementDataType(value) => value.len(length),
            Self::informationElementDescription(value) => value.len(length),
            Self::informationElementName(value) => value.len(length),
            Self::informationElementRangeBegin(value) => value.len(length),
            Self::informationElementRangeEnd(value) => value.len(length),
            Self::informationElementSemantics(value) => value.len(length),
            Self::informationElementUnits(value) => value.len(length),
            Self::privateEnterpriseNumber(value) => value.len(length),
            Self::virtualStationInterfaceId(value) => value.len(length),
            Self::virtualStationInterfaceName(value) => value.len(length),
            Self::virtualStationUUID(value) => value.len(length),
            Self::virtualStationName(value) => value.len(length),
            Self::layer2SegmentId(value) => value.len(length),
            Self::layer2OctetDeltaCount(value) => value.len(length),
            Self::layer2OctetTotalCount(value) => value.len(length),
            Self::ingressUnicastPacketTotalCount(value) => value.len(length),
            Self::ingressMulticastPacketTotalCount(value) => value.len(length),
            Self::ingressBroadcastPacketTotalCount(value) => value.len(length),
            Self::egressUnicastPacketTotalCount(value) => value.len(length),
            Self::egressBroadcastPacketTotalCount(value) => value.len(length),
            Self::monitoringIntervalStartMilliSeconds(value) => value.len(length),
            Self::monitoringIntervalEndMilliSeconds(value) => value.len(length),
            Self::portRangeStart(value) => value.len(length),
            Self::portRangeEnd(value) => value.len(length),
            Self::portRangeStepSize(value) => value.len(length),
            Self::portRangeNumPorts(value) => value.len(length),
            Self::staMacAddress(value) => value.len(length),
            Self::staIPv4Address(value) => value.len(length),
            Self::wtpMacAddress(value) => value.len(length),
            Self::ingressInterfaceType(value) => value.len(length),
            Self::egressInterfaceType(value) => value.len(length),
            Self::rtpSequenceNumber(value) => value.len(length),
            Self::userName(value) => value.len(length),
            Self::applicationCategoryName(value) => value.len(length),
            Self::applicationSubCategoryName(value) => value.len(length),
            Self::applicationGroupName(value) => value.len(length),
            Self::originalFlowsPresent(value) => value.len(length),
            Self::originalFlowsInitiated(value) => value.len(length),
            Self::originalFlowsCompleted(value) => value.len(length),
            Self::distinctCountOfSourceIPAddress(value) => value.len(length),
            Self::distinctCountOfDestinationIPAddress(value) => value.len(length),
            Self::distinctCountOfSourceIPv4Address(value) => value.len(length),
            Self::distinctCountOfDestinationIPv4Address(value) => value.len(length),
            Self::distinctCountOfSourceIPv6Address(value) => value.len(length),
            Self::distinctCountOfDestinationIPv6Address(value) => value.len(length),
            Self::valueDistributionMethod(value) => value.len(length),
            Self::rfc3550JitterMilliseconds(value) => value.len(length),
            Self::rfc3550JitterMicroseconds(value) => value.len(length),
            Self::rfc3550JitterNanoseconds(value) => value.len(length),
            Self::dot1qDEI(value) => value.len(length),
            Self::dot1qCustomerDEI(value) => value.len(length),
            Self::flowSelectorAlgorithm(value) => value.len(length),
            Self::flowSelectedOctetDeltaCount(value) => value.len(length),
            Self::flowSelectedPacketDeltaCount(value) => value.len(length),
            Self::flowSelectedFlowDeltaCount(value) => value.len(length),
            Self::selectorIDTotalFlowsObserved(value) => value.len(length),
            Self::selectorIDTotalFlowsSelected(value) => value.len(length),
            Self::samplingFlowInterval(value) => value.len(length),
            Self::samplingFlowSpacing(value) => value.len(length),
            Self::flowSamplingTimeInterval(value) => value.len(length),
            Self::flowSamplingTimeSpacing(value) => value.len(length),
            Self::hashFlowDomain(value) => value.len(length),
            Self::transportOctetDeltaCount(value) => value.len(length),
            Self::transportPacketDeltaCount(value) => value.len(length),
            Self::originalExporterIPv4Address(value) => value.len(length),
            Self::originalExporterIPv6Address(value) => value.len(length),
            Self::originalObservationDomainId(value) => value.len(length),
            Self::intermediateProcessId(value) => value.len(length),
            Self::ignoredDataRecordTotalCount(value) => value.len(length),
            Self::dataLinkFrameType(value) => value.len(length),
            Self::sectionOffset(value) => value.len(length),
            Self::sectionExportedOctets(value) => value.len(length),
            Self::dot1qServiceInstanceTag(value) => value.len(length),
            Self::dot1qServiceInstanceId(value) => value.len(length),
            Self::dot1qServiceInstancePriority(value) => value.len(length),
            Self::dot1qCustomerSourceMacAddress(value) => value.len(length),
            Self::dot1qCustomerDestinationMacAddress(value) => value.len(length),
            Self::postLayer2OctetDeltaCount(value) => value.len(length),
            Self::postMCastLayer2OctetDeltaCount(value) => value.len(length),
            Self::postLayer2OctetTotalCount(value) => value.len(length),
            Self::postMCastLayer2OctetTotalCount(value) => value.len(length),
            Self::minimumLayer2TotalLength(value) => value.len(length),
            Self::maximumLayer2TotalLength(value) => value.len(length),
            Self::droppedLayer2OctetDeltaCount(value) => value.len(length),
            Self::droppedLayer2OctetTotalCount(value) => value.len(length),
            Self::ignoredLayer2OctetTotalCount(value) => value.len(length),
            Self::notSentLayer2OctetTotalCount(value) => value.len(length),
            Self::layer2OctetDeltaSumOfSquares(value) => value.len(length),
            Self::layer2OctetTotalSumOfSquares(value) => value.len(length),
            Self::layer2FrameDeltaCount(value) => value.len(length),
            Self::layer2FrameTotalCount(value) => value.len(length),
            Self::pseudoWireDestinationIPv4Address(value) => value.len(length),
            Self::ignoredLayer2FrameTotalCount(value) => value.len(length),
            Self::mibObjectValueInteger(value) => value.len(length),
            Self::mibObjectValueOctetString(value) => value.len(length),
            Self::mibObjectValueOID(value) => value.len(length),
            Self::mibObjectValueBits(value) => value.len(length),
            Self::mibObjectValueIPAddress(value) => value.len(length),
            Self::mibObjectValueCounter(value) => value.len(length),
            Self::mibObjectValueGauge(value) => value.len(length),
            Self::mibObjectValueTimeTicks(value) => value.len(length),
            Self::mibObjectValueUnsigned(value) => value.len(length),
            Self::mibObjectValueTable(value) => value.len(length),
            Self::mibObjectValueRow(value) => value.len(length),
            Self::mibObjectIdentifier(value) => value.len(length),
            Self::mibSubIdentifier(value) => value.len(length),
            Self::mibIndexIndicator(value) => value.len(length),
            Self::mibCaptureTimeSemantics(value) => value.len(length),
            Self::mibContextEngineID(value) => value.len(length),
            Self::mibContextName(value) => value.len(length),
            Self::mibObjectName(value) => value.len(length),
            Self::mibObjectDescription(value) => value.len(length),
            Self::mibObjectSyntax(value) => value.len(length),
            Self::mibModuleName(value) => value.len(length),
            Self::mobileIMSI(value) => value.len(length),
            Self::mobileMSISDN(value) => value.len(length),
            Self::httpStatusCode(value) => value.len(length),
            Self::sourceTransportPortsLimit(value) => value.len(length),
            Self::httpRequestMethod(value) => value.len(length),
            Self::httpRequestHost(value) => value.len(length),
            Self::httpRequestTarget(value) => value.len(length),
            Self::httpMessageVersion(value) => value.len(length),
            Self::natInstanceID(value) => value.len(length),
            Self::internalAddressRealm(value) => value.len(length),
            Self::externalAddressRealm(value) => value.len(length),
            Self::natQuotaExceededEvent(value) => value.len(length),
            Self::natThresholdEvent(value) => value.len(length),
            Self::httpUserAgent(value) => value.len(length),
            Self::httpContentType(value) => value.len(length),
            Self::httpReasonPhrase(value) => value.len(length),
            Self::maxSessionEntries(value) => value.len(length),
            Self::maxBIBEntries(value) => value.len(length),
            Self::maxEntriesPerUser(value) => value.len(length),
            Self::maxSubscribers(value) => value.len(length),
            Self::maxFragmentsPendingReassembly(value) => value.len(length),
            Self::addressPoolHighThreshold(value) => value.len(length),
            Self::addressPoolLowThreshold(value) => value.len(length),
            Self::addressPortMappingHighThreshold(value) => value.len(length),
            Self::addressPortMappingLowThreshold(value) => value.len(length),
            Self::addressPortMappingPerUserHighThreshold(value) => value.len(length),
            Self::globalAddressMappingHighThreshold(value) => value.len(length),
            Self::vpnIdentifier(value) => value.len(length),
            Self::bgpCommunity(value) => value.len(length),
            Self::bgpSourceCommunityList(value) => value.len(length),
            Self::bgpDestinationCommunityList(value) => value.len(length),
            Self::bgpExtendedCommunity(value) => value.len(length),
            Self::bgpSourceExtendedCommunityList(value) => value.len(length),
            Self::bgpDestinationExtendedCommunityList(value) => value.len(length),
            Self::bgpLargeCommunity(value) => value.len(length),
            Self::bgpSourceLargeCommunityList(value) => value.len(length),
            Self::bgpDestinationLargeCommunityList(value) => value.len(length),
            Self::srhFlagsIPv6(value) => value.len(length),
            Self::srhTagIPv6(value) => value.len(length),
            Self::srhSegmentIPv6(value) => value.len(length),
            Self::srhActiveSegmentIPv6(value) => value.len(length),
            Self::srhSegmentIPv6BasicList(value) => value.len(length),
            Self::srhSegmentIPv6ListSection(value) => value.len(length),
            Self::srhSegmentsIPv6Left(value) => value.len(length),
            Self::srhIPv6Section(value) => value.len(length),
            Self::srhIPv6ActiveSegmentType(value) => value.len(length),
            Self::srhSegmentIPv6LocatorLength(value) => value.len(length),
            Self::srhSegmentIPv6EndpointBehavior(value) => value.len(length),
            Self::transportChecksum(value) => value.len(length),
            Self::icmpHeaderPacketSection(value) => value.len(length),
            Self::gtpuFlags(value) => value.len(length),
            Self::gtpuMsgType(value) => value.len(length),
            Self::gtpuTEid(value) => value.len(length),
            Self::gtpuSequenceNum(value) => value.len(length),
            Self::gtpuQFI(value) => value.len(length),
            Self::gtpuPduType(value) => value.len(length),
            Self::bgpSourceAsPathList(value) => value.len(length),
            Self::bgpDestinationAsPathList(value) => value.len(length),
         }
     }

     fn write<T:  std::io::Write>(&self, writer: &mut T, length: Option<u16>) -> Result<(), FieldWritingError> {
        match self {
            Self::Unknown(value) => writer.write_all(value)?,
            Self::Nokia(value) => value.write(writer, length)?,
            Self::NetGauze(value) => value.write(writer, length)?,
            Self::Cisco(value) => value.write(writer, length)?,
            Self::VMWare(value) => value.write(writer, length)?,
            Self::octetDeltaCount(value) => value.write(writer, length)?,
            Self::packetDeltaCount(value) => value.write(writer, length)?,
            Self::deltaFlowCount(value) => value.write(writer, length)?,
            Self::protocolIdentifier(value) => value.write(writer, length)?,
            Self::ipClassOfService(value) => value.write(writer, length)?,
            Self::tcpControlBits(value) => value.write(writer, length)?,
            Self::sourceTransportPort(value) => value.write(writer, length)?,
            Self::sourceIPv4Address(value) => value.write(writer, length)?,
            Self::sourceIPv4PrefixLength(value) => value.write(writer, length)?,
            Self::ingressInterface(value) => value.write(writer, length)?,
            Self::destinationTransportPort(value) => value.write(writer, length)?,
            Self::destinationIPv4Address(value) => value.write(writer, length)?,
            Self::destinationIPv4PrefixLength(value) => value.write(writer, length)?,
            Self::egressInterface(value) => value.write(writer, length)?,
            Self::ipNextHopIPv4Address(value) => value.write(writer, length)?,
            Self::bgpSourceAsNumber(value) => value.write(writer, length)?,
            Self::bgpDestinationAsNumber(value) => value.write(writer, length)?,
            Self::bgpNextHopIPv4Address(value) => value.write(writer, length)?,
            Self::postMCastPacketDeltaCount(value) => value.write(writer, length)?,
            Self::postMCastOctetDeltaCount(value) => value.write(writer, length)?,
            Self::flowEndSysUpTime(value) => value.write(writer, length)?,
            Self::flowStartSysUpTime(value) => value.write(writer, length)?,
            Self::postOctetDeltaCount(value) => value.write(writer, length)?,
            Self::postPacketDeltaCount(value) => value.write(writer, length)?,
            Self::minimumIpTotalLength(value) => value.write(writer, length)?,
            Self::maximumIpTotalLength(value) => value.write(writer, length)?,
            Self::sourceIPv6Address(value) => value.write(writer, length)?,
            Self::destinationIPv6Address(value) => value.write(writer, length)?,
            Self::sourceIPv6PrefixLength(value) => value.write(writer, length)?,
            Self::destinationIPv6PrefixLength(value) => value.write(writer, length)?,
            Self::flowLabelIPv6(value) => value.write(writer, length)?,
            Self::icmpTypeCodeIPv4(value) => value.write(writer, length)?,
            Self::igmpType(value) => value.write(writer, length)?,
            Self::samplingInterval(value) => value.write(writer, length)?,
            Self::samplingAlgorithm(value) => value.write(writer, length)?,
            Self::flowActiveTimeout(value) => value.write(writer, length)?,
            Self::flowIdleTimeout(value) => value.write(writer, length)?,
            Self::engineType(value) => value.write(writer, length)?,
            Self::engineId(value) => value.write(writer, length)?,
            Self::exportedOctetTotalCount(value) => value.write(writer, length)?,
            Self::exportedMessageTotalCount(value) => value.write(writer, length)?,
            Self::exportedFlowRecordTotalCount(value) => value.write(writer, length)?,
            Self::ipv4RouterSc(value) => value.write(writer, length)?,
            Self::sourceIPv4Prefix(value) => value.write(writer, length)?,
            Self::destinationIPv4Prefix(value) => value.write(writer, length)?,
            Self::mplsTopLabelType(value) => value.write(writer, length)?,
            Self::mplsTopLabelIPv4Address(value) => value.write(writer, length)?,
            Self::samplerId(value) => value.write(writer, length)?,
            Self::samplerMode(value) => value.write(writer, length)?,
            Self::samplerRandomInterval(value) => value.write(writer, length)?,
            Self::classId(value) => value.write(writer, length)?,
            Self::minimumTTL(value) => value.write(writer, length)?,
            Self::maximumTTL(value) => value.write(writer, length)?,
            Self::fragmentIdentification(value) => value.write(writer, length)?,
            Self::postIpClassOfService(value) => value.write(writer, length)?,
            Self::sourceMacAddress(value) => value.write(writer, length)?,
            Self::postDestinationMacAddress(value) => value.write(writer, length)?,
            Self::vlanId(value) => value.write(writer, length)?,
            Self::postVlanId(value) => value.write(writer, length)?,
            Self::ipVersion(value) => value.write(writer, length)?,
            Self::flowDirection(value) => value.write(writer, length)?,
            Self::ipNextHopIPv6Address(value) => value.write(writer, length)?,
            Self::bgpNextHopIPv6Address(value) => value.write(writer, length)?,
            Self::ipv6ExtensionHeaders(value) => value.write(writer, length)?,
            Self::mplsTopLabelStackSection(value) => value.write(writer, length)?,
            Self::mplsLabelStackSection2(value) => value.write(writer, length)?,
            Self::mplsLabelStackSection3(value) => value.write(writer, length)?,
            Self::mplsLabelStackSection4(value) => value.write(writer, length)?,
            Self::mplsLabelStackSection5(value) => value.write(writer, length)?,
            Self::mplsLabelStackSection6(value) => value.write(writer, length)?,
            Self::mplsLabelStackSection7(value) => value.write(writer, length)?,
            Self::mplsLabelStackSection8(value) => value.write(writer, length)?,
            Self::mplsLabelStackSection9(value) => value.write(writer, length)?,
            Self::mplsLabelStackSection10(value) => value.write(writer, length)?,
            Self::destinationMacAddress(value) => value.write(writer, length)?,
            Self::postSourceMacAddress(value) => value.write(writer, length)?,
            Self::interfaceName(value) => value.write(writer, length)?,
            Self::interfaceDescription(value) => value.write(writer, length)?,
            Self::samplerName(value) => value.write(writer, length)?,
            Self::octetTotalCount(value) => value.write(writer, length)?,
            Self::packetTotalCount(value) => value.write(writer, length)?,
            Self::flagsAndSamplerId(value) => value.write(writer, length)?,
            Self::fragmentOffset(value) => value.write(writer, length)?,
            Self::forwardingStatus(value) => value.write(writer, length)?,
            Self::mplsVpnRouteDistinguisher(value) => value.write(writer, length)?,
            Self::mplsTopLabelPrefixLength(value) => value.write(writer, length)?,
            Self::srcTrafficIndex(value) => value.write(writer, length)?,
            Self::dstTrafficIndex(value) => value.write(writer, length)?,
            Self::applicationDescription(value) => value.write(writer, length)?,
            Self::applicationId(value) => value.write(writer, length)?,
            Self::applicationName(value) => value.write(writer, length)?,
            Self::postIpDiffServCodePoint(value) => value.write(writer, length)?,
            Self::multicastReplicationFactor(value) => value.write(writer, length)?,
            Self::className(value) => value.write(writer, length)?,
            Self::classificationEngineId(value) => value.write(writer, length)?,
            Self::layer2packetSectionOffset(value) => value.write(writer, length)?,
            Self::layer2packetSectionSize(value) => value.write(writer, length)?,
            Self::layer2packetSectionData(value) => value.write(writer, length)?,
            Self::bgpNextAdjacentAsNumber(value) => value.write(writer, length)?,
            Self::bgpPrevAdjacentAsNumber(value) => value.write(writer, length)?,
            Self::exporterIPv4Address(value) => value.write(writer, length)?,
            Self::exporterIPv6Address(value) => value.write(writer, length)?,
            Self::droppedOctetDeltaCount(value) => value.write(writer, length)?,
            Self::droppedPacketDeltaCount(value) => value.write(writer, length)?,
            Self::droppedOctetTotalCount(value) => value.write(writer, length)?,
            Self::droppedPacketTotalCount(value) => value.write(writer, length)?,
            Self::flowEndReason(value) => value.write(writer, length)?,
            Self::commonPropertiesId(value) => value.write(writer, length)?,
            Self::observationPointId(value) => value.write(writer, length)?,
            Self::icmpTypeCodeIPv6(value) => value.write(writer, length)?,
            Self::mplsTopLabelIPv6Address(value) => value.write(writer, length)?,
            Self::lineCardId(value) => value.write(writer, length)?,
            Self::portId(value) => value.write(writer, length)?,
            Self::meteringProcessId(value) => value.write(writer, length)?,
            Self::exportingProcessId(value) => value.write(writer, length)?,
            Self::templateId(value) => value.write(writer, length)?,
            Self::wlanChannelId(value) => value.write(writer, length)?,
            Self::wlanSSID(value) => value.write(writer, length)?,
            Self::flowId(value) => value.write(writer, length)?,
            Self::observationDomainId(value) => value.write(writer, length)?,
            Self::flowStartSeconds(value) => value.write(writer, length)?,
            Self::flowEndSeconds(value) => value.write(writer, length)?,
            Self::flowStartMilliseconds(value) => value.write(writer, length)?,
            Self::flowEndMilliseconds(value) => value.write(writer, length)?,
            Self::flowStartMicroseconds(value) => value.write(writer, length)?,
            Self::flowEndMicroseconds(value) => value.write(writer, length)?,
            Self::flowStartNanoseconds(value) => value.write(writer, length)?,
            Self::flowEndNanoseconds(value) => value.write(writer, length)?,
            Self::flowStartDeltaMicroseconds(value) => value.write(writer, length)?,
            Self::flowEndDeltaMicroseconds(value) => value.write(writer, length)?,
            Self::systemInitTimeMilliseconds(value) => value.write(writer, length)?,
            Self::flowDurationMilliseconds(value) => value.write(writer, length)?,
            Self::flowDurationMicroseconds(value) => value.write(writer, length)?,
            Self::observedFlowTotalCount(value) => value.write(writer, length)?,
            Self::ignoredPacketTotalCount(value) => value.write(writer, length)?,
            Self::ignoredOctetTotalCount(value) => value.write(writer, length)?,
            Self::notSentFlowTotalCount(value) => value.write(writer, length)?,
            Self::notSentPacketTotalCount(value) => value.write(writer, length)?,
            Self::notSentOctetTotalCount(value) => value.write(writer, length)?,
            Self::destinationIPv6Prefix(value) => value.write(writer, length)?,
            Self::sourceIPv6Prefix(value) => value.write(writer, length)?,
            Self::postOctetTotalCount(value) => value.write(writer, length)?,
            Self::postPacketTotalCount(value) => value.write(writer, length)?,
            Self::flowKeyIndicator(value) => value.write(writer, length)?,
            Self::postMCastPacketTotalCount(value) => value.write(writer, length)?,
            Self::postMCastOctetTotalCount(value) => value.write(writer, length)?,
            Self::icmpTypeIPv4(value) => value.write(writer, length)?,
            Self::icmpCodeIPv4(value) => value.write(writer, length)?,
            Self::icmpTypeIPv6(value) => value.write(writer, length)?,
            Self::icmpCodeIPv6(value) => value.write(writer, length)?,
            Self::udpSourcePort(value) => value.write(writer, length)?,
            Self::udpDestinationPort(value) => value.write(writer, length)?,
            Self::tcpSourcePort(value) => value.write(writer, length)?,
            Self::tcpDestinationPort(value) => value.write(writer, length)?,
            Self::tcpSequenceNumber(value) => value.write(writer, length)?,
            Self::tcpAcknowledgementNumber(value) => value.write(writer, length)?,
            Self::tcpWindowSize(value) => value.write(writer, length)?,
            Self::tcpUrgentPointer(value) => value.write(writer, length)?,
            Self::tcpHeaderLength(value) => value.write(writer, length)?,
            Self::ipHeaderLength(value) => value.write(writer, length)?,
            Self::totalLengthIPv4(value) => value.write(writer, length)?,
            Self::payloadLengthIPv6(value) => value.write(writer, length)?,
            Self::ipTTL(value) => value.write(writer, length)?,
            Self::nextHeaderIPv6(value) => value.write(writer, length)?,
            Self::mplsPayloadLength(value) => value.write(writer, length)?,
            Self::ipDiffServCodePoint(value) => value.write(writer, length)?,
            Self::ipPrecedence(value) => value.write(writer, length)?,
            Self::fragmentFlags(value) => value.write(writer, length)?,
            Self::octetDeltaSumOfSquares(value) => value.write(writer, length)?,
            Self::octetTotalSumOfSquares(value) => value.write(writer, length)?,
            Self::mplsTopLabelTTL(value) => value.write(writer, length)?,
            Self::mplsLabelStackLength(value) => value.write(writer, length)?,
            Self::mplsLabelStackDepth(value) => value.write(writer, length)?,
            Self::mplsTopLabelExp(value) => value.write(writer, length)?,
            Self::ipPayloadLength(value) => value.write(writer, length)?,
            Self::udpMessageLength(value) => value.write(writer, length)?,
            Self::isMulticast(value) => value.write(writer, length)?,
            Self::ipv4IHL(value) => value.write(writer, length)?,
            Self::ipv4Options(value) => value.write(writer, length)?,
            Self::tcpOptions(value) => value.write(writer, length)?,
            Self::paddingOctets(value) => value.write(writer, length)?,
            Self::collectorIPv4Address(value) => value.write(writer, length)?,
            Self::collectorIPv6Address(value) => value.write(writer, length)?,
            Self::exportInterface(value) => value.write(writer, length)?,
            Self::exportProtocolVersion(value) => value.write(writer, length)?,
            Self::exportTransportProtocol(value) => value.write(writer, length)?,
            Self::collectorTransportPort(value) => value.write(writer, length)?,
            Self::exporterTransportPort(value) => value.write(writer, length)?,
            Self::tcpSynTotalCount(value) => value.write(writer, length)?,
            Self::tcpFinTotalCount(value) => value.write(writer, length)?,
            Self::tcpRstTotalCount(value) => value.write(writer, length)?,
            Self::tcpPshTotalCount(value) => value.write(writer, length)?,
            Self::tcpAckTotalCount(value) => value.write(writer, length)?,
            Self::tcpUrgTotalCount(value) => value.write(writer, length)?,
            Self::ipTotalLength(value) => value.write(writer, length)?,
            Self::postNATSourceIPv4Address(value) => value.write(writer, length)?,
            Self::postNATDestinationIPv4Address(value) => value.write(writer, length)?,
            Self::postNAPTSourceTransportPort(value) => value.write(writer, length)?,
            Self::postNAPTDestinationTransportPort(value) => value.write(writer, length)?,
            Self::natOriginatingAddressRealm(value) => value.write(writer, length)?,
            Self::natEvent(value) => value.write(writer, length)?,
            Self::initiatorOctets(value) => value.write(writer, length)?,
            Self::responderOctets(value) => value.write(writer, length)?,
            Self::firewallEvent(value) => value.write(writer, length)?,
            Self::ingressVRFID(value) => value.write(writer, length)?,
            Self::egressVRFID(value) => value.write(writer, length)?,
            Self::VRFname(value) => value.write(writer, length)?,
            Self::postMplsTopLabelExp(value) => value.write(writer, length)?,
            Self::tcpWindowScale(value) => value.write(writer, length)?,
            Self::biflowDirection(value) => value.write(writer, length)?,
            Self::ethernetHeaderLength(value) => value.write(writer, length)?,
            Self::ethernetPayloadLength(value) => value.write(writer, length)?,
            Self::ethernetTotalLength(value) => value.write(writer, length)?,
            Self::dot1qVlanId(value) => value.write(writer, length)?,
            Self::dot1qPriority(value) => value.write(writer, length)?,
            Self::dot1qCustomerVlanId(value) => value.write(writer, length)?,
            Self::dot1qCustomerPriority(value) => value.write(writer, length)?,
            Self::metroEvcId(value) => value.write(writer, length)?,
            Self::metroEvcType(value) => value.write(writer, length)?,
            Self::pseudoWireId(value) => value.write(writer, length)?,
            Self::pseudoWireType(value) => value.write(writer, length)?,
            Self::pseudoWireControlWord(value) => value.write(writer, length)?,
            Self::ingressPhysicalInterface(value) => value.write(writer, length)?,
            Self::egressPhysicalInterface(value) => value.write(writer, length)?,
            Self::postDot1qVlanId(value) => value.write(writer, length)?,
            Self::postDot1qCustomerVlanId(value) => value.write(writer, length)?,
            Self::ethernetType(value) => value.write(writer, length)?,
            Self::postIpPrecedence(value) => value.write(writer, length)?,
            Self::collectionTimeMilliseconds(value) => value.write(writer, length)?,
            Self::exportSctpStreamId(value) => value.write(writer, length)?,
            Self::maxExportSeconds(value) => value.write(writer, length)?,
            Self::maxFlowEndSeconds(value) => value.write(writer, length)?,
            Self::messageMD5Checksum(value) => value.write(writer, length)?,
            Self::messageScope(value) => value.write(writer, length)?,
            Self::minExportSeconds(value) => value.write(writer, length)?,
            Self::minFlowStartSeconds(value) => value.write(writer, length)?,
            Self::opaqueOctets(value) => value.write(writer, length)?,
            Self::sessionScope(value) => value.write(writer, length)?,
            Self::maxFlowEndMicroseconds(value) => value.write(writer, length)?,
            Self::maxFlowEndMilliseconds(value) => value.write(writer, length)?,
            Self::maxFlowEndNanoseconds(value) => value.write(writer, length)?,
            Self::minFlowStartMicroseconds(value) => value.write(writer, length)?,
            Self::minFlowStartMilliseconds(value) => value.write(writer, length)?,
            Self::minFlowStartNanoseconds(value) => value.write(writer, length)?,
            Self::collectorCertificate(value) => value.write(writer, length)?,
            Self::exporterCertificate(value) => value.write(writer, length)?,
            Self::dataRecordsReliability(value) => value.write(writer, length)?,
            Self::observationPointType(value) => value.write(writer, length)?,
            Self::newConnectionDeltaCount(value) => value.write(writer, length)?,
            Self::connectionSumDurationSeconds(value) => value.write(writer, length)?,
            Self::connectionTransactionId(value) => value.write(writer, length)?,
            Self::postNATSourceIPv6Address(value) => value.write(writer, length)?,
            Self::postNATDestinationIPv6Address(value) => value.write(writer, length)?,
            Self::natPoolId(value) => value.write(writer, length)?,
            Self::natPoolName(value) => value.write(writer, length)?,
            Self::anonymizationFlags(value) => value.write(writer, length)?,
            Self::anonymizationTechnique(value) => value.write(writer, length)?,
            Self::informationElementIndex(value) => value.write(writer, length)?,
            Self::p2pTechnology(value) => value.write(writer, length)?,
            Self::tunnelTechnology(value) => value.write(writer, length)?,
            Self::encryptedTechnology(value) => value.write(writer, length)?,
            Self::basicList(value) => value.write(writer, length)?,
            Self::subTemplateList(value) => value.write(writer, length)?,
            Self::subTemplateMultiList(value) => value.write(writer, length)?,
            Self::bgpValidityState(value) => value.write(writer, length)?,
            Self::IPSecSPI(value) => value.write(writer, length)?,
            Self::greKey(value) => value.write(writer, length)?,
            Self::natType(value) => value.write(writer, length)?,
            Self::initiatorPackets(value) => value.write(writer, length)?,
            Self::responderPackets(value) => value.write(writer, length)?,
            Self::observationDomainName(value) => value.write(writer, length)?,
            Self::selectionSequenceId(value) => value.write(writer, length)?,
            Self::selectorId(value) => value.write(writer, length)?,
            Self::informationElementId(value) => value.write(writer, length)?,
            Self::selectorAlgorithm(value) => value.write(writer, length)?,
            Self::samplingPacketInterval(value) => value.write(writer, length)?,
            Self::samplingPacketSpace(value) => value.write(writer, length)?,
            Self::samplingTimeInterval(value) => value.write(writer, length)?,
            Self::samplingTimeSpace(value) => value.write(writer, length)?,
            Self::samplingSize(value) => value.write(writer, length)?,
            Self::samplingPopulation(value) => value.write(writer, length)?,
            Self::samplingProbability(value) => value.write(writer, length)?,
            Self::dataLinkFrameSize(value) => value.write(writer, length)?,
            Self::ipHeaderPacketSection(value) => value.write(writer, length)?,
            Self::ipPayloadPacketSection(value) => value.write(writer, length)?,
            Self::dataLinkFrameSection(value) => value.write(writer, length)?,
            Self::mplsLabelStackSection(value) => value.write(writer, length)?,
            Self::mplsPayloadPacketSection(value) => value.write(writer, length)?,
            Self::selectorIdTotalPktsObserved(value) => value.write(writer, length)?,
            Self::selectorIdTotalPktsSelected(value) => value.write(writer, length)?,
            Self::absoluteError(value) => value.write(writer, length)?,
            Self::relativeError(value) => value.write(writer, length)?,
            Self::observationTimeSeconds(value) => value.write(writer, length)?,
            Self::observationTimeMilliseconds(value) => value.write(writer, length)?,
            Self::observationTimeMicroseconds(value) => value.write(writer, length)?,
            Self::observationTimeNanoseconds(value) => value.write(writer, length)?,
            Self::digestHashValue(value) => value.write(writer, length)?,
            Self::hashIPPayloadOffset(value) => value.write(writer, length)?,
            Self::hashIPPayloadSize(value) => value.write(writer, length)?,
            Self::hashOutputRangeMin(value) => value.write(writer, length)?,
            Self::hashOutputRangeMax(value) => value.write(writer, length)?,
            Self::hashSelectedRangeMin(value) => value.write(writer, length)?,
            Self::hashSelectedRangeMax(value) => value.write(writer, length)?,
            Self::hashDigestOutput(value) => value.write(writer, length)?,
            Self::hashInitialiserValue(value) => value.write(writer, length)?,
            Self::selectorName(value) => value.write(writer, length)?,
            Self::upperCILimit(value) => value.write(writer, length)?,
            Self::lowerCILimit(value) => value.write(writer, length)?,
            Self::confidenceLevel(value) => value.write(writer, length)?,
            Self::informationElementDataType(value) => value.write(writer, length)?,
            Self::informationElementDescription(value) => value.write(writer, length)?,
            Self::informationElementName(value) => value.write(writer, length)?,
            Self::informationElementRangeBegin(value) => value.write(writer, length)?,
            Self::informationElementRangeEnd(value) => value.write(writer, length)?,
            Self::informationElementSemantics(value) => value.write(writer, length)?,
            Self::informationElementUnits(value) => value.write(writer, length)?,
            Self::privateEnterpriseNumber(value) => value.write(writer, length)?,
            Self::virtualStationInterfaceId(value) => value.write(writer, length)?,
            Self::virtualStationInterfaceName(value) => value.write(writer, length)?,
            Self::virtualStationUUID(value) => value.write(writer, length)?,
            Self::virtualStationName(value) => value.write(writer, length)?,
            Self::layer2SegmentId(value) => value.write(writer, length)?,
            Self::layer2OctetDeltaCount(value) => value.write(writer, length)?,
            Self::layer2OctetTotalCount(value) => value.write(writer, length)?,
            Self::ingressUnicastPacketTotalCount(value) => value.write(writer, length)?,
            Self::ingressMulticastPacketTotalCount(value) => value.write(writer, length)?,
            Self::ingressBroadcastPacketTotalCount(value) => value.write(writer, length)?,
            Self::egressUnicastPacketTotalCount(value) => value.write(writer, length)?,
            Self::egressBroadcastPacketTotalCount(value) => value.write(writer, length)?,
            Self::monitoringIntervalStartMilliSeconds(value) => value.write(writer, length)?,
            Self::monitoringIntervalEndMilliSeconds(value) => value.write(writer, length)?,
            Self::portRangeStart(value) => value.write(writer, length)?,
            Self::portRangeEnd(value) => value.write(writer, length)?,
            Self::portRangeStepSize(value) => value.write(writer, length)?,
            Self::portRangeNumPorts(value) => value.write(writer, length)?,
            Self::staMacAddress(value) => value.write(writer, length)?,
            Self::staIPv4Address(value) => value.write(writer, length)?,
            Self::wtpMacAddress(value) => value.write(writer, length)?,
            Self::ingressInterfaceType(value) => value.write(writer, length)?,
            Self::egressInterfaceType(value) => value.write(writer, length)?,
            Self::rtpSequenceNumber(value) => value.write(writer, length)?,
            Self::userName(value) => value.write(writer, length)?,
            Self::applicationCategoryName(value) => value.write(writer, length)?,
            Self::applicationSubCategoryName(value) => value.write(writer, length)?,
            Self::applicationGroupName(value) => value.write(writer, length)?,
            Self::originalFlowsPresent(value) => value.write(writer, length)?,
            Self::originalFlowsInitiated(value) => value.write(writer, length)?,
            Self::originalFlowsCompleted(value) => value.write(writer, length)?,
            Self::distinctCountOfSourceIPAddress(value) => value.write(writer, length)?,
            Self::distinctCountOfDestinationIPAddress(value) => value.write(writer, length)?,
            Self::distinctCountOfSourceIPv4Address(value) => value.write(writer, length)?,
            Self::distinctCountOfDestinationIPv4Address(value) => value.write(writer, length)?,
            Self::distinctCountOfSourceIPv6Address(value) => value.write(writer, length)?,
            Self::distinctCountOfDestinationIPv6Address(value) => value.write(writer, length)?,
            Self::valueDistributionMethod(value) => value.write(writer, length)?,
            Self::rfc3550JitterMilliseconds(value) => value.write(writer, length)?,
            Self::rfc3550JitterMicroseconds(value) => value.write(writer, length)?,
            Self::rfc3550JitterNanoseconds(value) => value.write(writer, length)?,
            Self::dot1qDEI(value) => value.write(writer, length)?,
            Self::dot1qCustomerDEI(value) => value.write(writer, length)?,
            Self::flowSelectorAlgorithm(value) => value.write(writer, length)?,
            Self::flowSelectedOctetDeltaCount(value) => value.write(writer, length)?,
            Self::flowSelectedPacketDeltaCount(value) => value.write(writer, length)?,
            Self::flowSelectedFlowDeltaCount(value) => value.write(writer, length)?,
            Self::selectorIDTotalFlowsObserved(value) => value.write(writer, length)?,
            Self::selectorIDTotalFlowsSelected(value) => value.write(writer, length)?,
            Self::samplingFlowInterval(value) => value.write(writer, length)?,
            Self::samplingFlowSpacing(value) => value.write(writer, length)?,
            Self::flowSamplingTimeInterval(value) => value.write(writer, length)?,
            Self::flowSamplingTimeSpacing(value) => value.write(writer, length)?,
            Self::hashFlowDomain(value) => value.write(writer, length)?,
            Self::transportOctetDeltaCount(value) => value.write(writer, length)?,
            Self::transportPacketDeltaCount(value) => value.write(writer, length)?,
            Self::originalExporterIPv4Address(value) => value.write(writer, length)?,
            Self::originalExporterIPv6Address(value) => value.write(writer, length)?,
            Self::originalObservationDomainId(value) => value.write(writer, length)?,
            Self::intermediateProcessId(value) => value.write(writer, length)?,
            Self::ignoredDataRecordTotalCount(value) => value.write(writer, length)?,
            Self::dataLinkFrameType(value) => value.write(writer, length)?,
            Self::sectionOffset(value) => value.write(writer, length)?,
            Self::sectionExportedOctets(value) => value.write(writer, length)?,
            Self::dot1qServiceInstanceTag(value) => value.write(writer, length)?,
            Self::dot1qServiceInstanceId(value) => value.write(writer, length)?,
            Self::dot1qServiceInstancePriority(value) => value.write(writer, length)?,
            Self::dot1qCustomerSourceMacAddress(value) => value.write(writer, length)?,
            Self::dot1qCustomerDestinationMacAddress(value) => value.write(writer, length)?,
            Self::postLayer2OctetDeltaCount(value) => value.write(writer, length)?,
            Self::postMCastLayer2OctetDeltaCount(value) => value.write(writer, length)?,
            Self::postLayer2OctetTotalCount(value) => value.write(writer, length)?,
            Self::postMCastLayer2OctetTotalCount(value) => value.write(writer, length)?,
            Self::minimumLayer2TotalLength(value) => value.write(writer, length)?,
            Self::maximumLayer2TotalLength(value) => value.write(writer, length)?,
            Self::droppedLayer2OctetDeltaCount(value) => value.write(writer, length)?,
            Self::droppedLayer2OctetTotalCount(value) => value.write(writer, length)?,
            Self::ignoredLayer2OctetTotalCount(value) => value.write(writer, length)?,
            Self::notSentLayer2OctetTotalCount(value) => value.write(writer, length)?,
            Self::layer2OctetDeltaSumOfSquares(value) => value.write(writer, length)?,
            Self::layer2OctetTotalSumOfSquares(value) => value.write(writer, length)?,
            Self::layer2FrameDeltaCount(value) => value.write(writer, length)?,
            Self::layer2FrameTotalCount(value) => value.write(writer, length)?,
            Self::pseudoWireDestinationIPv4Address(value) => value.write(writer, length)?,
            Self::ignoredLayer2FrameTotalCount(value) => value.write(writer, length)?,
            Self::mibObjectValueInteger(value) => value.write(writer, length)?,
            Self::mibObjectValueOctetString(value) => value.write(writer, length)?,
            Self::mibObjectValueOID(value) => value.write(writer, length)?,
            Self::mibObjectValueBits(value) => value.write(writer, length)?,
            Self::mibObjectValueIPAddress(value) => value.write(writer, length)?,
            Self::mibObjectValueCounter(value) => value.write(writer, length)?,
            Self::mibObjectValueGauge(value) => value.write(writer, length)?,
            Self::mibObjectValueTimeTicks(value) => value.write(writer, length)?,
            Self::mibObjectValueUnsigned(value) => value.write(writer, length)?,
            Self::mibObjectValueTable(value) => value.write(writer, length)?,
            Self::mibObjectValueRow(value) => value.write(writer, length)?,
            Self::mibObjectIdentifier(value) => value.write(writer, length)?,
            Self::mibSubIdentifier(value) => value.write(writer, length)?,
            Self::mibIndexIndicator(value) => value.write(writer, length)?,
            Self::mibCaptureTimeSemantics(value) => value.write(writer, length)?,
            Self::mibContextEngineID(value) => value.write(writer, length)?,
            Self::mibContextName(value) => value.write(writer, length)?,
            Self::mibObjectName(value) => value.write(writer, length)?,
            Self::mibObjectDescription(value) => value.write(writer, length)?,
            Self::mibObjectSyntax(value) => value.write(writer, length)?,
            Self::mibModuleName(value) => value.write(writer, length)?,
            Self::mobileIMSI(value) => value.write(writer, length)?,
            Self::mobileMSISDN(value) => value.write(writer, length)?,
            Self::httpStatusCode(value) => value.write(writer, length)?,
            Self::sourceTransportPortsLimit(value) => value.write(writer, length)?,
            Self::httpRequestMethod(value) => value.write(writer, length)?,
            Self::httpRequestHost(value) => value.write(writer, length)?,
            Self::httpRequestTarget(value) => value.write(writer, length)?,
            Self::httpMessageVersion(value) => value.write(writer, length)?,
            Self::natInstanceID(value) => value.write(writer, length)?,
            Self::internalAddressRealm(value) => value.write(writer, length)?,
            Self::externalAddressRealm(value) => value.write(writer, length)?,
            Self::natQuotaExceededEvent(value) => value.write(writer, length)?,
            Self::natThresholdEvent(value) => value.write(writer, length)?,
            Self::httpUserAgent(value) => value.write(writer, length)?,
            Self::httpContentType(value) => value.write(writer, length)?,
            Self::httpReasonPhrase(value) => value.write(writer, length)?,
            Self::maxSessionEntries(value) => value.write(writer, length)?,
            Self::maxBIBEntries(value) => value.write(writer, length)?,
            Self::maxEntriesPerUser(value) => value.write(writer, length)?,
            Self::maxSubscribers(value) => value.write(writer, length)?,
            Self::maxFragmentsPendingReassembly(value) => value.write(writer, length)?,
            Self::addressPoolHighThreshold(value) => value.write(writer, length)?,
            Self::addressPoolLowThreshold(value) => value.write(writer, length)?,
            Self::addressPortMappingHighThreshold(value) => value.write(writer, length)?,
            Self::addressPortMappingLowThreshold(value) => value.write(writer, length)?,
            Self::addressPortMappingPerUserHighThreshold(value) => value.write(writer, length)?,
            Self::globalAddressMappingHighThreshold(value) => value.write(writer, length)?,
            Self::vpnIdentifier(value) => value.write(writer, length)?,
            Self::bgpCommunity(value) => value.write(writer, length)?,
            Self::bgpSourceCommunityList(value) => value.write(writer, length)?,
            Self::bgpDestinationCommunityList(value) => value.write(writer, length)?,
            Self::bgpExtendedCommunity(value) => value.write(writer, length)?,
            Self::bgpSourceExtendedCommunityList(value) => value.write(writer, length)?,
            Self::bgpDestinationExtendedCommunityList(value) => value.write(writer, length)?,
            Self::bgpLargeCommunity(value) => value.write(writer, length)?,
            Self::bgpSourceLargeCommunityList(value) => value.write(writer, length)?,
            Self::bgpDestinationLargeCommunityList(value) => value.write(writer, length)?,
            Self::srhFlagsIPv6(value) => value.write(writer, length)?,
            Self::srhTagIPv6(value) => value.write(writer, length)?,
            Self::srhSegmentIPv6(value) => value.write(writer, length)?,
            Self::srhActiveSegmentIPv6(value) => value.write(writer, length)?,
            Self::srhSegmentIPv6BasicList(value) => value.write(writer, length)?,
            Self::srhSegmentIPv6ListSection(value) => value.write(writer, length)?,
            Self::srhSegmentsIPv6Left(value) => value.write(writer, length)?,
            Self::srhIPv6Section(value) => value.write(writer, length)?,
            Self::srhIPv6ActiveSegmentType(value) => value.write(writer, length)?,
            Self::srhSegmentIPv6LocatorLength(value) => value.write(writer, length)?,
            Self::srhSegmentIPv6EndpointBehavior(value) => value.write(writer, length)?,
            Self::transportChecksum(value) => value.write(writer, length)?,
            Self::icmpHeaderPacketSection(value) => value.write(writer, length)?,
            Self::gtpuFlags(value) => value.write(writer, length)?,
            Self::gtpuMsgType(value) => value.write(writer, length)?,
            Self::gtpuTEid(value) => value.write(writer, length)?,
            Self::gtpuSequenceNum(value) => value.write(writer, length)?,
            Self::gtpuQFI(value) => value.write(writer, length)?,
            Self::gtpuPduType(value) => value.write(writer, length)?,
            Self::bgpSourceAsPathList(value) => value.write(writer, length)?,
            Self::bgpDestinationAsPathList(value) => value.write(writer, length)?,
         }
         Ok(())
     }
}

