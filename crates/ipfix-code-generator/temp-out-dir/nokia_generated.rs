#[allow(non_camel_case_types)]
#[repr(u16)]
#[derive(strum_macros::Display, strum_macros::FromRepr, Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum IE {
    /// The 16-bit service ID representing the inside service ID.
    /// This field is not applicable in L2-Aware NAT and is set to NULL in this case.
    ///
    /// Reference: [https://infocenter.nokia.com/public/7750SR225R1A/index.jsp?topic=%2Fcom.nokia.Multiservice_ISA_and_ESA_Guide%2Ftemplate_format-ai9jxkmf6f.html](https://infocenter.nokia.com/public/7750SR225R1A/index.jsp?topic=%2Fcom.nokia.Multiservice_ISA_and_ESA_Guide%2Ftemplate_format-ai9jxkmf6f.html)
    aluInsideServiceId = 91,
    /// The 16-bit service ID representing the outside service ID.
    ///
    /// Reference: [https://infocenter.nokia.com/public/7750SR225R1A/index.jsp?topic=%2Fcom.nokia.Multiservice_ISA_and_ESA_Guide%2Ftemplate_format-ai9jxkmf6f.html](https://infocenter.nokia.com/public/7750SR225R1A/index.jsp?topic=%2Fcom.nokia.Multiservice_ISA_and_ESA_Guide%2Ftemplate_format-ai9jxkmf6f.html)
    aluOutsideServiceId = 92,
    /// A variable 8B aligned string that represents the NAT subscriber construct
    /// (as currently used in the tools>dump>service>nat> session commands).
    /// The original IP source address, before NAT is performed is included in this string.
    /// For example:
    /// LSN-Host@10.10.10.101
    ///
    /// Reference: [https://infocenter.nokia.com/public/7750SR225R1A/index.jsp?topic=%2Fcom.nokia.Multiservice_ISA_and_ESA_Guide%2Ftemplate_format-ai9jxkmf6f.html](https://infocenter.nokia.com/public/7750SR225R1A/index.jsp?topic=%2Fcom.nokia.Multiservice_ISA_and_ESA_Guide%2Ftemplate_format-ai9jxkmf6f.html)
    aluNatSubString = 93,
}

impl super::InformationElementTemplate for IE {
    fn semantics(&self) -> Option<super::InformationElementSemantics> {
        match self {
            Self::aluInsideServiceId => Some(super::InformationElementSemantics::identifier),
            Self::aluOutsideServiceId => Some(super::InformationElementSemantics::identifier),
            Self::aluNatSubString => Some(super::InformationElementSemantics::identifier),
        }
    }

    fn data_type(&self) -> super::InformationElementDataType {
        match self {
            Self::aluInsideServiceId => super::InformationElementDataType::unsigned16,
            Self::aluOutsideServiceId => super::InformationElementDataType::unsigned16,
            Self::aluNatSubString => super::InformationElementDataType::string,
        }
    }

    fn units(&self) -> Option<super::InformationElementUnits> {
        match self {
            Self::aluInsideServiceId => Some(super::InformationElementUnits::octets),
            Self::aluOutsideServiceId => None,
            Self::aluNatSubString => None,
        }
    }

    fn value_range(&self) -> Option<std::ops::Range<u64>> {
        match self {
            Self::aluInsideServiceId => None,
            Self::aluOutsideServiceId => None,
            Self::aluNatSubString => None,
        }
    }

    fn id(&self) -> u16 {
        (*self) as u16
    }

    fn pen(&self) -> u32 {
        637
    }

}
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct UndefinedIE(pub u16);

impl From<IE> for u16 {
    fn from(value: IE) -> Self {
        value as u16
    }
}

impl TryFrom<u16> for IE {
    type Error = UndefinedIE;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
       // Remove Enterprise bit
       let value = value & 0x7FFF;
       match Self::from_repr(value) {
           Some(val) => Ok(val),
           None => Err(UndefinedIE(value)),
       }
    }
}



#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct aluInsideServiceId(pub u16);

impl crate::HasIE for aluInsideServiceId {
    fn ie(&self) -> crate::IE {
        crate::IE::Nokia(IE::aluInsideServiceId)
   }
}

#[allow(non_camel_case_types)]
#[derive(Copy, Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct aluOutsideServiceId(pub u16);

impl crate::HasIE for aluOutsideServiceId {
    fn ie(&self) -> crate::IE {
        crate::IE::Nokia(IE::aluOutsideServiceId)
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub struct aluNatSubString(pub String);

impl crate::HasIE for aluNatSubString {
    fn ie(&self) -> crate::IE {
        crate::IE::Nokia(IE::aluNatSubString)
   }
}

#[allow(non_camel_case_types)]
#[derive(Eq, Clone, PartialEq, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "fuzz", derive(arbitrary::Arbitrary))]
pub enum Field {
    aluInsideServiceId(aluInsideServiceId),
    aluOutsideServiceId(aluOutsideServiceId),
    aluNatSubString(aluNatSubString),
}

impl Field {
    /// Get the [IE] element for a given field
    pub const fn ie(&self) -> IE {
        match self {
            Self::aluInsideServiceId(_) => IE::aluInsideServiceId,
            Self::aluOutsideServiceId(_) => IE::aluOutsideServiceId,
            Self::aluNatSubString(_) => IE::aluNatSubString,
        }

    }

}

