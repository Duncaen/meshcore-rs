use cipher::generic_array::GenericArray;
#[cfg(feature = "defmt")]
use defmt;
use sha2::{Digest, Sha256};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, little_endian::U16};

use crate::{Error, Result};

pub mod ack;
pub mod advert;
pub mod grptext;
pub mod path;
pub mod txtmsg;

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum RouteType {
    /// Flood mode + Transport codes.
    TransportFlood = 0x00,
    /// Flood mode
    Flood = 0x01,
    /// Direct route
    Direct = 0x02,
    /// Direct route + Transport codes.
    TransportDirect = 0x04,
}

impl RouteType {
    pub fn has_transport_codes(&self) -> bool {
        match self {
            RouteType::TransportFlood => true,
            RouteType::Flood => false,
            RouteType::Direct => false,
            RouteType::TransportDirect => true,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum PayloadType {
    Req = 0x00,
    Resp = 0x01,
    TxtMsg = 0x02,
    Ack = 0x03,
    Advert = 0x04,
    GrpText = 0x05,
    GrpData = 0x06,
    AnonReq = 0x07,
    Path = 0x08,
    Trace = 0x09,
    RawCustom = 0x0F,
}

#[derive(Debug, PartialEq)]
#[repr(u8)]
pub enum PayloadVersion {
    Version1 = 0x00,
    Version2 = 0x01,
    Version3 = 0x02,
    Version4 = 0x03,
}

#[derive(Debug, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct Flags(pub u8);

pub const MAX_PACKET_PAYLOAD: usize = 184;
pub const MAX_PATH_SIZE: usize = 64;
pub const MAX_TRANS_UNIT: usize = 255;

impl Flags {
    const PH_ROUTE_MASK: u8 = 0x03; // 2-bits
    const PH_TYPE_SHIFT: u8 = 2;
    const PH_TYPE_MASK: u8 = 0x0F; // 4-bits
    const PH_VER_SHIFT: u8 = 6;
    const PH_VER_MASK: u8 = 0x03; // 2-bits

    pub fn route_type(&self) -> RouteType {
        match self.0 & Self::PH_ROUTE_MASK {
            0x00 => RouteType::TransportFlood,
            0x01 => RouteType::Flood,
            0x02 => RouteType::Direct,
            0x03 => RouteType::TransportDirect,
            _ => unreachable!(),
        }
    }
    pub fn payload_type(&self) -> Result<PayloadType> {
        match (self.0 >> Self::PH_TYPE_SHIFT) & Self::PH_TYPE_MASK {
            0x00 => Ok(PayloadType::Req),
            0x01 => Ok(PayloadType::Resp),
            0x02 => Ok(PayloadType::TxtMsg),
            0x03 => Ok(PayloadType::Ack),
            0x04 => Ok(PayloadType::Advert),
            0x05 => Ok(PayloadType::GrpText),
            0x06 => Ok(PayloadType::GrpData),
            0x07 => Ok(PayloadType::AnonReq),
            0x08 => Ok(PayloadType::Path),
            0x09 => Ok(PayloadType::Trace),
            0x0F => Ok(PayloadType::RawCustom),
            _ => Err(Error::ParseError),
        }
    }
    pub fn payload_version(&self) -> PayloadVersion {
        match (self.0 >> Self::PH_VER_SHIFT) & Self::PH_VER_MASK {
            0x00 => PayloadVersion::Version1,
            0x01 => PayloadVersion::Version2,
            0x02 => PayloadVersion::Version3,
            0x03 => PayloadVersion::Version4,
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct PacketHeader {
    pub flags: Flags,
    pub path_len: u8,
}

#[derive(Debug, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct TransportCodes(U16, U16);

#[derive(Debug, PartialEq)]
pub struct Packet<'a> {
    pub header: &'a PacketHeader,
    pub transport_codes: Option<TransportCodes>,
    pub path: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let (header, mut rest) =
            PacketHeader::ref_from_prefix(bytes).map_err(|_| Error::ParseError)?;

        let transport_codes;
        if header.flags.route_type().has_transport_codes() {
            (transport_codes, rest) = TransportCodes::read_from_prefix(rest)
                .map(|(a, b)| (Some(a), b))
                .map_err(|_| Error::ParseError)?;
        } else {
            transport_codes = None;
        }

        let Some((path, rest)) = rest.split_at_checked(header.path_len.into()) else {
            return Err(Error::ParseError);
        };

        Ok(Packet {
            header,
            transport_codes,
            path,
            payload: rest,
        })
    }
}

const MAX_HASH_SIZE: usize = 8;

impl<'a> Packet<'a> {
    pub fn payload_type(&self) -> Result<PayloadType> {
        self.header.flags.payload_type()
    }

    pub fn hash_packet(&self) -> [u8; MAX_HASH_SIZE] {
        let mut hash = Sha256::new();
        let payload_type = self.header.flags.payload_type().unwrap();
        hash.update(&[payload_type.clone() as u8]);
        if payload_type == PayloadType::Trace {
            hash.update(&[self.header.path_len])
        }
        hash.update(self.payload);
        let mut res = [0u8; MAX_HASH_SIZE];
        res.copy_from_slice(&hash.finalize()[..MAX_HASH_SIZE]);
        res
    }
}

pub struct PacketBuilder<'a> {
    header: PacketHeader,

    bytes: &'a mut [u8],
}

impl<'a> PacketBuilder<'a> {
    pub fn new(bytes: &'a mut [u8]) -> PacketBuilder<'a> {
        let header = PacketHeader {
            flags: Flags(0),
            path_len: 0,
        };
        PacketBuilder {
            bytes,
            header: header,
        }
    }

    // 0x00 => Ok(PayloadType::Req),
    // 0x01 => Ok(PayloadType::Resp),
    // 0x02 => Ok(PayloadType::TxtMsg),
    // 0x04 => Ok(PayloadType::Advert),
    // 0x05 => Ok(PayloadType::GrpText),
    // 0x06 => Ok(PayloadType::GrpData),
    // 0x07 => Ok(PayloadType::AnonReq),
    // 0x08 => Ok(PayloadType::Path),
    // 0x09 => Ok(PayloadType::Trace),
    // 0x0F => Ok(PayloadType::RawCustom),

    // pub fn req(self) -> ReqBuilder<'a> {
    //     todo!()
    // }

    // pub fn resp(self) -> RespBuilder<'a> {
    //     todo!()
    // }

    // pub fn txt_msg(self) -> TxtMsgBuilder<'a> {
    //     todo!()
    // }

    // pub fn grp_text(self) -> GrpTextBuilder<'a> {
    //     todo!()
    // }

    // pub fn grp_data(self) -> GrpDataBuilder<'a> {
    //     todo!()
    // }

    // pub fn anon_req(self) -> AnonReqBuilder<'a> {
    //     todo!()
    // }

    // pub fn path(self) -> PathBuilder<'a> {
    //     todo!()
    // }

    // pub fn trace(self) -> TraceBuilder<'a> {
    //     todo!()
    // }

    // pub fn raw_custom(self) -> RawCustomBuilder<'a> {
    //     todo!()
    // }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        assert_eq!(Packet::from_bytes(b""), Err(Error::ParseError));
        assert_eq!(Packet::from_bytes(b"\x00\x01"), Err(Error::ParseError));
        assert_eq!(
            Packet::from_bytes(b"\x01\x00"),
            Ok(Packet {
                header: &PacketHeader {
                    flags: Flags(RouteType::Flood as u8),
                    path_len: 0
                },
                transport_codes: None,
                path: &[],
                payload: &[],
            })
        );
        assert_eq!(
            Packet::from_bytes(b"\x01\x01\x00"),
            Ok(Packet {
                header: &PacketHeader {
                    flags: Flags(1),
                    path_len: 1
                },
                transport_codes: None,
                path: &[0],
                payload: &[],
            })
        );
        assert_eq!(
            Packet::from_bytes(b"\x01\x01\x00\x01"),
            Ok(Packet {
                header: &PacketHeader {
                    flags: Flags(1),
                    path_len: 1
                },
                transport_codes: None,
                path: &[0],
                payload: &[1],
            })
        );
        assert_eq!(
            Packet::from_bytes(b"\x00\x00\x00\x00\x00"),
            Err(Error::ParseError)
        );
        assert_eq!(
            Packet::from_bytes(b"\x00\x00\x00\x00\x00\x00\x00")
                .unwrap()
                .header
                .flags
                .route_type(),
            RouteType::TransportFlood
        );
        assert_eq!(
            Packet::from_bytes(b"\x01\x00")
                .unwrap()
                .header
                .flags
                .route_type(),
            RouteType::Flood
        );
        assert_eq!(
            Packet::from_bytes(b"\x02\x00")
                .unwrap()
                .header
                .flags
                .route_type(),
            RouteType::Direct
        );
        assert_eq!(
            Packet::from_bytes(b"\x03\x00\x00\x00\x00\0x00")
                .unwrap()
                .header
                .flags
                .route_type(),
            RouteType::TransportDirect
        );
        assert_eq!(Flags(0).route_type(), RouteType::TransportFlood);
        assert_eq!(Flags(0).payload_type(), Ok(PayloadType::Req));
        assert_eq!(Flags(0).payload_version(), PayloadVersion::Version1);
        assert_eq!(Flags(0b1000101).route_type(), RouteType::Flood);
        assert_eq!(Flags(0b000101).payload_type(), Ok(PayloadType::Resp));
        assert_eq!(Flags(0b001001).payload_type(), Ok(PayloadType::TxtMsg));
        assert_eq!(Flags(0b001101).payload_type(), Ok(PayloadType::Ack));
        assert_eq!(Flags(0b010001).payload_type(), Ok(PayloadType::Advert));
        assert_eq!(Flags(0b010101).payload_type(), Ok(PayloadType::GrpText));
        assert_eq!(Flags(0b011001).payload_type(), Ok(PayloadType::GrpData));
        assert_eq!(Flags(0b011101).payload_type(), Ok(PayloadType::AnonReq));
        assert_eq!(Flags(0b100001).payload_type(), Ok(PayloadType::Path));
        assert_eq!(Flags(0b100101).payload_type(), Ok(PayloadType::Trace));
        assert_eq!(Flags(0b111101).payload_type(), Ok(PayloadType::RawCustom));
        assert_eq!(Flags(0b1110101).payload_type(), Err(Error::ParseError));
        assert_eq!(Flags(0b1000101).payload_version(), PayloadVersion::Version2);
        assert_eq!(
            Flags(0b10000101).payload_version(),
            PayloadVersion::Version3
        );
        assert_eq!(
            Flags(0b11000101).payload_version(),
            PayloadVersion::Version4
        );
    }

    #[test]
    fn test_build() {
        let mut buf = [0u8; 1024];
        let _ = PacketBuilder::new(&mut buf).ack(0);
        // let _ = PacketBuilder::new(&mut buf).advert();
    }
}
