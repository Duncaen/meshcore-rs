use crate::{Error, Result, packet::PacketBuilder};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, little_endian::U32};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Ack {
    pub checksum: U32,
}

impl Ack {
    pub fn from_bytes(bytes: &'_ [u8]) -> Result<(&'_ Self, &'_ [u8])> {
        Ok(Ack::ref_from_prefix(bytes).map_err(|_| Error::ParseError)?)
    }
}

pub struct AckBuilder<'a> {
    bytes: &'a mut [u8],
}

impl<'a> PacketBuilder<'a> {
    pub fn ack(self, checksum: u32) -> AckBuilder<'a> {
        AckBuilder { bytes: self.bytes }
    }
}
