use zerocopy::{ByteSlice, FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{Error, Result, packet::PayloadType};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C, packed)]
pub struct ReturnedPath {
    pub destination: u8,
    pub source: u8,
    pub cipher_mac: [u8; 2],
    pub cipher_text: [u8],
}

impl ReturnedPath {
    pub fn from_bytes<'a>(bytes: &'a [u8]) -> Result<&'a Self> {
        Ok(Self::ref_from_bytes(bytes).map_err(|_| Error::ParseError)?)
    }
}

impl ReturnedPath {
    pub fn decrypt(&self) -> Result<ReturnedPathPayload<'_>> {
        let dst: [u8; 255];
        ReturnedPathPayload::from_bytes(&self.cipher_text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test() {
        let mut buf = [0u8; 255];
        let r = ReturnedPath::from_bytes(&buf[..]);
    }
}

#[derive(Debug, PartialEq, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct ExtraType(pub u8);

impl ExtraType {
    pub fn payload_type(&self) -> Result<PayloadType> {
        match self.0 & 0x0F {
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
}

impl From<u8> for ExtraType {
    fn from(value: u8) -> Self {
        Self(value)
    }
}

pub struct ReturnedPathPayload<'a> {
    pub path_len: u8,
    pub path: &'a [u8],
    pub extra_type: ExtraType,
    pub extra: &'a [u8],
}

impl<'a> ReturnedPathPayload<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let (path_len, bytes) = (bytes[0], &bytes[1..]);
        let (path, bytes) = bytes
            .split_at_checked(path_len.into())
            .ok_or(Error::ParseError)?;
        let (extra_type, bytes) = (bytes[0].into(), &bytes[1..]);
        Ok(Self {
            path_len,
            path,
            extra_type,
            extra: bytes,
        })
    }
}
