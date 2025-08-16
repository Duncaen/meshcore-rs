use zerocopy::little_endian::U32;

use crate::{Error, Result};

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct GrpText<'a> {
    pub channel_hash: [u8; 1],
    pub cipher_mac: &'a [u8],
    pub data: &'a [u8],
}

impl<'a> GrpText<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        if bytes.len() < 3 {
            return Err(Error::ParseError);
        }
        Ok(Self {
            channel_hash: [bytes[0]],
            cipher_mac: &bytes[1..3],
            data: &bytes[3..],
        })
    }
}

#[repr(u8)]
pub enum MessageType {
    Plain = 0x00,
    Command = 0x01,
    Signed = 0x02,
}

impl TryFrom<u8> for MessageType {
    type Error = Error;
    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::Plain),
            0x01 => Ok(Self::Command),
            0x02 => Ok(Self::Signed),
            _ => Err(Error::ParseError),
        }
    }
}

pub struct PlainText {
    pub timestamp: U32,
    pub flags: u8,
    pub message: [u8],
}

impl PlainText {
    pub fn attempts(&self) -> u8 {
        self.flags & 0b11
    }

    pub fn message_type(&self) -> Result<MessageType> {
        MessageType::try_from(self.flags >> 2)
    }
}
