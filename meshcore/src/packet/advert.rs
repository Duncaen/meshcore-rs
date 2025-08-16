#[cfg(feature = "defmt")]
use defmt::debug;

use core::ops::BitOr;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey};

use crate::{
    Error, Result,
    crypto::{PublicKey, Signature},
    identity::Identity,
    packet::PacketBuilder,
};
use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout,
    little_endian::{U16, U32},
};

#[repr(u8)]
pub enum AdvertType {
    None = 0x00,
    Chat = 0x01,
    Repeater = 0x02,
    Room = 0x03,
    Sensor = 0x04,
}

impl Into<Flags> for AdvertType {
    fn into(self) -> Flags {
        match self {
            AdvertType::None => Flags(0),
            AdvertType::Chat => Flags::CHAT,
            AdvertType::Repeater => Flags::REPEATER,
            AdvertType::Room => Flags::ROOM_SERVER,
            AdvertType::Sensor => Flags::SENSOR,
        }
    }
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct Flags(pub u8);

impl BitOr for Flags {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl Flags {
    pub const CHAT: Self = Self(0x01);
    pub const REPEATER: Self = Self(0x02);
    pub const ROOM_SERVER: Self = Self(0x03);
    pub const SENSOR: Self = Self(0x04);
    pub const LOCATION: Self = Self(0x10);
    pub const BATTERY: Self = Self(0x20);
    pub const TEMPERATURE: Self = Self(0x40);
    pub const NAME: Self = Self(0x80);

    pub fn contains(&self, flags: Self) -> bool {
        self.0 & flags.0 != 0
    }
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct Header {
    pub pub_key: PublicKey,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub timestamp: U32,
    pub signature: Signature,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct Location {
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub lat: U32,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub long: U32,
}

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct Battery(#[cfg_attr(feature = "defmt", defmt(Display2Format))] pub U16);

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct Temperature(#[cfg_attr(feature = "defmt", defmt(Display2Format))] pub U16);

#[derive(Debug, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Name(pub [u8]);

#[cfg(feature = "defmt")]
impl defmt::Format for Name {
    fn format(&self, f: defmt::Formatter) {
        defmt::write!(f, "{:a}", self.0)
    }
}

const MAX_ADVERT_DATA_SIZE: usize = 32;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[derive(Debug)]
pub struct Data<'a> {
    pub bytes: &'a [u8],
    pub flags: Flags,
    pub location: Option<&'a Location>,
    pub battery: Option<&'a Battery>,
    pub temperature: Option<&'a Temperature>,
    pub name: Option<&'a Name>,
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Advert<'a> {
    pub header: &'a Header,
    pub data: Data<'a>,
}

impl<'a> Advert<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self> {
        let (header, bytes) = Header::ref_from_prefix(bytes).map_err(|_| Error::ParseError)?;
        let mut location = None;
        let mut battery = None;
        let mut temperature = None;
        let mut name = None;
        let mut tail;

        let flags;
        (flags, tail) = Flags::read_from_prefix(bytes).map_err(|_| Error::ParseError)?;

        if flags.contains(Flags::LOCATION) {
            (location, tail) = Location::ref_from_prefix(tail)
                .map(|(a, b)| (Some(a), b))
                .map_err(|_| Error::ParseError)?;
        }
        if flags.contains(Flags::BATTERY) {
            (battery, tail) = Battery::ref_from_prefix(tail)
                .map(|(a, b)| (Some(a), b))
                .map_err(|_| Error::ParseError)?;
        }
        if flags.contains(Flags::LOCATION) {
            (temperature, tail) = Temperature::ref_from_prefix(tail)
                .map(|(a, b)| (Some(a), b))
                .map_err(|_| Error::ParseError)?;
        }
        if flags.contains(Flags::NAME) {
            name = Some(Name::ref_from_bytes(tail).map_err(|_| Error::ParseError)?);
        }

        Ok(Advert {
            header,
            data: Data {
                bytes,
                flags,
                location,
                battery,
                temperature,
                name,
            },
        })
    }
}

impl<'a> Advert<'a> {
    pub fn identity(&self) -> Result<Identity> {
        Ok(Identity::from_bytes(&self.header.pub_key.0)?)
    }

    pub fn verify(&self) -> Result<()> {
        let pub_key =
            VerifyingKey::from_bytes(&self.header.pub_key.0).map_err(|_| Error::ParseError)?;
        let sig = Ed25519Signature::from_bytes(&self.header.signature.0);

        let mut msg = [0u8; size_of::<PublicKey>() + 4 + MAX_ADVERT_DATA_SIZE];
        let mut offset = 0;

        msg[offset..offset + size_of_val(&self.header.pub_key)]
            .copy_from_slice(&self.header.pub_key.as_bytes());
        offset += size_of_val(&self.header.pub_key);

        msg[offset..offset + size_of_val(&self.header.timestamp)]
            .copy_from_slice(&self.header.timestamp.as_bytes());
        offset += size_of_val(&self.header.timestamp);

        msg[offset..offset + self.data.bytes.len()].copy_from_slice(self.data.bytes.as_bytes());
        offset += self.data.bytes.len();

        #[cfg(feature = "defmt")]
        {
            debug!("pubkey={}", self.header.pub_key.as_bytes());
            debug!("timestamp={}", &self.header.timestamp.as_bytes());
            debug!("app_data={}", self.data.bytes);
            debug!(
                "offset={} size={} {}",
                offset,
                size_of_val(&msg),
                msg[..offset]
            );
        }
        pub_key
            .verify_strict(&msg[..offset], &sig)
            .map_err(|_| Error::VerifyError)?;
        Ok(())
    }
}

pub struct AdvertBuilder<'a> {
    header: Header,

    location: Option<Location>,
    battery: Option<Battery>,
    temperature: Option<Temperature>,
    name: Option<&'a [u8]>,

    bytes: &'a [u8],
}

impl<'a> AdvertBuilder<'a> {
    pub fn set_location(mut self, lat: u32, long: u32) -> Self {
        self.location = Some(Location {
            lat: lat.into(),
            long: long.into(),
        });
        self
    }

    pub fn set_battery(mut self, battery: u16) -> Self {
        self.battery = Some(Battery(battery.into()));
        self
    }

    pub fn set_temperature(mut self, temp: u16) -> Self {
        self.temperature = Some(Temperature(temp.into()));
        self
    }

    pub fn set_name(mut self, name: &'a [u8]) -> Self {
        self.name = Some(name);
        self
    }
}

impl<'a> PacketBuilder<'a> {
    pub fn advert(
        self,
        advert_type: AdvertType,
        pub_key: PublicKey,
        timestamp: u32,
    ) -> AdvertBuilder<'a> {
        let (header, bytes) = Header::mut_from_prefix(self.bytes).unwrap();
        header.pub_key = pub_key;
        header.timestamp = timestamp.into();
        let data = Data {
            bytes: &[],
            flags: advert_type.into(),
            location: None,
            battery: None,
            temperature: None,
            name: None,
        };
        AdvertBuilder {
            bytes,
            header: todo!(),
            location: todo!(),
            battery: todo!(),
            temperature: todo!(),
            name: todo!(),
        }
    }
}
