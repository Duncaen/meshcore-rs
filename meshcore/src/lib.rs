#![no_std]

#[cfg(feature = "defmt")]
use defmt::{debug, info};

use heapless::{FnvIndexSet, Vec};

use crate::{
    crypto::{PublicKey, aes_ecb_decrypt, cipher_mac},
    packet::{Packet, PayloadType, advert::Advert, grptext::GrpText},
};

pub const PREAMBLE_LENGTH: u16 = 16;
pub const SYNCWORD: u8 = 0x12;
pub const MAX_TRANS_UNIT: usize = 255;

pub mod crypto;
pub mod identity;
pub mod mesh;
pub mod packet;

#[derive(Debug, PartialEq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum Error {
    ParseError,
    VerifyError,
    FullQueue,
}

pub type Result<T> = core::result::Result<T, Error>;

pub struct Location {
    pub lat: u32,
    pub long: u32,
}

const MAX_PACKET_HASHES: usize = 128;

#[derive(Debug)]
struct GroupChannel {
    hash: [u8; 1],
    shared_secret: [u8; 16],
}

pub struct Mesh {
    // tx_queue: Queue<32>,
    // rx_queue: Queue<32>,
    pub pub_key: PublicKey,
    pub location: Option<Location>,
    pub battery: Option<u16>,
    pub temperature: Option<u16>,
    pub name: Option<[u8; 64]>,
    pub seen: FnvIndexSet<u32, MAX_PACKET_HASHES>,

    channels: Vec<GroupChannel, 8>,
}

impl Mesh {
    pub fn new() -> Self {
        let mut name = [0u8; 64];
        name[..b"test".len()].copy_from_slice(b"test");
        let mut channels = Vec::new();
        channels
            .push(GroupChannel {
                hash: [17],
                shared_secret: [
                    0x8b, 0x33, 0x87, 0xe9, 0xc5, 0xcd, 0xea, 0x6a, 0xc9, 0xe5, 0xed, 0xba, 0xa1,
                    0x15, 0xcd, 0x72,
                ],
            })
            .unwrap();
        Self {
            pub_key: PublicKey([0u8; 32]),
            location: None,
            battery: None,
            temperature: None,
            name: Some(name),
            seen: FnvIndexSet::new(),
            channels,
        }
    }
}

impl Mesh {
    pub fn handle_packet(&self, buf: &[u8]) -> Result<()> {
        let pkt = Packet::from_bytes(buf)?;
        let payload_type = pkt.payload_type()?;
        let hash = pkt.hash_packet();
        match payload_type {
            PayloadType::Req => todo!(),
            PayloadType::Resp => todo!(),
            PayloadType::TxtMsg => todo!(),
            PayloadType::Ack => todo!(),
            PayloadType::Advert => {
                let advert = Advert::from_bytes(pkt.payload)?;
                advert.verify()?;
                #[cfg(feature = "defmt")]
                debug!("advert: {}", advert);
            }
            PayloadType::GrpText => {
                let grptext = GrpText::from_bytes(pkt.payload)?;
                let mut buf = [0u8; 255];
                for ch in self
                    .channels
                    .iter()
                    .filter(|ch| ch.hash == grptext.channel_hash)
                {
                    if !cipher_mac(grptext.data, &ch.shared_secret)?.eq(&grptext.cipher_mac) {
                        continue;
                    }
                    if let Ok(res) = aes_ecb_decrypt(&mut buf, grptext.data, &ch.shared_secret) {
                        #[cfg(feature = "defmt")]
                        debug!("message: {:a}", res[5..]);
                        break;
                    }
                }
            }
            PayloadType::GrpData => todo!(),
            PayloadType::AnonReq => todo!(),
            PayloadType::Path => todo!(),
            PayloadType::Trace => todo!(),
            PayloadType::RawCustom => todo!(),
        };
        Ok(())
    }
}
