#![no_std]

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes,
    little_endian::{I32, U16, U32},
};

#[derive(TryFromBytes, Immutable, KnownLayout)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum Command {
    AppStart = 1,
    SendTxtMsg = 2,
    SendChannelTxtMsg = 3,
    GetContacts = 4, // with optional 'since' (for efficient sync)
    GetDeviceTime = 5,
    SetDeviceTime = 6,
    SendSelfAdvert = 7,
    SetAdvertName = 8,
    AddUpdateContact = 9,
    SyncNextMessage = 10,
    SetRadioParams = 11,
    SetRadioTxPower = 12,
    ResetPath = 13,
    SetAdvertLatLon = 14,
    RemoveContact = 15,
    ShareContact = 16,
    ExportContact = 17,
    ImportContact = 18,
    Reboot = 19,
    GetBattAndStorage = 20, // was CMD_GET_BATTERY_VOLTAGE
    SetTuningParams = 21,
    DeviceQuery = 22,
    ExportPrivateKey = 23,
    ImportPrivateKey = 24,
    SendRawData = 25,
    SendLogin = 26,
    SendStatusReq = 27,
    HasConnection = 28,
    Logout = 29, // 'Disconnect'
    GetContactByKey = 30,
    GetChannel = 31,
    SetChannel = 32,
    SignStart = 33,
    SignData = 34,
    SignFinish = 35,
    SendTracePath = 36,
    SetDevicePin = 37,
    SetOtherParams = 38,
    SendTelemetryReq = 39,
    GetCustomVars = 40,
    SetCustomVar = 41,
    GetAdvertPath = 42,
    GetTuningParams = 43,
    // NOTE: CMD range 44..49 parked, potentially for WiFi operations
    SendBinaryReq = 50,
    FactoryReset = 51,
}

impl Command {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum FrameType {
    Incoming = b'<',
    Outgoing = b'>',
}

impl TryFrom<u8> for FrameType {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::Incoming as u8 => Ok(Self::Incoming),
            x if x == Self::Outgoing as u8 => Ok(Self::Outgoing),
            _ => Err(()),
        }
    }
}

#[derive(TryFromBytes, IntoBytes, Immutable, KnownLayout)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct FrameHeader {
    pub kind: FrameType,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub length: U16,
}

impl FrameHeader {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok((Self::try_ref_from_prefix(buf)).map_err(|_| ())?)
    }
}

impl TryFrom<u8> for Command {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            x if x == Self::AppStart as u8 => Ok(Self::AppStart),
            x if x == Self::SendTxtMsg as u8 => Ok(Self::SendTxtMsg),
            x if x == Self::SendChannelTxtMsg as u8 => Ok(Self::SendChannelTxtMsg),
            x if x == Self::GetContacts as u8 => Ok(Self::GetContacts),
            x if x == Self::GetDeviceTime as u8 => Ok(Self::GetDeviceTime),
            x if x == Self::SetDeviceTime as u8 => Ok(Self::SetDeviceTime),
            x if x == Self::SendSelfAdvert as u8 => Ok(Self::SendSelfAdvert),
            x if x == Self::SetAdvertName as u8 => Ok(Self::SetAdvertName),
            x if x == Self::AddUpdateContact as u8 => Ok(Self::AddUpdateContact),
            x if x == Self::SyncNextMessage as u8 => Ok(Self::SyncNextMessage),
            x if x == Self::SetRadioParams as u8 => Ok(Self::SetRadioParams),
            x if x == Self::SetRadioTxPower as u8 => Ok(Self::SetRadioTxPower),
            x if x == Self::ResetPath as u8 => Ok(Self::ResetPath),
            x if x == Self::SetAdvertLatLon as u8 => Ok(Self::SetAdvertLatLon),
            x if x == Self::RemoveContact as u8 => Ok(Self::RemoveContact),
            x if x == Self::ShareContact as u8 => Ok(Self::ShareContact),
            x if x == Self::ExportContact as u8 => Ok(Self::ExportContact),
            x if x == Self::ImportContact as u8 => Ok(Self::ImportContact),
            x if x == Self::Reboot as u8 => Ok(Self::Reboot),
            x if x == Self::GetBattAndStorage as u8 => Ok(Self::GetBattAndStorage),
            x if x == Self::SetTuningParams as u8 => Ok(Self::SetTuningParams),
            x if x == Self::DeviceQuery as u8 => Ok(Self::DeviceQuery),
            x if x == Self::ExportPrivateKey as u8 => Ok(Self::ExportPrivateKey),
            x if x == Self::ImportPrivateKey as u8 => Ok(Self::ImportPrivateKey),
            x if x == Self::SendRawData as u8 => Ok(Self::SendRawData),
            x if x == Self::SendLogin as u8 => Ok(Self::SendLogin),
            x if x == Self::SendStatusReq as u8 => Ok(Self::SendStatusReq),
            x if x == Self::HasConnection as u8 => Ok(Self::HasConnection),
            x if x == Self::Logout as u8 => Ok(Self::Logout),
            x if x == Self::GetContactByKey as u8 => Ok(Self::GetContactByKey),
            x if x == Self::GetChannel as u8 => Ok(Self::GetChannel),
            x if x == Self::SetChannel as u8 => Ok(Self::SetChannel),
            x if x == Self::SignStart as u8 => Ok(Self::SignStart),
            x if x == Self::SignData as u8 => Ok(Self::SignData),
            x if x == Self::SignFinish as u8 => Ok(Self::SignFinish),
            x if x == Self::SendTracePath as u8 => Ok(Self::SendTracePath),
            x if x == Self::SetDevicePin as u8 => Ok(Self::SetDevicePin),
            x if x == Self::SetOtherParams as u8 => Ok(Self::SetOtherParams),
            x if x == Self::SendTelemetryReq as u8 => Ok(Self::SendTelemetryReq),
            x if x == Self::GetCustomVars as u8 => Ok(Self::GetCustomVars),
            x if x == Self::SetCustomVar as u8 => Ok(Self::SetCustomVar),
            x if x == Self::GetAdvertPath as u8 => Ok(Self::GetAdvertPath),
            x if x == Self::GetTuningParams as u8 => Ok(Self::GetTuningParams),
            x if x == Self::SendBinaryReq as u8 => Ok(Self::SendBinaryReq),
            x if x == Self::FactoryReset as u8 => Ok(Self::FactoryReset),
            _ => Err(()),
        }
    }
}

#[repr(u8)]
pub enum ResponseCode {
    Ok = 0,
    Err = 1,
    ContactsStart = 2,   // first reply to CMD_GET_CONTACTS
    Contact = 3,         // multiple of these (after CMD_GET_CONTACTS)
    EndOfContacts = 4,   // last reply to CMD_GET_CONTACTS
    SelfInfo = 5,        // reply to CMD_APP_START
    Sent = 6,            // reply to CMD_SEND_TXT_MSG
    ContactMsgRecv = 7,  // a reply to CMD_SYNC_NEXT_MESSAGE (ver < 3)
    ChannelMsgRecv = 8,  // a reply to CMD_SYNC_NEXT_MESSAGE (ver < 3)
    CurrTime = 9,        // a reply to CMD_GET_DEVICE_TIME
    NoMoreMessages = 10, // a reply to CMD_SYNC_NEXT_MESSAGE
    ExportContact = 11,
    BattAndStorage = 12, // a reply to a CMD_GET_BATT_AND_STORAGE
    DeviceInfo = 13,     // a reply to CMD_DEVICE_QEURY
    PrivateKey = 14,     // a reply to CMD_EXPORT_PRIVATE_KEY
    Disabled = 15,
    ContactMsgRecvV3 = 16, // a reply to CMD_SYNC_NEXT_MESSAGE (ver >= 3)
    ChannelMsgRecvV3 = 17, // a reply to CMD_SYNC_NEXT_MESSAGE (ver >= 3)
    ChannelInfo = 18,      // a reply to CMD_GET_CHANNEL
    SignStart = 19,
    Signature = 20,
    CustomVars = 21,
    AdvertPath = 22,
    TuningParams = 23,
}

#[derive(IntoBytes, KnownLayout, Immutable)]
#[repr(u8)]
pub enum AdvertLocation {
    None = 0,
    Share = 1,
}

pub const MAX_FRAME_SIZE: usize = 172;

struct Cursor<'a> {
    pos: usize,
    buf: &'a mut [u8],
}

impl<'a> Cursor<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { pos: 0, buf }
    }

    fn write(&mut self, src: &[u8]) -> Result<(), ()> {
        let start = self.pos;
        let end = start + src.len();
        if end > self.buf.len() {
            return Err(());
        }
        self.buf[start..end].copy_from_slice(src);
        self.pos = end;
        Ok(())
    }

    fn position(&self) -> usize {
        self.pos
    }
}

pub trait ProtocolResponse {
    const RESPONSE_CODE: ResponseCode;

    #[doc(hidden)]
    fn serialize_payload<'b>(&self, frame: &'b mut [u8]) -> Result<usize, ()>;

    fn serialize<'b>(&self, buffer: &'b mut [u8]) -> Result<&'b [u8], ()> {
        let header_len = 3;
        let payload_len = self.serialize_payload(&mut buffer[header_len + 1..])?;
        buffer[0] = FrameType::Outgoing as u8;
        U16::try_from(payload_len + 1)
            .map_err(|_| ())?
            .write_to(&mut buffer[1..3])
            .map_err(|_| ())?;
        buffer[3] = Self::RESPONSE_CODE as u8;
        Ok(&buffer[..header_len + 1 + payload_len])
    }
}

pub struct OkResponse;

impl ProtocolResponse for OkResponse {
    const RESPONSE_CODE: ResponseCode = ResponseCode::Ok;

    fn serialize_payload<'b>(&self, _buf: &'b mut [u8]) -> Result<usize, ()> {
        Ok(0)
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum ErrorCode {
    UnsupportedCmd = 1,
    NotFound = 2,
    TableFull = 3,
    BadState = 4,
    FileIoError = 5,
    IllegalArg = 6,
}

pub struct ErrorResponse(pub ErrorCode);

impl ProtocolResponse for ErrorResponse {
    const RESPONSE_CODE: ResponseCode = ResponseCode::Err;

    fn serialize_payload<'b>(&self, buf: &'b mut [u8]) -> Result<usize, ()> {
        buf[0] = self.0 as u8;
        Ok(1)
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SelfInfoResponse<'a> {
    pub adv_type: u8,
    pub tx_power: u8,
    pub max_tx_power: u8,
    pub pubkey: [u8; 32],
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub lat: I32,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub lon: I32,
    pub multi_acks: u8,
    pub advert_location_policy: u8,
    pub telemetry_mode: u8,
    pub manual_add_contacts: u8,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub frequency: U32,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub bandwidth: U32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
    pub name: &'a [u8],
}

impl<'a> ProtocolResponse for SelfInfoResponse<'_> {
    const RESPONSE_CODE: ResponseCode = ResponseCode::SelfInfo;

    fn serialize_payload<'b>(&self, buf: &'b mut [u8]) -> Result<usize, ()> {
        let mut buf = Cursor::new(buf);
        buf.write(self.adv_type.as_bytes())?;
        buf.write(self.tx_power.as_bytes())?;
        buf.write(self.max_tx_power.as_bytes())?;
        buf.write(self.pubkey.as_bytes())?;
        buf.write(self.lat.as_bytes())?;
        buf.write(self.lon.as_bytes())?;
        buf.write(self.multi_acks.as_bytes())?;
        buf.write(self.advert_location_policy.as_bytes())?;
        buf.write(self.telemetry_mode.as_bytes())?;
        buf.write(self.manual_add_contacts.as_bytes())?;
        buf.write(self.frequency.as_bytes())?;
        buf.write(self.bandwidth.as_bytes())?;
        buf.write(self.spreading_factor.as_bytes())?;
        buf.write(self.coding_rate.as_bytes())?;
        buf.write(self.name)?;
        Ok(buf.position())
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ContactsStartResponse {
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub num_contacts: U32,
}

impl ProtocolResponse for ContactsStartResponse {
    const RESPONSE_CODE: ResponseCode = ResponseCode::ContactsStart;

    fn serialize_payload<'b>(&self, buf: &'b mut [u8]) -> Result<usize, ()> {
        let mut buf = Cursor::new(buf);
        buf.write(self.num_contacts.as_bytes())?;
        Ok(buf.position())
    }
}

pub struct ContactsEndResponse {
    pub most_recent_lastmod: u32,
}

impl ProtocolResponse for ContactsEndResponse {
    const RESPONSE_CODE: ResponseCode = ResponseCode::EndOfContacts;

    fn serialize_payload<'b>(&self, buf: &'b mut [u8]) -> Result<usize, ()> {
        let mut buf = Cursor::new(buf);
        buf.write(U32::from(self.most_recent_lastmod).as_bytes())?;
        Ok(buf.position())
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct ContactInfoResponse<'a> {
    pub pub_key: &'a [u8; 32],
    pub adv_type: u8,
    pub flags: u8,
    pub out_path_len: u8,
    pub out_path: &'a [u8; 64],
    pub name: &'a [u8; 32],
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub last_advert_timestamp: U32,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub gps_lat: I32,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub gps_lon: I32,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub last_mod: U32,
}

impl<'a> ProtocolResponse for ContactInfoResponse<'_> {
    const RESPONSE_CODE: ResponseCode = ResponseCode::Contact;

    fn serialize_payload<'b>(&self, buf: &'b mut [u8]) -> Result<usize, ()> {
        let mut buf = Cursor::new(buf);
        buf.write(self.pub_key.as_bytes())?;
        buf.write(self.adv_type.as_bytes())?;
        buf.write(self.flags.as_bytes())?;
        buf.write(self.out_path_len.as_bytes())?;
        buf.write(self.out_path)?;
        buf.write(self.name)?;
        buf.write(self.last_advert_timestamp.as_bytes())?;
        buf.write(self.gps_lat.as_bytes())?;
        buf.write(self.gps_lon.as_bytes())?;
        buf.write(self.last_mod.as_bytes())?;
        Ok(buf.position())
    }
}

pub struct NoMoreMessagesResponse;

impl ProtocolResponse for NoMoreMessagesResponse {
    const RESPONSE_CODE: ResponseCode = ResponseCode::NoMoreMessages;

    fn serialize_payload<'b>(&self, _buf: &'b mut [u8]) -> Result<usize, ()> {
        Ok(0)
    }
}

const FIRMWARE_VER_CODE: u8 = 7;

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct DeviceInfoRepsonse<'a> {
    // pub firmware_ver_code: u8,
    pub max_contacts: u16,
    pub max_group_channels: u8,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub ble_pin: U32,
    pub build_date: &'a [u8; 12],
    pub manufacturer: &'a [u8; 40],
    pub firmware_version: &'a [u8; 20],
}

impl<'a> ProtocolResponse for DeviceInfoRepsonse<'a> {
    const RESPONSE_CODE: ResponseCode = ResponseCode::DeviceInfo;

    fn serialize_payload<'b>(&self, buf: &'b mut [u8]) -> Result<usize, ()> {
        let mut buf = Cursor::new(buf);
        buf.write(FIRMWARE_VER_CODE.as_bytes())?;
        buf.write(u8::try_from(self.max_contacts / 2).unwrap().as_bytes())?;
        buf.write(self.max_group_channels.as_bytes())?;
        buf.write(self.ble_pin.as_bytes())?;
        buf.write(self.build_date)?;
        buf.write(self.manufacturer)?;
        buf.write(self.firmware_version)?;
        Ok(buf.position())
    }
}

#[derive(IntoBytes, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct BattAndStorageResponse {
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub battery_millivolts: U16,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub storage_used: U32,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub storage_total: U32,
}

impl ProtocolResponse for BattAndStorageResponse {
    const RESPONSE_CODE: ResponseCode = ResponseCode::BattAndStorage;

    fn serialize_payload<'b>(&self, buf: &'b mut [u8]) -> Result<usize, ()> {
        let mut buf = Cursor::new(buf);
        buf.write(self.as_bytes())?;
        Ok(buf.position())
    }
}

pub struct ChannelInfoResponse<'a> {
    pub index: u8,
    pub name: &'a [u8; 32],
    pub shared_secret: &'a [u8; 16],
}

impl<'a> ProtocolResponse for ChannelInfoResponse<'a> {
    const RESPONSE_CODE: ResponseCode = ResponseCode::ChannelInfo;

    fn serialize_payload<'b>(&self, buf: &'b mut [u8]) -> Result<usize, ()> {
        let mut buf = Cursor::new(buf);
        buf.write(self.index.as_bytes())?;
        buf.write(self.name)?;
        buf.write(self.shared_secret)?;
        Ok(buf.position())
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct DeviceQueryRequest {
    pub app_ver: u8,
}

impl DeviceQueryRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(TryFromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct AppStartRequest {
    _reserved: [u8; 7],
    pub name: [u8],
}

impl AppStartRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(TryFromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum TxtType {
    Plain = 0,
    Command = 1,
    SignedPlain = 2,
}

#[derive(TryFromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SendTxtMsgRequest {
    pub kind: TxtType,
    pub attempt: u8,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub timestamp: U32,
    pub pubkey_prefix: [u8; 6],
    pub text: [u8],
}

impl SendTxtMsgRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(TryFromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SendChannelTxtMsgRequest {
    pub kind: TxtType,
    pub channel_index: u8,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub timestamp: U32,
    pub text: [u8],
}

impl SendChannelTxtMsgRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct GetContactsRequest {
    pub since: U32,
}

impl GetContactsRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(Self, &'a [u8]), ()> {
        if buf.len() == 0 {
            Ok((Self { since: 0.into() }, buf))
        } else {
            Ok(Self::try_read_from_prefix(buf).map_err(|_| ())?)
        }
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct SetAdvertNameRequest {
    pub name: [u8],
}

impl SetAdvertNameRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        let max = buf.len().max(32 - 1); // C version requires trailing \0
        Ok(Self::ref_from_prefix(&buf[..max]).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct SetAdvertLatLonRequest {
    pub lat: U32,
    pub lon: U32,
}

impl SetAdvertLatLonRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        let max = buf.len().max(32 - 1); // C version requires trailing \0
        Ok(Self::ref_from_prefix(&buf[..max]).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct GetDeviceTimeRequest;

impl GetDeviceTimeRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SetDeviceTimeRequest {
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub time: U32,
}

impl SetDeviceTimeRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SendSelfAdvertRequest {
    pub flood: bool,
}

impl SendSelfAdvertRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(Self, &'a [u8]), ()> {
        let (flood, buf) = take_optional_u8(buf);
        Ok((
            SendSelfAdvertRequest {
                flood: flood.is_some_and(|v| v == 1),
            },
            buf,
        ))
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct ResetPathRequest {
    pub pub_key: [u8; 32],
}

impl ResetPathRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct AddUpdateContactRequest {
    pub pub_key: [u8; 32],
    pub kind: u8,
    pub flags: u8,
    pub out_path_len: u8,
    pub out_path: [u8; 64],
    pub name: [u8; 32],
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub last_advert_timestamp: U32,
}

impl AddUpdateContactRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct RemoveContactRequest {
    pub pub_key: [u8; 32],
}

impl RemoveContactRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct ShareContactRequest {
    pub pub_key: [u8; 32],
}

impl ShareContactRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct GetContactByKeyRequest {
    pub pub_key: [u8; 32],
}

impl GetContactByKeyRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

pub enum ExportContactRequest<'a> {
    This,
    Other { pub_key: &'a [u8; 32] },
}

impl<'a> ExportContactRequest<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<(Self, &'a [u8]), ()> {
        if buf.len() >= 32 {
            let (pub_key, buf) = <[u8; 32]>::try_ref_from_prefix(buf).map_err(|_| ())?;
            Ok((Self::Other { pub_key }, buf))
        } else {
            Ok((Self::This, buf))
        }
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct ImportContactRequest {
    pub packet: [u8],
}

impl ImportContactRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SyncNextMessageRequest {}

impl SyncNextMessageRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SetRadioParamsRequest {
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub frequency: U32,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub bandwidth: U32,
    pub spreading_factor: u8,
    pub coding_rate: u8,
}

impl SetRadioParamsRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SetRadioTxPowerRequest {
    pub tx_power_dbm: u8,
}

impl SetRadioTxPowerRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SetTuningParamsRequest {
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub rx_delay_base: U32,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub airtime_factor: U32,
}

impl SetTuningParamsRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct GetTuningParamsRequest;

impl GetTuningParamsRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SetOtherParamsRequest {
    pub manual_add_contacts: u8,
    pub telemetry_mode: Option<u8>,
    pub advert_location_policy: Option<u8>,
    pub multi_acks: Option<u8>,
}

impl SetOtherParamsRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(Self, &'a [u8]), ()> {
        if buf.len() == 0 {
            return Err(());
        }
        let (manual_add_contacts, buf) = (buf[0], &buf[1..]);
        let (telemetry_mode, buf) = take_optional_u8(buf);
        let (advert_location_policy, buf) = take_optional_u8(buf);
        let (multi_acks, buf) = take_optional_u8(buf);

        return Ok((
            Self {
                manual_add_contacts,
                telemetry_mode,
                advert_location_policy,
                multi_acks,
            },
            buf,
        ));
    }
}

#[derive(Debug, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct RebootRequest;

impl RebootRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        if buf.starts_with(b"reboot") {
            Ok((&RebootRequest {}, &buf[b"reboot".len()..]))
        } else {
            Err(())
        }
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct GetBattAndStorageRequest {}

impl GetBattAndStorageRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct ImportPrivateKeyRequest {
    pub private_key: [u8; 64],
}

impl ImportPrivateKeyRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct ExportPrivateKeyRequest;

impl ExportPrivateKeyRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

fn take_u8(buf: &[u8]) -> Result<(u8, &[u8]), ()> {
    Ok((*buf.get(0).ok_or(())?, &buf[1..]))
}

fn take_n_u8(buf: &[u8], n: usize) -> Result<(&[u8], &[u8]), ()> {
    return buf.split_at_checked(n).ok_or(());
}

fn take_optional_u8(buf: &[u8]) -> (Option<u8>, &[u8]) {
    if buf.len() > 0 {
        (Some(buf[0]), &buf[1..])
    } else {
        (None, buf)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SendRawDataRequest<'a> {
    pub path_len: u8,
    pub path: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> SendRawDataRequest<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<(Self, &'a [u8]), ()> {
        let (path_len, buf) = take_u8(buf)?;
        // minimum 4 byte payload
        if path_len == 0 || path_len > 64 || usize::from(path_len) + 4 <= buf.len() {
            return Err(());
        }
        let (path, buf) = take_n_u8(buf, path_len.into())?;
        let (payload, buf) = (buf, &[]);
        Ok((
            Self {
                path_len,
                path,
                payload,
            },
            buf,
        ))
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SendLoginRequest {
    pub pub_key: [u8; 32],
    pub password: [u8],
}

impl SendLoginRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SendStatusReqRequest {
    pub pub_key: [u8; 32],
}

impl SendStatusReqRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum SendTelemetryReqRequest<'a> {
    This,
    Contact { pub_key: &'a [u8; 32] },
}

impl<'a> SendTelemetryReqRequest<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<(Self, &'a [u8]), ()> {
        if buf.len() == 3 {
            // 'self' telemetry request
            Ok((Self::This {}, &buf[3..]))
        } else {
            let (pub_key, buf) = <[u8; 32]>::try_ref_from_prefix(buf).map_err(|_| ())?;
            Ok((Self::Contact { pub_key: pub_key }, buf))
        }
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SendBinaryReqRequest {
    pub pub_key: [u8; 32],
    pub payload: [u8],
}

impl SendBinaryReqRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct HasConnectionRequest {
    pub pub_key: [u8; 32],
}

impl HasConnectionRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct LogoutRequest {
    pub pub_key: [u8; 32],
}

impl LogoutRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct GetChannelRequest {
    pub index: u8,
}

impl GetChannelRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SetChannelAes128 {
    pub index: u8,
    pub name: [u8; 32],
    pub secret: [u8; 16],
}

pub enum SetChannelRequest<'a> {
    Aes128(&'a SetChannelAes128),
}

impl<'a> SetChannelRequest<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<(Self, &'a [u8]), ()> {
        if buf.len() >= 1 + 32 + 32 {
            Err(())
        } else if buf.len() >= 1 + 32 + 16 {
            let (req, buf) = SetChannelAes128::try_ref_from_prefix(buf).map_err(|_| ())?;
            Ok((SetChannelRequest::Aes128(req), buf))
        } else {
            Err(())
        }
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SignStartRequest;

impl SignStartRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SignDataRequest {
    pub sign_data_chunk: [u8],
}

impl SignDataRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SignFinishRequest;

impl SignFinishRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SendTracePathRequest {
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub tag: U32,
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub auth: U32,
    pub flags: u8,
    pub path: [u8],
}

impl SendTracePathRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        let (req, buf) = Self::try_ref_from_prefix(buf).map_err(|_| ())?;
        if req.path.len() >= 64 {
            return Err(());
        }
        Ok((req, buf))
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SetDevicePinRequest {
    #[cfg_attr(feature = "defmt", defmt(Display2Format))]
    pub pin: U32,
}

impl SetDevicePinRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        let (req, buf) = Self::try_ref_from_prefix(buf).map_err(|_| ())?;
        // XXX: what about leading zeros?
        if req.pin != 0 && (req.pin < 100000 || req.pin > 999999) {
            return Err(());
        }
        Ok((req, buf))
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct GetCustomVarRequest;

impl GetCustomVarRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(Debug, FromBytes, KnownLayout, Immutable, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct SetCustomVarRequest<'a> {
    pub key: &'a [u8],
    pub value: &'a [u8],
}

impl<'a> SetCustomVarRequest<'a> {
    pub fn parse(buf: &'a [u8]) -> Result<(Self, &'a [u8]), ()> {
        let sep = buf.iter().position(|b| *b == b':').ok_or(())?;
        let (key, value) = (&buf[..sep], &buf[sep + 1..]);
        Ok((Self { key, value }, &[]))
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct GetAdvertPathRequest {
    reserved: u8,
    pub pub_key: [u8; 32],
}

impl GetAdvertPathRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        Ok(Self::try_ref_from_prefix(buf).map_err(|_| ())?)
    }
}

#[derive(FromBytes, KnownLayout, Immutable)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(C)]
pub struct FactoryResetRequest;

impl FactoryResetRequest {
    pub fn parse<'a>(buf: &'a [u8]) -> Result<(&'a Self, &'a [u8]), ()> {
        if buf.starts_with(b"reset") {
            Ok((&FactoryResetRequest {}, &buf[b"reset".len()..]))
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_set_custom_var_req() {
        assert_eq!(
            SetCustomVarRequest::parse(b"foo:bar").unwrap(),
            (
                SetCustomVarRequest {
                    key: b"foo",
                    value: b"bar"
                },
                &b""[..],
            )
        );
    }

    #[test]
    fn test_parse_reboot() {
        assert_eq!(
            RebootRequest::parse(b"reboot").unwrap(),
            (&RebootRequest {}, &b""[..],)
        );
        assert_eq!(
            RebootRequest::parse(b"rebootrest").unwrap(),
            (&RebootRequest {}, &b"rest"[..],)
        );
    }
}
