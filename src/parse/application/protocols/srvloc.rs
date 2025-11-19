#[derive(Debug)]
pub struct SrvlocPacket {
    pub header: SrvlocHeader,
    pub payload: SrvlocMessage,
}

#[derive(Debug)]
pub enum SrvlocHeader {
    V1(SrvlocHeaderV1),
    V2(SrvlocHeaderV2),
}

#[derive(Debug)]
pub struct SrvlocHeaderV2 {
    pub version: u8,
    pub function: u8,
    pub packet_length: u16,
    pub flags: u8,
    pub next_extension_offset: u8,
    pub xid: u32,
    pub lang_tag_len: u8,
    pub lang_tag: u8,
}

#[derive(Debug)]
pub struct SrvlocHeaderV1 {
    pub version: u8,
    pub function: u8,
    pub packet_length: u16,
    pub flags: u8,
    pub dialect: u8,
    pub language: u8,
    encoding
    transaction_id,
    error_code,
    url_length,
    url:
    scope_list_lengh:
    scope_list
}

