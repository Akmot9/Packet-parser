// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! The C ABI between a plugin and its host, version 1.
//!
//! A plugin exports one function, [`ENTRY_POINT`], which returns a pointer
//! to its [`PluginDescriptorV1`]. Only C types cross the boundary: the host
//! and the plugin may be built by different versions of rustc, and against
//! different versions of `packet_parser`.
//!
//! [`export_parser!`](crate::export_parser) writes the plugin side and
//! [`load_parser`](crate::load_parser) reads it: neither the author of a
//! parser nor the host has to touch these types.
//!
//! A change to any of them is a new version: a new descriptor type, a new
//! entry point, a new [`ABI_VERSION`]. Version 1 never changes.

use std::ffi::c_void;

use packet_parser::{CustomTransports, PayloadContext, TransportProtocol};

/// The version this kit writes and reads.
pub const ABI_VERSION: u32 = 1;

/// The name of the function a plugin exports.
pub const ENTRY_POINT: &str = "packet_parser_plugin_v1";

/// [`ENTRY_POINT`], NUL-terminated, for the dynamic loader.
pub(crate) const ENTRY_POINT_SYMBOL: &[u8] = b"packet_parser_plugin_v1\0";

/// [`PluginDescriptorV1::transports`]: TCP segments.
pub const TRANSPORT_TCP: u8 = 0b01;
/// [`PluginDescriptorV1::transports`]: UDP datagrams.
pub const TRANSPORT_UDP: u8 = 0b10;

/// [`PayloadContextV1::transport`] for TCP: its IP protocol number.
pub const IP_PROTOCOL_TCP: u8 = 6;
/// [`PayloadContextV1::transport`] for UDP: its IP protocol number.
pub const IP_PROTOCOL_UDP: u8 = 17;

/// [`PayloadContextV1::known_ports`]: the source port is known.
pub const SOURCE_PORT_KNOWN: u8 = 0b01;
/// [`PayloadContextV1::known_ports`]: the destination port is known.
pub const DESTINATION_PORT_KNOWN: u8 = 0b10;

/// What [`MatchesV1`] returns for a payload it recognizes. Any other value
/// is a refusal, a panic included.
pub const MATCHED: u8 = 1;

/// What [`FieldsV1`] returns when every field was emitted. Any other value
/// means the fields are not usable, and the host drops those it received.
pub const FIELDS_COMPLETE: u8 = 1;

/// The context of a payload, as `packet_parser::PayloadContext`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadContextV1 {
    /// [`IP_PROTOCOL_TCP`] or [`IP_PROTOCOL_UDP`].
    pub transport: u8,
    /// [`SOURCE_PORT_KNOWN`] and [`DESTINATION_PORT_KNOWN`].
    pub known_ports: u8,
    /// The source port, or 0 when it is not known.
    pub source_port: u16,
    /// The destination port, or 0 when it is not known.
    pub destination_port: u16,
}

/// Receives one field from [`FieldsV1`]: name and value, UTF-8 bytes that
/// are only valid during the call.
pub type EmitFieldV1 = unsafe extern "C" fn(
    sink: *mut c_void,
    name: *const u8,
    name_len: usize,
    value: *const u8,
    value_len: usize,
);

/// `ApplicationParser::matches`. The payload and the context are only valid
/// during the call. Returns [`MATCHED`] for a payload the parser recognizes.
pub type MatchesV1 = unsafe extern "C" fn(
    payload: *const u8,
    payload_len: usize,
    context: *const PayloadContextV1,
) -> u8;

/// `ApplicationParser::fields`: calls `emit` once per field, in display
/// order, with `sink` unchanged. Returns [`FIELDS_COMPLETE`] when it
/// emitted all of them.
pub type FieldsV1 = unsafe extern "C" fn(
    payload: *const u8,
    payload_len: usize,
    context: *const PayloadContextV1,
    sink: *mut c_void,
    emit: EmitFieldV1,
) -> u8;

/// The type of [`ENTRY_POINT`]. A null pointer means the plugin could not
/// build its parser.
pub type EntryPointV1 = unsafe extern "C" fn() -> *const PluginDescriptorV1;

/// What a plugin declares. The memory it points to belongs to the plugin and
/// stays valid as long as the library is loaded.
#[repr(C)]
#[derive(Debug)]
pub struct PluginDescriptorV1 {
    /// [`ABI_VERSION`]: 1. The host reads this field first, and nothing
    /// else when it does not know the version.
    pub abi_version: u32,
    /// `size_of::<PluginDescriptorV1>()`, in bytes.
    pub size: u32,
    /// The label, UTF-8, not NUL-terminated.
    pub label: *const u8,
    /// Its length in bytes.
    pub label_len: usize,
    /// [`TRANSPORT_TCP`], [`TRANSPORT_UDP`], or both.
    pub transports: u8,
    /// The ports, as `ApplicationParser::ports`. Null when `ports_len` is 0.
    pub ports: *const u16,
    /// Their number.
    pub ports_len: usize,
    /// See [`MatchesV1`].
    pub matches: MatchesV1,
    /// See [`FieldsV1`].
    pub fields: FieldsV1,
}

/// The first two fields of every version of the descriptor.
#[repr(C)]
pub(crate) struct DescriptorHeader {
    pub(crate) abi_version: u32,
    pub(crate) size: u32,
}

/// `size_of::<PluginDescriptorV1>()` as written in [`PluginDescriptorV1::size`].
pub(crate) const DESCRIPTOR_V1_SIZE: u32 = {
    let size = size_of::<PluginDescriptorV1>();
    assert!(size <= u32::MAX as usize);
    size as u32
};

/// `PayloadContext` to C. `None` for a transport other than TCP and UDP.
pub(crate) fn context_to_abi(context: &PayloadContext) -> Option<PayloadContextV1> {
    let transport = match context.transport {
        TransportProtocol::Tcp => IP_PROTOCOL_TCP,
        TransportProtocol::Udp => IP_PROTOCOL_UDP,
        _ => return None,
    };
    let known = |port: Option<u16>, flag: u8| port.map_or(0, |_| flag);
    Some(PayloadContextV1 {
        transport,
        known_ports: known(context.source_port, SOURCE_PORT_KNOWN)
            | known(context.destination_port, DESTINATION_PORT_KNOWN),
        source_port: context.source_port.unwrap_or(0),
        destination_port: context.destination_port.unwrap_or(0),
    })
}

/// C to `PayloadContext`. `None` for an unknown transport.
pub(crate) fn context_from_abi(context: &PayloadContextV1) -> Option<PayloadContext> {
    let transport = match context.transport {
        IP_PROTOCOL_TCP => TransportProtocol::Tcp,
        IP_PROTOCOL_UDP => TransportProtocol::Udp,
        _ => return None,
    };
    let port = |port: u16, flag: u8| (context.known_ports & flag != 0).then_some(port);
    Some(PayloadContext::new(
        transport,
        port(context.source_port, SOURCE_PORT_KNOWN),
        port(context.destination_port, DESTINATION_PORT_KNOWN),
    ))
}

/// `CustomTransports` to its mask.
pub(crate) fn transports_to_abi(transports: CustomTransports) -> u8 {
    [
        (TransportProtocol::Tcp, TRANSPORT_TCP),
        (TransportProtocol::Udp, TRANSPORT_UDP),
    ]
    .into_iter()
    .filter(|(protocol, _)| transports.admits(*protocol))
    .fold(0, |mask, (_, flag)| mask | flag)
}

/// A mask to `CustomTransports`. `None` for an empty mask or an unknown bit.
pub(crate) fn transports_from_abi(mask: u8) -> Option<CustomTransports> {
    match mask {
        TRANSPORT_TCP => Some(CustomTransports::Tcp),
        TRANSPORT_UDP => Some(CustomTransports::Udp),
        mask if mask == TRANSPORT_TCP | TRANSPORT_UDP => Some(CustomTransports::TcpAndUdp),
        _ => None,
    }
}

/// The bytes at `data`, or an empty slice when the pointer is null.
///
/// # Safety
///
/// A non-null `data` points to `len` initialized bytes, valid and unchanged
/// for `'a`.
pub(crate) unsafe fn bytes<'a>(data: *const u8, len: usize) -> &'a [u8] {
    if data.is_null() || len == 0 {
        &[]
    } else {
        // SAFETY: the caller guarantees `len` readable bytes at `data`.
        unsafe { std::slice::from_raw_parts(data, len) }
    }
}
