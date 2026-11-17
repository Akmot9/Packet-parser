// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! The host side: loading a plugin.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use packet_parser::parse::application::custom::MAX_LABEL_LENGTH;
use packet_parser::{ApplicationParser, CustomTransports, PayloadContext};

use crate::abi::{
    self, ABI_VERSION, DESCRIPTOR_V1_SIZE, DescriptorHeader, ENTRY_POINT, ENTRY_POINT_SYMBOL,
    EntryPointV1, FIELDS_COMPLETE, FieldsV1, MATCHED, MatchesV1, PluginDescriptorV1,
};

/// Most ports a plugin may declare: one per port number.
const MAX_PORTS: usize = 1 << 16;

/// Why [`load_parser`] refused a library.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PluginLoadError {
    /// The dynamic loader could not open the file.
    #[error("impossible d'ouvrir {path:?} : {source}")]
    Open {
        /// The file.
        path: PathBuf,
        /// The error of the loader.
        source: libloading::Error,
    },
    /// The library does not export [`ENTRY_POINT`]: it is not a plugin.
    #[error("{path:?} n'exporte pas {ENTRY_POINT} : ce n'est pas un plugin packet_parser")]
    MissingEntryPoint {
        /// The file.
        path: PathBuf,
        /// The error of the loader.
        source: libloading::Error,
    },
    /// The entry point returned null: the constructor of the parser
    /// panicked.
    #[error("le plugin n'a pas construit son parseur")]
    InitFailed,
    /// The plugin speaks another version of the ABI.
    #[error("version d'ABI {found}, ce chargeur lit la {expected}")]
    AbiVersion {
        /// The version of the plugin.
        found: u32,
        /// [`ABI_VERSION`].
        expected: u32,
    },
    /// The descriptor is smaller than its version requires.
    #[error("descripteur de {size} octets, {expected} attendus")]
    DescriptorTooSmall {
        /// The size the plugin declared.
        size: u32,
        /// The size of version 1.
        expected: u32,
    },
    /// The label is null, empty, longer than `MAX_LABEL_LENGTH` bytes, or
    /// not UTF-8.
    #[error("etiquette du plugin invalide")]
    InvalidLabel,
    /// The transport mask is empty or has an unknown bit.
    #[error("masque de transports invalide : {mask:#04x}")]
    InvalidTransports {
        /// The mask.
        mask: u8,
    },
    /// The list of ports is null while not empty, or too long.
    #[error("liste de ports invalide ({len} ports)")]
    InvalidPorts {
        /// The number of ports declared.
        len: usize,
    },
}

/// A parser loaded from a plugin.
struct LoadedParser {
    label: &'static str,
    transports: CustomTransports,
    ports: Vec<u16>,
    matches: MatchesV1,
    fields: FieldsV1,
}

impl LoadedParser {
    /// Reads and checks a descriptor, and copies what it declares.
    ///
    /// # Safety
    ///
    /// `descriptor` is null, or points to at least a [`DescriptorHeader`];
    /// when that header reads version 1 and a size large enough, to a whole
    /// [`PluginDescriptorV1`], whose pointers are valid as declared and
    /// whose functions follow their contract for as long as the parser
    /// lives.
    unsafe fn from_descriptor(
        descriptor: *const PluginDescriptorV1,
    ) -> Result<Self, PluginLoadError> {
        // SAFETY: null, or a header at least (contract of the function).
        let Some(header) = (unsafe { descriptor.cast::<DescriptorHeader>().as_ref() }) else {
            return Err(PluginLoadError::InitFailed);
        };
        if header.abi_version != ABI_VERSION {
            return Err(PluginLoadError::AbiVersion {
                found: header.abi_version,
                expected: ABI_VERSION,
            });
        }
        if header.size < DESCRIPTOR_V1_SIZE {
            return Err(PluginLoadError::DescriptorTooSmall {
                size: header.size,
                expected: DESCRIPTOR_V1_SIZE,
            });
        }
        // SAFETY: version 1 and its size: a whole descriptor.
        let descriptor = unsafe { &*descriptor };

        if descriptor.label.is_null()
            || descriptor.label_len == 0
            || descriptor.label_len > MAX_LABEL_LENGTH
        {
            return Err(PluginLoadError::InvalidLabel);
        }
        // SAFETY: a non-null label of `label_len` bytes (contract).
        let label = unsafe { abi::bytes(descriptor.label, descriptor.label_len) };
        let label = std::str::from_utf8(label).map_err(|_| PluginLoadError::InvalidLabel)?;

        let transports = abi::transports_from_abi(descriptor.transports).ok_or(
            PluginLoadError::InvalidTransports {
                mask: descriptor.transports,
            },
        )?;

        let len = descriptor.ports_len;
        if len > MAX_PORTS || (len > 0 && descriptor.ports.is_null()) {
            return Err(PluginLoadError::InvalidPorts { len });
        }
        let ports = if len == 0 {
            Vec::new()
        } else {
            // SAFETY: a non-null list of `len` ports (contract).
            unsafe { std::slice::from_raw_parts(descriptor.ports, len) }.to_vec()
        };

        Ok(Self {
            // L'etiquette est copiee hors du plugin : les
            // `ApplicationProtocol::Custom` qui la portent ne dependent pas
            // de sa memoire. Une fuite voulue, une fois par chargement.
            label: Box::leak(label.into()),
            transports,
            ports,
            matches: descriptor.matches,
            fields: descriptor.fields,
        })
    }
}

impl ApplicationParser for LoadedParser {
    fn label(&self) -> &'static str {
        self.label
    }

    fn transports(&self) -> CustomTransports {
        self.transports
    }

    fn ports(&self) -> &[u16] {
        &self.ports
    }

    fn matches(&self, payload: &[u8], context: &PayloadContext) -> bool {
        let Some(context) = abi::context_to_abi(context) else {
            return false;
        };
        // SAFETY: the payload and the context are valid for the call, and
        // the plugin follows the contract of `MatchesV1` (checked at load).
        unsafe { (self.matches)(payload.as_ptr(), payload.len(), &raw const context) == MATCHED }
    }

    fn fields(&self, payload: &[u8], context: &PayloadContext) -> Vec<(String, String)> {
        let Some(context) = abi::context_to_abi(context) else {
            return Vec::new();
        };
        let mut fields: Vec<(String, String)> = Vec::new();
        // SAFETY: as in `matches`; `sink` is `fields`, which `emit_field`
        // casts back, during the call only.
        let status = unsafe {
            (self.fields)(
                payload.as_ptr(),
                payload.len(),
                &raw const context,
                (&raw mut fields).cast::<c_void>(),
                emit_field,
            )
        };
        if status == FIELDS_COMPLETE {
            fields
        } else {
            Vec::new()
        }
    }
}

/// The `EmitFieldV1` of the host: appends one field to the `Vec` in `sink`.
/// Bytes that are not UTF-8 are replaced, never refused.
///
/// # Safety
///
/// `sink` is the `Vec` that [`LoadedParser::fields`] passed, and the two
/// strings are `len` readable bytes, or null.
unsafe extern "C" fn emit_field(
    sink: *mut c_void,
    name: *const u8,
    name_len: usize,
    value: *const u8,
    value_len: usize,
) {
    // SAFETY: `sink` is the `Vec` of `fields`, borrowed for the call.
    let Some(fields) = (unsafe { sink.cast::<Vec<(String, String)>>().as_mut() }) else {
        return;
    };
    // SAFETY: readable bytes, or null (contract of `EmitFieldV1`).
    let (name, value) = unsafe { (abi::bytes(name, name_len), abi::bytes(value, value_len)) };
    fields.push((
        String::from_utf8_lossy(name).into_owned(),
        String::from_utf8_lossy(value).into_owned(),
    ));
}

/// Loads the parser of a plugin: a native library (`.so`, `.dylib` or
/// `.dll`) built with [`export_parser!`](crate::export_parser).
///
/// The loader checks the entry point, the version of the ABI, the size of
/// the descriptor, the label (UTF-8, at most `MAX_LABEL_LENGTH` bytes), the
/// transports and the ports. The rules of the label itself are checked on
/// registration, by `ParseConfig::add_parser`.
///
/// The library is never unloaded: it stays mapped until the process exits.
/// Unloading Rust code is not reliable (thread-local destructors, statics),
/// and a host loads a plugin once.
///
/// # Safety
///
/// Loading a library runs its code, with every right of the process: its
/// initializers on loading, its parser on every payload it is given. The
/// kit checks the shape of what the plugin declares, not what its code
/// does. Load only a file you trust, whose origin you checked (a signature,
/// a known digest), and that was built with `export_parser!`.
///
/// # Errors
///
/// [`PluginLoadError`]: the file cannot be opened, is not a plugin, speaks
/// another version of the ABI, or declares an invalid label, transport
/// mask or list of ports.
pub unsafe fn load_parser(
    path: impl AsRef<Path>,
) -> Result<Arc<dyn ApplicationParser>, PluginLoadError> {
    let path = path.as_ref();
    // SAFETY: the caller trusts the library (contract of this function).
    let library =
        unsafe { libloading::Library::new(path) }.map_err(|source| PluginLoadError::Open {
            path: path.to_path_buf(),
            source,
        })?;
    // SAFETY: the symbol is the entry point of ABI 1, of this type.
    let entry: EntryPointV1 = match unsafe { library.get::<EntryPointV1>(ENTRY_POINT_SYMBOL) } {
        Ok(entry) => *entry,
        Err(source) => {
            return Err(PluginLoadError::MissingEntryPoint {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    // Une fois son code lance, la bibliotheque n'est plus dechargee, meme
    // si elle est refusee ensuite.
    std::mem::forget(library);
    // SAFETY: a plugin built with `export_parser!` returns its descriptor,
    // valid while the library is loaded, that is forever.
    let parser = unsafe { LoadedParser::from_descriptor(entry()) }?;
    Ok(Arc::new(parser))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abi::{PayloadContextV1, TRANSPORT_TCP, TRANSPORT_UDP};
    use packet_parser::TransportProtocol;

    /// Un parseur de test, exporte dans ce binaire comme dans un plugin :
    /// `BOOM` le fait paniquer, dans `matches` et dans `fields`.
    struct Fragile;

    impl ApplicationParser for Fragile {
        fn label(&self) -> &'static str {
            "FRAGILE"
        }
        fn transports(&self) -> CustomTransports {
            CustomTransports::Udp
        }
        fn ports(&self) -> &[u16] {
            &[47_000, 47_001]
        }
        fn matches(&self, payload: &[u8], context: &PayloadContext) -> bool {
            assert!(!payload.starts_with(b"BOOM"), "panique voulue");
            payload.starts_with(b"FR") && context.has_port(47_000)
        }
        fn fields(&self, payload: &[u8], context: &PayloadContext) -> Vec<(String, String)> {
            assert!(!payload.starts_with(b"BOOM"), "panique voulue");
            vec![
                ("length".into(), payload.len().to_string()),
                ("source".into(), format!("{:?}", context.source_port)),
            ]
        }
    }

    crate::export_parser!(Fragile);

    fn loaded() -> LoadedParser {
        // SAFETY: the descriptor of `export_parser!`, in this binary.
        unsafe { LoadedParser::from_descriptor(packet_parser_plugin_v1()) }.expect("valide")
    }

    fn udp(source: Option<u16>) -> PayloadContext {
        PayloadContext::new(TransportProtocol::Udp, source, Some(47_000))
    }

    #[test]
    fn the_descriptor_carries_the_parser_across_the_abi() {
        let parser = loaded();
        assert_eq!(parser.label(), "FRAGILE");
        assert_eq!(parser.transports(), CustomTransports::Udp);
        assert_eq!(parser.ports(), [47_000, 47_001]);
        assert!(parser.matches(b"FR\x01", &udp(Some(1_024))));
        assert!(!parser.matches(b"XX\x01", &udp(Some(1_024))));
        assert_eq!(
            parser.fields(b"FR\x01", &udp(None)),
            [
                ("length".to_string(), "3".to_string()),
                ("source".to_string(), "None".to_string())
            ]
        );
        assert_eq!(
            parser.fields(b"FR", &udp(Some(9))),
            [
                ("length".to_string(), "2".to_string()),
                ("source".to_string(), "Some(9)".to_string())
            ]
        );
    }

    #[test]
    fn a_panic_of_the_parser_stops_at_the_boundary() {
        let parser = loaded();
        assert!(!parser.matches(b"BOOM", &udp(Some(1_024))));
        assert!(parser.fields(b"BOOM", &udp(Some(1_024))).is_empty());
        // Le parseur sert encore apres.
        assert!(parser.matches(b"FR", &udp(Some(1_024))));
    }

    #[test]
    fn the_context_round_trips_through_c() {
        for context in [
            PayloadContext::new(TransportProtocol::Tcp, None, None),
            PayloadContext::new(TransportProtocol::Udp, Some(0), None),
            PayloadContext::new(TransportProtocol::Udp, None, Some(65_535)),
            PayloadContext::new(TransportProtocol::Tcp, Some(1), Some(2)),
        ] {
            let c = abi::context_to_abi(&context).expect("TCP ou UDP");
            assert_eq!(abi::context_from_abi(&c), Some(context));
        }
        let icmp = PayloadContext::new(TransportProtocol::Icmp, None, None);
        assert_eq!(abi::context_to_abi(&icmp), None);
        let unknown = PayloadContextV1 {
            transport: 1,
            known_ports: 0,
            source_port: 0,
            destination_port: 0,
        };
        assert_eq!(abi::context_from_abi(&unknown), None);
        for transports in [
            CustomTransports::Tcp,
            CustomTransports::Udp,
            CustomTransports::TcpAndUdp,
        ] {
            let mask = abi::transports_to_abi(transports);
            assert_eq!(abi::transports_from_abi(mask), Some(transports));
        }
        assert_eq!(abi::transports_from_abi(0), None);
        assert_eq!(abi::transports_from_abi(TRANSPORT_TCP | 0b100), None);
    }

    unsafe extern "C" fn never(_: *const u8, _: usize, _: *const PayloadContextV1) -> u8 {
        0
    }

    unsafe extern "C" fn no_fields(
        _: *const u8,
        _: usize,
        _: *const PayloadContextV1,
        _: *mut c_void,
        _: abi::EmitFieldV1,
    ) -> u8 {
        FIELDS_COMPLETE
    }

    fn descriptor(label: &'static [u8]) -> PluginDescriptorV1 {
        PluginDescriptorV1 {
            abi_version: ABI_VERSION,
            size: DESCRIPTOR_V1_SIZE,
            label: label.as_ptr(),
            label_len: label.len(),
            transports: TRANSPORT_UDP,
            ports: std::ptr::null(),
            ports_len: 0,
            matches: never,
            fields: no_fields,
        }
    }

    fn refusal(descriptor: &PluginDescriptorV1) -> PluginLoadError {
        // SAFETY: a whole descriptor, whose pointers are valid as declared
        // or null.
        match unsafe { LoadedParser::from_descriptor(descriptor) } {
            Ok(parser) => panic!("accepte : {}", parser.label),
            Err(error) => error,
        }
    }

    #[test]
    fn the_loader_refuses_what_it_cannot_trust() {
        assert!(matches!(
            // SAFETY: null is accepted, and refused.
            unsafe { LoadedParser::from_descriptor(std::ptr::null()) },
            Err(PluginLoadError::InitFailed)
        ));
        // Une version inconnue : seul l'en-tete est lu.
        let header = DescriptorHeader {
            abi_version: 2,
            size: 8,
        };
        assert!(matches!(
            // SAFETY: a header, whose version stops the reading.
            unsafe { LoadedParser::from_descriptor((&raw const header).cast()) },
            Err(PluginLoadError::AbiVersion {
                found: 2,
                expected: 1
            })
        ));
        let small = DescriptorHeader {
            abi_version: 1,
            size: 8,
        };
        assert!(matches!(
            // SAFETY: a header, whose size stops the reading.
            unsafe { LoadedParser::from_descriptor((&raw const small).cast()) },
            Err(PluginLoadError::DescriptorTooSmall { size: 8, .. })
        ));

        assert!(matches!(
            refusal(&descriptor(b"")),
            PluginLoadError::InvalidLabel
        ));
        assert!(matches!(
            refusal(&descriptor(b"\xff\xfe")),
            PluginLoadError::InvalidLabel
        ));
        let long = [b'L'; MAX_LABEL_LENGTH + 1];
        assert!(matches!(
            refusal(&descriptor(Box::leak(Box::new(long)))),
            PluginLoadError::InvalidLabel
        ));
        let null_label = PluginDescriptorV1 {
            label: std::ptr::null(),
            ..descriptor(b"OK")
        };
        assert!(matches!(
            refusal(&null_label),
            PluginLoadError::InvalidLabel
        ));
        for mask in [0, 0b100, 0xff] {
            let bad = PluginDescriptorV1 {
                transports: mask,
                ..descriptor(b"OK")
            };
            assert!(matches!(
                refusal(&bad),
                PluginLoadError::InvalidTransports { mask: found } if found == mask
            ));
        }
        let null_ports = PluginDescriptorV1 {
            ports_len: 2,
            ..descriptor(b"OK")
        };
        assert!(matches!(
            refusal(&null_ports),
            PluginLoadError::InvalidPorts { len: 2 }
        ));
        let both = PluginDescriptorV1 {
            transports: TRANSPORT_TCP | TRANSPORT_UDP,
            ..descriptor(b"OK")
        };
        // SAFETY: a whole descriptor.
        let parser = unsafe { LoadedParser::from_descriptor(&both) }.expect("valide");
        assert_eq!(parser.transports(), CustomTransports::TcpAndUdp);
    }
}
