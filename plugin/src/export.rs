// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! The plugin side: what [`export_parser!`](crate::export_parser) expands
//! to. Not meant to be called by hand.

use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::OnceLock;

use packet_parser::ApplicationParser;

use crate::abi::{
    self, ABI_VERSION, DESCRIPTOR_V1_SIZE, EmitFieldV1, FIELDS_COMPLETE, FieldsV1, MATCHED,
    MatchesV1, PayloadContextV1, PluginDescriptorV1,
};

/// The parser of a plugin and the descriptor that points into it.
pub struct Exported {
    parser: Box<dyn ApplicationParser>,
    // Le descripteur pointe dans `ports` et dans l'etiquette, qui ne bougent
    // plus : `Exported` vit dans un `OnceLock` statique.
    _ports: Box<[u16]>,
    descriptor: PluginDescriptorV1,
}

// SAFETY: the raw pointers of the descriptor point to the label, a
// `&'static str`, and to `_ports`, which `Exported` owns and never changes.
// The parser itself is `Send + Sync`.
unsafe impl Send for Exported {}
// SAFETY: see `Send`; nothing is ever written through those pointers.
unsafe impl Sync for Exported {}

impl Exported {
    fn new(parser: Box<dyn ApplicationParser>, matches: MatchesV1, fields: FieldsV1) -> Self {
        let label = parser.label();
        let ports: Box<[u16]> = parser.ports().into();
        let descriptor = PluginDescriptorV1 {
            abi_version: ABI_VERSION,
            size: DESCRIPTOR_V1_SIZE,
            label: label.as_ptr(),
            label_len: label.len(),
            transports: abi::transports_to_abi(parser.transports()),
            ports: if ports.is_empty() {
                std::ptr::null()
            } else {
                ports.as_ptr()
            },
            ports_len: ports.len(),
            matches,
            fields,
        };
        Self {
            parser,
            _ports: ports,
            descriptor,
        }
    }

    /// `MatchesV1`, on this parser. A panic of the parser is a refusal.
    ///
    /// # Safety
    ///
    /// The contract of [`MatchesV1`](crate::abi::MatchesV1).
    pub unsafe fn matches(
        &self,
        payload: *const u8,
        payload_len: usize,
        context: *const PayloadContextV1,
    ) -> u8 {
        // SAFETY: the host passes a valid context, or null, for the call.
        let Some(context) = unsafe { context.as_ref() }.and_then(abi::context_from_abi) else {
            return 0;
        };
        // SAFETY: the host passes `payload_len` bytes valid for the call.
        let payload = unsafe { abi::bytes(payload, payload_len) };
        match catch_unwind(AssertUnwindSafe(|| self.parser.matches(payload, &context))) {
            Ok(true) => MATCHED,
            Ok(false) | Err(_) => 0,
        }
    }

    /// `FieldsV1`, on this parser. A panic of the parser emits nothing.
    ///
    /// # Safety
    ///
    /// The contract of [`FieldsV1`](crate::abi::FieldsV1).
    pub unsafe fn fields(
        &self,
        payload: *const u8,
        payload_len: usize,
        context: *const PayloadContextV1,
        sink: *mut c_void,
        emit: EmitFieldV1,
    ) -> u8 {
        // SAFETY: as in `matches`.
        let Some(context) = unsafe { context.as_ref() }.and_then(abi::context_from_abi) else {
            return 0;
        };
        // SAFETY: as in `matches`.
        let payload = unsafe { abi::bytes(payload, payload_len) };
        let Ok(fields) = catch_unwind(AssertUnwindSafe(|| self.parser.fields(payload, &context)))
        else {
            return 0;
        };
        for (name, value) in &fields {
            // SAFETY: `emit` and `sink` come from the host, which gave them
            // together; the strings outlive the call.
            unsafe { emit(sink, name.as_ptr(), name.len(), value.as_ptr(), value.len()) };
        }
        FIELDS_COMPLETE
    }
}

/// The body of the entry point: builds the parser once, and returns the
/// descriptor, or null when the constructor panicked.
#[doc(hidden)]
pub fn entry<P: ApplicationParser + 'static>(
    cell: &'static OnceLock<Option<Exported>>,
    init: fn() -> P,
    matches: MatchesV1,
    fields: FieldsV1,
) -> *const PluginDescriptorV1 {
    cell.get_or_init(|| catch_unwind(|| Exported::new(Box::new(init()), matches, fields)).ok())
        .as_ref()
        .map_or(std::ptr::null(), |exported| &raw const exported.descriptor)
}

/// Exports an [`ApplicationParser`] from a native library, for
/// [`load_parser`](crate::load_parser).
///
/// The library is a crate of type `cdylib`; this macro is called once, at
/// its root, with an expression that builds the parser. It defines the
/// entry point [`ENTRY_POINT`](crate::abi::ENTRY_POINT), which builds the
/// parser on its first call.
///
/// A panic of the parser, in its constructor, in `matches` or in `fields`,
/// is caught at the boundary: the plugin is refused, the payload is not
/// recognized, or it has no fields. The library must therefore be built with
/// `panic = "unwind"`, the default of Cargo profiles: with `panic =
/// "abort"`, a panic ends the host process.
///
/// ```ignore
/// use packet_parser_plugin::{ApplicationParser, PayloadContext, export_parser};
///
/// struct Acme;
///
/// impl ApplicationParser for Acme {
///     fn label(&self) -> &'static str {
///         "ACME"
///     }
///     fn matches(&self, payload: &[u8], _context: &PayloadContext) -> bool {
///         payload.starts_with(b"ACME")
///     }
/// }
///
/// export_parser!(Acme);
/// ```
#[macro_export]
macro_rules! export_parser {
    ($parser:expr $(,)?) => {
        static __PACKET_PARSER_PLUGIN: ::std::sync::OnceLock<
            ::core::option::Option<$crate::export::Exported>,
        > = ::std::sync::OnceLock::new();

        unsafe extern "C" fn __packet_parser_plugin_matches(
            payload: *const u8,
            payload_len: usize,
            context: *const $crate::abi::PayloadContextV1,
        ) -> u8 {
            match __PACKET_PARSER_PLUGIN.get() {
                // SAFETY: the host follows the contract of `MatchesV1`.
                ::core::option::Option::Some(::core::option::Option::Some(exported)) => unsafe {
                    exported.matches(payload, payload_len, context)
                },
                _ => 0,
            }
        }

        unsafe extern "C" fn __packet_parser_plugin_fields(
            payload: *const u8,
            payload_len: usize,
            context: *const $crate::abi::PayloadContextV1,
            sink: *mut ::core::ffi::c_void,
            emit: $crate::abi::EmitFieldV1,
        ) -> u8 {
            match __PACKET_PARSER_PLUGIN.get() {
                // SAFETY: the host follows the contract of `FieldsV1`.
                ::core::option::Option::Some(::core::option::Option::Some(exported)) => unsafe {
                    exported.fields(payload, payload_len, context, sink, emit)
                },
                _ => 0,
            }
        }

        /// The entry point of this plugin (`packet_parser_plugin` ABI 1).
        #[unsafe(no_mangle)]
        pub extern "C" fn packet_parser_plugin_v1() -> *const $crate::abi::PluginDescriptorV1 {
            $crate::export::entry(
                &__PACKET_PARSER_PLUGIN,
                || $parser,
                __packet_parser_plugin_matches,
                __packet_parser_plugin_fields,
            )
        }
    };
}
