# Custom parsers and plugins

`packet_parser` names the protocols it decodes. For one it does not decode,
such as a proprietary format or an in-house protocol, an application adds its
own parser (issue #319). There are two ways:

- **In the application.** A type implements `ApplicationParser`, and the
  application registers it with `ParseConfig::with_parser`. Nothing else is
  needed.
- **In a plugin.** The same type lives in its own native library, a `.so`
  on Linux, `.dylib` on macOS or `.dll` on Windows, built apart. An
  application that is already compiled loads it at run time, for instance
  behind an "Import parsers" button. The `packet_parser_plugin` kit, in the
  [`plugin/`](../plugin) folder, writes and reads such libraries.

A `.rs` file cannot be loaded as it is: Rust is compiled. A plugin is the
compiled form of that file.

When byte patterns at fixed offsets recognize the protocol, a **rule
file** is a third way, without code: a TOML file that the application
reads at run time, behind the `rules` feature ([docs/rules.md](rules.md)).
It cannot do more than recognize and show fields, and that is its point:
an application that must show it is passive and verifiable can load rules,
where it cannot load native code.

## What an added parser can do

An added parser runs **after** the built-in table, and only on a payload the
table left `Unknown`:

- a non-empty TCP or UDP payload;
- of a flow at any level, the inner flows of a tunnel included;
- with the transports and ports the parser declares.

It never takes a payload from the crate: an SSH banner stays `SSH` even if
every parser accepts it. The parsers run in the order they were registered,
and the first one that accepts the payload names the flow
`ApplicationProtocol::Custom(label)`. The JSON output writes that label like
any other: `"application_protocol": "ACME"`.

Its fields are not decoded during parsing. An application asks for them when
it shows one packet, with `ParseConfig::custom_fields(&flow)`.

What an added parser cannot do: read a protocol carried by something other
than TCP or UDP, reassemble a stream, rename a protocol the crate already
recognizes, or see the flows the table names.

## The parser

```rust
use packet_parser::{ApplicationParser, CustomTransports, PayloadContext};

/// ACME is made up for this guide: datagrams that start with `ACME`.
struct Acme;

impl ApplicationParser for Acme {
    /// Written in the JSON output and in `ApplicationProtocol::Custom`.
    fn label(&self) -> &'static str {
        "ACME"
    }

    /// TCP and UDP by default.
    fn transports(&self) -> CustomTransports {
        CustomTransports::Udp
    }

    /// Any port by default. With a list, the parser is only called when the
    /// source or the destination port is in it.
    fn ports(&self) -> &[u16] {
        &[47_000]
    }

    fn matches(&self, payload: &[u8], _context: &PayloadContext) -> bool {
        payload.starts_with(b"ACME")
    }

    /// Name and value, in display order. Empty by default.
    fn fields(&self, payload: &[u8], _context: &PayloadContext) -> Vec<(String, String)> {
        vec![("length".to_string(), payload.len().to_string())]
    }
}
```

Rules for the parser:

- `matches` is called on many payloads: it must be fast, and it must
  decide from the bytes and the context alone. No file, no network, no
  clock, no global state.
- It must not panic. A panic in a plugin is caught at the boundary, and the
  payload is not recognized, but a parser registered directly in the
  application has no such net.
- A signature too weak to stand alone should come with a port list: two
  magic bytes match a random payload often.

The label is checked on registration. It is refused when it is empty,
longer than 64 bytes, has a control character or spaces around it, is the
label of a built-in protocol, or is already registered. The last two
comparisons ignore ASCII case: `"dns"` is refused because of `"DNS"`.

## Registering it in the application

```rust
use std::sync::Arc;

use packet_parser::{LinkType, ParseConfig, parse_with};

let config = ParseConfig::new().with_parser(Arc::new(Acme))?;
let flow = parse_with(LinkType::ETHERNET, &frame, &config)?;
if let Some(fields) = config.custom_fields(&flow) {
    for (name, value) in fields {
        println!("{name}: {value}");
    }
}
```

`add_parser(&mut self, ..)` does the same on an existing configuration and
leaves it unchanged on a refusal. `remove_parser(label)` removes a parser,
`parser(label)` returns it, and `parser_labels()` lists them in the order
they run. `classify_payload_with` goes through the same parsers.

### Reading a stored label back

An application that stores its labels as text, in an export or a flow
matrix, reads them back with `config.application_protocol(label)`. It gives
`ApplicationProtocol::Custom` for the parsers of `config`, and the answer of
`str::parse` for the built-in protocols. `str::parse` alone refuses a custom
label: it knows only the protocols of the crate, not the parsers of a
configuration. The comparison is exact, case included, and a parser that
was removed or never registered is an `UnknownApplicationLabel` error:
the application decides whether to keep the text or to report the missing
parser (#323).

## Writing a plugin

A plugin is a crate of type `cdylib` that calls `export_parser!` once:

```toml
[package]
name = "acme"
version = "0.1.0"
edition = "2024"

[lib]
crate-type = ["cdylib"]

[dependencies]
packet_parser_plugin = { git = "https://github.com/Akmot9/Packet-parser" }
```

```rust
// src/lib.rs
use packet_parser_plugin::{ApplicationParser, CustomTransports, PayloadContext, export_parser};

struct Acme;

impl ApplicationParser for Acme {
    // ... as above
}

export_parser!(Acme);
```

The kit is not published on crates.io yet: the dependency goes through git,
or a path to a checkout. `cargo build --release` then gives:

| System | File |
| --- | --- |
| Linux | `target/release/libacme.so` |
| macOS | `target/release/libacme.dylib` |
| Windows | `target/release/acme.dll` |

A library runs on one operating system and one architecture: build one per
target the application ships to. The plugin and the application do not need
the same version of rustc nor of `packet_parser`, since they only exchange
C types.

Keep `panic = "unwind"`, the default of Cargo profiles. With `panic =
"abort"` in the plugin's profile, a panic of the parser ends the
application.

[`plugin/examples/demo_parser.rs`](../plugin/examples/demo_parser.rs) is a
complete plugin, for a toy protocol with a header, a length and fields.

## Loading a plugin

```rust
use packet_parser::ParseConfig;
use packet_parser_plugin::load_parser;

// SAFETY: a library whose origin was checked, see below.
let parser = unsafe { load_parser(&path) }?;
let label = parser.label();
config.add_parser(parser)?;
```

`load_parser` checks what the library declares: the entry point, the
version of the ABI, the size of the descriptor, the label (UTF-8, at most 64
bytes), the transports and the ports. The rules of the label itself are
those of `add_parser`.

[`plugin/examples/plugin_host.rs`](../plugin/examples/plugin_host.rs) loads
plugins and counts the labels of a capture, on the local machine:

```text
cd plugin
cargo build --example demo_parser
cargo run --example plugin_host -- --fields capture.pcapng target/debug/examples/libdemo_parser.so
```

### For an "Import parsers" button

- Copy the imported file into a folder of the application, under a name that
  changes with each version (`acme-0.2.0.so`), and load it from there.
- A library is never unloaded: it stays mapped until the process exits.
  Unloading Rust code is not reliable (thread-local destructors, statics).
  `remove_parser` stops using a parser, but its code stays in memory. The
  loader of the system also returns the library already loaded for a path
  it has seen: a new version under the same name is only read after a
  restart.
- Keep one `ParseConfig`, add each parser to it, and pass it to every
  `parse_with`. Show its labels with `parser_labels()`, and a packet's
  fields with `custom_fields`.
- Show the refusals: `PluginLoadError` (not a plugin, another version of
  the ABI, invalid declaration) and `ParserRegistrationError` (label taken
  or invalid) have readable messages.

## Security

A plugin is native code: it is not a sandbox. Once loaded, it runs with
every right of the application. It can read its memory and its files, use
the network, and crash it by a fault other than a panic. This is why
`load_parser` is `unsafe`: the kit checks the shape of what the plugin
declares, not what its code does.

Load only a library whose origin you checked: built by yourself, or signed
by someone you trust, with the signature or a known digest verified before
loading. A file picked by a user from anywhere is a way to run any code in
the application.

## The ABI

The plugin exports one function, `packet_parser_plugin_v1`, which returns a
pointer to a `PluginDescriptorV1`: version (1), size, label, transports,
ports, and two C functions, `matches` and `fields`. The types are in
`packet_parser_plugin::abi`. `export_parser!` writes the plugin side and
`load_parser` reads it: neither the author of a parser nor the application
handles them.

Version 1 never changes. A change to any of these types is a new version,
with a new descriptor and a new entry point; the loader refuses a version it
does not know, after reading only the first two fields.
