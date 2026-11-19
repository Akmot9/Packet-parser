# Rule files

A rule file names a protocol that `packet_parser` does not decode, such as a
proprietary format or a protocol that cannot be published, from the bytes
that recognize it, and describes the fields to show (issue #325). It is a
TOML file read at run time, behind the `rules` feature.

A rule file runs no code. It cannot use the network, read a file, or crash
the application, and what a reviewer reads is exactly what runs. That is
the difference with a native plugin ([docs/plugins.md](plugins.md)), which
has every right of the process. An application that must show it is
passive and verifiable can load rules where it cannot load a plugin.

Rules have the guarantees of every parser added to the crate (#319):

- they run **after** the built-in table, only on a non-empty TCP or UDP
  payload the table left `Unknown`, at every flow level, tunnels included;
- they **never take a payload from the crate**: an SSH banner stays `SSH`;
- their label cannot be the label of a built-in protocol.

## Enabling it

```toml
[dependencies]
packet_parser = { version = "13.1", features = ["rules"] }
```

The feature arrived in 13.1.0. Without it, the crate has no dependency on
`toml`.

## Loading rules

```rust
use packet_parser::{LinkType, ParseConfig, RuleSet, parse_with};

let text = std::fs::read_to_string("site-rules.toml")?;
let rules = RuleSet::from_toml(&text)?;          // checks the whole file
let config = ParseConfig::new().with_rules(&rules)?;

let flow = parse_with(LinkType::ETHERNET, &frame, &config)?;
if let Some(fields) = config.custom_fields(&flow) {
    for (name, value) in fields {
        println!("{name}: {value}");
    }
}
```

- `RuleSet::from_toml` refuses a file at its first mistake. Its
  `RulesError` gives the line, the column and the reason; for an unknown
  key on line 12, its message starts with `ligne 12, colonne 1 : `.
- `add_rules` and `with_rules` add every label of the file, or none. They
  refuse a label that the configuration already has.
- A label stored as text, in an export or a flow matrix, reads back with
  `config.application_protocol(label)` (#323).

## The format, version 1

```toml
version = 1                        # required

# ACME is made up for this guide.
[[rule]]
label = "ACME"                     # required
transport = "udp"                  # "tcp", "udp" or "tcp+udp" (default)
ports = [47000]                    # optional; empty or absent: any port
min_length = 12                    # optional; default: end of the last pattern
max_length = 1500                  # optional; default: no limit

[[rule.pattern]]                   # at least one
offset = 0
bytes = "41 43 4D 45"              # hexadecimal, spaces allowed

[[rule.pattern]]
offset = 4
bytes = "01"
mask = "0F"                        # optional, same length as bytes

[[rule.field]]                     # optional
name = "type"
offset = 5
type = "u8"
values = { 1 = "request", 2 = "response", 0x7F = "error" }

[[rule.field]]
name = "id"
offset = 8
type = "hex"
length = 4
```

[`examples/acme_rules.toml`](../examples/acme_rules.toml) is a complete
file, with two made-up protocols.

### Recognizing a payload

A rule recognizes a payload when every condition holds:

1. the transport is one of `transport`;
2. the source or the destination port is in `ports`, when it is given;
3. the length is between `min_length` and `max_length`;
4. each pattern holds: for each byte `i`,
   `payload[offset + i] & mask[i] == bytes[i]`. Without `mask`, every bit
   counts.

Several rules with the same label are **variants** of one protocol, such
as a request and a response. The label goes to a payload that any of them
recognizes, and the fields are those of the first that does. The labels of
a file run in the order of their first rule, and the first label that
recognizes a payload names it.

### Fields

Fields are decoded only on demand, when the application shows a packet
with `custom_fields`: they cost nothing while parsing.

| `type` | Shown as | Keys |
| --- | --- | --- |
| `u8`, `u16be`, `u16le`, `u32be`, `u32le`, `u64be`, `u64le` | Unsigned integer, in decimal | Optional `mask`, `values` |
| `hex` | The bytes in hexadecimal: `41 43 4D 45` | `length` (required) |
| `text` | The bytes up to the first NUL: printable ASCII as is, `\` as `\\`, any other byte as `\xNN` | `length` (required) |

- `mask` on an integer keeps some bits and shifts them down. It is written
  in hexadecimal, most significant byte first, with as many bytes as the
  type: for a `u16be`, `mask = "0F F0"` turns `0x1234` into `0x23`.
- `values` names some values, keyed in decimal or in `0x` hexadecimal. A
  named value is shown as `request (1)`, any other as its number.
- A field that does not fit in the payload is not shown: nothing is made
  up.

## What is refused

The file is refused, with the line and the column of the mistake, when:

- it is not valid TOML, or has an unknown key: a typo such as `masq`
  would otherwise drop a condition without a word;
- `version` is missing, or is not `1`;
- a label is empty, longer than 64 bytes, has a control character or
  spaces around it, is the label of a built-in protocol, or differs from
  another label of the file only by case;
- a rule has no pattern;
- **the patterns of a rule check fewer than 16 bits in all**. A random
  payload would then match more than once in 65 536, and a busy network
  would show the label on traffic that is not the protocol. A rule on a
  port alone is therefore impossible: a port is a convention, not proof;
- the hexadecimal of `bytes` or `mask` is invalid, a `mask` has another
  length than its `bytes`, a byte has bits outside its mask (it could
  never match), or a mask is all zero;
- `min_length` ends before the last pattern, or `max_length` is below
  `min_length`;
- a field has an unknown `type`, a `length` it does not use or misses one
  it needs, a `mask` or `values` on a type that is not an integer, a value
  key that the field can never hold, a value named twice, or a name used
  by another field of the rule;
- a bound is exceeded:

| Bound | Value |
| --- | --- |
| `offset` of a pattern or a field | 65 535 |
| `bytes` of a pattern | 64 bytes |
| `length` of a `hex` or `text` field | 256 bytes |
| Rules in a file | 256 |
| `ports` of a rule | 256 |
| Fields of a rule | 64 |
| `values` of a field | 256 |
| Name of a field or a value | 64 bytes |

## What a rule cannot do

- Read a protocol carried by something other than TCP or UDP: the payload
  of a proprietary EtherType is out of reach.
- Follow a position read from the payload: a length, a TLV, a repeated
  structure. Positions are fixed.
- Reassemble a stream: on TCP, only the segment that starts a message is
  recognized, and the segments after it stay `Unknown`.
- Rename what the crate recognizes.

A protocol that needs any of these deserves a decoder in the crate.

## Cost

A rule is only tried on payloads the crate left `Unknown`, so a file costs
nothing on traffic the crate recognizes. On an `Unknown` payload, each
label costs about 10 ns: the length bounds and the most selective byte of
its patterns, kept in the rule itself, turn away almost every payload of
another protocol before the patterns are read. Measured on the 384 395
frames of the repository's corpus, 14 % of whose flows are `Unknown`, with
rules that match none of them:

| Labels | Cost per `Unknown` flow | Whole corpus |
| --- | --- | --- |
| 1 | 27 ns | +1.2 % |
| 5 | 58 ns | +2.4 % |
| 20 | 220 ns | +9.3 % |
| 50 | 460 ns | +18.6 % |

A rule with `ports` is turned away even sooner on other ports. Fields cost
nothing while parsing: they are decoded only when asked for.

## Trying a rule file

`examples/rules_check.rs` checks a rule file against captures:

```text
cargo run --release --features rules --example rules_check -- \
    site-rules.toml capture1.pcapng capture2.pcap --fields 3
```

It prints:
- every mistake of the file, with its line;
- for each label, the number of flows it names;
- the number of `Unknown` flows before and after the rules;
- with `--fields N`, the fields of the first N flows of each label.

It exits with an error if a flow the crate had named changed label, which
would be a defect of the crate.

## Confidential rules

The rules of a confidential protocol do not need to leave the machine they
are written on:

- the rule file is data that the application reads at start-up: it is not
  part of the crate, of the application's source, nor of its build;
- `rules_check` reads only the files given on its command line and writes
  only to the terminal: a rule file is tried on local captures without
  sending anything anywhere;
- keep the file out of public repositories. To report a problem with the
  feature, reproduce it with made-up bytes, as `acme_rules.toml` does.

Recording which rules produced a result is the application's job: it can
store the name and a digest of the file it loaded, so that anyone can
redo the same labels with the same file.

## When the crate learns the protocol

If a later version of the crate decodes a protocol under the label of one
of your rules, `RuleSet::from_toml` refuses the file: the label is now the
label of a built-in protocol. The crate's decoder then names the traffic:
remove the rule, or rename it if it describes something else.
