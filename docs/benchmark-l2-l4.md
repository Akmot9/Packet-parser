# L2-L4 benchmark against etherparse and pnet_packet

> Measured on 23 November 2026, on `packet_parser` 13.4.0 (issue #375).

How fast is `packet_parser` from Ethernet to TCP, UDP and ICMP, next to the
two crates Rust programs usually pick for that job,
[`etherparse`](https://crates.io/crates/etherparse) and
[`pnet_packet`](https://crates.io/crates/pnet_packet)? This page gives the
numbers, how to redo them, and what they do not say.

## Reading the numbers

- **On frames with no payload, `parse` takes 94 to 115 ns.** That is the
  comparison on equal scope, since there is no layer 7 to read. It is 1.4
  to 1.6 times the cost of reading every header through the views of
  `etherparse` (65 to 79 ns), 2 to 2.8 times the cost of reading every field
  through `pnet_packet` (39 to 57 ns), and 2.4 to 7.7 times **faster** than
  `etherparse::PacketHeaders` (264 to 820 ns).
- **On whole captures, `parse` takes 190 to 470 ns**, because it then also
  names the application protocol and decodes its header, which the two other
  crates do not do. That figure is the price of the whole job, not of
  layers 2 to 4: the ratio to `pnet_packet` on these tables (5 to 13) compares
  two different jobs.
- **`packet_parser` has no slicing level.** A program that only needs to
  find the transport payload, and reads no field, pays 8 to 36 ns with the
  other two crates and 94 ns or more with `parse`.
- `etherparse::PacketHeaders` is slow for a reason that has nothing to do
  with parsing: the value it returns weighs 9,504 bytes (its IPv6 extension
  headers are stored inline), and it is written for every frame. Reading the
  same fields through `SlicedPacket` and `to_header` avoids it; both are
  measured.

## Method

- **Same frames, loaded in memory before the measure**: only decoding is
  timed, not reading the file.
- **Two levels**, so that like is compared with like:
  1. *slicing*: the headers are located and their lengths checked, the fields
     are not read;
  2. *full decode*: every field from Ethernet to layer 4 is read and stored
     in a value.
- **The three crates must read the same thing.** Before measuring, each
  function decodes each frame, and a frame is kept only if all six readings
  agree on the addresses, the layer-4 protocol, the ports (type and code for
  ICMP) and the payload length. A crate cannot win by doing less. The table
  "Frames measured" counts what is left out.
- **Captures**: only captures versioned in `pcaps_exemple/`, whose origin is
  in [`pcaps_exemple/SOURCE.md`](../pcaps_exemple/SOURCE.md): the 4SICS Geek
  Lounge capture (CS3Sthlm, via Netresec), The Ultimate PCAP (Johannes
  Weber), and the twelve captures of the crate's own bench (`subset`).
- **Each result is observed by reference** (`black_box(&value)`), so that no
  crate pays for moving its result.
- criterion, 100 samples of 5 s after 2 s of warm-up; the tables give the
  median and the median absolute deviation, per frame. The process is pinned
  to one core (`taskset -c 3`).

Run it again:

```text
taskset -c 3 cargo bench --manifest-path tools/compare/Cargo.toml
python3 tools/compare/report.py
```

`cargo run --release --manifest-path tools/compare/Cargo.toml --bin agreement -- -v`
lists the frames left out and what each crate read in them.

## Machine and versions

- CPU: Intel(R) Core(TM) i7-10875H CPU @ 2.30GHz, one core, governor `powersave`
- OS: Linux 6.8.0-59-generic
- Compiler: rustc 1.99.1 (58cf8f9c3 2026-10-13), profile `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`
- Crates: packet_parser 13.4.0 (this repository), etherparse 0.21.0, pnet_packet 0.35.0, criterion 0.8.2

## Frames measured

| Corpus | Frames read | Kept | Bytes | Not Ethernet | No layer 4 | Disagreement |
|---|---:|---:|---:|---:|---:|---:|
| `4sics` | 246,137 | 239,267 | 21,350,446 | 0 | 6,870 | 0 |
| `ultimate` | 51,328 | 25,174 | 7,670,424 | 11,771 | 7,702 | 6,681 |
| `subset` | 775 | 731 | 73,411 | 17 | 27 | 0 |

## Corpus `4sics`: 239,267 frames

| Crate | Call | Level | ns per frame | ± | M frames/s | Gbit/s | packet_parser = 1 |
|---|---|---|---:|---:|---:|---:|---:|
| etherparse | `SlicedPacket::from_ethernet` | slicing | 25.5 | 1.13 | 39.2 | 28.0 | 0.13 |
| pnet_packet | views, fields not read | slicing | 12.0 | 0.99 | 83.3 | 59.5 | 0.06 |
| etherparse | `PacketHeaders::from_ethernet_slice` | full decode, L2-L4 | 267.2 | 6.93 | 3.7 | 2.7 | 1.39 |
| etherparse | `SlicedPacket`, then `to_header` on each view | full decode, L2-L4 | 68.9 | 1.88 | 14.5 | 10.4 | 0.36 |
| pnet_packet | views, every accessor | full decode, L2-L4 | 42.3 | 1.02 | 23.6 | 16.9 | 0.22 |
| **packet_parser** | `parse` | full decode, L2-L7 | 192.8 | 2.62 | 5.2 | 3.7 | 1.00 |

The 90,914 TCP frames of this corpus that carry no payload:

| Crate | Call | Level | ns per frame | ± | M frames/s | packet_parser = 1 |
|---|---|---|---:|---:|---:|---:|
| etherparse | `SlicedPacket::from_ethernet` | slicing | 35.7 | 5.24 | 28.0 | 0.31 |
| pnet_packet | views, fields not read | slicing | 20.2 | 2.06 | 49.5 | 0.18 |
| etherparse | `PacketHeaders::from_ethernet_slice` | full decode, L2-L4 | 281.3 | 13.41 | 3.6 | 2.45 |
| etherparse | `SlicedPacket`, then `to_header` on each view | full decode, L2-L4 | 78.9 | 6.14 | 12.7 | 0.69 |
| pnet_packet | views, every accessor | full decode, L2-L4 | 56.5 | 6.49 | 17.7 | 0.49 |
| **packet_parser** | `parse` | full decode, L2-L7 | 114.7 | 6.90 | 8.7 | 1.00 |

## Corpus `ultimate`: 25,174 frames

| Crate | Call | Level | ns per frame | ± | M frames/s | Gbit/s | packet_parser = 1 |
|---|---|---|---:|---:|---:|---:|---:|
| etherparse | `SlicedPacket::from_ethernet` | slicing | 26.2 | 1.49 | 38.2 | 93.1 | 0.06 |
| pnet_packet | views, fields not read | slicing | 10.3 | 0.33 | 97.5 | 237.7 | 0.02 |
| etherparse | `PacketHeaders::from_ethernet_slice` | full decode, L2-L4 | 764.8 | 24.83 | 1.3 | 3.2 | 1.63 |
| etherparse | `SlicedPacket`, then `to_header` on each view | full decode, L2-L4 | 64.2 | 3.28 | 15.6 | 38.0 | 0.14 |
| pnet_packet | views, every accessor | full decode, L2-L4 | 37.1 | 1.32 | 26.9 | 65.6 | 0.08 |
| **packet_parser** | `parse` | full decode, L2-L7 | 470.2 | 22.14 | 2.1 | 5.2 | 1.00 |

The 5,935 TCP frames of this corpus that carry no payload:

| Crate | Call | Level | ns per frame | ± | M frames/s | packet_parser = 1 |
|---|---|---|---:|---:|---:|---:|
| etherparse | `SlicedPacket::from_ethernet` | slicing | 24.6 | 0.26 | 40.6 | 0.23 |
| pnet_packet | views, fields not read | slicing | 9.7 | 0.02 | 103.5 | 0.09 |
| etherparse | `PacketHeaders::from_ethernet_slice` | full decode, L2-L4 | 819.6 | 23.65 | 1.2 | 7.67 |
| etherparse | `SlicedPacket`, then `to_header` on each view | full decode, L2-L4 | 67.4 | 0.25 | 14.8 | 0.63 |
| pnet_packet | views, every accessor | full decode, L2-L4 | 38.8 | 0.12 | 25.8 | 0.36 |
| **packet_parser** | `parse` | full decode, L2-L7 | 106.9 | 0.65 | 9.4 | 1.00 |

## Corpus `subset`: 731 frames

| Crate | Call | Level | ns per frame | ± | M frames/s | Gbit/s | packet_parser = 1 |
|---|---|---|---:|---:|---:|---:|---:|
| etherparse | `SlicedPacket::from_ethernet` | slicing | 19.7 | 0.11 | 50.8 | 40.8 | 0.05 |
| pnet_packet | views, fields not read | slicing | 9.3 | 0.65 | 107.4 | 86.3 | 0.02 |
| etherparse | `PacketHeaders::from_ethernet_slice` | full decode, L2-L4 | 265.6 | 3.76 | 3.8 | 3.0 | 0.67 |
| etherparse | `SlicedPacket`, then `to_header` on each view | full decode, L2-L4 | 61.4 | 0.24 | 16.3 | 13.1 | 0.15 |
| pnet_packet | views, every accessor | full decode, L2-L4 | 31.5 | 0.53 | 31.8 | 25.5 | 0.08 |
| **packet_parser** | `parse` | full decode, L2-L7 | 396.5 | 4.22 | 2.5 | 2.0 | 1.00 |

The 167 TCP frames of this corpus that carry no payload:

| Crate | Call | Level | ns per frame | ± | M frames/s | packet_parser = 1 |
|---|---|---|---:|---:|---:|---:|
| etherparse | `SlicedPacket::from_ethernet` | slicing | 19.0 | 0.28 | 52.7 | 0.20 |
| pnet_packet | views, fields not read | slicing | 7.8 | 0.22 | 127.5 | 0.08 |
| etherparse | `PacketHeaders::from_ethernet_slice` | full decode, L2-L4 | 264.2 | 6.16 | 3.8 | 2.80 |
| etherparse | `SlicedPacket`, then `to_header` on each view | full decode, L2-L4 | 64.6 | 0.58 | 15.5 | 0.69 |
| pnet_packet | views, every accessor | full decode, L2-L4 | 39.0 | 0.43 | 25.6 | 0.41 |
| **packet_parser** | `parse` | full decode, L2-L7 | 94.2 | 1.44 | 10.6 | 1.00 |

## One frame per family

ns per frame.

| Frame | `slice_etherparse` | `slice_pnet` | `full_etherparse` | `full_etherparse_slices` | `full_pnet` | `full_packet_parser` |
|---|---:|---:|---:|---:|---:|---:|
| TCP over IPv4, no payload | 18.8 | 6.4 | 264.8 | 64.3 | 38.5 | 88.7 |
| TCP over IPv4, 1,000 bytes or more | 18.7 | 6.4 | 260.0 | 63.8 | 37.7 | 875.4 |
| UDP over IPv4, DNS | 18.2 | 6.3 | 249.5 | 49.1 | 31.2 | 358.2 |
| TCP over IPv6 | 25.1 | 6.7 | 1127.5 | 78.4 | 32.0 | 107.6 |
| ICMP | 18.1 | 5.7 | 260.5 | 54.5 | 30.4 | 85.4 |
| UDP under an 802.1Q tag | 25.1 | 7.3 | 1111.8 | 53.8 | 25.1 | 522.6 |

## What each crate does, and where the comparison stops

| | packet_parser | etherparse | pnet_packet |
|---|---|---|---|
| One call from Ethernet to layer 4 | yes | yes | no: one view per header, the walk is the caller's |
| Checks lengths | yes | yes | no: only the minimum size of each header |
| Slicing without reading fields | no | yes | yes |
| Application layer | yes | no | no |
| Tunnels (VXLAN, GRE, PPPoE...) | decoded, inner flow included | not followed | not followed |
| Reports a corrupted layer and keeps the layers before it | yes | error, or the `Lax` variants | no |

- **The `pnet_packet` walk is ours** ([`tools/compare/src/lib.rs`](../tools/compare/src/lib.rs)),
  since the crate has none. It does the checks without which it would read
  outside the frame, and no more. Someone else would write it differently.
- **Frames left out.** In `ultimate`, 6,680 frames are PPPoE under a VLAN tag,
  which only `packet_parser` goes through, and one frame has a zero IPv4
  total length (segmentation offload), which `packet_parser` reads and the
  two others refuse. Frames with no layer 4 for any crate (ARP, LLDP,
  Profinet, IP fragments) and frames of non-Ethernet interfaces are not
  measured either. All of this is work `packet_parser` does and the bench
  does not count.
- **In `subset` and `ultimate`, some frames are tunnels**: `parse` decodes
  the inner flow as well, the two others stop at the outer UDP header.
- **Checksums** are verified by none of the three.
- **One machine, a laptop**, with the `powersave` governor: the ratios hold
  better than the absolute figures. Slicing times of a few nanoseconds move
  by 10 to 20 % from one run to the next.
- The competing crates are dependencies of `tools/compare` only, never of
  `packet_parser`.
