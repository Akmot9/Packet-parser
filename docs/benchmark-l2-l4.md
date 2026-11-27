# L2-L4 benchmark against etherparse and pnet_packet

> Measured on 27 November 2026, on `packet_parser` 13.4.0 plus the
> performance review of #393, not yet released. First measured on
> 23 November 2026 on 13.4.0 as published (issue #375), on another machine:
> the figures of the two measures do not compare, the ratios do.

How fast is `packet_parser` from Ethernet to TCP, UDP and ICMP, next to the
two crates Rust programs usually pick for that job,
[`etherparse`](https://crates.io/crates/etherparse) and
[`pnet_packet`](https://crates.io/crates/pnet_packet)? This page gives the
numbers, how to redo them, and what they do not say.

## Reading the numbers

- **On frames with no payload, `parse` takes 35 to 58 ns.** That is the
  comparison on equal scope, since there is no layer 7 to read. It is 0.6
  to 0.9 times the cost of reading every header through the views of
  `etherparse` (59 to 68 ns), 1.1 to 2 times the cost of reading every field
  through `pnet_packet` (29 to 44 ns), and 4.8 to 7.5 times **faster** than
  `etherparse::PacketHeaders` (198 to 430 ns).
- **On whole captures, `parse` takes 69 to 143 ns**, because it then also
  names the application protocol and decodes its header, which the two other
  crates do not do. That figure is the price of the whole job, not of
  layers 2 to 4: the ratio to `pnet_packet` on these tables (2 to 4) compares
  two different jobs.
- **Before the performance review of #393**, 13.4.0 as published took 73 to
  86 ns on the frames with no payload and 158 to 382 ns on whole captures,
  on the same machine and with the same bench: above the view-based decode
  of `etherparse`, where `parse` is now below it.
- **`packet_parser` has no slicing level.** A program that only needs to
  find the transport payload, and reads no field, pays 5 to 28 ns with the
  other two crates and 35 ns or more with `parse`.
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

- CPU: Intel(R) Xeon(R) Processor @ 2.10GHz, one core of a virtual machine, governor not exposed
- OS: Linux 6.18.44-fc-v880
- Compiler: rustc 1.97.0 (2d8144b78 2026-07-07), profile `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`
- Crates: packet_parser 13.4.0 plus #393 (this repository), etherparse 0.21.0, pnet_packet 0.35.0, criterion 0.8.2

## Frames measured

| Corpus | Frames read | Kept | Bytes | Not Ethernet | No layer 4 | Disagreement |
|---|---:|---:|---:|---:|---:|---:|
| `4sics` | 246,137 | 239,267 | 21,350,446 | 0 | 6,870 | 0 |
| `ultimate` | 51,328 | 25,174 | 7,670,424 | 11,771 | 7,702 | 6,681 |
| `subset` | 775 | 731 | 73,411 | 17 | 27 | 0 |

## Corpus `4sics`: 239,267 frames

| Crate | Call | Level | ns per frame | ± | M frames/s | Gbit/s | packet_parser = 1 |
|---|---|---|---:|---:|---:|---:|---:|
| etherparse | `SlicedPacket::from_ethernet` | slicing | 16.9 | 0.97 | 59.3 | 42.3 | 0.24 |
| pnet_packet | views, fields not read | slicing | 9.1 | 1.18 | 110.2 | 78.6 | 0.13 |
| etherparse | `PacketHeaders::from_ethernet_slice` | full decode, L2-L4 | 184.6 | 21.26 | 5.4 | 3.9 | 2.68 |
| etherparse | `SlicedPacket`, then `to_header` on each view | full decode, L2-L4 | 57.5 | 6.85 | 17.4 | 12.4 | 0.83 |
| pnet_packet | views, every accessor | full decode, L2-L4 | 32.3 | 3.42 | 30.9 | 22.1 | 0.47 |
| **packet_parser** | `parse` | full decode, L2-L7 | 69.0 | 6.60 | 14.5 | 10.4 | 1.00 |

The 90,914 TCP frames of this corpus that carry no payload:

| Crate | Call | Level | ns per frame | ± | M frames/s | packet_parser = 1 |
|---|---|---|---:|---:|---:|---:|
| etherparse | `SlicedPacket::from_ethernet` | slicing | 28.1 | 3.87 | 35.6 | 0.60 |
| pnet_packet | views, fields not read | slicing | 16.6 | 3.10 | 60.3 | 0.35 |
| etherparse | `PacketHeaders::from_ethernet_slice` | full decode, L2-L4 | 227.1 | 14.67 | 4.4 | 4.83 |
| etherparse | `SlicedPacket`, then `to_header` on each view | full decode, L2-L4 | 68.1 | 4.82 | 14.7 | 1.45 |
| pnet_packet | views, every accessor | full decode, L2-L4 | 43.6 | 5.73 | 22.9 | 0.93 |
| **packet_parser** | `parse` | full decode, L2-L7 | 47.0 | 4.66 | 21.3 | 1.00 |

## Corpus `ultimate`: 25,174 frames

| Crate | Call | Level | ns per frame | ± | M frames/s | Gbit/s | packet_parser = 1 |
|---|---|---|---:|---:|---:|---:|---:|
| etherparse | `SlicedPacket::from_ethernet` | slicing | 29.2 | 2.72 | 34.2 | 83.4 | 0.20 |
| pnet_packet | views, fields not read | slicing | 16.6 | 3.85 | 60.4 | 147.3 | 0.12 |
| etherparse | `PacketHeaders::from_ethernet_slice` | full decode, L2-L4 | 459.7 | 46.79 | 2.2 | 5.3 | 3.21 |
| etherparse | `SlicedPacket`, then `to_header` on each view | full decode, L2-L4 | 60.1 | 5.05 | 16.6 | 40.6 | 0.42 |
| pnet_packet | views, every accessor | full decode, L2-L4 | 39.8 | 4.56 | 25.1 | 61.3 | 0.28 |
| **packet_parser** | `parse` | full decode, L2-L7 | 143.0 | 19.52 | 7.0 | 17.0 | 1.00 |

The 5,935 TCP frames of this corpus that carry no payload:

| Crate | Call | Level | ns per frame | ± | M frames/s | packet_parser = 1 |
|---|---|---|---:|---:|---:|---:|
| etherparse | `SlicedPacket::from_ethernet` | slicing | 18.5 | 2.41 | 54.0 | 0.32 |
| pnet_packet | views, fields not read | slicing | 5.4 | 0.56 | 184.3 | 0.09 |
| etherparse | `PacketHeaders::from_ethernet_slice` | full decode, L2-L4 | 430.1 | 79.81 | 2.3 | 7.46 |
| etherparse | `SlicedPacket`, then `to_header` on each view | full decode, L2-L4 | 65.6 | 7.28 | 15.3 | 1.14 |
| pnet_packet | views, every accessor | full decode, L2-L4 | 28.6 | 5.51 | 35.0 | 0.49 |
| **packet_parser** | `parse` | full decode, L2-L7 | 57.7 | 9.62 | 17.3 | 1.00 |

## Corpus `subset`: 731 frames

| Crate | Call | Level | ns per frame | ± | M frames/s | Gbit/s | packet_parser = 1 |
|---|---|---|---:|---:|---:|---:|---:|
| etherparse | `SlicedPacket::from_ethernet` | slicing | 15.0 | 0.60 | 66.7 | 53.5 | 0.14 |
| pnet_packet | views, fields not read | slicing | 5.7 | 0.25 | 174.9 | 140.5 | 0.05 |
| etherparse | `PacketHeaders::from_ethernet_slice` | full decode, L2-L4 | 198.6 | 31.54 | 5.0 | 4.0 | 1.90 |
| etherparse | `SlicedPacket`, then `to_header` on each view | full decode, L2-L4 | 49.9 | 8.56 | 20.0 | 16.1 | 0.48 |
| pnet_packet | views, every accessor | full decode, L2-L4 | 30.8 | 3.02 | 32.5 | 26.1 | 0.29 |
| **packet_parser** | `parse` | full decode, L2-L7 | 104.4 | 19.72 | 9.6 | 7.7 | 1.00 |

The 167 TCP frames of this corpus that carry no payload:

| Crate | Call | Level | ns per frame | ± | M frames/s | packet_parser = 1 |
|---|---|---|---:|---:|---:|---:|
| etherparse | `SlicedPacket::from_ethernet` | slicing | 15.3 | 1.90 | 65.5 | 0.43 |
| pnet_packet | views, fields not read | slicing | 4.7 | 0.33 | 214.9 | 0.13 |
| etherparse | `PacketHeaders::from_ethernet_slice` | full decode, L2-L4 | 198.0 | 16.77 | 5.1 | 5.61 |
| etherparse | `SlicedPacket`, then `to_header` on each view | full decode, L2-L4 | 59.0 | 2.71 | 17.0 | 1.67 |
| pnet_packet | views, every accessor | full decode, L2-L4 | 30.2 | 1.25 | 33.1 | 0.86 |
| **packet_parser** | `parse` | full decode, L2-L7 | 35.3 | 3.85 | 28.3 | 1.00 |

## One frame per family

ns per frame.

| Frame | `slice_etherparse` | `slice_pnet` | `full_etherparse` | `full_etherparse_slices` | `full_pnet` | `full_packet_parser` |
|---|---:|---:|---:|---:|---:|---:|
| TCP over IPv4, no payload | 11.4 | 4.2 | 182.4 | 75.8 | 32.1 | 36.2 |
| TCP over IPv4, 1,000 bytes or more | 14.8 | 4.4 | 196.8 | 60.9 | 31.2 | 176.7 |
| UDP over IPv4, DNS | 15.8 | 4.4 | 185.3 | 45.0 | 28.1 | 143.7 |
| TCP over IPv6 | 19.5 | 5.1 | 614.3 | 62.9 | 27.4 | 61.1 |
| ICMP | 14.2 | 3.7 | 225.1 | 49.4 | 22.8 | 37.4 |
| UDP under an 802.1Q tag | 19.3 | 5.3 | 608.9 | 42.3 | 18.6 | 164.5 |

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
- **One machine, a shared virtual machine**: the ratios hold better than the
  absolute figures. The median absolute deviation given in the tables is
  often 10 % of the value and reaches 20 %: a figure moves by as much from
  one run to the next.
- The competing crates are dependencies of `tools/compare` only, never of
  `packet_parser`.
