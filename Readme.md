# Packet Parser

**Packet Parser** is a powerful and modular Rust crate designed for analyzing and decoding network frames. It provides flexible tools to process various layers of network packets (data link, network, transport, and application).

## Features
- **Multi-layer Support**: Analyze Data Link, Network, Transport, and Application layers.
- **Data Validation**: Validation mechanisms at every stage of processing.
- **Error Management**: Precise error types for better problem handling.
- **Integrated Benchmarks**: Performance analysis using Criterion.
- **Extensible**: Modular architecture for easily adding new protocols.

## Installation
Add the following dependency to your `Cargo.toml`:

```toml
[dependencies]
packet_parser = "0.1.0"
```

Then, import the crate in your project:

```rust
extern crate packet_parser;
```

## Usage

### Basic Example

Here is an example to decode a MAC address from an Ethernet frame:

```rust
use packet_parser::parsed_packet::data_link::mac_address;

fn main() {
    let raw_data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    let mac = mac_address::parse(&raw_data).unwrap();
    println!("MAC Address: {}", mac);
}
```

### Integration Example

The following example demonstrates how to capture and parse network packets:

```rust
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use packet_parser::parsed_packet::ParsedPacket;
use std::convert::TryFrom;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PacketCaptureError {
    #[error("Interface {0} not found")]
    InterfaceNotFound(String),

    #[error("Failed to create channel: {0}")]
    ChannelCreationError(String),

    #[error("Failed to receive packet: {0}")]
    PacketReceiveError(String),

    #[error("Failed to parse packet: {0:?}")]
    PacketParseError(String),
}

fn find_interface(interface_name: &str) -> Result<NetworkInterface, PacketCaptureError> {
    let interfaces = datalink::interfaces();
    interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .ok_or_else(|| PacketCaptureError::InterfaceNotFound(interface_name.to_string()))
}

fn create_channel(interface: &NetworkInterface) -> Result<(Box<dyn datalink::DataLinkSender>, Box<dyn datalink::DataLinkReceiver>), PacketCaptureError> {
    match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => Ok((tx, rx)),
        Ok(_) => Err(PacketCaptureError::ChannelCreationError("Unhandled channel type".to_string())),
        Err(e) => Err(PacketCaptureError::ChannelCreationError(e.to_string())),
    }
}

fn main() -> Result<(), PacketCaptureError> {
    let interface_name = "wlp0s20f3"; // Example network interface

    let interface = find_interface(interface_name)?;

    let (_tx, mut rx) = create_channel(&interface)?;

    loop {
        let packet = match rx.next() {
            Ok(packet) => packet,
            Err(e) => {
                eprintln!("Failed to receive packet: {}", e);
                continue;
            }
        };

        println!("Received packet: {:2X?}", packet);

        match ParsedPacket::try_from(packet) {
            Ok(parsed_packet) => println!("{}", parsed_packet),
            Err(e) => eprintln!("Error parsing packet: {:?}", PacketCaptureError::PacketParseError(e.to_string())),
        }
    }
}
```

## Modules

### `parsed_packet`
- **data_link**: Handles physical and data link layers, such as MAC addresses.
- **network**: Manages network protocols like IP (IPv4/IPv6).
- **transport**: Analyzes transport protocols like TCP and UDP.
- **application**: Supports application protocols like HTTP and DNS.

### `errors`
Specific error types for each layer to handle exceptions effectively.

### `validations`
Verification utilities to ensure the integrity and validity of parsed data.

### `displays`
Tools for formatting and presenting parsed data.

## Tests and Benchmarks

### Tests
Unit and integration tests are located in the `tests/` directory.
Run all tests using:

```bash
cargo test
```

### Benchmarks
Benchmarks are available in the `benches/` directory and use Criterion.
Run the benchmarks using:

```bash
cargo bench
```

## Contribution
Contributions are welcome! To report a bug or propose a feature, open an issue or a pull request on the GitHub repository.

1. Fork the repository.
2. Create a branch for your feature: `git checkout -b feature/your-feature-name`.
3. Make and commit your changes: `git commit -m "Add feature X"`.
4. Push the branch: `git push origin feature/your-feature-name`.
5. Open a pull request.

## License
This crate is distributed under the MIT license. See the [LICENSE](LICENSE) file for more information.

---

**Packet Parser** is designed to make network frame analysis easy in complex environments. If you have suggestions or feedback, feel free to reach out!

