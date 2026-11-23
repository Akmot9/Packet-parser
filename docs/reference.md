# packet_parser reference

What the crate decodes, layer by layer, and how each API behaves. This page
holds the detail that used to live in the README (#224). The
[book](https://akmot9.github.io/packet-parser-book/) explains the design and
has one page per layer and per recent protocol; the
[API reference](https://docs.rs/packet_parser) documents every type.

Adding a decoder? Add its entry under [Protocol Support](#protocol-support)
and its label to the list in the [README](../README.md#protocols).

## Choosing the LINKTYPE

`parse` is fail-closed on the link layer: the LINKTYPE comes from the caller and
is never guessed from the bytes. Check it up front to reject a capture before
reading a single packet:

```rust
use packet_parser::{LinkType, is_supported, parse};

let link_type = LinkType::ETHERNET;
if !is_supported(link_type) {
    return Err(format!("unsupported LINKTYPE {}", link_type).into());
}

let flow = parse(link_type, packet_bytes)?;
```

`packet_bytes` must contain exactly one packet, without a PCAP or PCAPNG record
header. `LinkType` uses the canonical `LINKTYPE_*` namespace stored in capture
files. A live-capture adapter must normalize `DLT_*` values first when their
numeric value differs. For PCAPNG, the capture reader resolves the interface
referenced by each packet and passes that interface's LINKTYPE.

### Do not use the Ethernet shortcut on an unknown capture

`PacketFlow::try_from(&[u8])` and `DataLink::try_from(&[u8])` take a bare byte
slice and **assume Ethernet**. They are kept for compatibility and will be
removed in a future major release.

They do not fail on a non-Ethernet capture — they silently produce wrong data. A
`LINKTYPE_LINUX_SLL` frame (what a capture on the Linux `any` interface yields)
has its 16 cooked-header bytes reinterpreted as an Ethernet header: the call
returns `Ok` with fabricated MAC addresses, `internet: None` and
`corrupted: None`. Nothing signals the mistake, and a flow matrix built from it
fills up with addresses that never existed on the wire.

Supported LINKTYPEs:

| LINKTYPE | Value | Decoder status |
| --- | ---: | --- |
| BSD loopback (NULL) | 0 | Supported: four address-family bytes, then the IP packet. The byte order is the capturing host's, so the field is read both ways and cross-checked against the IP version. `LINKTYPE_LOOP` (108), its network-order OpenBSD twin, is not handled — no capture attests it |
| Ethernet | 1 | Supported |
| RAW IP | 101 | Supported for IPv4 and IPv6 |
| Native IEEE 802.11 | 105 | Modelled for CAPWAP inner flows; top-level decoder not yet supported |
| Linux SLL v1 | 113 | Supported |
| Bluetooth H4 with pseudo-header | 201 | Identified, explicitly unsupported |
| IPv4 raw | 228 | Supported |
| IPv6 raw | 229 | Supported |
| IEEE 802.3br mPacket | 274 | Supported for express mPackets (SMD-E); preemptible fragments (SMD-S/C) are refused with a named error, their reassembly being stateful |
| Linux SLL v2 | 276 | Supported |
| Any other value | Preserved as-is | `ParseError::UnsupportedLinkType` |

An unsupported LINKTYPE is rejected before packet bytes are decoded. Unknown
upper-layer protocols still use the graceful `None`/`corrupted` behaviour
described above.

For RAW IP, an empty packet or a version nibble other than 4/6 returns a
structured `InvalidLinkLayer(LinkLayerError)`. Once IPv4 or IPv6 is identified,
an invalid or truncated IP header remains a successful partial flow with
`corrupted: Internet`; the link layer and its accounting are preserved.

Linux SLL v1 decodes its 16-byte cooked header in network byte order and keeps
the packet type, raw ARPHRD hardware type, declared address length, available
source-address bytes and protocol value. Unknown numeric values are preserved;
an address longer than the eight-byte wire slot is reported as truncated rather
than rejected. Use canonical `LinkType::LINUX_SLL` (113): the value 25 displayed
by some Wireshark fields is an internal WTAP encapsulation identifier.

Linux SLL v2 independently decodes its 20-byte header and additionally keeps
the numeric capture-machine interface index and the reserved-MBZ field. A
non-zero reserved value is preserved and reported by `reserved_is_zero()`
rather than discarding an otherwise decodable packet, matching Tshark's
tolerant dissection. Interface names are not resolved because they belong to
the capture machine. Use canonical `LinkType::LINUX_SLL2` (276); Wireshark's
current internal WTAP encapsulation identifier for this format is 210.

Every parsed flow now carries a generic `LinkLayer`. Its common accessors do
not assume Ethernet:

```rust
println!("LINKTYPE={}", flow.data_link.link_type());
println!("next={:?}", flow.data_link.network_protocol());

if let Some(ethernet) = flow.data_link.as_ethernet() {
    println!("{} -> {}", ethernet.source_mac, ethernet.destination_mac);
}
```

`network_payload()` returns the borrowed L3 slice. Format-specific views are
explicit (`as_ethernet()`, `as_raw_ip()`, `as_linux_sll()`,
`as_linux_sll2()`, `as_ieee80211()`), so RAW and both SLL formats cannot
silently manufacture Ethernet fields.

## Main API

| Need | API |
| --- | --- |
| Check whether a link decoder exists | `is_supported(LinkType)` |
| **Parse a packet (canonical)** | `parse(LinkType, &[u8])` |
| Parse with caller-declared ports ("Decode As": my FTP runs on 2121) | `parse_with(LinkType, &[u8], &ParseConfig::new().decode_as(port, DecodeAsProtocol::..))` |
| Name a protocol the crate does not decode, with your own parser | `parse_with(LinkType, &[u8], &ParseConfig::new().with_parser(Arc::new(MyParser))?)`; see [Custom parsers](#custom-parsers) |
| Parse Ethernet, compat shortcut — assumes Ethernet, see above | `PacketFlow::try_from(&[u8])` |
| Parse only Ethernet/VLAN — assumes Ethernet, see above | `DataLink::try_from(&[u8])` |
| Parse only L3, from the protocol the link layer announced | `Internet::try_from_network_parts(NetworkProtocol, &[u8])` |
| Parse only L4, from the protocol the IP header announced | `Transport::try_from_parts(Option<TransportProtocol>, &[u8])` |
| Classify a payload without its frame (a reassembled stream, a stored payload), with the label `parse` would give it | `classify_payload(TransportProtocol, source_port, destination_port, &[u8])`; with declared ports, `classify_payload_with(.., &ParseConfig)` |
| Detach the result from the original buffer | `flow.to_owned_flow()` → `PacketFlowOwned` |
| Iterate over encapsulated flows | `flow.flatten()` |
| Measure an explicit LINKTYPE | `parse_timed(...)` with the `parse_timing` feature |
| Measure Ethernet through the compatibility API | `PacketFlow::try_from_timed(...)` with the `parse_timing` feature |

`PacketFlow` contains:

```rust
pub struct PacketFlow<'a> {
    pub data_link: LinkLayer<'a>,
    pub internet: Option<Internet<'a>>,
    pub transport: Option<Transport<'a>>,
    pub application: Option<Application>,
    pub inner: Option<Box<PacketFlow<'a>>>,
}
```

The 7.0 serialization schema nests the link layer and uses stable tags. The
borrowed and owned link models serialize identically (payload bytes are not
serialized):

```json
{
  "data_link": {
    "link_type": 1,
    "network_protocol": { "kind": "ipv4" },
    "link_kind": "ethernet",
    "link_details": {
      "destination_mac": "00:11:22:33:44:55",
      "source_mac": "66:77:88:99:aa:bb",
      "ethertype": "IPv4"
    }
  }
}
```

## Protocol Support

### Data Link

- Ethernet II
- VLAN 802.1Q
- PPPoE session (EtherType `0x8864`, RFC 2516): unwrapped like a VLAN tag
  when PPP carries IPv4 or IPv6 (`DataLink::pppoe` keeps the session id,
  length and PPP protocol); PPP control protocols (LCP, IPCP, IPv6CP) are
  named, PPPoE Discovery (`0x8863`) only by its EtherType
- RAW IPv4/IPv6 (`LINKTYPE_RAW`)
- Linux cooked capture v1 (`LINKTYPE_LINUX_SLL`)
- Linux cooked capture v2 (`LINKTYPE_LINUX_SLL2`)
- MAC addresses and internal OUI resolution
- Native IEEE 802.11 representation for CAPWAP inner flows (not yet a
  top-level LINKTYPE decoder)

### Internet

- ARP
- IPv4
- IPv6
- Profinet: every RT Frame ID class (cyclic data, alarms, PTCP, fragments) is
  validated; DCP messages are decoded by `ProfinetPacket`, block by block
- PTP (IEEE 1588) directly over Ethernet, EtherType `0x88F7`, decoded into
  `InternetDetails::Ptp`
- GOOSE (IEC 61850-8-1) directly over Ethernet, EtherType `0x88B8`, with or
  without a VLAN tag, decoded into `InternetDetails::Goose`: APPID, length,
  reserved words (simulation bit), then the goosePdu (control block
  reference, time allowed to live, data set, goID, UtcTime timestamp, state
  and sequence numbers, simulation, configuration revision, needs
  commissioning, number of entries, every `allData` value with its BER tag
  and bytes); also recognised blindly when the EtherType is unknown
- LLDP (IEEE 802.1AB) directly over Ethernet, EtherType `0x88CC`, decoded into
  `InternetDetails::Lldp`: every TLV borrowed, the mandatory chassis ID, port
  ID and time to live, then port description, system name and description,
  capabilities, management addresses and organizationally specific TLVs
  (OUI, subtype, information: PROFINET, IEEE 802.1, IEEE 802.3, LLDP-MED...);
  also recognised blindly when the EtherType is unknown

For fragmented IPv4 packets, the crate does not perform IP reassembly. In that
case `payload_protocol` is set to `None` so the transport layer is not parsed
from incomplete data.

### Transport

- TCP
- UDP
- ICMPv4 (echo request/reply, and the error reports that quote the original
  datagram: destination unreachable, redirect, time exceeded, parameter
  problem). Reached through IP protocol number 1, never through probing.
- ICMPv6 (echo request/reply, the error reports that quote the invoking packet,
  and the neighbor discovery messages of RFC 4861: router solicitation and
  advertisement — the latter with its hop limit, M/O flags, router lifetime,
  reachable time and retransmit timer — plus neighbor solicitation and
  advertisement with their target address and R/S/O flags). Reached through
  IPv6 next header 58. Type numbering is disjoint from ICMPv4 — 128 is an echo
  request there, 8 is undefined — so the two have separate parsers.

Neither ICMP version carries an application layer, so `payload` stays `None`
and the decoded message is exposed through `TransportDetails::Icmp` /
`TransportDetails::Icmpv6`.
- Mapping from many IP protocol numbers to `TransportProtocol`

Protocols other than TCP/UDP/ICMP can be represented by the enum, but they do
not always expose ports or application payloads.

### Application

Application detection is intentionally best-effort. Parser modules include:

- DNS (including mDNS through `DnsPacket::try_from_mdns`)
- TLS
- SNMP
- NTP (modes 1 to 5) on UDP 123; on any other port only when the poll,
  precision and root delay are values real implementations send and the
  bytes after the 48-byte header are well-formed extension fields and MAC
  (NTS, MS-SNTP)
- DHCP / DHCPv6
- HTTP/1.x (RFC 9112): requests and responses, head validated, body as bytes
- RTP (RFC 3550) over UDP, on a declared port: the fixed header (marker, payload
  type, sequence number, timestamp, SSRC), the CSRC list, the header
  extension and the padding; the payload is borrowed, not decoded.
  `RtpPacket::static_payload_name` names the static types of RFC 3551. RTP
  has no port and no magic, only two version bits, so no stateless probe
  can tell it from another format that starts with `0x80`: there is no
  blind rule, and RTP is labelled on a port declared with
  `DecodeAsProtocol::Rtp` only, where any well-formed packet is taken.
  Stateless limits: nothing ties a packet to its session; SRTP keeps its
  header in clear and decodes as RTP; RTP over TCP (RFC 4571) is not read
- RTCP (RFC 3550 §6) over UDP, on any port: the packets of a datagram
  (`RtcpCompound::packets`), each with its type (200 to 207), count and
  body, the sender SSRC and the sender information of a Sender Report;
  report blocks, SDES items and feedback messages are borrowed, not decoded.
  The blind rule is the last of the UDP cascade and asks for packet lengths that tile
  the datagram exactly, a minimum size per type and count, and a Sender or
  Receiver Report first, or a lone feedback message (reduced-size RTCP,
  RFC 5506). `DecodeAsProtocol::Rtcp` takes any well-formed datagram on a
  declared port. Stateless limits: SRTCP appends an index and an
  authentication tag, so its lengths no longer tile the datagram and it
  stays `Unknown`
- .NET Message Framing ([MC-NMF], the framing of WCF `net.tcp`) over TCP, on
  any port: the records of a segment (`NmfSegment::records`), from Version
  and Via to the sized envelope, whose payload is borrowed, not decoded. A
  Via or a sized envelope of length zero is refused ([MC-NMF] §2.2.3.3 and
  §2.2.4.1). NMF has no port; the blind rule takes a preamble (Version 1.0, Mode, Via and
  its URI) or a sized envelope that opens as binary XML with a session
  dictionary ([MC-NBFSE]). `DecodeAsProtocol::Nmf` takes any segment made of
  records on a declared port, the one-byte records (Preamble Ack, End)
  included. Stateless limits: an envelope longer than its segment is cut
  (`NmfRecord::is_truncated`) and the segments that carry the rest of it
  stay `Unknown`; envelopes in SOAP text or in binary XML without a session
  dictionary are named on a declared port only
- Connection-oriented DCE/RPC (DCE 1.1: RPC, the transport of MSRPC and
  DCOM) over TCP, on any port: the common header (minor version, PDU type,
  flags, data representation, fragment and authentication lengths, call
  identifier, read in the byte order the header states) and, for a Request,
  the allocation hint, presentation context and operation number
  (`DceRpcPdu::request`). The body is borrowed, not decoded; a `bind_nak`
  carries at least its reject reason. Stateless
  limits: a fragment longer than its segment is cut
  (`DceRpcPdu::is_truncated`) and the segments that carry the rest stay
  `Unknown`; only the first PDU of a segment is read (`DceRpcPdu::rest`
  gives the next); connectionless DCE/RPC (version 4, over UDP) and DCE/RPC
  inside an SMB named pipe are not read
- SIP (RFC 3261) over UDP and TCP, on any port: a request (a method of the
  IANA registry, a Request-URI with a scheme, `SIP/2.0`) or a response
  (`SIP/2.0`, a code from 100 to 699), a complete head up to the empty line
  with Via, From, To, Call-ID and CSeq, in long or compact form, and a CSeq
  whose method is the request's. `SipMessage` exposes them as fields, the
  other headers through `SipHeaders::get`, which finds a compact form from
  its long name and the other way round, and the body cut at
  Content-Length. Folded headers are accepted, their value returned as
  carried; a message with two Content-Length headers is refused
  (`SipError::DuplicateHeader`). Stateless limits: a head cut between two TCP segments, the
  continuation segments, IPv4 fragments and the keep-alives of port 5060
  (blanks, `hello`, CRLF) are not SIP; SIP over TLS (5061) stays TLS.
  `DecodeAsProtocol::Sip` takes it on a port another rule guards
- Skinny (SCCP, the Skinny Client Control Protocol of Cisco IP phones; not
  the SCCP of SS7) on TCP 2000 or a Decode As port
  (`DecodeAsProtocol::Skinny`), never on another port: twelve mostly-zero
  bytes make no blind probe. `SkinnyMessage` exposes the little-endian
  header (data length, header version, message identifier) and borrows the
  body, which is not decoded; `SkinnyMessage::messages` iterates over the
  messages of a segment. The port rule asks for messages that tile the
  segment, a header version among 0, 10, 11 and 15 to 22, and a plausible
  message identifier; behind a whole message, the start of a header that
  TCP cut before its twelfth byte is accepted. The protocol has no public specification: the
  reference is the Wireshark dissector, and messages are not named.
  Stateless limits: a message longer than its segment is cut
  (`SkinnyMessage::is_truncated`), the segments that carry the rest stay
  `Unknown`, and so does a message that starts in the middle of a segment;
  encrypted signalling (TLS on TCP 2443) is TLS
- LDAP (RFC 4511) on TCP 389, on TCP 3268 (the global catalog of an Active
  Directory domain), on UDP 389 (CLDAP, under the same label) or a Decode As
  port (`DecodeAsProtocol::Ldap`), never on another port: a `30` byte and a
  BER length make no blind probe. An `LdapPdu` is a message or a buffer of
  the SASL security layer, and `LdapPdu::pdus` iterates over the PDUs of a
  segment or of a datagram. `LdapMessage` exposes the message identifier
  and the operation (`LdapOperation`) and borrows the body and the
  controls, which are not decoded, except by three readers: `result()`
  (code, matched DN and diagnostic of a response), `bind_request()`
  (version, name, simple or SASL authentication) and `search_request()`
  (base and scope). `LdapSaslBuffer` exposes its length and the header of
  its token (`LdapSaslToken`): the Kerberos V5 Wrap token of RFC 4121 or of
  RFC 1964, or an NTLMSSP signature; `messages()` yields the messages of a
  Kerberos token that is signed without being sealed. The port rule asks
  for PDUs that tile the payload; behind a whole PDU, the start of a PDU
  that TCP cut before the end of its header is accepted. A BER length goes
  up to 2^31 - 1, a SASL buffer up to 2^24 - 1 bytes. Stateless limits: a PDU longer than its
  segment is cut (`LdapPdu::is_truncated`) and the segments that carry the
  rest stay `Unknown`; a sealed buffer shows its header only, and nothing
  is read behind an NTLMSSP signature, which does not say whether the
  message is encrypted; the security layer of DIGEST-MD5 is not read;
  LDAPS (TCP 636 and 3269) is TLS
- Syslog (RFC 3164, RFC 5424) on UDP 514, on TCP 514 and 601 (RFC 6587) or
  a Decode As port (`DecodeAsProtocol::Syslog`), never on another port: the
  three to five bytes of a priority make no blind probe. `SyslogMessage`
  reads a UDP datagram: the priority (`facility()`, `severity()`), the
  version of RFC 5424 when it is there, and the content, borrowed;
  `header()` reads the five header fields of an RFC 5424 message, and the
  BSD content is left as it is. Over TCP, `SyslogFrame::frames` iterates
  over the frames of a segment, under octet counting (`octet_count`) or
  ended by LF; the port rule asks for frames that tile the segment, each
  one opened by a priority. A message without a priority is not named,
  where tshark names any payload of UDP 514. Stateless limits: a message
  longer than its segment is cut (`SyslogFrame::is_truncated`) and the
  segments that carry the rest stay `Unknown`; a message with an inner LF
  is not told from two messages; TCP 514 is also the port of `rsh`, whose
  segments do not open with a priority; syslog over TLS (TCP 6514) is TLS
- Kerberos V5 (RFC 4120) on UDP 88 and TCP 88, or on a Decode As port
  (`DecodeAsProtocol::Kerberos`): the exchange of a client with the key
  distribution centre of its realm. `KerberosMessage` reads the type of the
  message (`KerberosMessageType`, the ten of the RFC), checked against its
  `msg-type` field, and the version, 5; the fields are borrowed
  (`KerberosMessage::field`), and five accessors read the AS-REQ, AS-REP,
  TGS-REQ, TGS-REP and KRB-ERROR further: `error_code()`, `realm()`,
  `client_realm()`, `client_name()` and `service_name()`
  (`KerberosPrincipalName`). Over TCP, `KerberosRecord` reads the four
  bytes of length before each message, and `KerberosRecord::records`
  iterates over the records of a segment. The port rules ask for one
  whole message per datagram, and for records that tile the segment;
  behind a whole record, the start of a record that TCP cut in its mark or
  in the header of its message is accepted, unless its mark is whole and
  wrong (reserved high bit, fewer than 14 bytes, or another length than
  the one the message announces).
  Tickets, authenticators and pre-authentication data are encrypted and not
  read. Stateless limits: a message longer than its segment is cut
  (`KerberosMessage::is_truncated`) and the segments that carry the rest
  stay `Unknown`; Kerberos carried by another protocol (GSS-API in LDAP or
  SMB, kpasswd on port 464) is not looked for
- NetBIOS (RFC 1001 and 1002), one label per service: `NBNS`, the name
  service on UDP 137; `NBSS`, the session service on TCP 139 and 445; `NBDS`,
  the datagram service on UDP 138 or a Decode As port
  (`DecodeAsProtocol::Nbds`). `NbdsPacket` exposes the message type
  (`NbdsMessageType`), the flags, the datagram identifier, the source
  address and port, then, by type (`NbdsBody`): the length, the packet
  offset, the source and destination names (`NetbiosName`) and the user
  data of a datagram; the code of an error; the name of a query to a
  datagram distribution server. The announced length must be that of the
  UDP datagram, except in the first of two fragments (flags `FIRST` and
  `MORE`), which announces the whole datagram and so more than it carries.
  A `FIRST` packet, whole datagram or first fragment, has a zero offset.
  The user data, most often SMB on a mailslot (Browser announcements and
  elections, NETLOGON), is borrowed, not decoded; a fragmented datagram is
  not reassembled, and its second fragment is not read. `NbnsPacket` reads
  the records its four counts announce, and one more form: the negative
  name query response as the figure of RFC 1002 §4.2.14 draws it, four
  zero counts followed by a NULL record, with one of the five error codes
  of that section
- MQTT
- PostgreSQL
- FTP
- SMTP
- NNTP
- SSH (identification string only: everything after the version exchange is
  encrypted, so a stateless parser labels the banner frames and nothing else)
- Modbus TCP on TCP 502 or a Decode As port; on any other port only when
  every PDU carries a common public function code and the length it implies
  (a bounded Read Device Identification for function 43), Active Directory
  LDAP and DICOM association rejects excepted
- Modbus over UDP, label `ModbusUDP`: the same MBAP envelope on UDP 502 or
  a Decode As port (`DecodeAsProtocol::ModbusUdp`), never on another port
- UMAS (Schneider Electric)
- EtherNet/IP
- OPC UA
- S7Comm
- COTP
- AMS
- GIOP
- Java RMI (JRMP, *Java RMI Specification* chapter 10) over TCP: stream
  header (`JRMI`, version, Stream, SingleOp or Multiplex protocol),
  ProtocolAck with its endpoint, ProtocolNotSupported, Call (target `ObjID`,
  operation, method hash; the registry and DGC methods named), Return
  (normal or exceptional, acknowledgement UID), Ping, PingAck, DgcAck.
  Arguments and return values stay serialized bytes, borrowed. The header,
  Call and Return are recognised on any TCP port; the one-byte messages,
  DgcAck and ProtocolAck only on TCP 1099 or a Decode As port
  (`DecodeAsProtocol::JavaRmi`), where exported objects and JMX connectors
  usually listen; there, a segment may hold several messages, a
  fixed-size one followed by another (`JavaRmiPacket::messages`). The
  client's EndpointIdentifier, which has no type byte, and continuation
  segments stay `Unknown`
- SRVLOC
- ASTERIX (EUROCONTROL surveillance data, eleven categories: CAT 048 and
  034 monoradar reports and service messages, CAT 001 and 002 their
  first-generation counterparts, CAT 008 weather, CAT 021 ADS-B, CAT 023
  ground station status, CAT 062 system tracks, CAT 063 sensor status,
  CAT 065 SDPS status, CAT 247 version numbers). Recognised by structure
  alone — every data block of a known category, records split exactly along
  the UAP, Random Field Sequencing included — since the protocol has
  neither a magic nor an IANA port
- QUIC
- Bitcoin
- RTPS (OMG DDSI-RTPS 2.x, the wire protocol of DDS): header, submessages
  split and typed (DATA, DATA_FRAG, HEARTBEAT, ACKNACK, GAP, INFO_TS,
  INFO_DST, INFO_SRC, fragment submessages, the 2.5 HEADER_EXTENSION with
  its message length, send timestamp, extensions and checksum, DDS Security
  and vendor ones), entity ids, sequence numbers and counts. The DDS layer
  of DATA and DATA_FRAG decodes on demand (`rtps::dds`): inline QoS, the
  encapsulation header of the serialized payload (CDR, PL_CDR, XCDR2, byte
  order), and SPDP/SEDP discovery from the built-in writers (DDS Security
  ones included) as a parameter list, with typed accessors for topic and
  type names, entity names, participant and endpoint GUIDs, domain,
  protocol version, vendorId, locators and their role, lease duration,
  built-in endpoint set, reliability, durability, key hash and status
  info; vendor parameters stay bytes. User data (the CDR of an application
  type), DATA_FRAG reassembly and the HEADER_EXTENSION parameter list stay
  opaque. Recognised by its magic (`RTPS`, or RTI's `RTPX`) and the
  exact tiling of its submessages, on any UDP port; RTI's sixteen-byte
  `NDDSPING` pings are reported too. A datagram may carry several
  messages: the `messageLength` of a HEADER_EXTENSION ends its message
  before the next one (`RtpsMessage::rest`, `RtpsPacket::messages`)
- BACnet/IP (ASHRAE 135 annex J) on UDP 47808: BVLC (function named,
  length equal to the datagram, origin of a Forwarded-NPDU), NPDU (version,
  control, destination and source network addresses, hop count, network
  messages with vendor id) and APDU (type, flags, invoke id, segmentation,
  confirmed and unconfirmed services named); recognised on its ports and
  blindly on any UDP port
- IEC 60870-5-104 on TCP 2404: APDUs of a segment (the last one cut by
  segmentation is decoded as far as it goes), I/S/U formats with sequence
  numbers or the STARTDT/STOPDT/TESTFR function, and for each ASDU the
  type named by its IEC 60870-5-101 mnemonic, cause of transmission,
  originator and common addresses, and the information objects (address,
  element sized from the standard, in sequence or not)
- RDP (MS-RDPBCGR) on TCP 3389: TPKT and COTP X.224 Connection Request
  (routing token or `mstshash` cookie, negotiation request and its
  correlation info) and Confirm
  (negotiation response or failure), then the MCS PDUs of the standard RDP
  security path (Connect-Initial/Response, Erect Domain, Attach User,
  Channel Join, Send Data with user and channel, Disconnect Provider
  Ultimatum); several TPKTs per segment, a TPKT cut by segmentation is
  decoded as far as it goes. After a TLS or CredSSP negotiation the
  connection is labelled TLS, by decision
- RADIUS (RFC 2865, accounting RFC 2866, CoA RFC 5176): header (code named,
  identifier, length, authenticator) and the attribute list (type named for
  the assigned codes 1-190 and 241-246, as in the IANA registry except 89,
  101 and 241-246, which carry their RFC names, and 124 and 125, whose
  deprecated variants carry the names of two Diameter AVPs behind the
  `Mip6FeatureVector` and `Mip6HomeLinkPrefix` constants; value borrowed,
  accessors for integers,
  IPv4 addresses, texts and Vendor-Specific); recognised on UDP
  1812/1813/1645/1646/3799 and blindly on any port (known code, length equal
  to the datagram, attributes tiling it)
- WireGuard: the four messages (handshake initiation and response, cookie
  reply, transport data) with their reserved bytes, session indexes, data
  counter and fixed fields (ephemeral key, encrypted fields, mac1, mac2),
  borrowed; nothing is decrypted. Recognised through Decode As by its shape;
  on UDP 51820 like tshark's heuristic (zero reserved bytes for a cookie or
  data); blindly on any other port only with zero reserved bytes and, for
  data, a counter below 2^60 and a plaintext padded to 16 bytes or cut at an
  MTU of at least 552 bytes. boringtun-based peers, which do not pad, are
  only recognised blindly on their handshakes, keepalives and round-sized
  packets; the official Cloudflare WARP client (message types 0xC1-0xC4) is
  not decoded
- DNP3 (IEEE 1815): link frames with their header and per-block CRC-16/DNP
  verified (length, control bits and function, addresses), transport header,
  application header (control, function code, internal indications) and the
  chain of object headers (group, variation, qualifier, range or count,
  position of the data sized from annex A), several frames per payload.
  Recognised blindly on TCP and UDP, the CRCs are the signature
- IKE (ISAKMP/IKEv1 RFC 2408, IKEv2 RFC 7296) on UDP 500 and 4500: 28-byte
  header (SPIs, version, exchange type named, flags, message ID, length),
  chain of top-level payloads with named types, protected bytes kept as such
  (IKEv1 E flag; IKEv2 SK or SKF payload body, clear IV and integrity data
  included); UDP 4500 demultiplexed per RFC 3948 (non-ESP marker,
  NAT-keepalive, ESP)
- ESP (RFC 4303): SPI and sequence number, native (IP protocol 50, exposed as
  `TransportDetails::Esp`) and UDP-encapsulated on 4500 (`EspPacket`), the
  rest (IV, ciphertext, ICV, sized by the negotiated algorithm) kept as bytes
- DIS (IEEE 1278.1, Distributed Interactive Simulation): PDU header
  (versions 1 to 7, the 72 standard PDU types named, family, timestamp,
  length, PDU Status), Entity State, Transmitter and Signal bodies typed,
  other bodies as bytes, several PDUs per datagram. Recognised blindly when
  the PDUs tile the datagram exactly; on UDP 3000 (or a Decode As port) a
  wrong declared length is tolerated and the rest kept as trailing bytes
- STANAG 5066 SIS (Subnetwork Interface Sublayer, NATO HF radio data
  stack) on TCP 5066: every S_PDU type (bind, hard links, subnet
  availability, management, unidata and expedited unidata with their
  confirmations and rejections), node addresses, SAPs, service types,
  TTL, U_PDU sizes; the first S_PDU of a segment, flagged when it overflows
  into the next segment, `consumed` for the following ones. Port-guarded,
  other ports via Decode As
- PTP (IEEE 1588) on UDP 319/320: PTPv2 decoded in full (common header, the
  ten message bodies, TLVs listed without decoding their value), PTPv1
  recognised by its header. Port-guarded: a Delay_Req has exactly the shape of
  an SLPv1 header
- Valmet DNA (the process network of Metso/Valmet distributed control
  systems; proprietary, no public specification): decoded from traffic
  observation alone, read-only. Header (`AB 01` magic, source node `0x80NN`,
  destination, length equal to the datagram minus two, message kind), the
  126-byte periodic status telegram (node IPv4 address, ten-byte BCD clock,
  node number, multicast group, two microsecond counters) and the tag
  message (72-byte header, tag length written twice, tag borrowed, text
  accessors for the `:e:<class>:<path>` form); other kinds keep their body
  as bytes. Recognised on UDP 2517 (messages, any kind) and 4516/4517 (the
  42-byte beacon that carries the same clock), and blindly on any UDP port
  for the two known kinds at their exact size

FTP, SMTP and NNTP detection in `PacketFlow` is both parser-validated and
restricted to their plaintext control ports (TCP 21, 25/587 and 119
respectively). Payloads on other ports are not labelled as these protocols:
their line-oriented syntax can also occur inside another text protocol's body.
An FTP or SMTP multi-line reply (`230-…` up to `230 …`) is recognised only
when the whole reply, its final `code SP` line included, sits in one segment:
a server that sends one line per segment leaves those segments `Unknown`,
the last one excepted, since a free-form continuation line carries no code
and nothing stateless tells it from other text. The ProFTPD banner of
`pcaps_exemple/protocols/sip/wireshark_aaa.pcap` is such a case: frames 53
to 75 stay `Unknown`, frame 77 is FTP.
Complete TLS records on implicit-TLS ports such as 465, 563 and 990 are
reported as TLS. To inspect externally decrypted application data, call the
detailed protocol parser directly.

`PacketFlow` exposes the application protocol as an enum,
`Application { protocol: ApplicationProtocol }`; `protocol.label()` gives its
text label, the one written in the JSON output. For detailed protocol-specific parsing,
use the corresponding module under
`packet_parser::parse::application::protocols`.

## Tunnels

`PacketFlow` can represent several flow levels through `inner`.

The currently supported tunnels are:

| Tunnel | Carried over | Inner |
| --- | --- | --- |
| CAPWAP-Data | UDP/5247 | IEEE 802.11 → LLC/SNAP → L3 |
| GRE (v0) | IP protocol 47 | IPv4, IPv6 or Ethernet |
| IP-in-IP | IP protocols 4 and 41 | bare IPv4 / IPv6 |
| VXLAN | UDP/4789 | full Ethernet frame |
| Geneve | UDP/6081 | Ethernet (0x6558) or bare IP |
| GTP-U | UDP/2152 | bare IP, no L2 |

CAPWAP outside the peeled case: a well-formed datagram on UDP 5246 (control)
or 5247 (data) is labelled `CAPWAP` without an inner flow. That covers the
RFC 5415 header (control messages, fragments, 802.11 management frames,
and the data channel keep-alive, whose header is all zero but HLEN and the
K bit) and the DTLS preamble followed by a DTLS 1.0 or 1.2 record, whose
encrypted content is not read. The same bytes on another port are not
labelled.

Variants we cannot attest are refused rather than guessed: ERSPAN and GRE
version 1, the VXLAN GBP/GPE flag extensions, Geneve OAM control messages,
and — for GTP-U — GTPv0, GTP' and every message type other than G-PDU.

Fragmented outer datagrams are not peeled: reassembly is stateful and out of
scope for this parser, so a tunnel is never reported as more complete than
the datagram carrying it.

Example:

```rust
let flow = PacketFlow::try_from(packet.as_slice())?;

for level in flow.flatten() {
    println!("{:?} -> {:?}", level.internet, level.transport);
}
```

## Custom parsers

A protocol the crate does not decode can still be named, by a parser the
application adds (issue #319). The parser implements `ApplicationParser`
(label, transports, ports, `matches`, and optionally `fields`) and is
registered with `ParseConfig::with_parser` or `add_parser`.

- It runs after the built-in table, only on a non-empty TCP or UDP payload
  the table left `Unknown`, at every flow level, tunnels included. It never
  takes a payload from the crate.
- The first parser that accepts the payload, in registration order, names
  the flow `ApplicationProtocol::Custom(label)`, written as its label in the
  JSON output.
- Its fields are decoded on demand: `ParseConfig::custom_fields(&flow)`.
- A label stored as text reads back with `ParseConfig::application_protocol(label)`,
  custom labels included; `str::parse` reads only the built-in ones (#323).
- Registration refuses an empty or invalid label, the label of a built-in
  protocol and a label already registered, ignoring ASCII case.

The parser can also live in a native library (`.so`, `.dylib`, `.dll`)
loaded at run time: the `packet_parser_plugin` kit, in `plugin/`, exports
it with `export_parser!` and loads it with `load_parser`. The guide is
[docs/plugins.md](plugins.md).

## Rule files

With the `rules` feature, such parsers can be declared in a TOML file
instead of code (issue #325): `RuleSet::from_toml(&text)` reads and checks
it, and `ParseConfig::with_rules(&rules)` registers one parser per label.

- A rule recognizes a payload by its transport, ports, length bounds, and
  byte patterns at fixed offsets, each with an optional mask. The patterns
  of a rule must check at least 16 bits: a port alone is not enough.
- Fields at fixed offsets are decoded on demand by `custom_fields`:
  integers of 8 to 64 bits (either byte order, optional mask and value
  names), hexadecimal bytes, or text.
- A mistake is refused with its line and column, unknown keys included.
- A rule file runs no code; the guarantees of custom parsers apply.

The guide, with the whole format, is [docs/rules.md](rules.md);
`examples/rules_check.rs` tries a rule file on captures, locally.

## Features

| Feature | Effect |
| --- | --- |
| `parse_timing` | Makes `parse_timed` and `PacketFlow::try_from_timed` actually measure each layer; without it the same API exists and `ParseTiming` stays zeroed |
| `rules` | `RuleSet` and `ParseConfig::with_rules`: parsers declared in a TOML file ([docs/rules.md](rules.md)); adds the `toml` dependency |

The `parse_timing` feature is intended for benchmarks. The normal
`PacketFlow::try_from` path does not measure parsing time.

Example:

```rust
use packet_parser::{PacketFlow, timing::ParseTiming};

let mut timing = ParseTiming::default();
let flow = PacketFlow::try_from_timed(packet.as_slice(), &mut timing)?;

println!("L2={}ns L3={}ns L4={}ns L7={}ns total={}ns",
    timing.l2_ns,
    timing.l3_ns,
    timing.l4_ns,
    timing.l7_ns,
    timing.total_ns,
);
```

Enable it with:

```bash
cargo test --features parse_timing
```

## Benchmarks and HTML Report

Two tools measure the crate:

- [`benches/`](../benches): a criterion bench of `parse` on the versioned
  corpus, one representative frame per family plus a fixed subset of
  captures. Run it with `cargo bench --manifest-path benches/Cargo.toml`.
  CI measures it with CodSpeed on every push to `main` and every pull
  request; [codspeed.io/Akmot9/Packet-parser](https://codspeed.io/Akmot9/Packet-parser)
  tracks each bench over time.
- `tools/verbench`, below: the same reference packet across every published
  version, on one machine.

The main benchmark harness is `tools/verbench`. It compares published crate
versions from crates.io with the local working copy, then generates:

- `tools/verbench/perf_by_version.json`
- `tools/verbench/perf_by_version.html`

Run the full benchmark:

```bash
tools/verbench/run.sh
```

Regenerate only the HTML report from an existing JSON file:

```bash
python3 tools/verbench/report.py
```

The HTML report is standalone. It opens directly in a browser and does not need
Docker, Postgres, Grafana or any CDN.

```bash
xdg-open tools/verbench/perf_by_version.html
```

`tools/verbench` reports average `l2_ns`, `l3_ns`, `l4_ns`, `l7_ns` and
`total_ns` values on a fixed reference packet after warmup. Use these numbers to
compare trends between versions on the same machine, not as universal absolute
latency claims.

## Optional PCAP Pipeline

[`tools/lab`](../tools/lab) contains `benchmark_db`, a binary that parses local PCAP
files and writes JSONL events containing:

- `run_id`
- `crate_code`
- `pcap`
- packet index
- packet hash
- total duration
- OSI timings when `parse_timing` is enabled

Run it with:

```bash
cd tools/lab && cargo run -p benchmark_db --release
```

Output files are written to:

```text
~/.local/share/packet_parser_bench/jsonl/
```

The optional `tools/lab/docker-compose.yml` pipeline can ingest those JSONL files into
Postgres and display them in Grafana. This is not required for the standalone
`verbench` HTML report.

## Examples

The `examples/` directory contains several useful entry points:

```bash
cargo run --example parse_tcp
cargo run --example parse_hex_dump
cargo run --example pars_quic
cargo run --example parse_pgadm
```
