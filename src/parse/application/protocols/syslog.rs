// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Syslog (#374), le journal des equipements et des systemes envoye a un
//! collecteur : format BSD de la RFC 3164, format de la RFC 5424, sur UDP
//! 514 (RFC 5426) ou sur TCP (RFC 6587).
//!
//! Un message s'ouvre par sa priorite, `<PRI>`, de 0 a 191 : la facilite
//! (qui parle) fois huit, plus la gravite. La RFC 5424 la fait suivre de sa
//! version, `1`, puis d'un en-tete de cinq champs separes par une espace
//! ([`SyslogMessage::header`]). Le format BSD n'a pas d'en-tete fiable : les
//! equipements ecrivent ce qu'ils veulent derriere la priorite, et le
//! contenu est rendu tel quel.
//!
//! Un datagramme UDP porte un message ([`SyslogMessage`]). Un segment TCP
//! porte des trames ([`SyslogFrame`]), sous l'un des deux cadrages de la RFC
//! 6587 : le comptage d'octets (`MSG-LEN SP SYSLOG-MSG`) ou le message
//! termine par LF.
//!
//! Detection : regles a port sur UDP 514, TCP 514 et TCP 601. La sonde
//! exige la priorite : trois a cinq octets ne font pas une sonde aveugle, et
//! un texte sans priorite n'a pas de signature. TCP 514 est aussi le port de
//! `rsh`, dont les segments ne s'ouvrent pas ainsi. Le port 6514 (RFC 5425)
//! est du TLS.
//!
//! Limites, sans etat : un message plus long que son segment est coupe
//! ([`SyslogFrame::is_truncated`]) et les segments de suite restent
//! `Unknown`. Un message a LF interne n'est pas distingue de deux messages :
//! chaque ligne doit s'ouvrir par une priorite.

use std::convert::TryFrom;

use crate::errors::application::syslog::SyslogError;

/// One syslog message: a UDP datagram, or the message of a
/// [`SyslogFrame`].
///
/// ```mermaid
/// ---
/// title: SyslogMessage
/// ---
/// packet-beta
/// 0-7: "'<'"
/// 8-31: "PRI, 1 to 3 digits (facility * 8 + severity)"
/// 32-39: "'>'"
/// 40-55: "'1' SP (RFC 5424 only)"
/// 56-127: "content (RFC 5424: TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG])"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SyslogMessage<'a> {
    /// The priority, from 0 to 191: [`SyslogMessage::facility`] times
    /// eight, plus [`SyslogMessage::severity`].
    pub priority: u8,
    /// The version of RFC 5424, `Some(1)`, or `None` for the BSD format of
    /// RFC 3164.
    pub version: Option<u8>,
    /// What follows the priority, or the version and its space, up to the
    /// end of the message.
    pub content: &'a [u8],
}

impl<'a> SyslogMessage<'a> {
    /// The facility, from 0 (kernel) to 23 (local7).
    pub fn facility(&self) -> u8 {
        self.priority >> 3
    }

    /// The severity, from 0 (emergency) to 7 (debug).
    pub fn severity(&self) -> u8 {
        self.priority & 0x07
    }

    /// The header of an RFC 5424 message (§6.2). `None` for the BSD format,
    /// or when the five fields are not all there.
    pub fn header(&self) -> Option<SyslogHeader<'a>> {
        self.version?;
        let mut rest = self.content;
        let mut fields = [None; 5];
        for (index, field) in fields.iter_mut().enumerate() {
            let (value, after) = checks::extract_header_field(rest, index == 4)?;
            *field = value;
            rest = after;
        }
        let [timestamp, hostname, app_name, procid, msgid] = fields;
        Some(SyslogHeader {
            timestamp,
            hostname,
            app_name,
            procid,
            msgid,
            rest,
        })
    }
}

impl<'a> TryFrom<&'a [u8]> for SyslogMessage<'a> {
    type Error = SyslogError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (priority, after) = checks::extract_priority(bytes)?;
        let (version, content) = checks::extract_version(after);
        Ok(Self {
            priority,
            version,
            content,
        })
    }
}

/// Header of an RFC 5424 message ([`SyslogMessage::header`]). A field is
/// `None` when the message writes the nil value, `-`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SyslogHeader<'a> {
    /// Timestamp, in the format of RFC 3339.
    pub timestamp: Option<&'a str>,
    /// Name or address of the machine that wrote the message.
    pub hostname: Option<&'a str>,
    /// Name of the application.
    pub app_name: Option<&'a str>,
    /// Identifier of the process.
    pub procid: Option<&'a str>,
    /// Type of the message.
    pub msgid: Option<&'a str>,
    /// What follows the header: the structured data, then the text of the
    /// message.
    pub rest: &'a [u8],
}

/// One frame of syslog over TCP (RFC 6587), the first of the bytes it is
/// read from.
///
/// ```mermaid
/// ---
/// title: SyslogFrame, octet counting (RFC 6587 §3.4.1)
/// ---
/// packet-beta
/// 0-23: "MSG-LEN, 1 to 10 digits"
/// 24-31: "SP"
/// 32-95: "SYSLOG-MSG (MSG-LEN bytes)"
/// ```
///
/// ```mermaid
/// ---
/// title: SyslogFrame, non-transparent framing (RFC 6587 §3.4.2)
/// ---
/// packet-beta
/// 0-87: "SYSLOG-MSG (opens with '<')"
/// 88-95: "LF"
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SyslogFrame<'a> {
    /// The length the frame announces, under octet counting; `None` for a
    /// message that ends with LF.
    pub octet_count: Option<u32>,
    /// The message. Its content stops at the end of the segment when the
    /// frame is cut, and never holds the LF that ends the frame.
    pub message: SyslogMessage<'a>,
    is_truncated: bool,
    rest: &'a [u8],
}

impl<'a> SyslogFrame<'a> {
    /// `true` when the frame goes on in the next TCP segment: fewer bytes
    /// than announced, or no LF.
    pub fn is_truncated(&self) -> bool {
        self.is_truncated
    }

    /// The bytes of the segment that follow this frame: another frame, or
    /// nothing.
    pub fn rest(&self) -> &'a [u8] {
        self.rest
    }

    /// The frames of a TCP segment, in order. The iterator stops after the
    /// first error, or after a frame that its segment cuts.
    pub fn frames(payload: &'a [u8]) -> SyslogFrames<'a> {
        SyslogFrames { rest: payload }
    }

    /// Sonde des regles a port TCP : des trames bien formees qui pavent le
    /// segment. Seule la derniere peut etre coupee par le segment.
    pub(crate) fn is_port_match(payload: &'a [u8]) -> bool {
        !payload.is_empty() && Self::frames(payload).all(|frame| frame.is_ok())
    }
}

impl<'a> TryFrom<&'a [u8]> for SyslogFrame<'a> {
    type Error = SyslogError;

    fn try_from(bytes: &'a [u8]) -> Result<Self, Self::Error> {
        let (octet_count, after) = checks::extract_octet_count(bytes)?;
        let (message, rest, is_truncated) = match octet_count {
            Some(count) => checks::extract_counted_message(after, count),
            None => checks::extract_line(after),
        };
        Ok(Self {
            octet_count,
            message: SyslogMessage::try_from(message)?,
            is_truncated,
            rest,
        })
    }
}

/// Iterator over the frames of a TCP segment ([`SyslogFrame::frames`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SyslogFrames<'a> {
    rest: &'a [u8],
}

impl<'a> Iterator for SyslogFrames<'a> {
    type Item = Result<SyslogFrame<'a>, SyslogError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let frame = SyslogFrame::try_from(self.rest);
        // Apres une erreur, la suite du segment n'a plus de frontiere.
        self.rest = frame.as_ref().map_or(&[], |frame| frame.rest);
        Some(frame)
    }
}

mod checks {
    use super::SyslogError;

    /// Le plus court des messages : `<0>`.
    const MIN_LENGTH: usize = 3;
    /// La plus grande priorite : facilite 23, gravite 7.
    const MAX_PRIORITY: u16 = 191;
    /// Chiffres d'une priorite, au plus.
    const MAX_PRIORITY_DIGITS: usize = 3;
    /// Chiffres d'un comptage d'octets, au plus : ceux de 2^32 - 1.
    const MAX_COUNT_DIGITS: usize = 10;
    /// La version de la RFC 5424 et son espace.
    const VERSION_1: &[u8] = b"1 ";

    /// Le nombre que forment les chiffres en tete de `bytes`, et leur
    /// nombre. Pas de zero de tete, sauf le nombre zero.
    fn extract_number(bytes: &[u8], max_digits: usize) -> Option<(u64, usize)> {
        let digits = bytes
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        if digits == 0 || digits > max_digits || (digits > 1 && bytes[0] == b'0') {
            return None;
        }
        let value = bytes[..digits]
            .iter()
            .fold(0u64, |value, digit| value * 10 + u64::from(digit - b'0'));
        Some((value, digits))
    }

    /// La priorite, `<` 1 a 3 chiffres `>`, et ce qui la suit.
    pub(super) fn extract_priority(bytes: &[u8]) -> Result<(u8, &[u8]), SyslogError> {
        let Some((&first, after)) = bytes.split_first() else {
            return Err(SyslogError::TooShort {
                expected: MIN_LENGTH,
                actual: 0,
            });
        };
        if first != b'<' {
            return Err(SyslogError::MissingPriority(first));
        }
        if bytes.len() < MIN_LENGTH {
            return Err(SyslogError::TooShort {
                expected: MIN_LENGTH,
                actual: bytes.len(),
            });
        }
        let (value, digits) =
            extract_number(after, MAX_PRIORITY_DIGITS).ok_or(SyslogError::InvalidPriority)?;
        let priority = u8::try_from(value)
            .ok()
            .filter(|priority| u16::from(*priority) <= MAX_PRIORITY)
            .ok_or(SyslogError::InvalidPriority)?;
        match after.get(digits) {
            Some(b'>') => Ok((priority, &after[digits + 1..])),
            _ => Err(SyslogError::InvalidPriority),
        }
    }

    /// La version de la RFC 5424, `1` suivi d'une espace, et le contenu.
    /// Sans elle, le message est au format BSD.
    pub(super) fn extract_version(after_priority: &[u8]) -> (Option<u8>, &[u8]) {
        match after_priority.strip_prefix(VERSION_1) {
            Some(content) => (Some(1), content),
            None => (None, after_priority),
        }
    }

    /// Un champ de l'en-tete de la RFC 5424 : des caracteres ASCII
    /// imprimables sans espace, `-` pour une valeur absente, puis une
    /// espace, que le dernier champ peut ne pas avoir en fin de message.
    pub(super) fn extract_header_field(
        bytes: &[u8],
        is_last: bool,
    ) -> Option<(Option<&str>, &[u8])> {
        let length = bytes
            .iter()
            .take_while(|byte| byte.is_ascii_graphic())
            .count();
        let (field, after) = bytes.split_at(length);
        let rest = match after.split_first() {
            Some((b' ', rest)) => rest,
            None if is_last => after,
            _ => return None,
        };
        let field = std::str::from_utf8(field)
            .ok()
            .filter(|field| !field.is_empty())?;
        Some(((field != "-").then_some(field), rest))
    }

    /// Le comptage d'octets d'une trame, `MSG-LEN SP`, et ce qui le suit ;
    /// `None` pour une trame qui s'ouvre par un message.
    pub(super) fn extract_octet_count(bytes: &[u8]) -> Result<(Option<u32>, &[u8]), SyslogError> {
        if !bytes.first().is_some_and(u8::is_ascii_digit) {
            return Ok((None, bytes));
        }
        let (value, digits) =
            extract_number(bytes, MAX_COUNT_DIGITS).ok_or(SyslogError::InvalidOctetCount)?;
        let count = u32::try_from(value)
            .ok()
            .filter(|count| *count > 0)
            .ok_or(SyslogError::InvalidOctetCount)?;
        match bytes.get(digits) {
            Some(b' ') => Ok((Some(count), &bytes[digits + 1..])),
            _ => Err(SyslogError::InvalidOctetCount),
        }
    }

    /// Le message d'une trame a comptage d'octets, la suite du segment, et
    /// si le segment coupe la trame.
    pub(super) fn extract_counted_message(bytes: &[u8], count: u32) -> (&[u8], &[u8], bool) {
        let count = usize::try_from(count).unwrap_or(usize::MAX);
        let (message, rest) = bytes.split_at(count.min(bytes.len()));
        (message, rest, message.len() < count)
    }

    /// Le message d'une trame terminee par LF, sans son LF, la suite du
    /// segment, et si le segment finit avant le LF.
    pub(super) fn extract_line(bytes: &[u8]) -> (&[u8], &[u8], bool) {
        match bytes.iter().position(|byte| *byte == b'\n') {
            Some(end) => (&bytes[..end], &bytes[end + 1..], false),
            None => (bytes, &[], true),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Datagramme reel d'un routeur Cisco, format BSD :
    /// pcaps_exemple/The-Ultimate-PCAP.pcapng, trame 2248 (115 octets).
    const CISCO: &[u8] =
        b"<189>72: Mar  3 19:57:17.371: %LINK-5-CHANGED: Interface GigabitEthernet0/2, changed s\
        tate to administratively down";

    /// Segment reel de TCP 514, un message termine par LF (rsyslog) : meme
    /// capture, trame 32915 (66 octets).
    const LINE: &[u8] = b"<30>May 20 15:29:21 pi05-random systemd[1]: Time has been changed\n";

    /// Segment reel de TCP 514, une trame a comptage d'octets (FortiGate) :
    /// meme capture, trame 32952 (604 octets).
    const COUNTED: &[u8] =
        b"600 <189>date=2021-05-20 time=15:30:53 devname=\"fg2\" devid=\"FWF61ETK18000066\" lo\
        gid=\"0001000014\" type=\"traffic\" subtype=\"local\" level=\"notice\" vd=\"root\" e\
        venttime=1621517453701194386 tz=\"+0200\" srcip=84.146.128.167 srcport=52235 srcintf\
        =\"wan1\" srcintfrole=\"wan\" dstip=194.247.5.1 dstport=8443 dstintf=\"unknown0\" ds\
        tintfrole=\"undefined\" sessionid=10119734 proto=6 action=\"close\" policyid=2 polic\
        ytype=\"local-in-policy\" service=\"HTTPS-8443\" dstcountry=\"Germany\" srccountry=\
        \"Germany\" trandisp=\"noop\" app=\"Web Management(HTTPS)\" duration=6 sentbyte=5501 r\
        cvdbyte=4207 sentpkt=13 rcvdpkt=11 appcat=\"unscanned\"";

    /// Segment reel, RFC 5424, sur TCP 52173 :
    /// pcaps_exemple/protocols/syslog/ndpi_syslog.pcap, trame 81 (136
    /// octets).
    const RFC5424_TCP: &[u8] =
        b"<22>1 2021-04-18T14:51:48+04:00 iPhone7,2 com.dts.freefireth - - - [1.60.1-4.0.5] <6\
        0BF7143-144> <+[BeeTalk handleDidBecomeActive]:321>\n";

    /// Datagramme reel, RFC 5424 (pfSense) : meme capture, trame 85 (475
    /// octets).
    const RFC5424_UDP: &[u8] =
        b"<45>1 2022-03-02T12:39:47.689392-01:00 pfSense.localdomain suricata 37046 - - {\"tim\
        estamp\": \"2022-03-02T12:39:47.561523-0100\", \"flow_id\": 381079355822573, \"in_if\
        ace\": \"bge9\", \"event_type\": \"ssh\", \"src_ip\": \"106.13.223.1\", \"src_port\"\
        : 52532, \"dest_ip\": \"195.120.165.134\", \"dest_port\": 2222, \"proto\": \"TCP\", \"\
        ssh\": {\"client\": {\"proto_version\": \"2.0\", \"software_version\": \"libssh-0.6.\
        3\"}, \"server\": {\"proto_version\": \"2.0\", \"software_version\": \"OpenSSH_6.7p1 D\
        ebian-5+deb8u3\"}}}";

    /// Segment reel de TCP 514, trois messages termines par LF :
    /// pcaps_exemple/protocols/syslog/ndpi_rsh-syslog-false-positive.pcap,
    /// trame 4 (438 octets).
    const THREE_LINES: &[u8] =
        b"<167>2016-05-24T09:50:52.957910+02:00 ldap01 slapd[34534]: conn=1159023 op=45 SRCH a\
        ttr=objectClass cn userPassword gidNumber modifyTimestamp modifyTimestamp\n<167>2016\
        -05-24T09:50:52.957916+02:00 ldap01 slapd[34534]: conn=1159023 op=45 ENTRY dn=\"cn=i\
        ntsir-admins,ou=groupes,dc=in,dc=phm,dc=education,dc=gouv,dc=fr\"\n<167>2016-05-24T0\
        9:50:52.957920+02:00 ldap01 slapd[34534]: conn=1159023 op=45 SEARCH RESULT tag=101 e\
        rr=0 nentries=1 text=\n";

    #[test]
    fn bsd_datagram_is_read() {
        let message = SyslogMessage::try_from(CISCO).expect("message Cisco");
        assert_eq!(message.priority, 189);
        assert_eq!((message.facility(), message.severity()), (23, 5));
        assert_eq!(message.version, None);
        assert!(
            message
                .content
                .starts_with(b"72: Mar  3 19:57:17.371: %LINK-5-CHANGED")
        );
        assert_eq!(message.content.len(), CISCO.len() - 5);
        assert_eq!(message.header(), None);
    }

    #[test]
    fn rfc5424_header_is_read() {
        let message = SyslogMessage::try_from(RFC5424_UDP).expect("message pfSense");
        assert_eq!((message.facility(), message.severity()), (5, 5));
        assert_eq!(message.version, Some(1));
        let header = message.header().expect("en-tete");
        assert_eq!(header.timestamp, Some("2022-03-02T12:39:47.689392-01:00"));
        assert_eq!(header.hostname, Some("pfSense.localdomain"));
        assert_eq!(header.app_name, Some("suricata"));
        assert_eq!(header.procid, Some("37046"));
        assert_eq!(header.msgid, None);
        assert!(header.rest.starts_with(b"- {\"timestamp\""));

        // Sur TCP, les valeurs absentes de l'identifiant de processus et de
        // l'identifiant de message.
        let frame = SyslogFrame::try_from(RFC5424_TCP).expect("trame");
        assert_eq!(frame.octet_count, None);
        assert!(!frame.is_truncated());
        assert!(frame.rest().is_empty());
        let header = frame.message.header().expect("en-tete");
        assert_eq!(header.timestamp, Some("2021-04-18T14:51:48+04:00"));
        assert_eq!(header.hostname, Some("iPhone7,2"));
        assert_eq!(header.app_name, Some("com.dts.freefireth"));
        assert_eq!((header.procid, header.msgid), (None, None));
        assert!(header.rest.starts_with(b"- [1.60.1-4.0.5]"));
    }

    #[test]
    fn line_frame_is_read() {
        let frame = SyslogFrame::try_from(LINE).expect("trame");
        assert_eq!(frame.octet_count, None);
        assert_eq!(frame.message.priority, 30);
        assert_eq!((frame.message.facility(), frame.message.severity()), (3, 6));
        // Le LF finit la trame : il n'est pas dans le contenu.
        assert_eq!(
            frame.message.content,
            b"May 20 15:29:21 pi05-random systemd[1]: Time has been changed"
        );
        assert!(!frame.is_truncated());
        assert!(frame.rest().is_empty());
        assert!(SyslogFrame::is_port_match(LINE));
    }

    #[test]
    fn counted_frame_is_read() {
        let frame = SyslogFrame::try_from(COUNTED).expect("trame");
        assert_eq!(frame.octet_count, Some(600));
        assert_eq!(frame.message.priority, 189);
        // Le comptage couvre la priorite, cinq octets, et le contenu.
        assert_eq!(frame.message.content.len(), 595);
        assert!(frame.message.content.starts_with(b"date=2021-05-20"));
        assert!(!frame.is_truncated());
        assert!(frame.rest().is_empty());
        assert!(SyslogFrame::is_port_match(COUNTED));
    }

    #[test]
    fn frames_of_a_segment_are_iterated() {
        let frames: Vec<_> = SyslogFrame::frames(THREE_LINES)
            .collect::<Result<_, _>>()
            .expect("trois trames");
        assert_eq!(frames.len(), 3);
        assert!(frames.iter().all(|frame| frame.message.priority == 167));
        assert!(frames.iter().all(|frame| !frame.is_truncated()));
        assert!(frames[2].rest().is_empty());
        assert!(frames[2].message.content.ends_with(b"nentries=1 text="));
        assert!(SyslogFrame::is_port_match(THREE_LINES));

        // Deux trames comptees a la suite : la trame reelle, deux fois.
        let twice = [COUNTED, COUNTED].concat();
        let frames: Vec<_> = SyslogFrame::frames(&twice)
            .collect::<Result<_, _>>()
            .expect("deux trames");
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].rest(), COUNTED);
    }

    /// Les trames reelles coupees a un octet donne, comme par un segment.
    #[test]
    fn cut_frames_are_truncated() {
        let frame = SyslogFrame::try_from(&COUNTED[..100]).expect("trame coupee");
        assert_eq!(frame.octet_count, Some(600));
        assert!(frame.is_truncated());
        assert_eq!(frame.message.content.len(), 100 - 9);
        assert!(frame.rest().is_empty());

        let frame = SyslogFrame::try_from(&LINE[..40]).expect("ligne coupee");
        assert!(frame.is_truncated());
        assert_eq!(frame.message.content.len(), 40 - 4);

        // La derniere ligne d'un segment peut etre coupee, pas les autres.
        let cut = &THREE_LINES[..THREE_LINES.len() - 1];
        let frames: Vec<_> = SyslogFrame::frames(cut).collect();
        assert_eq!(frames.len(), 3);
        assert!(frames[2].as_ref().is_ok_and(SyslogFrame::is_truncated));
        assert!(SyslogFrame::is_port_match(cut));

        // Un comptage que la priorite ne suit pas dans le segment.
        assert!(SyslogFrame::try_from(&COUNTED[..4]).is_err());
        assert!(SyslogFrame::try_from(&COUNTED[..7]).is_err());
    }

    /// Octets synthetiques : les bornes de la priorite.
    #[test]
    fn priority_is_checked() {
        let priority = |bytes: &[u8]| SyslogMessage::try_from(bytes).map(|m| m.priority);
        assert_eq!(priority(b"<0>"), Ok(0));
        assert_eq!(priority(b"<191>x"), Ok(191));
        assert_eq!(priority(b"<192>x"), Err(SyslogError::InvalidPriority));
        assert_eq!(priority(b"<999>x"), Err(SyslogError::InvalidPriority));
        assert_eq!(priority(b"<00>x"), Err(SyslogError::InvalidPriority));
        assert_eq!(priority(b"<013>x"), Err(SyslogError::InvalidPriority));
        assert_eq!(priority(b"<1234>x"), Err(SyslogError::InvalidPriority));
        assert_eq!(priority(b"<>xx"), Err(SyslogError::InvalidPriority));
        assert_eq!(priority(b"<13 x"), Err(SyslogError::InvalidPriority));
        assert_eq!(priority(b"<13"), Err(SyslogError::InvalidPriority));
        assert_eq!(priority(b"x<13>"), Err(SyslogError::MissingPriority(b'x')));
        assert_eq!(
            priority(b"<1"),
            Err(SyslogError::TooShort {
                expected: 3,
                actual: 2
            })
        );
        assert_eq!(
            priority(b""),
            Err(SyslogError::TooShort {
                expected: 3,
                actual: 0
            })
        );
    }

    /// Octets synthetiques : la version, et un en-tete incomplet.
    #[test]
    fn version_needs_its_space() {
        let message = SyslogMessage::try_from(&b"<13>1 - host app - - - text"[..]).expect("5424");
        assert_eq!(message.version, Some(1));
        let header = message.header().expect("en-tete");
        assert_eq!(header.timestamp, None);
        assert_eq!(header.hostname, Some("host"));
        assert_eq!(header.rest, b"- text");

        // `1:` ouvre le numero de sequence d'un message BSD.
        let message = SyslogMessage::try_from(&b"<13>1: text"[..]).expect("BSD");
        assert_eq!(message.version, None);
        assert_eq!(message.content, b"1: text");

        // Quatre champs sur cinq, un champ vide, un octet non imprimable.
        for content in [
            &b"<13>1 - host app -"[..],
            b"<13>1 -  app - - -",
            b"<13>1 - h\x01 a - - -",
        ] {
            let message = SyslogMessage::try_from(content).expect("message");
            assert_eq!(message.version, Some(1));
            assert_eq!(message.header(), None);
        }
        // Le cinquieme champ peut finir le message.
        let message = SyslogMessage::try_from(&b"<13>1 - host app - ID47"[..]).expect("5424");
        let header = message.header().expect("en-tete");
        assert_eq!(header.msgid, Some("ID47"));
        assert!(header.rest.is_empty());
    }

    /// Octets synthetiques : le comptage d'octets.
    #[test]
    fn octet_count_is_checked() {
        let count = |bytes: &[u8]| SyslogFrame::try_from(bytes).map(|frame| frame.octet_count);
        assert_eq!(count(b"5 <13>x"), Ok(Some(5)));
        assert_eq!(count(b"0 <13>x"), Err(SyslogError::InvalidOctetCount));
        assert_eq!(count(b"05 <13>x"), Err(SyslogError::InvalidOctetCount));
        assert_eq!(count(b"5<13>x"), Err(SyslogError::InvalidOctetCount));
        assert_eq!(count(b"5"), Err(SyslogError::InvalidOctetCount));
        assert_eq!(count(b"4294967295 <13>x"), Ok(Some(u32::MAX)));
        assert_eq!(
            count(b"4294967296 <13>x"),
            Err(SyslogError::InvalidOctetCount)
        );
        assert_eq!(
            count(b"12345678901 <13>x"),
            Err(SyslogError::InvalidOctetCount)
        );
        // Un comptage plus court que la priorite.
        assert_eq!(
            count(b"2 <13>x"),
            Err(SyslogError::TooShort {
                expected: 3,
                actual: 2
            })
        );
        // Ce que le comptage laisse est la trame suivante.
        let frame = SyslogFrame::try_from(&b"5 <13>x<14>y\n"[..]).expect("trame");
        assert_eq!(frame.message.content, b"x");
        assert_eq!(frame.rest(), b"<14>y\n");
    }

    /// Octets synthetiques : ce que la sonde des ports TCP refuse.
    #[test]
    fn port_probe_needs_frames_that_tile_the_segment() {
        assert!(SyslogFrame::is_port_match(b"<13>a\n<14>b\n"));
        assert!(SyslogFrame::is_port_match(b"<13>a\n<14>b"));
        assert!(!SyslogFrame::is_port_match(b""));
        // La suite d'un message coupe, puis un message entier.
        assert!(!SyslogFrame::is_port_match(b"end of a message\n<14>b\n"));
        // Une ligne sans priorite, une ligne vide.
        assert!(!SyslogFrame::is_port_match(b"<13>a\nb\n"));
        assert!(!SyslogFrame::is_port_match(b"<13>a\n\n"));
        // Le debut d'une session rsh : le port d'erreur, puis des noms.
        assert!(!SyslogFrame::is_port_match(b"1021\0root\0root\0ls\0"));

        // L'iterateur s'arrete apres la premiere erreur.
        let mut frames = SyslogFrame::frames(b"<13>a\nb\n<14>c\n");
        assert!(frames.next().is_some_and(|frame| frame.is_ok()));
        assert!(frames.next().is_some_and(|frame| frame.is_err()));
        assert!(frames.next().is_none());
    }
}
