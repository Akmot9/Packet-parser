// Fuzz du decodeur syslog : priorite, version de la RFC 5424 et son en-tete,
// trames de la RFC 6587 (comptage d'octets ou LF) et leur iteration. Ni
// panic ni boucle ; quand le decodage reussit, la priorite relue a la main
// est celle du message, le contenu est la fin exacte de l'entree, chaque
// emprunt pointe dans l'entree, une trame ne consomme jamais plus que ce
// qu'elle annonce et l'iterateur rend les memes trames que des `try_from`
// enchaines.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::syslog::{SyslogFrame, SyslogMessage};
use seeds::{inside, replay_mutated};

// The-Ultimate-PCAP.pcapng, trame 2248 : datagramme d'un routeur Cisco,
// format BSD.
const CISCO: &[u8] =
    b"<189>72: Mar  3 19:57:17.371: %LINK-5-CHANGED: Interface GigabitEthernet0/2, changed sta\
    te to administratively down";

// Meme capture, trame 32915 : un message termine par LF sur TCP 514.
const LINE: &[u8] = b"<30>May 20 15:29:21 pi05-random systemd[1]: Time has been changed\n";

// Meme capture, trame 32952 : une trame a comptage d'octets (FortiGate).
const COUNTED: &[u8] =
    b"600 <189>date=2021-05-20 time=15:30:53 devname=\"fg2\" devid=\"FWF61ETK18000066\" logid=\
    \"0001000014\" type=\"traffic\" subtype=\"local\" level=\"notice\" vd=\"root\" eventtime\
    =1621517453701194386 tz=\"+0200\" srcip=84.146.128.167 srcport=52235 srcintf=\"wan1\" sr\
    cintfrole=\"wan\" dstip=194.247.5.1 dstport=8443 dstintf=\"unknown0\" dstintfrole=\"unde\
    fined\" sessionid=10119734 proto=6 action=\"close\" policyid=2 policytype=\"local-in-pol\
    icy\" service=\"HTTPS-8443\" dstcountry=\"Germany\" srccountry=\"Germany\" trandisp=\"no\
    op\" app=\"Web Management(HTTPS)\" duration=6 sentbyte=5501 rcvdbyte=4207 sentpkt=13 rcv\
    dpkt=11 appcat=\"unscanned\"";

// ndpi_syslog.pcap, trame 81 : RFC 5424 sur TCP.
const RFC5424: &[u8] =
    b"<22>1 2021-04-18T14:51:48+04:00 iPhone7,2 com.dts.freefireth - - - [1.60.1-4.0.5] <60BF7\
    143-144> <+[BeeTalk handleDidBecomeActive]:321>\n";

// ndpi_rsh-syslog-false-positive.pcap, trame 4 : trois messages termines
// par LF dans un segment.
const THREE_LINES: &[u8] =
    b"<167>2016-05-24T09:50:52.957910+02:00 ldap01 slapd[34534]: conn=1159023 op=45 SRCH attr=\
    objectClass cn userPassword gidNumber modifyTimestamp modifyTimestamp\n<167>2016-05-24T0\
    9:50:52.957916+02:00 ldap01 slapd[34534]: conn=1159023 op=45 ENTRY dn=\"cn=intsir-admins\
    ,ou=groupes,dc=in,dc=phm,dc=education,dc=gouv,dc=fr\"\n<167>2016-05-24T09:50:52.957920+0\
    2:00 ldap01 slapd[34534]: conn=1159023 op=45 SEARCH RESULT tag=101 err=0 nentries=1 text\
    =\n";

/// La priorite relue a la main : `<`, un a trois chiffres sans zero de
/// tete, `>`, de 0 a 191. Rend la valeur et sa longueur sur le fil.
fn priority(data: &[u8]) -> Option<(u8, usize)> {
    if data.first() != Some(&b'<') {
        return None;
    }
    let close = data.iter().position(|byte| *byte == b'>')?;
    let digits = &data[1..close];
    if digits.is_empty() || digits.len() > 3 || (digits.len() > 1 && digits[0] == b'0') {
        return None;
    }
    let text = std::str::from_utf8(digits).ok()?;
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let value: u16 = text.parse().ok()?;
    (value <= 191).then(|| (value as u8, close + 1))
}

fn check_message(data: &[u8], message: &SyslogMessage<'_>) {
    let (value, length) = priority(data).expect("priorite que l'oracle ne lit pas");
    assert_eq!(message.priority, value);
    assert_eq!(
        u16::from(message.facility()) * 8 + u16::from(message.severity()),
        u16::from(value)
    );
    assert!(message.facility() <= 23 && message.severity() <= 7);
    assert!(inside(data, message.content));
    // Le contenu est la fin de l'entree, derriere la priorite et, pour la
    // RFC 5424, derriere `1 `.
    let after = &data[length..];
    match message.version {
        Some(version) => {
            assert_eq!(version, 1);
            assert_eq!(after.strip_prefix(b"1 "), Some(message.content));
        }
        None => {
            assert!(!after.starts_with(b"1 "));
            assert_eq!(after, message.content);
        }
    }
    match message.header() {
        Some(header) => {
            assert!(message.version.is_some());
            let fields = [
                header.timestamp,
                header.hostname,
                header.app_name,
                header.procid,
                header.msgid,
            ];
            for field in fields.into_iter().flatten() {
                assert!(inside(message.content, field.as_bytes()));
                assert!(!field.is_empty() && field != "-");
                assert!(field.bytes().all(|byte| byte.is_ascii_graphic()));
            }
            assert!(inside(message.content, header.rest));
            // Cinq champs et leurs separateurs precedent la suite.
            assert!(message.content.len() >= header.rest.len() + 9);
        }
        None => {
            // Cinq champs imprimables suivis d'une espace font un en-tete.
            let mut fields = message.content.splitn(6, |byte| *byte == b' ');
            let complete = (0..5).all(|_| {
                fields.next().is_some_and(|field| {
                    !field.is_empty() && field.iter().all(u8::is_ascii_graphic)
                })
            }) && fields.next().is_some();
            assert!(message.version.is_none() || !complete);
        }
    }
}

fn check_frame(data: &[u8], frame: &SyslogFrame<'_>) {
    assert!(inside(data, frame.rest()));
    assert!(inside(data, frame.message.content));
    let consumed = data.len() - frame.rest().len();
    let message = match frame.octet_count {
        Some(count) => {
            // `MSG-LEN SP`, puis au plus MSG-LEN octets.
            let prefix = format!("{count} ");
            assert!(count > 0);
            assert!(data.starts_with(prefix.as_bytes()));
            let available = data.len() - prefix.len();
            let announced = usize::try_from(count).unwrap_or(usize::MAX);
            assert_eq!(consumed, prefix.len() + announced.min(available));
            assert_eq!(frame.is_truncated(), available < announced);
            &data[prefix.len()..consumed]
        }
        None => {
            // Jusqu'au premier LF, qui n'est pas dans le message.
            match data.iter().position(|byte| *byte == b'\n') {
                Some(end) => {
                    assert!(!frame.is_truncated());
                    assert_eq!(consumed, end + 1);
                    &data[..end]
                }
                None => {
                    assert!(frame.is_truncated());
                    assert_eq!(consumed, data.len());
                    data
                }
            }
        }
    };
    assert!(frame.rest().is_empty() || !frame.is_truncated());
    assert_eq!(SyslogMessage::try_from(message), Ok(frame.message));
    check_message(message, &frame.message);
}

fn exercise(data: &[u8]) {
    match SyslogMessage::try_from(data) {
        Ok(message) => check_message(data, &message),
        Err(_) => assert!(priority(data).is_none(), "priorite valide refusee"),
    }

    // L'iterateur : au plus une trame par quatre octets (`<0>` et son LF),
    // les memes trames que des `try_from` enchaines, et rien apres une
    // erreur.
    let mut rest = data;
    let mut count = 0usize;
    let mut failed = false;
    for item in SyslogFrame::frames(data) {
        assert!(!failed, "un element apres une erreur");
        assert!(!rest.is_empty());
        count += 1;
        assert_eq!(item, SyslogFrame::try_from(rest));
        match item {
            Ok(frame) => {
                check_frame(rest, &frame);
                rest = frame.rest();
            }
            Err(_) => failed = true,
        }
    }
    assert!(failed || rest.is_empty());
    assert!(count <= data.len() / 4 + 1);
    assert_eq!(count == 0, data.is_empty());
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(
        &[CISCO, LINE, COUNTED, RFC5424, THREE_LINES],
        data,
        exercise,
    );
});
