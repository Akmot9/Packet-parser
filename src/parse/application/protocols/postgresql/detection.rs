// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Detection de PostgreSQL pour le dispatch : la garde a cout constant, la
//! sonde aveugle stricte ([`is_likely_postgresql_payload`]) et la sonde de
//! port tolerante ([`is_plausible_postgresql_payload`]), avec leurs
//! heuristiques par type de message.

use super::*;

/// Garde a cout constant devant le parse integral (audit 8.1.0 §4.3, issue
/// #20) : tout payload PostgreSQL commence soit par un message sans octet de
/// type (longueur BE sur 4 octets, au moins 8 pour porter un code protocole)
/// soit par un message type (octet ASCII imprimable + longueur BE >= 4).
/// Volontairement plus lache que le parse complet — aucune borne superieure,
/// aucun code impose — pour ne jamais rejeter un payload qu'il accepterait :
/// elle ne sert qu'a ecarter sans allocation le trafic arbitraire qui
/// coutait un parse entier (x60 mesure sur un pseudo-payload hostile).
pub(super) fn has_plausible_first_message_header(payload: &[u8]) -> bool {
    if payload.len() >= 8 {
        let untyped_length = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        if untyped_length >= 8 {
            return true;
        }
    }
    if payload.len() >= 5 {
        let typed_length = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        if payload[0].is_ascii_graphic() && typed_length >= 4 {
            return true;
        }
    }
    false
}

pub(crate) fn is_likely_postgresql_payload(payload: &[u8]) -> bool {
    if !has_plausible_first_message_header(payload) {
        return false;
    }
    let Ok(packet) = PostgreSqlPacket::try_from(payload) else {
        return false;
    };

    !packet.messages.is_empty()
        && packet
            .messages
            .iter()
            .all(message_has_detection_compatible_shape)
        && packet
            .messages
            .iter()
            .any(message_has_strong_detection_evidence)
}

/// Sur le port 5432 ou un port declare (#98) : un payload qui se decode et
/// dont chaque message a une forme compatible suffit — un `Terminate`, un
/// `ReadyForQuery` ou un mot de passe seuls dans leur segment, ou la reponse
/// d'un octet a SSLRequest, que la sonde aveugle ne peut pas retenir. Mesure
/// sur le corpus Zeek : aucun faux positif sur HTTP et MySQL rejoues sur 5432.
pub(crate) fn is_plausible_postgresql_payload(payload: &[u8]) -> bool {
    let Ok(packet) = PostgreSqlPacket::try_from(payload) else {
        return false;
    };
    !packet.messages.is_empty()
        && packet
            .messages
            .iter()
            .all(message_has_detection_compatible_shape)
}

pub(super) fn message_has_strong_detection_evidence(message: &PostgreSqlMessage<'_>) -> bool {
    match (&message.message_type, &message.body) {
        (PostgreSqlMessageType::StartupMessage, PostgreSqlMessageBody::Startup(startup)) => {
            message.payload.last() == Some(&0) && startup_has_known_parameter(startup)
        }
        (PostgreSqlMessageType::SslRequest | PostgreSqlMessageType::GssEncRequest, _) => {
            message.length == POSTGRESQL_UNTYPED_HEADER_LEN as u32 && message.payload.is_empty()
        }
        (
            PostgreSqlMessageType::CancelRequest,
            PostgreSqlMessageBody::CancelRequest {
                process_id: _,
                secret_key,
            },
        ) => {
            postgresql_secret_key_len_is_valid(secret_key.len())
                && message.payload.len() == 4 + secret_key.len()
        }
        (PostgreSqlMessageType::Parse, PostgreSqlMessageBody::Parse(parse)) => {
            looks_like_sql(parse.query)
        }
        (PostgreSqlMessageType::Query, PostgreSqlMessageBody::Query { query }) => {
            looks_like_sql(query)
        }
        (PostgreSqlMessageType::Authentication, PostgreSqlMessageBody::Raw(body)) => {
            authentication_body_has_strong_evidence(body)
        }
        (PostgreSqlMessageType::CloseOrCommandComplete, PostgreSqlMessageBody::Raw(body)) => {
            command_complete_body_is_likely(body)
        }
        (PostgreSqlMessageType::ErrorResponseOrExecute, PostgreSqlMessageBody::Raw(body))
        | (PostgreSqlMessageType::NoticeResponse, PostgreSqlMessageBody::Raw(body)) => {
            error_or_notice_body_is_likely(body)
        }
        (PostgreSqlMessageType::ParameterStatusOrSync, PostgreSqlMessageBody::Raw(body)) => {
            parameter_status_body_is_likely(body)
        }
        (PostgreSqlMessageType::PasswordOrSaslResponse, PostgreSqlMessageBody::Raw(body)) => {
            password_body_has_strong_evidence(body)
        }
        _ => false,
    }
}

pub(super) fn message_has_detection_compatible_shape(message: &PostgreSqlMessage<'_>) -> bool {
    if message_has_strong_detection_evidence(message) {
        return true;
    }

    match (&message.message_type, &message.body) {
        (_, PostgreSqlMessageBody::Empty) => message.payload.is_empty(),
        (_, PostgreSqlMessageBody::Bind(_))
        | (_, PostgreSqlMessageBody::Execute(_))
        | (_, PostgreSqlMessageBody::CancelRequest { .. }) => true,
        (PostgreSqlMessageType::Parse, PostgreSqlMessageBody::Parse(parse)) => {
            is_plain_text(parse.statement) && is_plain_text(parse.query)
        }
        (PostgreSqlMessageType::Query, PostgreSqlMessageBody::Query { query }) => {
            is_plain_text(query)
        }
        (PostgreSqlMessageType::StartupMessage, PostgreSqlMessageBody::Startup(startup)) => {
            message.payload.last() == Some(&0)
                && !startup.parameters.is_empty()
                && startup
                    .parameters
                    .iter()
                    .all(|(key, value)| is_plain_text(key) && is_plain_text(value))
        }
        (PostgreSqlMessageType::ErrorResponseOrExecute, PostgreSqlMessageBody::Raw(body)) => {
            error_or_notice_body_is_likely(body)
        }
        (PostgreSqlMessageType::NoticeResponse, PostgreSqlMessageBody::Raw(body)) => {
            error_or_notice_body_is_likely(body)
        }
        // Forme compatible : deux C-strings, quel que soit le nom — les
        // serveurs recents en ajoutent (scram_iterations, search_path) ; la
        // preuve forte, elle, exige un nom connu.
        (PostgreSqlMessageType::ParameterStatusOrSync, PostgreSqlMessageBody::Raw(body)) => {
            body.is_empty() || parse_two_cstrings_allow_empty_value(body).is_some()
        }
        (PostgreSqlMessageType::Authentication, PostgreSqlMessageBody::Raw(body)) => {
            authentication_body_is_compatible(body)
        }
        (PostgreSqlMessageType::BackendKeyData, PostgreSqlMessageBody::Raw(body)) => {
            backend_key_data_body_is_compatible(body)
        }
        (PostgreSqlMessageType::CloseOrCommandComplete, PostgreSqlMessageBody::Raw(body)) => {
            close_body_is_likely(body) || command_complete_body_is_likely(body)
        }
        (PostgreSqlMessageType::ReadyForQuery, PostgreSqlMessageBody::Raw(body)) => {
            matches!(body, [b'I' | b'T' | b'E'])
        }
        (PostgreSqlMessageType::PasswordOrSaslResponse, PostgreSqlMessageBody::Raw(body)) => {
            password_body_is_compatible(body)
        }
        // La reponse d'un octet a SSLRequest : forme compatible sur le port,
        // jamais une preuve a l'aveugle.
        (PostgreSqlMessageType::SslResponse, PostgreSqlMessageBody::SslResponse { .. }) => true,
        (_, PostgreSqlMessageBody::Raw(_)) => true,
        _ => false,
    }
}

pub(super) fn startup_has_known_parameter(startup: &PostgreSqlStartup<'_>) -> bool {
    startup.parameters.iter().any(|(key, value)| {
        !value.is_empty()
            && matches!(
                *key,
                "user"
                    | "database"
                    | "application_name"
                    | "client_encoding"
                    | "options"
                    | "replication"
            )
    })
}

pub(super) fn looks_like_sql(query: &str) -> bool {
    let Some(token) = first_ascii_token(query) else {
        return false;
    };

    is_sql_keyword(token)
}

pub(super) fn is_sql_keyword(token: &str) -> bool {
    const SQL_KEYWORDS: &[&str] = &[
        "ABORT",
        "ALTER",
        "ANALYZE",
        "BEGIN",
        "CALL",
        "CHECKPOINT",
        "CLOSE",
        "CLUSTER",
        "COMMENT",
        "COMMIT",
        "COPY",
        "CREATE",
        "DEALLOCATE",
        "DECLARE",
        "DELETE",
        "DISCARD",
        "DO",
        "DROP",
        "EXECUTE",
        "EXPLAIN",
        "FETCH",
        "GRANT",
        "INSERT",
        "LISTEN",
        "LOAD",
        "LOCK",
        "MERGE",
        "MOVE",
        "NOTIFY",
        "PREPARE",
        "REASSIGN",
        "REFRESH",
        "REINDEX",
        "RELEASE",
        "RESET",
        "REVOKE",
        "ROLLBACK",
        "SAVEPOINT",
        "SELECT",
        "SET",
        "SHOW",
        "START",
        "TRUNCATE",
        "UNLISTEN",
        "UPDATE",
        "VACUUM",
        "VALUES",
        "WITH",
    ];

    SQL_KEYWORDS
        .iter()
        .any(|keyword| token.eq_ignore_ascii_case(keyword))
}

pub(super) fn first_ascii_token(query: &str) -> Option<&str> {
    let mut rest = query.trim_start();

    loop {
        if let Some(stripped) = rest.strip_prefix("--") {
            let newline = stripped.find('\n')?;
            rest = stripped[newline + 1..].trim_start();
            continue;
        }

        if let Some(stripped) = rest.strip_prefix("/*") {
            let end = stripped.find("*/")?;
            rest = stripped[end + 2..].trim_start();
            continue;
        }

        break;
    }

    let token_end = rest
        .bytes()
        .position(|byte| !byte.is_ascii_alphabetic())
        .unwrap_or(rest.len());

    if token_end == 0 {
        return None;
    }

    let token = &rest[..token_end];
    if !token.is_ascii() {
        return None;
    }

    Some(token)
}

/// Preuve forte d'une AuthenticationRequest (#98, corpus Zeek) : les formes
/// a longueur fixe (Ok, cleartext, Kerberos, SCM, GSS, SSPI : neuf octets
/// imposes ; MD5 : neuf octets et un sel), la liste de mecanismes SASL, et
/// les messages SCRAM du serveur (`r=…,s=…,i=…` puis `v=…`).
pub(super) fn authentication_body_has_strong_evidence(body: &[u8]) -> bool {
    if body.len() < 4 {
        return false;
    }

    let auth_code = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let rest = &body[4..];
    match auth_code {
        0 | 2 | 3 | 6 | 7 | 8 => rest.is_empty(),
        5 => rest.len() == 4,
        10 => has_cstring_list(rest),
        11 => scram_server_first_message(rest),
        12 => scram_server_final_message(rest),
        _ => false,
    }
}

/// SCRAM server-first-message (RFC 5802 §7) : `r=<nonce>,s=<sel>,i=<iterations>`.
pub(super) fn scram_server_first_message(body: &[u8]) -> bool {
    let Ok(text) = str::from_utf8(body) else {
        return false;
    };
    text.starts_with("r=")
        && text.contains(",s=")
        && text.rsplit(",i=").next().is_some_and(|iterations| {
            !iterations.is_empty() && iterations.bytes().all(|b| b.is_ascii_digit())
        })
        && is_plain_text(text)
}

/// SCRAM server-final-message : `v=<signature en base64>`.
pub(super) fn scram_server_final_message(body: &[u8]) -> bool {
    let Ok(text) = str::from_utf8(body) else {
        return false;
    };
    text.strip_prefix("v=")
        .is_some_and(|signature| !signature.is_empty() && is_base64_text(signature))
}

pub(super) fn is_base64_text(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

/// Preuve forte d'un message `p` : le hache MD5 de `PasswordMessage`
/// (`md5` et trente-deux chiffres hexadecimaux), le SASLInitialResponse
/// SCRAM (nom du mecanisme, longueur, `n,,n=…,r=…`) ou le SASLResponse
/// SCRAM (`c=…,r=…,p=…`). Un mot de passe en clair n'a pas de forme.
pub(super) fn password_body_has_strong_evidence(body: &[u8]) -> bool {
    md5_password(body) || scram_client_first_message(body) || scram_client_final_message(body)
}

/// Un mot de passe en clair (texte termine par NUL) ou une forme SASL.
pub(super) fn password_body_is_compatible(body: &[u8]) -> bool {
    parse_single_cstring(body).is_some() || password_body_has_strong_evidence(body)
}

pub(super) fn md5_password(body: &[u8]) -> bool {
    body.len() == 36
        && body.starts_with(b"md5")
        && body[3..35].iter().all(u8::is_ascii_hexdigit)
        && body[35] == 0
}

/// SASLInitialResponse : mecanisme en C-string, longueur i32 de la reponse
/// initiale, puis le client-first-message SCRAM (`n,,n=…,r=…`).
pub(super) fn scram_client_first_message(body: &[u8]) -> bool {
    let Some(end) = body.iter().position(|byte| *byte == 0) else {
        return false;
    };
    if !matches!(&body[..end], b"SCRAM-SHA-256" | b"SCRAM-SHA-256-PLUS") {
        return false;
    }
    let rest = &body[end + 1..];
    if rest.len() < 4 {
        return false;
    }
    let declared = i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
    let initial = &rest[4..];
    if declared < 0 || declared as usize != initial.len() {
        return false;
    }
    let Ok(text) = str::from_utf8(initial) else {
        return false;
    };
    (text.starts_with("n,") || text.starts_with("y,") || text.starts_with("p="))
        && text.contains("n=")
        && text.contains(",r=")
        && is_plain_text(text)
}

/// SASLResponse : client-final-message SCRAM, `c=<binding>,r=<nonce>,p=<preuve>`.
pub(super) fn scram_client_final_message(body: &[u8]) -> bool {
    let Ok(text) = str::from_utf8(body) else {
        return false;
    };
    text.starts_with("c=") && text.contains(",r=") && text.contains(",p=") && is_plain_text(text)
}

pub(super) fn authentication_body_is_compatible(body: &[u8]) -> bool {
    if body.len() < 4 {
        return false;
    }

    let auth_code = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    match auth_code {
        0 | 2 | 3 | 6 | 7 | 8 => body.len() == 4,
        5 => body.len() == 8,
        10 => has_cstring_list(&body[4..]),
        11 | 12 => body.len() >= 4,
        _ => false,
    }
}

pub(super) fn backend_key_data_body_is_compatible(body: &[u8]) -> bool {
    body.len() >= 4 + POSTGRESQL_SECRET_KEY_MIN_LEN
        && body.len() <= 4 + POSTGRESQL_SECRET_KEY_MAX_LEN
}

/// Un nom de parametre que tout serveur envoie ; la valeur peut etre vide
/// (`application_name` d'un client qui ne s'est pas nomme, corpus Zeek).
pub(super) fn parameter_status_body_is_likely(body: &[u8]) -> bool {
    let Some((key, value)) = parse_two_cstrings_allow_empty_value(body) else {
        return false;
    };

    (value.is_empty() || is_plain_text(value))
        && matches!(
            key,
            "application_name"
                | "client_encoding"
                | "DateStyle"
                | "default_transaction_read_only"
                | "in_hot_standby"
                | "integer_datetimes"
                | "IntervalStyle"
                | "is_superuser"
                | "scram_iterations"
                | "search_path"
                | "server_encoding"
                | "server_version"
                | "session_authorization"
                | "standard_conforming_strings"
                | "TimeZone"
        )
}

pub(super) fn command_complete_body_is_likely(body: &[u8]) -> bool {
    let Some(tag) = parse_single_cstring(body) else {
        return false;
    };
    let Some(token) = first_ascii_token(tag) else {
        return false;
    };

    looks_like_sql(token)
}

pub(super) fn close_body_is_likely(body: &[u8]) -> bool {
    matches!(body.first(), Some(b'S' | b'P')) && str_from_cstring(&body[1..]).is_some()
}

pub(super) fn error_or_notice_body_is_likely(body: &[u8]) -> bool {
    if body.len() < 2 || body.last() != Some(&0) {
        return false;
    }

    let mut offset = 0usize;
    let mut saw_message = false;
    let mut saw_sqlstate = false;
    let mut saw_severity = false;

    while offset < body.len() - 1 {
        let field = body[offset];
        if !field.is_ascii_alphabetic() {
            return false;
        }
        offset += 1;

        let Some(end) = body[offset..].iter().position(|byte| *byte == 0) else {
            return false;
        };
        if end == 0 {
            return false;
        }

        let value = &body[offset..offset + end];
        let Ok(value) = str::from_utf8(value) else {
            return false;
        };
        if !is_plain_text(value) {
            return false;
        }

        match field {
            b'C' => saw_sqlstate = value.len() == 5 && value.bytes().all(|byte| byte.is_ascii()),
            b'M' => saw_message = true,
            b'S' | b'V' => saw_severity = true,
            _ => {}
        }

        offset += end + 1;
    }

    offset == body.len() - 1 && (saw_message || saw_sqlstate || saw_severity)
}

pub(super) fn has_cstring_list(body: &[u8]) -> bool {
    if body.len() < 2 || body.last() != Some(&0) {
        return false;
    }

    let mut offset = 0usize;
    let mut count = 0usize;

    while offset < body.len() - 1 {
        let Some(end) = body[offset..].iter().position(|byte| *byte == 0) else {
            return false;
        };
        if end == 0 {
            return false;
        }
        if str::from_utf8(&body[offset..offset + end])
            .map(|value| !is_plain_text(value))
            .unwrap_or(true)
        {
            return false;
        }
        offset += end + 1;
        count += 1;
    }

    count > 0 && offset == body.len() - 1
}

pub(super) fn parse_single_cstring(body: &[u8]) -> Option<&str> {
    if body.is_empty() || body.last() != Some(&0) {
        return None;
    }

    let value = &body[..body.len() - 1];
    if value.contains(&0) {
        return None;
    }

    let value = str::from_utf8(value).ok()?;
    is_plain_text(value).then_some(value)
}

/// Deux C-strings qui epuisent le corps, la seconde eventuellement vide.
pub(super) fn parse_two_cstrings_allow_empty_value(body: &[u8]) -> Option<(&str, &str)> {
    let first_end = body.iter().position(|byte| *byte == 0)?;
    let first = str::from_utf8(&body[..first_end]).ok()?;
    let rest = &body[first_end + 1..];
    let (&0, value) = rest.split_last()? else {
        return None;
    };
    if value.contains(&0) {
        return None;
    }
    let value = str::from_utf8(value).ok()?;
    is_plain_text(first).then_some((first, value))
}

pub(super) fn str_from_cstring(body: &[u8]) -> Option<&str> {
    parse_single_cstring(body)
}

pub(super) fn is_plain_text(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| !ch.is_control() || matches!(ch, '\t' | '\n' | '\r'))
}

pub(super) fn postgresql_secret_key_len_is_valid(length: usize) -> bool {
    (POSTGRESQL_SECRET_KEY_MIN_LEN..=POSTGRESQL_SECRET_KEY_MAX_LEN).contains(&length)
}
