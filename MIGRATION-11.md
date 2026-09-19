# Migrer vers packet_parser 11.0.0

Une entrée par rupture : avant, après, raison. Ce guide se remplit lot par
lot pendant le chantier de l'epic #76 ; la liste est recoupée avec
`cargo semver-checks` avant publication.

## GIOP

Le décodeur GIOP passe d'un header + Request à tout le protocole. Rien ne
change pour qui ne lit que l'étiquette `"GIOP"` du `PacketFlow` — sinon que
davantage de trames la portent (premier segment d'un message fragmenté par
TCP).

### `GiopReply` porte le message décodé

```rust
// 10.x : struct vide
if let GiopMessage::Reply(_) = packet.payload { /* rien à lire */ }

// 11.0
if let GiopMessage::Reply(reply) = &packet.payload {
    println!("{} {:?}", reply.request_id, reply.reply_status);
    if let GiopReplyDetail::LocationForward(ior) = &reply.detail
        && let Some(iiop) = ior.iiop()
    {
        println!("redirigé vers {}:{}", iiop.host, iiop.port);
    }
}
```

### `GiopMessage` : nouveaux types, et `Other` change de sens

En 10.x, `Other` couvrait tout ce qui n'était ni Request ni Reply. En 11.0
chaque type a sa variante (`CancelRequest`, `LocateRequest`, `LocateReply`,
`CloseConnection`, `MessageError`, `Fragment`) ; `Other` signifie « type
valide, body illisible ». L'enum est `#[non_exhaustive]` : un `match` externe
doit garder un bras `_`.

### `TargetAddress`

```rust
// 10.x
TargetAddress::ProfileAddr(profile_data) => …
TargetAddress::ReferenceAddr(raw_span) => …

// 11.0
TargetAddress::ProfileAddr(profile) => { profile.tag; profile.profile_data; }
TargetAddress::ReferenceAddr { selected_profile_index, ior } => …
```

### Messages tronqués : `Ok` + `truncated`, plus `Err(TruncatedBody)`

```rust
// 10.x
match GiopPacket::try_from(payload) {
    Err(GiopParseError::TruncatedBody { .. }) => /* message > segment TCP */,
    …
}

// 11.0
let packet = GiopPacket::try_from(payload)?;
if packet.truncated { /* body partiel : packet.wire_len() octets présents */ }
```

Raison : un message GIOP dépasse couramment le MSS ; le rejeter faisait
sortir son premier segment en `Unknown`, alors qu'il porte l'en-tête complet
(request id, opération, object key).

### `stub_data` sans le padding

En GIOP 1.2 le stub data est aligné sur 8 octets. Le padding était compté
dans `GiopRequest::stub_data` ; il ne l'est plus. Qui décodait les arguments
CDR à partir de `stub_data` doit retirer son propre saut de padding.

### Erreurs et `checks`

- `GiopParseError::UnknownTargetDiscriminator(u8)` → `(u16)`.
- `GiopParseError::TruncatedBody` supprimée (voir ci-dessus).
- `GiopParseError` est `#[non_exhaustive]` : bras `_` requis.
- `checks::application::giop::extract_message_length(payload)` →
  `extract_message_size(payload, little_endian)`.
- `checks::application::giop::validate_total_length` supprimée.
- `validate_target_discriminator(u8)` → `(u16)`.

### Construction des types

Tous les types GIOP sont `#[non_exhaustive]` : ils ne se construisent plus
par littéral hors de la crate, et se déstructurent avec `..`.
