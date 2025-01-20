use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetworkProtocolError {
    #[error("Le paquet est trop court pour déterminer le protocole.")]
    PacketTooShort,

    #[error("Protocole inconnu.")]
    UnknownProtocol,
}
