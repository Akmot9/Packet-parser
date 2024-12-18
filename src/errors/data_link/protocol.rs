use thiserror::Error;

#[derive(Debug, Error)]
pub enum DataLinkProtocolError {
    #[error("Le paquet est trop court pour déterminer le protocole.")]
    PacketTooShort,

    #[error("Protocole inconnu.")]
    UnknownProtocol,
}