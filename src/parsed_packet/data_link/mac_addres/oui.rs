impl Oui {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes {
            [0x2C, 0xFD, 0xA1, ..] => Oui::ASUSTek,
            [0xE0, 0xDC, 0xA0, ..] => Oui::Siemens,
            [0xB0, 0x5B, 0x99, ..] => Oui::Sagemcom,
            _ => Oui::Unknown,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Oui {
    ASUSTek,
    Siemens,
    Sagemcom,
    Unknown,
}
