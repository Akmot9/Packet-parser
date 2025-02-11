use std::fmt::{self, Display};

use crate::parse::data_link::mac_addres::oui::Oui;

/// Implements `Display` for `Oui` so it can be converted into a string.
impl Display for Oui {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            Oui::ASUSTek => "ASUSTek",
            Oui::Siemens => "Siemens",
            Oui::Sagemcom => "Sagemcom",
            Oui::Intel => "Intel",
            Oui::Unknown => "Unknown",
        };
        write!(f, "{}", name)
    }
}
