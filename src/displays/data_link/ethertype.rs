use std::fmt::{Display, Formatter};

use crate::parse::data_link::ethertype::Ethertype;

impl Display for Ethertype {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{:04X} ({})", self.0, self.name())
    }
}
