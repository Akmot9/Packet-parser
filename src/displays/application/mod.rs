// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use crate::parse::application::Application;
use std::fmt;
pub mod bitcoin;
pub mod dhcp;
pub mod http;
impl fmt::Display for Application {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.application_protocol)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_application_display() {
        let app = Application {
            application_protocol: "NTP",
        };
        assert_eq!(app.to_string(), "NTP ");
    }
}
