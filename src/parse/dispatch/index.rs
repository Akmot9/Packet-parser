// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Index de la table, derive de [`RULES`] a la compilation : une liste de
//! regles par transport. [`RULES`] reste la seule source ; rien ne se
//! declare ici.

use super::rules::{RULES, Rule};
use crate::parse::transport::protocols::TransportProtocol;

/// Nombre de regles dont la garde de transport admet `protocol`.
const fn admitted_count(protocol: TransportProtocol) -> usize {
    let mut count = 0;
    let mut index = 0;
    while index < RULES.len() {
        if RULES[index].guard.admits(protocol) {
            count += 1;
        }
        index += 1;
    }
    count
}

/// Les regles dont la garde de transport admet `protocol`, dans l'ordre de
/// la table. `N` vaut [`admitted_count`] : une autre valeur ne compile pas.
const fn admitted<const N: usize>(protocol: TransportProtocol) -> [&'static Rule; N] {
    let mut rules = [&RULES[0]; N];
    let mut rank = 0;
    let mut index = 0;
    while index < RULES.len() {
        if RULES[index].guard.admits(protocol) {
            rules[rank] = &RULES[index];
            rank += 1;
        }
        index += 1;
    }
    assert!(rank == N);
    rules
}

static TCP_RULES: [&Rule; admitted_count(TransportProtocol::Tcp)] =
    admitted(TransportProtocol::Tcp);
static UDP_RULES: [&Rule; admitted_count(TransportProtocol::Udp)] =
    admitted(TransportProtocol::Udp);
/// Ni TCP ni UDP : une garde ne distingue pas ces protocoles entre eux, et
/// n'en admet que les regles `Guard::Any`. `Hopopt` les represente tous.
static OTHER_RULES: [&Rule; admitted_count(TransportProtocol::Hopopt)] =
    admitted(TransportProtocol::Hopopt);

/// Les regles de la table dont la garde admet `protocol`, dans l'ordre de la
/// table : la boucle de [`classify`](super::classify) ne visite pas les
/// regles de l'autre transport.
pub(super) fn rules_for(protocol: TransportProtocol) -> &'static [&'static Rule] {
    match protocol {
        TransportProtocol::Tcp => &TCP_RULES,
        TransportProtocol::Udp => &UDP_RULES,
        _ => &OTHER_RULES,
    }
}
