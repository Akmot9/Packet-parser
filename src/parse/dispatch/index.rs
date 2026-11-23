// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Index de la table, derive de [`RULES`] a la compilation : une liste de
//! regles par transport et, pour chaque port que cite une de ses regles,
//! les regles qu'il ouvre et celles qu'il interdit. [`RULES`] reste la seule
//! source ; rien ne se declare ici.
//!
//! [`classify`](super::classify) lit les deux ports une fois, en tire
//! l'ensemble des regles a visiter, et ne parcourt que celles-la, dans
//! l'ordre de la table. Une sonde qui echoue en retire les regles suivantes
//! qui la portent : la memoisation des echecs est ce meme ensemble.

use super::ports::Ports;
use super::probes::ProbeMask;
use super::rules::{RULES, Rule};
use crate::parse::transport::protocols::TransportProtocol;

/// Un ensemble de regles d'une liste : le bit `n` est la regle de rang `n`.
/// Le bit de poids faible est la premiere regle de la table : parcourir les
/// bits du plus faible au plus fort suit l'ordre de la table.
///
/// Limite : 64 regles par transport, verifiee a la compilation. Au-dela,
/// passer a `u128`.
pub(super) type RuleSet = u64;

/// Ce qu'un port fait aux regles d'une liste.
#[derive(Clone, Copy)]
pub(super) struct PortEffect {
    /// Les regles dont la garde de port reconnait ce port.
    pub(super) opens: RuleSet,
    /// Les regles dont le veto de port reconnait ce port.
    pub(super) vetoes: RuleSet,
}

impl PortEffect {
    /// Un port qu'aucune regle ne cite, ou un port inconnu.
    const NONE: Self = Self {
        opens: 0,
        vetoes: 0,
    };
}

/// Une regle d'une liste, et ce que l'echec de sa sonde apprend.
#[derive(Clone, Copy)]
pub(super) struct Listed {
    pub(super) rule: &'static Rule,
    /// Les regles suivantes de la liste qui portent la meme sonde : apres
    /// un echec, elles ne la rejouent pas. Une regle terminale n'y est
    /// jamais : son verdict, `None`, doit etre rendu a son rang, et elle
    /// rejoue la sonde, qui echoue de nouveau.
    pub(super) twins: RuleSet,
}

/// Les regles de la table qu'un transport admet, et l'effet des ports sur
/// elles.
pub(super) struct RuleList {
    /// Les regles dont la garde de transport admet ce transport, dans
    /// l'ordre de la table.
    pub(super) rules: &'static [Listed],
    /// Les regles sans garde de port : a visiter quels que soient les ports.
    pub(super) portless: RuleSet,
    /// Les regles terminales a garde de port : leurs ports sont reserves.
    pub(super) terminal: RuleSet,
    /// Pour l'octet de poids fort d'un port, sa page dans `slots`. La page 0
    /// est celle des ports qu'aucune regle ne cite.
    pages: [u8; 256],
    /// Par page, pour l'octet de poids faible d'un port, le rang de son
    /// effet dans `effects`. Un octet par rang : au plus 255 ports cites et
    /// 255 pages par transport, verifie a la compilation.
    slots: &'static [[u8; 256]],
    /// Les effets des ports cites ; au rang 0, celui d'un port qu'aucune
    /// regle ne cite.
    effects: &'static [PortEffect],
}

impl RuleList {
    /// L'effet de `port` sur les regles de la liste : trois lectures, sans
    /// recherche.
    pub(super) fn port_effect(&self, port: Option<u16>) -> PortEffect {
        let Some(port) = port else {
            return PortEffect::NONE;
        };
        let [high, low] = port.to_be_bytes();
        let page = self.pages[usize::from(high)];
        self.slots
            .get(usize::from(page))
            .and_then(|slots| self.effects.get(usize::from(slots[usize::from(low)])))
            .copied()
            .unwrap_or(PortEffect::NONE)
    }

    /// Les regles de la liste qu'il ne reste pas a visiter quand les sondes
    /// de `failed` ont deja echoue : celles qui portent une de ces sondes,
    /// hors regles terminales (voir [`Listed::twins`]).
    pub(super) fn already_failed(&self, failed: ProbeMask) -> RuleSet {
        self.rules
            .iter()
            .enumerate()
            .filter(|(_, listed)| {
                !listed.rule.terminal_on_port && failed & listed.rule.probe.bit() != 0
            })
            .fold(0, |set, (rank, _)| set | 1 << rank)
    }
}

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
    assert!(
        N <= RuleSet::BITS as usize,
        "trop de regles pour un transport : elargir RuleSet"
    );
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

/// Chaque regle avec ses jumelles : les regles non terminales qui la
/// suivent et portent la meme sonde.
const fn listed<const N: usize>(rules: &[&'static Rule; N]) -> [Listed; N] {
    let mut list = [Listed {
        rule: &RULES[0],
        twins: 0,
    }; N];
    let mut rank = 0;
    while rank < N {
        let mut twins = 0;
        let mut later = rank + 1;
        while later < N {
            if rules[later].probe as u32 == rules[rank].probe as u32
                && !rules[later].terminal_on_port
            {
                twins |= 1 << later;
            }
            later += 1;
        }
        list[rank] = Listed {
            rule: rules[rank],
            twins,
        };
        rank += 1;
    }
    list
}

/// Le plus petit port, a partir de `floor`, que cite la famille.
const fn first_port_from(ports: Option<Ports>, floor: u16) -> Option<u16> {
    match ports {
        Some(ports) => ports.first_from(floor),
        None => None,
    }
}

/// Le plus petit de deux ports eventuels.
const fn earliest(left: Option<u16>, right: Option<u16>) -> Option<u16> {
    match (left, right) {
        (Some(left), Some(right)) => Some(if right < left { right } else { left }),
        (Some(port), None) | (None, Some(port)) => Some(port),
        (None, None) => None,
    }
}

/// Le plus petit port, a partir de `floor`, que cite la garde ou le veto
/// d'une des regles.
const fn next_cited_port(rules: &[&Rule], floor: u16) -> Option<u16> {
    let mut next = None;
    let mut rank = 0;
    while rank < rules.len() {
        next = earliest(next, first_port_from(rules[rank].ports, floor));
        next = earliest(next, first_port_from(rules[rank].ports_veto, floor));
        rank += 1;
    }
    next
}

/// Nombre de ports distincts que citent les regles.
const fn cited_port_count(rules: &[&Rule]) -> usize {
    let mut count = 0;
    let mut floor = 0;
    while let Some(port) = next_cited_port(rules, floor) {
        count += 1;
        if port == u16::MAX {
            break;
        }
        floor = port + 1;
    }
    count
}

/// Les ports distincts que citent les regles, tries. `P` vaut
/// [`cited_port_count`] : une autre valeur ne compile pas.
const fn cited_ports<const P: usize>(rules: &[&Rule]) -> [u16; P] {
    let mut ports = [0; P];
    let mut count = 0;
    let mut floor = 0;
    while let Some(port) = next_cited_port(rules, floor) {
        ports[count] = port;
        count += 1;
        if port == u16::MAX {
            break;
        }
        floor = port + 1;
    }
    assert!(count == P);
    ports
}

/// La famille reconnait-elle `port` ?
const fn cites(ports: Option<Ports>, port: u16) -> bool {
    match ports {
        Some(ports) => ports.contains(port),
        None => false,
    }
}

/// L'effet de chaque port de `ports` sur les regles, un rang plus loin : le
/// rang 0 reste celui d'un port qu'aucune regle ne cite. `E` vaut le nombre
/// de ports plus un.
const fn port_effects<const E: usize>(rules: &[&Rule], ports: &[u16]) -> [PortEffect; E] {
    assert!(E == ports.len() + 1);
    let mut effects = [PortEffect::NONE; E];
    let mut at = 0;
    while at < ports.len() {
        let mut rank = 0;
        while rank < rules.len() {
            if cites(rules[rank].ports, ports[at]) {
                effects[at + 1].opens |= 1 << rank;
            }
            if cites(rules[rank].ports_veto, ports[at]) {
                effects[at + 1].vetoes |= 1 << rank;
            }
            rank += 1;
        }
        at += 1;
    }
    effects
}

/// L'octet de poids fort de `port`, en indice.
const fn high_byte(port: u16) -> usize {
    (port >> 8) as usize
}

/// L'octet de poids faible de `port`, en indice.
const fn low_byte(port: u16) -> usize {
    (port & 0xff) as usize
}

/// Pour chaque octet de poids fort, la page de ses ports : numerotees a
/// partir de 1 dans l'ordre des ports, 0 quand aucun port de `ports` n'a cet
/// octet. `ports` est trie.
const fn port_pages(ports: &[u16]) -> [u8; 256] {
    let mut pages = [0; 256];
    let mut last: u8 = 0;
    let mut at = 0;
    while at < ports.len() {
        let high = high_byte(ports[at]);
        if pages[high] == 0 {
            assert!(last < u8::MAX, "trop de pages de ports");
            last += 1;
            pages[high] = last;
        }
        at += 1;
    }
    pages
}

/// Nombre de pages, la page vide comprise.
const fn page_count(ports: &[u16]) -> usize {
    let pages = port_pages(ports);
    let mut count = 1;
    let mut high = 0;
    while high < pages.len() {
        if pages[high] != 0 {
            count += 1;
        }
        high += 1;
    }
    count
}

/// Par page, pour chaque octet de poids faible, le rang de l'effet du port
/// dans [`port_effects`] : son rang dans `ports` plus un, 0 pour un port
/// absent de `ports`. `G` vaut [`page_count`].
const fn port_slots<const G: usize>(ports: &[u16]) -> [[u8; 256]; G] {
    assert!(G == page_count(ports));
    let pages = port_pages(ports);
    let mut slots = [[0; 256]; G];
    let mut effect: u8 = 0;
    let mut at = 0;
    while at < ports.len() {
        assert!(effect < u8::MAX, "trop de ports cites");
        effect += 1;
        slots[pages[high_byte(ports[at])] as usize][low_byte(ports[at])] = effect;
        at += 1;
    }
    slots
}

/// Les regles sans garde de port.
const fn portless(rules: &[&Rule]) -> RuleSet {
    let mut set = 0;
    let mut rank = 0;
    while rank < rules.len() {
        if rules[rank].ports.is_none() {
            set |= 1 << rank;
        }
        rank += 1;
    }
    set
}

/// Les regles terminales a garde de port.
const fn terminal(rules: &[&Rule]) -> RuleSet {
    let mut set = 0;
    let mut rank = 0;
    while rank < rules.len() {
        if rules[rank].terminal_on_port && rules[rank].ports.is_some() {
            set |= 1 << rank;
        }
        rank += 1;
    }
    set
}

/// La liste des regles qu'admet un transport, calculee a la compilation.
macro_rules! rule_list {
    ($protocol:expr) => {{
        const RULE_COUNT: usize = admitted_count($protocol);
        const LISTED: [&Rule; RULE_COUNT] = admitted($protocol);
        const PORT_COUNT: usize = cited_port_count(&LISTED);
        const PORTS: [u16; PORT_COUNT] = cited_ports(&LISTED);
        const SLOTS: [[u8; 256]; page_count(&PORTS)] = port_slots(&PORTS);
        const EFFECTS: [PortEffect; PORT_COUNT + 1] = port_effects(&LISTED, &PORTS);
        RuleList {
            rules: &listed(&LISTED),
            portless: portless(&LISTED),
            terminal: terminal(&LISTED),
            pages: port_pages(&PORTS),
            slots: &SLOTS,
            effects: &EFFECTS,
        }
    }};
}

static TCP: RuleList = rule_list!(TransportProtocol::Tcp);
static UDP: RuleList = rule_list!(TransportProtocol::Udp);
/// Ni TCP ni UDP : une garde ne distingue pas ces protocoles entre eux, et
/// n'en admet que les regles `Guard::Any`. `Hopopt` les represente tous.
static OTHER: RuleList = rule_list!(TransportProtocol::Hopopt);

/// Les regles de la table dont la garde admet `protocol` : la boucle de
/// [`classify`](super::classify) ne visite pas les regles de l'autre
/// transport.
pub(super) fn list_for(protocol: TransportProtocol) -> &'static RuleList {
    match protocol {
        TransportProtocol::Tcp => &TCP,
        TransportProtocol::Udp => &UDP,
        _ => &OTHER,
    }
}
