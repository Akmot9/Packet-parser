// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Chronometrage optionnel du pipeline de parsing.
//!
//! L'API est **la meme que la feature `parse_timing` soit activee ou non** :
//! [`ParseTiming`] a toujours ses cinq champs et
//! [`parse_timed`](crate::parse_timed) existe toujours. Sans la feature,
//! rien n'est mesure et les champs restent a zero ; avec, chaque couche est
//! chronometree. Une feature Cargo doit etre additive : comme Cargo unifie
//! les features du graphe, une forme de struct qui change avec la feature
//! casserait un consommateur qui ne l'a jamais demandee (#26).
//!
//! Le chemin normal ([`parse`](crate::parse)) n'est jamais chronometre, que
//! la feature soit activee ou non : il est monomorphise sur [`NoTiming`],
//! dont chaque etape se reduit a l'appel du corps.

/// Duree de chaque couche du pipeline, en nanosecondes. Tous les champs sont
/// a zero quand la feature `parse_timing` est desactivee.
///
/// `l*_ns` est le cout de la *tentative* : il peut etre non nul meme quand
/// la couche n'est pas supportee. `l7_ns` inclut la detection de tunnel et
/// le parsing recursif des paquets encapsules.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ParseTiming {
    pub l2_ns: u64,
    pub l3_ns: u64,
    pub l4_ns: u64,
    pub l7_ns: u64,
    pub total_ns: u64,
}

/// Etape chronometree du pipeline.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Stage {
    L2,
    L3,
    L4,
    L7,
}

/// Puits de mesures traverse par le pipeline unique. Le pipeline est
/// generique dessus : le chemin normal et le chemin chronometre partagent le
/// meme code source, sans branche ni cout a l'execution.
pub(crate) trait TimingSink {
    fn time<T>(&mut self, stage: Stage, body: impl FnOnce() -> T) -> T;
}

/// Puits du chemin normal : ne mesure rien.
pub(crate) struct NoTiming;

impl TimingSink for NoTiming {
    #[inline(always)]
    fn time<T>(&mut self, _stage: Stage, body: impl FnOnce() -> T) -> T {
        body()
    }
}

impl TimingSink for ParseTiming {
    #[inline(always)]
    fn time<T>(&mut self, stage: Stage, body: impl FnOnce() -> T) -> T {
        #[cfg(feature = "parse_timing")]
        {
            let t0 = std::time::Instant::now();
            let out = body();
            let elapsed = t0.elapsed().as_nanos() as u64;
            match stage {
                Stage::L2 => self.l2_ns = elapsed,
                Stage::L3 => self.l3_ns = elapsed,
                Stage::L4 => self.l4_ns = elapsed,
                Stage::L7 => self.l7_ns = elapsed,
            }
            out
        }
        #[cfg(not(feature = "parse_timing"))]
        {
            let _ = stage;
            body()
        }
    }
}

impl ParseTiming {
    /// Remet les mesures a zero, execute `body` et renseigne `total_ns`.
    #[inline(always)]
    pub(crate) fn time_total<T>(&mut self, body: impl FnOnce(&mut Self) -> T) -> T {
        *self = Self::default();
        #[cfg(feature = "parse_timing")]
        {
            let t0 = std::time::Instant::now();
            let out = body(self);
            self.total_ns = t0.elapsed().as_nanos() as u64;
            out
        }
        #[cfg(not(feature = "parse_timing"))]
        {
            body(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_timing_has_one_shape_whatever_the_feature() {
        let timing = ParseTiming::default();
        assert_eq!(
            (
                timing.l2_ns,
                timing.l3_ns,
                timing.l4_ns,
                timing.l7_ns,
                timing.total_ns
            ),
            (0, 0, 0, 0, 0)
        );
    }

    #[test]
    fn no_timing_sink_only_runs_the_body() {
        assert_eq!(NoTiming.time(Stage::L3, || 41 + 1), 42);
    }

    #[test]
    fn parse_timing_sink_runs_the_body_and_records_only_with_the_feature() {
        let mut timing = ParseTiming::default();
        let out = timing.time_total(|timing| {
            timing.time(Stage::L2, || {
                std::hint::black_box((0..1_000u64).sum::<u64>())
            })
        });
        assert_eq!(out, 499_500);

        #[cfg(not(feature = "parse_timing"))]
        assert_eq!(timing, ParseTiming::default());
        #[cfg(feature = "parse_timing")]
        assert!(timing.total_ns >= timing.l2_ns);
    }
}
