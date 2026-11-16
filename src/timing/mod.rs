// Copyright (c) 2026 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! Optional timing of the parsing pipeline.
//!
//! The API is **the same whether the `parse_timing` feature is enabled or
//! not**: [`ParseTiming`] always has its five fields and
//! [`parse_timed`](crate::parse_timed) always exists. Without the feature,
//! nothing is measured and the fields stay at zero; with it, each layer is
//! timed. A Cargo feature must be additive: since Cargo unifies the features
//! of the graph, a struct whose shape changed with the feature would break a
//! consumer that never asked for it (#26).
//!
//! The normal path ([`parse`](fn@crate::parse)) is never timed, whether the
//! feature is enabled or not: it is monomorphised over an empty measurement
//! sink, where each stage reduces to calling its body.

/// Duration of each layer of the pipeline, in nanoseconds. Every field is
/// zero when the `parse_timing` feature is disabled.
///
/// `l*_ns` is the cost of the *attempt*: it can be non-zero even when the
/// layer is not supported. `l7_ns` includes tunnel detection and the
/// recursive parsing of encapsulated packets.
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
            let elapsed = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
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
            self.total_ns = u64::try_from(t0.elapsed().as_nanos()).unwrap_or(u64::MAX);
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
