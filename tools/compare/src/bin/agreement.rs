//! Dit ce que le bench mesure : combien de trames de chaque corpus sont
//! gardees, et pourquoi les autres sont ecartees.
//!
//!   cargo run --release --manifest-path tools/compare/Cargo.toml --bin agreement [-- -v]

use packet_parser_compare::corpus::load_all;

fn main() {
    let verbose = std::env::args().any(|arg| arg == "-v");
    println!("corpus\tlues\tgardees\toctets\tnon_ethernet\tsans_couche_4\tdesaccord");
    for corpus in load_all() {
        let c = corpus.counts;
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            corpus.name,
            c.read,
            corpus.frames.len(),
            corpus.bytes,
            c.not_ethernet,
            c.out_of_scope,
            c.disagreed
        );
        if verbose {
            for (capture, number, readings) in &corpus.disagreements {
                println!("  {capture} trame {number}\n    {readings:?}");
            }
        }
    }
}
