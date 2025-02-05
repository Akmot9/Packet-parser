use criterion::{black_box, criterion_group, criterion_main, Criterion};
use packet_parser::ParsedPacket;
use std::convert::TryFrom;

fn benchmark_with_references(c: &mut Criterion) {
    let packet = vec![0; 1500]; // Exemple de paquet pour le test

    c.bench_function("ParsedPacket with &[u8]", |b| {
        b.iter(|| {
            let parsed_packet = ParsedPacket::try_from(black_box(&packet[..]));
            black_box(parsed_packet);
        })
    });
}

fn benchmark_with_vec(c: &mut Criterion) {
    let packet = vec![0; 1500]; // Exemple de paquet pour le test

    c.bench_function("ParsedPacket with Vec<u8>", |b| {
        b.iter(|| {
            let packet_clone = packet.clone();
            let parsed_packet = ParsedPacket::try_from(black_box(&packet_clone[..]));
            black_box(parsed_packet);
        })
    });
}

fn benchmark_with_specific_packets(c: &mut Criterion) {
    // Exemple de paquet spécifique (vous pouvez remplacer par vos propres données)
    let packet: Vec<u8> = vec![
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, // Destination MAC
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, // Source MAC
        0x08, 0x00, // Ethertype (IPv4)
        // Payload (remplissage)
        0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x57, 0x6F, 0x72, 0x6C, 0x64,
    ];

    c.bench_function("ParsedPacket with specific packet", |b| {
        b.iter(|| {
            let parsed_packet = ParsedPacket::try_from(black_box(&packet[..])).unwrap();
            black_box(parsed_packet);
        })
    });
}

criterion_group!(
    benches,
    benchmark_with_references,
    benchmark_with_vec,
    benchmark_with_specific_packets
);
criterion_main!(benches);
