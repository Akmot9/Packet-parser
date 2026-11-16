// Fuzz du decodeur HTTP/1.x : ligne de requete, ligne de statut, en-tetes
// parcourus a la demande, corps. Ni panic ni boucle ; quand le decodage
// reussit, methode, URI, version et en-tetes sont empruntes a l'entree, le
// corps en est la fin, et l'iterateur d'en-tetes, `len`, `is_empty` et `get`
// s'accordent. Les fonctions `parse_http_*` rendent le verdict de `try_from`.
#![no_main]

#[path = "../oracles/seeds.rs"]
mod seeds;

use libfuzzer_sys::fuzz_target;
use packet_parser::parse::application::protocols::http::{
    HttpHeaders, HttpRequest, HttpResponse, parse_http_request, parse_http_response,
};
use seeds::{inside, replay_mutated};

// The-Ultimate-PCAP.pcapng, trame 1976 : requete HEAD, trois en-tetes.
const HEAD_REQUEST: &[u8] = &[
    0x48, 0x45, 0x41, 0x44, 0x20, 0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x0d,
    0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x48, 0x54, 0x54,
    0x50, 0x69, 0x6e, 0x67, 0x20, 0x76, 0x31, 0x2e, 0x35, 0x2e, 0x38, 0x0d, 0x0a, 0x48, 0x6f, 0x73,
    0x74, 0x3a, 0x20, 0x62, 0x6c, 0x6f, 0x67, 0x2e, 0x77, 0x65, 0x62, 0x65, 0x72, 0x6e, 0x65, 0x74,
    0x7a, 0x2e, 0x6e, 0x65, 0x74, 0x0d, 0x0a, 0x0d, 0x0a,
];

// The-Ultimate-PCAP.pcapng, trame 1519 : debut d'une reponse 200.
const OK_RESPONSE: &[u8] = &[
    0x6b, 0x22, 0x3e, 0x6d, 0x79, 0x49, 0x50, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x2e, 0x63,
    0x6f, 0x6d, 0x3c, 0x2f, 0x61, 0x3e, 0x3c, 0x62, 0x72, 0x2f, 0x3e, 0x3c, 0x2f, 0x6c, 0x69, 0x3e,
    0x0a, 0x3c, 0x2f, 0x75, 0x6c, 0x3e, 0x0a, 0x3c, 0x2f, 0x70, 0x3e,
];

fn check_headers(data: &[u8], headers: &HttpHeaders<'_>) {
    let mut count = 0;
    for (name, value) in headers.iter() {
        assert!(inside(data, name.as_bytes()) && inside(data, value.as_bytes()));
        assert!(headers.get(name).is_some());
        count += 1;
    }
    assert_eq!(headers.len(), count);
    assert_eq!(headers.is_empty(), count == 0);
    let _ = format!("{headers:?}");
}

fn exercise(data: &[u8]) {
    let request = HttpRequest::try_from(data);
    assert_eq!(request.is_ok(), parse_http_request(data).is_ok());
    if let Ok(request) = request {
        for field in [request.method, request.uri, request.version] {
            assert!(!field.is_empty() && inside(data, field.as_bytes()));
        }
        assert!(data.ends_with(request.body_bytes) && inside(data, request.body_bytes));
        assert_eq!(
            request.body,
            std::str::from_utf8(request.body_bytes).unwrap_or_default()
        );
        check_headers(data, &request.headers);
    }

    let response = HttpResponse::try_from(data);
    assert_eq!(response.is_ok(), parse_http_response(data).is_ok());
    if let Ok(response) = response {
        assert!(!response.version.is_empty() && inside(data, response.version.as_bytes()));
        assert!(inside(data, response.reason.as_bytes()));
        assert!(data.ends_with(response.body) && inside(data, response.body));
        check_headers(data, &response.headers);
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    replay_mutated(&[HEAD_REQUEST, OK_RESPONSE], data, exercise);
});
