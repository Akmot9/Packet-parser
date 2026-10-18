// Copyright (c) 2024 Cyprien Avico avicocyprien@yahoo.com
//
// Licensed under the MIT License <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

use std::fmt::{self, Display};

use crate::parse::application::protocols::http::{HttpRequest, HttpResponse};

impl Display for HttpRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HTTP Request: method={}, uri={}, version={}, headers={:?}, body={}",
            self.method, self.uri, self.version, self.headers, self.body
        )
    }
}

impl Display for HttpResponse<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "HTTP Response: version={}, status={} {}, headers={:?}, body={} bytes",
            self.version,
            self.status_code,
            self.reason,
            self.headers,
            self.body.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::parse::application::protocols::http::{HttpRequest, HttpResponse};

    #[test]
    fn test_http_request_display() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: www.example.com\r\n\r\n";
        let request = HttpRequest::try_from(&payload[..]).expect("requete valide");

        let rendered = request.to_string();
        assert!(rendered.starts_with("HTTP Request:"));
        assert!(rendered.contains("method=GET"));
        assert!(rendered.contains("uri=/index.html"));
        assert!(rendered.contains("version=HTTP/1.1"));
        assert!(rendered.contains("Host"));
    }

    #[test]
    fn test_http_response_display() {
        let payload = b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\n\xff\xfe\xfd";
        let response = HttpResponse::try_from(&payload[..]).expect("reponse valide");
        let rendered = response.to_string();
        assert!(rendered.starts_with("HTTP Response:"));
        assert!(rendered.contains("status=404 Not Found"));
        assert!(rendered.contains("Content-Length"));
        assert!(rendered.ends_with("body=3 bytes"));
    }
}
