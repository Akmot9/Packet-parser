use crate::{
    errors::application::http::HttpRequestParseError, 
    utils::application::http::*};


/// The `HttpRequest` struct represents a parsed HTTP request.
#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub uri: String,
    pub version: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl TryFrom<&[u8]> for HttpRequest {
    type Error = HttpRequestParseError;

    fn try_from(payload: &[u8]) -> Result<Self, Self::Error> {
        let payload_str = std::str::from_utf8(payload).map_err(|_| HttpRequestParseError::InvalidRequestLine)?;
        let mut lines = payload_str.split("\r\n");

        validate_http_request_line(&mut lines)?;
        let method = extract_method(&mut lines)?;
        let uri = extract_uri(&mut lines)?;
        let version = extract_version(&mut lines)?;
        let headers = extract_headers(&mut lines)?;
        let body = extract_body(&mut lines);

        Ok(HttpRequest {
            method,
            uri,
            version,
            headers,
            body,
        })
    }
}


