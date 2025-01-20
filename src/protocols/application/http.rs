use crate::errors::application::http::HttpRequestParseError;

pub fn validate_http_request_line(lines: &mut std::str::Split<&str>) -> Result<(), HttpRequestParseError> {
    if lines.next().is_none() {
        return Err(HttpRequestParseError::InvalidRequestLine);
    }
    Ok(())
}

pub fn extract_method(lines: &mut std::str::Split<&str>) -> Result<String, HttpRequestParseError> {
    let request_line = lines.next().ok_or(HttpRequestParseError::InvalidRequestLine)?;
    let mut parts = request_line.split_whitespace();
    parts.next().map(String::from).ok_or(HttpRequestParseError::InvalidRequestLine)
}

pub fn extract_uri(lines: &mut std::str::Split<&str>) -> Result<String, HttpRequestParseError> {
    let request_line = lines.next().ok_or(HttpRequestParseError::InvalidRequestLine)?;
    let mut parts = request_line.split_whitespace();
    parts.nth(1).map(String::from).ok_or(HttpRequestParseError::InvalidRequestLine)
}

pub fn extract_version(lines: &mut std::str::Split<&str>) -> Result<String, HttpRequestParseError> {
    let request_line = lines.next().ok_or(HttpRequestParseError::InvalidRequestLine)?;
    let mut parts = request_line.split_whitespace();
    parts.nth(2).map(String::from).ok_or(HttpRequestParseError::InvalidRequestLine)
}

pub fn extract_headers(lines: &mut std::str::Split<&str>) -> Result<Vec<(String, String)>, HttpRequestParseError> {
    let mut headers = Vec::new();
    for line in lines.by_ref() {
        if line.is_empty() {
            break;
        }
        let mut parts = line.splitn(2, ':');
        let key = parts.next().map(str::trim).map(String::from).ok_or(HttpRequestParseError::InvalidHeader)?;
        let value = parts.next().map(str::trim).map(String::from).ok_or(HttpRequestParseError::InvalidHeader)?;
        headers.push((key, value));
    }
    Ok(headers)
}

pub fn extract_body(lines: &mut std::str::Split<&str>) -> String {
    lines.collect::<Vec<&str>>().join("\r\n")
}