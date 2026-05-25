use crate::errors::application::opcua::OpcuaParseError;

pub const OPCUA_TCP_HEADER_LEN: usize = 8;

pub fn validate_tcp_header_length(len: usize) -> Result<(), OpcuaParseError> {
    if len < OPCUA_TCP_HEADER_LEN {
        return Err(OpcuaParseError::PacketTooShort {
            expected: OPCUA_TCP_HEADER_LEN,
            actual: len,
        });
    }

    Ok(())
}

pub fn validate_message_size(message_size: u32) -> Result<(), OpcuaParseError> {
    if message_size < OPCUA_TCP_HEADER_LEN as u32 {
        return Err(OpcuaParseError::InvalidMessageSize { size: message_size });
    }

    Ok(())
}

pub fn validate_body_len(actual: usize, expected: usize) -> Result<(), OpcuaParseError> {
    if actual < expected {
        return Err(OpcuaParseError::BodyTooShort { expected, actual });
    }

    Ok(())
}

pub fn validate_ua_string_len(length: i32) -> Result<(), OpcuaParseError> {
    if length < -1 {
        return Err(OpcuaParseError::InvalidStringLength { length });
    }

    Ok(())
}

pub fn validate_ua_string_available(actual: usize, expected: usize) -> Result<(), OpcuaParseError> {
    if actual < expected {
        return Err(OpcuaParseError::TruncatedString { expected, actual });
    }

    Ok(())
}
