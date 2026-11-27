// SPDX-License-Identifier: Apache-2.0

use reqwest::blocking::Response;
use std::io::Read;

#[derive(Debug)]
pub enum ResponseReadError {
    TooLarge { limit_bytes: usize },
    Read(std::io::Error),
}

impl core::fmt::Display for ResponseReadError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooLarge { limit_bytes } => {
                write!(formatter, "response exceeds {limit_bytes}-byte limit")
            }
            Self::Read(error) => write!(formatter, "read response: {error}"),
        }
    }
}

impl std::error::Error for ResponseReadError {}

pub fn read_response_bounded(
    mut response: Response,
    limit: usize,
) -> Result<Vec<u8>, ResponseReadError> {
    let limit_u64 = u64::try_from(limit).unwrap_or(u64::MAX);
    if response
        .content_length()
        .is_some_and(|length| length > limit_u64)
    {
        return Err(ResponseReadError::TooLarge { limit_bytes: limit });
    }
    let mut body = Vec::new();
    response
        .by_ref()
        .take(limit_u64.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(ResponseReadError::Read)?;
    if body.len() > limit {
        return Err(ResponseReadError::TooLarge { limit_bytes: limit });
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_reports_limit() {
        assert_eq!(
            ResponseReadError::TooLarge { limit_bytes: 10 }.to_string(),
            "response exceeds 10-byte limit"
        );
    }
}
