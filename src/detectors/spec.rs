use regex::Regex;

pub const COMMAND_TOKENS: &[&str] = &["powershell", "cmd.exe", "/bin/sh", "curl", "wget"];

pub fn extract_urls<'a>(strings: impl Iterator<Item = &'a str>) -> Vec<String> {
    let regex = Regex::new(
        r#"(?i)https?://[a-z0-9][a-z0-9._:%+\-]*(?:\.[a-z0-9][a-z0-9._:%+\-]*)+(?:/[^\s\"'<>]*)?"#,
    )
    .expect("url regex must compile");

    let mut urls = Vec::new();
    for value in strings {
        for found in regex.find_iter(value) {
            urls.push(found.as_str().to_string());
        }
    }

    urls.sort();
    urls.dedup();
    urls
}

pub fn contains_any_token(haystack: &str, tokens: &[&str]) -> bool {
    let normalized_haystack = haystack.to_ascii_lowercase();
    tokens
        .iter()
        .any(|token| normalized_haystack.contains(&token.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_urls_is_conservative_and_deduplicated() {
        let strings = vec![
            "ping https://example.invalid/bootstrap",
            "fallback https://example.invalid/bootstrap and http://api.example.test/v1",
            "not-a-url: hxxps://example.invalid",
        ];

        let urls = extract_urls(strings.iter().copied());
        assert_eq!(
            urls,
            vec![
                "http://api.example.test/v1".to_string(),
                "https://example.invalid/bootstrap".to_string(),
            ]
        );
    }

    #[test]
    fn contains_any_token_matches_case_insensitively() {
        assert!(contains_any_token(
            "Runtime.getRuntime().exec(\"PowerShell -enc ...\")",
            COMMAND_TOKENS
        ));
        assert!(!contains_any_token(
            "System.out.println(\"hello\")",
            COMMAND_TOKENS
        ));
    }
}
