use regex::Regex;
use std::collections::BTreeSet;

pub const COMMAND_TOKENS: &[&str] = &["powershell", "cmd.exe", "/bin/sh", "curl", "wget"];
pub const NETWORK_PRIMITIVE_MATCHERS: &[(&str, &str, &str)] = &[
    ("java/net/URL", "<init>", "java/net/URL.<init>"),
    (
        "java/net/URL",
        "openConnection",
        "java/net/URL.openConnection",
    ),
    (
        "java/net/URLConnection",
        "connect",
        "java/net/URLConnection.connect",
    ),
    ("java/net/Socket", "<init>", "java/net/Socket.<init>"),
    ("java/net/Socket", "connect", "java/net/Socket.connect"),
    (
        "java/net/DatagramSocket",
        "send",
        "java/net/DatagramSocket.send",
    ),
    (
        "java/net/http/HttpClient",
        "send",
        "java/net/http/HttpClient.send",
    ),
    (
        "java/net/http/HttpClient",
        "sendAsync",
        "java/net/http/HttpClient.sendAsync",
    ),
];

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

pub fn matching_token_strings<'a>(
    strings: impl Iterator<Item = &'a str>,
    tokens: &[&str],
) -> Vec<String> {
    let mut normalized_seen = BTreeSet::new();
    let mut matches = Vec::new();
    for value in strings {
        if contains_any_token(value, tokens) && normalized_seen.insert(value.to_ascii_lowercase()) {
            matches.push(value.to_string());
        }
    }

    matches.sort();
    matches.dedup();
    matches
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

    #[test]
    fn matching_token_strings_returns_unique_case_insensitive_matches() {
        let strings = ["mods/evil.jar", "MODS/evil.jar", "../payload", "benign"];

        let matches = matching_token_strings(strings.iter().copied(), &["mods/", "../"]);
        assert_eq!(
            matches,
            vec!["../payload".to_string(), "mods/evil.jar".to_string()]
        );
    }
}
