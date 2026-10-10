//! Username generation through the SDK's `bitwarden-generators`. Forwarded aliases make network
//! calls with the caller's API token, so nothing here logs request fields or the SDK's error text.
use bitwarden_generators::{GeneratorClientsExt, UsernameError, UsernameGeneratorRequest};
use serde_json::{Value, json};
use crate::account::Error;

pub struct UsernameInput {
    pub kind: String, pub capitalize: Option<bool>, pub include_number: Option<bool>,
    pub email: Option<String>, pub domain: Option<String>, pub service: Option<String>,
    pub token: Option<String>, pub base_url: Option<String>, pub website: Option<String>,
}

fn invalid(message: &'static str) -> Error { Error::new("invalidInput", message) }

fn required(value: Option<String>, message: &'static str) -> Result<String, Error> {
    let value = value.map(|text| text.trim().to_owned()).unwrap_or_default();
    if value.is_empty() { Err(invalid(message)) } else { Ok(value) }
}

/// A bare host name such as `example.com`: no user info, port, path or whitespace.
fn valid_domain(domain: &str) -> bool {
    !domain.is_empty() && domain.len() <= 253 && domain.contains('.')
        && domain.split('.').all(|label| !label.is_empty() && label.len() <= 63
            && !label.starts_with('-') && !label.ends_with('-')
            && label.chars().all(|character| character.is_ascii_alphanumeric() || character == '-'))
}

fn valid_email(email: &str) -> bool {
    email.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty() && !local.chars().any(|c| c.is_whitespace() || c == '@') && valid_domain(domain)
    })
}

/// The tokens are sent to this URL, so it must be HTTPS. Plain HTTP is only for loopback hosts.
fn base_url(value: Option<String>) -> Result<String, Error> {
    let value = required(value, "Enter the service's base URL.")?;
    let url = url::Url::parse(&value).map_err(|_| invalid("The base URL is not valid."))?;
    let loopback = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    let scheme_ok = url.scheme() == "https" || (url.scheme() == "http" && loopback);
    if !scheme_ok || url.host_str().is_none() || !url.username().is_empty() || url.password().is_some()
        || url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("The base URL must be an https:// address."));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// The SDK splices the website into a query string, so only a plain host name is passed on.
fn website(value: Option<String>) -> Option<String> {
    let value = value?;
    let host = url::Url::parse(&value).ok().and_then(|url| url.host_str().map(str::to_owned))
        .or_else(|| url::Url::parse(&format!("https://{value}")).ok().and_then(|url| url.host_str().map(str::to_owned)))?;
    (host.len() <= 253 && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')).then_some(host)
}

/// The SDK keeps `AppendType` private, so requests are built as serde JSON (see AGENTS.md).
fn service(input: &mut UsernameInput) -> Result<Value, Error> {
    let name = input.service.clone().unwrap_or_default();
    let token = required(input.token.take(), "Enter the API key or token.")?;
    Ok(match name.as_str() {
        "simplelogin" => json!({"simpleLogin": {"api_key": token, "base_url": base_url(input.base_url.take())?}}),
        "addy" => json!({"addyIo": {
            "api_token": token,
            "domain": required(input.domain.take(), "Enter the alias domain.")?,
            "base_url": base_url(input.base_url.take())?,
        }}),
        "firefox" => json!({"firefox": {"api_token": token}}),
        "fastmail" => json!({"fastmail": {"api_token": token}}),
        "duckduckgo" => json!({"duckDuckGo": {"token": token}}),
        "forwardemail" => {
            let domain = required(input.domain.take(), "Enter the alias domain.")?;
            if !valid_domain(&domain) { return Err(invalid("The alias domain is not valid.")); }
            json!({"forwardEmail": {"api_token": token, "domain": domain}})
        }
        _ => return Err(invalid("Unknown email forwarding service.")),
    })
}

fn request(mut input: UsernameInput) -> Result<UsernameGeneratorRequest, Error> {
    let value = match input.kind.as_str() {
        "word" => json!({"word": {
            "capitalize": input.capitalize.unwrap_or(false), "include_number": input.include_number.unwrap_or(false),
        }}),
        "subaddress" => {
            let email = required(input.email.take(), "Enter your email address.")?;
            if !valid_email(&email) { return Err(invalid("Enter a valid email address.")); }
            json!({"subaddress": {"type": "random", "email": email}})
        }
        "catchall" => {
            let domain = required(input.domain.take(), "Enter the catch-all domain.")?;
            if !valid_domain(&domain) { return Err(invalid("The catch-all domain is not valid.")); }
            json!({"catchall": {"type": "random", "domain": domain}})
        }
        "forwarded" => {
            let website = website(input.website.take());
            json!({"forwarded": {"service": service(&mut input)?, "website": website}})
        }
        _ => return Err(invalid("Unknown username type.")),
    };
    serde_json::from_value(value).map_err(|_| invalid("Invalid username generator options."))
}

fn failure(error: UsernameError) -> Error {
    match error {
        UsernameError::InvalidApiKey => Error::new("invalidInput", "The service rejected the API key or token."),
        UsernameError::Reqwest(error) if error.is_status() =>
            Error::new("invalidResponse", "The service returned an error. Check the settings and try again."),
        UsernameError::Reqwest(_) => Error::new("networkUnavailable", "Couldn’t reach the service."),
        UsernameError::ResponseContent { .. } =>
            Error::new("invalidResponse", "The service returned an error. Check the settings and try again."),
        UsernameError::Unknown => Error::new("invalidResponse", "The service returned an unexpected reply."),
    }
}

pub fn username(input: UsernameInput) -> Result<String, Error> {
    let request = request(input)?;
    crate::RUNTIME.block_on(async { crate::app::GENERATOR.generator().username(request).await }).map_err(failure)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn input(kind: &str) -> UsernameInput {
        UsernameInput { kind: kind.into(), capitalize: None, include_number: None, email: None, domain: None,
                        service: None, token: None, base_url: None, website: None }
    }
    fn message(result: Result<String, Error>) -> &'static str { result.expect_err("must fail").message }

    #[test]
    fn random_word_honours_capitalize_and_number() {
        for _ in 0..20 {
            let word = username(UsernameInput { capitalize: Some(true), include_number: Some(true), ..input("word") }).unwrap();
            assert!(word.chars().next().unwrap().is_ascii_uppercase(), "{word}");
            assert!(word[word.len() - 4..].chars().all(|c| c.is_ascii_digit()), "{word}");
            let plain = username(UsernameInput { capitalize: Some(false), include_number: Some(false), ..input("word") }).unwrap();
            assert!(plain.chars().all(|c| c.is_ascii_lowercase() || c == '-'), "{plain}");
        }
    }

    #[test]
    fn plus_addressed_email_adds_a_random_tag() {
        let address = username(UsernameInput { email: Some("you@example.com".into()), ..input("subaddress") }).unwrap();
        let tag = address.strip_prefix("you+").and_then(|rest| rest.strip_suffix("@example.com")).unwrap();
        assert_eq!(tag.len(), 8);
        assert!(tag.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn catch_all_uses_a_random_local_part() {
        let address = username(UsernameInput { domain: Some("example.org".into()), ..input("catchall") }).unwrap();
        let local = address.strip_suffix("@example.org").unwrap();
        assert_eq!(local.len(), 8);
    }

    #[test]
    fn bad_email_and_domain_fail_instead_of_echoing_the_input() {
        for email in ["", "you", "@example.com", "you@", "you@localhost", "a b@example.com"] {
            let result = username(UsernameInput { email: Some(email.into()), ..input("subaddress") });
            assert_eq!(message(result), if email.is_empty() { "Enter your email address." } else { "Enter a valid email address." }, "{email}");
        }
        for domain in ["", "nodot", "a..b", "-a.com", "exa mple.com", "example.com/path"] {
            assert!(username(UsernameInput { domain: Some(domain.into()), ..input("catchall") }).is_err(), "{domain}");
        }
        assert_eq!(message(username(input("nonsense"))), "Unknown username type.");
    }

    #[test]
    fn forwarders_validate_before_any_network_call() {
        let forwarded = |service: &str, token: Option<&str>, base: Option<&str>, domain: Option<&str>| UsernameInput {
            service: Some(service.into()), token: token.map(Into::into), base_url: base.map(Into::into),
            domain: domain.map(Into::into), ..input("forwarded")
        };
        assert_eq!(message(username(forwarded("firefox", None, None, None))), "Enter the API key or token.");
        assert_eq!(message(username(forwarded("firefox", Some("  "), None, None))), "Enter the API key or token.");
        assert_eq!(message(username(forwarded("nope", Some("t"), None, None))), "Unknown email forwarding service.");
        assert_eq!(message(username(forwarded("simplelogin", Some("t"), None, None))), "Enter the service's base URL.");
        // Tokens must not travel over plain HTTP to a remote host, nor to URLs with credentials.
        for base in ["http://example.com", "ftp://example.com", "https://user:pw@example.com", "https://example.com/?x=1", "nonsense"] {
            assert!(username(forwarded("simplelogin", Some("t"), Some(base), None)).is_err(), "{base}");
        }
        assert_eq!(message(username(forwarded("addy", Some("t"), Some("https://app.addy.io"), None))), "Enter the alias domain.");
        assert_eq!(message(username(forwarded("forwardemail", Some("t"), None, Some("a b.com")))), "The alias domain is not valid.");
    }

    #[test]
    fn website_is_reduced_to_a_host_name() {
        assert_eq!(website(Some("https://www.example.com/login?a=b".into())).as_deref(), Some("www.example.com"));
        assert_eq!(website(Some("example.com".into())).as_deref(), Some("example.com"));
        assert_eq!(website(Some("".into())), None);
        assert_eq!(website(None), None);
    }

    /// A loopback stand-in for a SimpleLogin server: never a real forwarder.
    fn mock_server(status: &'static str, body: &'static str) -> Option<(String, std::thread::JoinHandle<String>)> {
        let listener = match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            // Sandboxes that forbid local sockets cannot run the mock; nothing else is skipped.
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => { eprintln!("skipped: cannot bind loopback"); return None }
            Err(error) => panic!("{error}"),
        };
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = Vec::new();
            let mut buffer = [0u8; 4096];
            loop {
                let count = stream.read(&mut buffer).unwrap();
                received.extend_from_slice(&buffer[..count]);
                let text = String::from_utf8_lossy(&received).to_string();
                if let Some((head, rest)) = text.split_once("\r\n\r\n") {
                    let length = head.lines().find_map(|line| line.to_ascii_lowercase().strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())).unwrap_or(0);
                    if rest.len() >= length { break; }
                }
                if count == 0 { break; }
            }
            let reply = format!("HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            stream.write_all(reply.as_bytes()).unwrap();
            String::from_utf8_lossy(&received).to_string()
        });
        Some((format!("http://{address}"), handle))
    }

    #[test]
    fn simplelogin_alias_comes_from_the_mock_server() {
        let Some((base, server)) = mock_server("201 Created", r#"{"alias":"alias.abc@example.test"}"#) else { return };
        let alias = username(UsernameInput { service: Some("simplelogin".into()), token: Some("mock-token".into()),
            base_url: Some(base), website: Some("https://shop.example.com/x".into()), ..input("forwarded") }).unwrap();
        assert_eq!(alias, "alias.abc@example.test");
        let request = server.join().unwrap();
        assert!(request.starts_with("POST /api/alias/random/new?hostname=shop.example.com "), "{request}");
        assert!(request.to_ascii_lowercase().contains("authentication: mock-token"));
    }

    #[test]
    fn forwarder_errors_surface_without_the_token() {
        let Some((base, server)) = mock_server("401 Unauthorized", "{}") else { return };
        let error = username(UsernameInput { service: Some("simplelogin".into()), token: Some("secret-token".into()),
            base_url: Some(base), ..input("forwarded") }).unwrap_err();
        server.join().unwrap();
        assert_eq!(error.message, "The service rejected the API key or token.");
        let Some((base, server)) = mock_server("500 Internal Server Error", "{}") else { return };
        let error = username(UsernameInput { service: Some("simplelogin".into()), token: Some("secret-token".into()),
            base_url: Some(base), ..input("forwarded") }).unwrap_err();
        server.join().unwrap();
        assert!(!format!("{error:?}").contains("secret-token"));
        assert_eq!(error.code, "invalidResponse");
    }
}
