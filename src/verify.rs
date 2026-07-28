/*
 * Copyright (c) 2026 Chris Kruger <montdidier@users.noreply.github.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

use std::net::SocketAddr;
use std::time::SystemTime;

use mail_auth::common::verify::VerifySignature;
use mail_auth::{AuthenticatedMessage, DkimResult, Resolver};

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub dkim_pass: bool,
    pub dkim_domain: Option<String>,
    pub dkim_detail: String,
    pub spf_aligned: bool,
    pub spf_detail: String,
}

pub async fn verify_message(
    resolver: &Resolver,
    raw_message: &[u8],
    mail_from: Option<&str>,
    _helo_domain: Option<&str>,
    _source_ip: Option<&str>,
) -> VerificationResult {
    let dkim_result = verify_dkim(resolver, raw_message).await;
    let spf_result = check_spf_alignment(&dkim_result, mail_from);

    VerificationResult {
        dkim_pass: dkim_result.pass,
        dkim_domain: dkim_result.domain,
        dkim_detail: dkim_result.detail,
        spf_aligned: spf_result.aligned,
        spf_detail: spf_result.detail,
    }
}

struct DkimVerifyResult {
    pass: bool,
    domain: Option<String>,
    detail: String,
}

struct SpfAlignmentResult {
    aligned: bool,
    detail: String,
}

async fn verify_dkim(resolver: &Resolver, raw_message: &[u8]) -> DkimVerifyResult {
    let authenticated_message = match AuthenticatedMessage::parse(raw_message) {
        Some(msg) => msg,
        None => {
            return DkimVerifyResult {
                pass: false,
                domain: None,
                detail: "none (message parse failure)".to_string(),
            };
        }
    };

    let dkim_output = resolver.verify_dkim(&authenticated_message).await;

    if dkim_output.is_empty() {
        return DkimVerifyResult {
            pass: false,
            domain: None,
            detail: "none (no signature)".to_string(),
        };
    }

    for result in dkim_output.iter() {
        match result.result() {
            DkimResult::Pass => {
                let domain = result.signature().map(|s| s.domain().to_string());
                let domain_str = domain.clone().unwrap_or_default();
                return DkimVerifyResult {
                    pass: true,
                    domain,
                    detail: format!("pass (domain={})", domain_str),
                };
            }
            DkimResult::Fail(err) => {
                let domain = result.signature().map(|s| s.domain().to_string());
                let domain_str = domain.clone().unwrap_or_default();
                return DkimVerifyResult {
                    pass: false,
                    domain,
                    detail: format!("fail (domain={}, reason={})", domain_str, err),
                };
            }
            _ => continue,
        }
    }

    DkimVerifyResult {
        pass: false,
        domain: None,
        detail: "none (no valid signature found)".to_string(),
    }
}

fn check_spf_alignment(dkim_result: &DkimVerifyResult, mail_from: Option<&str>) -> SpfAlignmentResult {
    let mail_from_domain = match mail_from {
        Some(addr) => {
            if let Some(at_pos) = addr.rfind('@') {
                Some(addr[at_pos + 1..].to_lowercase())
            } else {
                None
            }
        }
        None => None,
    };

    let dkim_domain = match &dkim_result.domain {
        Some(d) => d.to_lowercase(),
        None => {
            return SpfAlignmentResult {
                aligned: false,
                detail: "none (no DKIM domain to align against)".to_string(),
            };
        }
    };

    let mail_domain = match mail_from_domain {
        Some(d) => d,
        None => {
            return SpfAlignmentResult {
                aligned: false,
                detail: "none (no envelope sender domain)".to_string(),
            };
        }
    };

    let aligned = domains_align(&mail_domain, &dkim_domain);

    if aligned {
        SpfAlignmentResult {
            aligned: true,
            detail: format!("pass (domain alignment: {} ~ {})", mail_domain, dkim_domain),
        }
    } else {
        SpfAlignmentResult {
            aligned: false,
            detail: format!("fail (domain mismatch: {} vs {})", mail_domain, dkim_domain),
        }
    }
}

fn domains_align(domain_a: &str, domain_b: &str) -> bool {
    if domain_a == domain_b {
        return true;
    }
    let org_a = organizational_domain(domain_a);
    let org_b = organizational_domain(domain_b);
    org_a == org_b
}

fn organizational_domain(domain: &str) -> &str {
    let last_dot = match domain.rfind('.') {
        Some(pos) => pos,
        None => return domain,
    };
    let second_last = domain[..last_dot].rfind('.').map(|p| p + 1).unwrap_or(0);
    &domain[second_last..]
}

pub fn format_auth_results(hostname: &str, result: &VerificationResult) -> String {
    format!(
        "Authentication-Results: {}; dkim={}; spf={}",
        hostname, result.dkim_detail, result.spf_detail
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domains_align_exact() {
        assert!(domains_align("example.com", "example.com"));
    }

    #[test]
    fn test_domains_align_subdomain() {
        assert!(domains_align("mail.example.com", "example.com"));
        assert!(domains_align("example.com", "sub.example.com"));
    }

    #[test]
    fn test_domains_no_align() {
        assert!(!domains_align("example.com", "other.com"));
        assert!(!domains_align("evil-example.com", "example.com"));
    }

    #[test]
    fn test_organizational_domain() {
        assert_eq!(organizational_domain("example.com"), "example.com");
        assert_eq!(organizational_domain("mail.example.com"), "example.com");
        assert_eq!(organizational_domain("a.b.example.com"), "example.com");
    }
}
