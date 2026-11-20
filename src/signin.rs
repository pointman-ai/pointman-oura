//! Signing an Oura account in from the apps, with Oura's authorization-code flow and PKCE
//! (https://cloud.ouraring.com/docs/authentication): the link the app opens asks Oura for every read scope and comes
//! back by redirect with `state`, which core matches to the sign-in. Core then gives the node the code
//! (`credentials.code`), and the extension exchanges it with the PKCE verifier it kept and the same redirect.
//!
//! Which client: on a hosted Pointman, core's shared client, Pointman's own (`Client::Shared`): its redirect is the
//! cloud's callback, and the code is exchanged through core, which adds the secret. On a self-hosted one, the vault's
//! `oura.client` (`Client::Own`), with core's own `/oauth/callback`.
//!
//! The value that goes in the vault is `accounts::value`'s. Nothing here logs it, and the code and the verifier are
//! never in a log or an error.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use pointman_extension::protocol::CredentialsSignInResponse;
use pointman_extension::{Handle, HostError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;

use crate::accounts;
use crate::api::{exchange, Endpoints, OAuthClient};
use crate::PROVIDER;

/// Every read scope Oura has.
pub const SCOPES: &str = "email personal daily heartrate workout tag session spo2 heart_health";

/// The one every summary needs, which a person can untick: a sign-in without it is refused.
pub const NEEDED: &str = "daily";

/// How long a sign-in waits for its code, at most.
pub const WAIT: Duration = Duration::from_secs(30 * 60);

/// A node that gives a sign-in no redirect back to Pointman.
pub const UPGRADE: &str = "this node can't sign an Oura account in yet: it doesn't give sign-ins a redirect back to \
                           Pointman. Upgrade it (pointman upgrade), then sign in again";

/// The Oura client a sign-in goes through.
#[derive(Debug, Clone)]
pub enum Client {
    /// Core's shared client, Pointman's own: only its id, as the exchange goes through core.
    Shared { id: String },
    /// A self-hosted Pointman's own client, the vault's `oura.client`.
    Own(OAuthClient),
}

impl Client {
    pub fn id(&self) -> &str {
        match self {
            Client::Shared { id } => id,
            Client::Own(c) => &c.id,
        }
    }
}

struct Pending {
    client: Client,
    verifier: String,
    redirect: String,
    label: String,
    until: Instant,
}

/// The sign-ins under way, by the node's session id.
#[derive(Default)]
pub struct SignIns {
    open: Mutex<HashMap<String, Pending>>,
}

/// `n` random bytes, base64url without padding: URL-safe, as a state and a PKCE verifier must be.
pub fn random(n: usize) -> anyhow::Result<String> {
    let mut buf = vec![0u8; n];
    getrandom::getrandom(&mut buf).map_err(|e| anyhow!("no randomness for the sign-in: {e}"))?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

/// PKCE's S256 challenge for a verifier (RFC 7636 §4.2).
pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// A query value, percent-encoded.
pub fn escape(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

/// The link the person opens: Oura's sign-in, asking for every read scope, with PKCE.
pub fn link(auth: &str, client_id: &str, redirect: &str, state: &str, challenge: &str) -> String {
    let query = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect),
        ("scope", SCOPES),
        ("state", state),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ];
    let query: Vec<String> = query.iter().map(|(k, v)| format!("{k}={}", escape(v))).collect();
    format!("{auth}?{}", query.join("&"))
}

/// Whether Oura's `scope` answer has a scope: it may name them `extapi:daily`. An answer without one says nothing.
pub fn allowed(scope: &str, want: &str) -> bool {
    scope.trim().is_empty() || scope.split_whitespace().any(|s| s.rsplit(':').next() == Some(want))
}

impl SignIns {
    /// Start one: Oura's link, and the state core matches its callback to.
    pub fn start(
        &self,
        ends: &Endpoints,
        client: Client,
        session: &str,
        redirect: &str,
        label: &str,
    ) -> anyhow::Result<CredentialsSignInResponse> {
        if session.is_empty() {
            bail!("a sign-in needs the node's session");
        }
        let redirect = redirect.trim();
        if redirect.is_empty() {
            bail!(UPGRADE);
        }
        let (verifier, state) = (random(48)?, random(24)?);
        let url = link(&ends.auth, client.id(), redirect, &state, &challenge(&verifier));
        let named = if label.is_empty() { String::new() } else { format!(" for {label}") };
        let prompt = format!("Sign in to Oura{named} and allow every box. Pointman finishes by itself.");
        let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
        open.retain(|_, p| p.until > Instant::now());
        let pending =
            Pending { client, verifier, redirect: redirect.into(), label: label.into(), until: Instant::now() + WAIT };
        open.insert(session.to_string(), pending);
        Ok(CredentialsSignInResponse { url, prompt: Some(prompt), state: Some(state), ..Default::default() })
    }

    /// Core's callback gave the code: the vault's value, once Oura takes it with the verifier, through core with the
    /// shared client.
    pub fn code(
        &self,
        h: &Handle,
        agent: &ureq::Agent,
        ends: &Endpoints,
        session: &str,
        code: &str,
    ) -> anyhow::Result<String> {
        let p = {
            let mut open = self.open.lock().unwrap_or_else(|e| e.into_inner());
            open.retain(|_, p| p.until > Instant::now());
            open.remove(session).ok_or_else(|| anyhow!("this sign-in has ended: start it again"))?
        };
        let code = code.trim();
        if code.is_empty() {
            bail!("Oura gave no code: start the sign-in again");
        }
        let v = match &p.client {
            Client::Shared { .. } => shared_exchange(h, code, &p.verifier, &p.redirect)?,
            Client::Own(client) => exchange(agent, ends, client, code, &p.verifier, &p.redirect)?,
        };
        let Some(access) = v["access_token"].as_str().filter(|t| !t.is_empty()) else {
            bail!("Oura signed it in but gave no access token: start the sign-in again");
        };
        if !allowed(v["scope"].as_str().unwrap_or_default(), NEEDED) {
            let who = if p.label.is_empty() { "it".to_string() } else { p.label.clone() };
            bail!("the sign-in didn't allow {NEEDED}: sign {who} in again and leave every box ticked");
        }
        let lasts = v["expires_in"].as_i64().filter(|s| *s > 0).unwrap_or(86_400);
        let until = OffsetDateTime::now_utc().unix_timestamp() + lasts;
        Ok(accounts::value(access, until, v["refresh_token"].as_str().unwrap_or_default()))
    }
}

/// The code exchanged through core with Pointman's shared client (core adds its secret). Core's refusal says what
/// to do, never the code.
fn shared_exchange(h: &Handle, code: &str, verifier: &str, redirect: &str) -> anyhow::Result<Value> {
    let t = h.oauth_token(PROVIDER, code, verifier, redirect).map_err(|e| {
        match e.downcast_ref::<HostError>().map(|h| (h.code.as_deref(), h.message.clone())) {
            Some((Some("invalid_grant"), _)) => {
                anyhow!("Oura didn't take the sign-in's code (it ran out or was used): start the sign-in again")
            }
            Some((Some("upstream"), _)) => anyhow!("Pointman's Oura sign-in service didn't answer: try in a minute"),
            Some((Some("not_yours"), _)) => anyhow!("the sign-in's code was for another Pointman: start it again here"),
            Some((_, said)) => anyhow!("Pointman couldn't finish the sign-in with Oura: {said}"),
            None => anyhow!("Pointman couldn't finish the sign-in with Oura: {e:#}"),
        }
    })?;
    Ok(json!({"access_token": t.access_token, "expires_in": t.expires_in, "scope": t.scope,
        "refresh_token": t.refresh_token}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_challenge_is_rfc_7636s() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn the_link_asks_for_every_read_scope_with_pkce() {
        let url = link(
            "https://cloud.ouraring.com/oauth/authorize",
            "CLIENT1234",
            "https://api.pointman.ai/v1/oauth/oura/callback",
            "st4te",
            "ch4llenge",
        );
        assert!(url.starts_with("https://cloud.ouraring.com/oauth/authorize?response_type=code&client_id=CLIENT1234&"));
        for part in [
            "redirect_uri=https%3A%2F%2Fapi.pointman.ai%2Fv1%2Foauth%2Foura%2Fcallback",
            "scope=email%20personal%20daily%20heartrate%20workout%20tag%20session%20spo2%20heart_health",
            "state=st4te",
            "code_challenge=ch4llenge",
            "code_challenge_method=S256",
        ] {
            assert!(url.contains(&format!("&{part}")), "{part} in {url}");
        }
    }

    #[test]
    fn a_scope_may_come_back_prefixed() {
        assert!(allowed("extapi:email extapi:daily", "daily"));
        assert!(allowed("daily heartrate", "daily"));
        assert!(!allowed("extapi:email", "daily"));
        assert!(allowed("", "daily"), "no scope in the answer says nothing");
    }
}
