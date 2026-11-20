//! Which Oura accounts a call uses, and what each keeps in the vault. Each is a label (`oura.me` is `me`). A call may
//! name one with `account`; else the `account` setting's is used; with neither, every account signed in.
//!
//! An account's vault value is `<access token> <when it runs out, unix seconds> [<refresh token>]`. Oura's refresh
//! tokens work once each, and an extension can't write the vault, so the extension never refreshes: a sign-in lasts
//! as long as its access token (30 days), then the person signs in again. The refresh token is kept for the day the
//! extension can store the next one.

use anyhow::{anyhow, bail};

use crate::CLIENT_ITEM;

/// The accounts' labels from the vault's `oura.*` names: sorted, without the client's.
pub fn labels(items: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = items
        .into_iter()
        .filter(|n| n != CLIENT_ITEM)
        .filter_map(|n| n.strip_prefix("oura.").map(String::from))
        .filter(|l| !l.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The vault item of a label.
pub fn item(label: &str) -> String {
    format!("oura.{label}")
}

/// A sign-in as the vault keeps it.
pub fn value(access: &str, until: i64, refresh: &str) -> String {
    format!("{access} {until} {refresh}").trim_end().to_string()
}

/// An account's access token and when it runs out, from its vault value.
pub fn token(label: &str, value: &str) -> anyhow::Result<(String, i64)> {
    let mut parts = value.split_whitespace();
    let (Some(access), Some(until)) = (parts.next(), parts.next().and_then(|u| u.parse().ok())) else {
        bail!("oura.{label} isn't an Oura sign-in: sign it in again with /oura add {label}");
    };
    Ok((access.to_string(), until))
}

fn none_signed_in() -> anyhow::Error {
    anyhow!("no Oura account is signed in: type /oura add <label> in the app and tap Sign in")
}

/// The accounts a read uses: the one the call or the setting names, else every one signed in.
pub fn for_read(have: &[String], asked: &str, setting: &str) -> anyhow::Result<Vec<String>> {
    if have.is_empty() {
        return Err(none_signed_in());
    }
    let (want, from) = match (asked.trim(), setting.trim()) {
        ("", "") => return Ok(have.to_vec()),
        ("", s) => (s, "the account setting"),
        (a, _) => (a, "account"),
    };
    if have.iter().any(|h| h == want) {
        return Ok(vec![want.to_string()]);
    }
    bail!(
        "no Oura account {want} is signed in ({from}); there's {}: pass account=<label> of one of them, or sign \
         {want} in with /oura add {want}",
        have.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn have() -> Vec<String> {
        labels(vec!["oura.me".into(), "oura.client".into(), "oura.partner".into()])
    }

    #[test]
    fn the_client_isnt_an_account() {
        assert_eq!(have(), ["me", "partner"]);
        assert_eq!(item("me"), "oura.me");
    }

    #[test]
    fn a_read_uses_the_one_named_else_every_one() {
        assert_eq!(for_read(&have(), "", "").unwrap(), ["me", "partner"]);
        assert_eq!(for_read(&have(), "me", "partner").unwrap(), ["me"], "the call's beats the setting's");
        assert_eq!(for_read(&have(), "", "partner").unwrap(), ["partner"]);
        let e = for_read(&have(), "", "school").unwrap_err().to_string();
        assert!(e.contains("the account setting") && e.contains("me, partner") && e.contains("/oura add"), "{e}");
        assert!(for_read(&[], "", "").unwrap_err().to_string().contains("/oura add"));
    }

    #[test]
    fn a_sign_in_keeps_its_token_and_when_it_runs_out() {
        let v = value("ACCESS123", 1_800_000_000, "REFRESH9");
        assert_eq!(v, "ACCESS123 1800000000 REFRESH9");
        assert_eq!(token("me", &v).unwrap(), ("ACCESS123".to_string(), 1_800_000_000));
        assert_eq!(value("A", 5, ""), "A 5", "no refresh token, nothing after");
        assert!(token("me", "garbage").unwrap_err().to_string().contains("/oura add me"));
    }
}
