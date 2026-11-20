//! Oura's HTTP API (https://cloud.ouraring.com/v2/docs): its token endpoint for a sign-in's code, with a self-hosted
//! Pointman's own client, and the user collection's records, page by page. Errors say what Oura said, never a token
//! or a code.

use std::io::Read;
use std::time::Duration;

use anyhow::{anyhow, bail};
use regex::Regex;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::{Date, OffsetDateTime};

/// Where the calls go: Oura's own, unless a test's stand-in is named in the environment (the node never passes its
/// own environment on, so only a test can).
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// The API and its token endpoint: `{api}/v2/usercollection/…`, `{api}/oauth/token`.
    pub api: String,
    /// The page a person signs in on.
    pub auth: String,
}

impl Endpoints {
    pub fn from_env() -> Self {
        let get = |k: &str, default: &str| {
            std::env::var(k)
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| default.into())
                .trim_end_matches('/')
                .into()
        };
        Endpoints {
            api: get("OURA_API_BASE", "https://api.ouraring.com"),
            auth: get("OURA_AUTH_URL", "https://cloud.ouraring.com/oauth/authorize"),
        }
    }
}

/// A self-hosted Pointman's own Oura API application (the vault's `oura.client`).
#[derive(Clone)]
pub struct OAuthClient {
    pub id: String,
    pub secret: String,
}

impl std::fmt::Debug for OAuthClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthClient").field("id", &self.id).finish_non_exhaustive()
    }
}

impl OAuthClient {
    /// The vault item's value: the client id, then its secret (a space or a colon between).
    pub fn parse(value: &str) -> Option<Self> {
        let m = Regex::new(r"([A-Za-z0-9_-]{8,128})[\s:]+([A-Za-z0-9_-]{8,256})").expect("compiles").captures(value)?;
        Some(OAuthClient { id: m[1].to_string(), secret: m[2].to_string() })
    }
}

pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(30))
        .timeout_read(Duration::from_secs(120))
        .user_agent(concat!("pointman-oura/", env!("CARGO_PKG_VERSION")))
        .build()
}

fn text(r: ureq::Response) -> String {
    let mut s = String::new();
    let _ = r.into_reader().take(64 << 20).read_to_string(&mut s);
    s
}

/// What Oura's error body says (`{detail}`, or OAuth's `{error, error_description}`), at most 200 characters.
fn said(body: &str) -> String {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let words = [&v["detail"], &v["error_description"], &v["error"]].into_iter().find_map(|w| match w {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    });
    words.unwrap_or_default().chars().take(200).collect()
}

/// A sign-in's code exchanged with a self-hosted Pointman's own client: Oura's answer (access_token, expires_in,
/// refresh_token, scope). Oura's error, never the body: it may hold a token.
pub fn exchange(
    agent: &ureq::Agent,
    ends: &Endpoints,
    client: &OAuthClient,
    code: &str,
    verifier: &str,
    redirect: &str,
) -> anyhow::Result<Value> {
    let got = agent.post(&format!("{}/oauth/token", ends.api)).send_form(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect),
        ("client_id", client.id.as_str()),
        ("client_secret", client.secret.as_str()),
        ("code_verifier", verifier),
    ]);
    match got {
        Ok(r) => serde_json::from_str(&text(r)).map_err(|_| anyhow!("Oura's answer to the sign-in wasn't JSON")),
        Err(ureq::Error::Status(status, r)) => {
            let v: Value = serde_json::from_str(&text(r)).unwrap_or(Value::Null);
            match v["error"].as_str().unwrap_or_default() {
                "invalid_grant" => bail!("Oura didn't take the sign-in's code (it ran out or was used): sign in again"),
                "invalid_client" | "unauthorized_client" => {
                    bail!("Oura refused the client: oura.client must be your Oura application's client ID and secret")
                }
                e => bail!("Oura refused the sign-in ({status} {e})"),
            }
        }
        Err(ureq::Error::Transport(t)) => bail!("no answer from Oura: {t}"),
    }
}

/// A day as Oura names one: `2026-11-20`.
pub fn day(s: &str) -> anyhow::Result<Date> {
    Date::parse(s.trim(), format_description!("[year]-[month]-[day]"))
        .map_err(|_| anyhow!("{s:?} isn't a day: give it as 2026-11-20"))
}

pub fn ymd(d: Date) -> String {
    d.format(format_description!("[year]-[month]-[day]")).expect("formats")
}

/// The latest day anywhere now (UTC+14), so an open-ended range keeps the wearer's newest day: Oura dates a day in
/// the wearer's own time, and at UTC+8 a 07:00 waking is the day before in UTC.
pub fn today() -> Date {
    latest_day(OffsetDateTime::now_utc())
}

pub fn latest_day(now: OffsetDateTime) -> Date {
    (now + time::Duration::hours(14)).date()
}

/// A time for heartrate's query: RFC 3339 as given, or a day from its midnight UTC (`end` the day after, so the day
/// counts).
pub fn instant(s: &str, end: bool) -> anyhow::Result<String> {
    if let Ok(t) = OffsetDateTime::parse(s.trim(), &Rfc3339) {
        return Ok(t.format(&Rfc3339).expect("formats"));
    }
    let d = day(s.get(..10).unwrap_or(s)).map_err(|_| anyhow!("{s:?} isn't a day or an RFC 3339 time"))?;
    let d = if end { d.next_day().unwrap_or(d) } else { d };
    Ok(format!("{}T00:00:00Z", ymd(d)))
}

/// One account's calls, with its access token.
pub struct Api<'a> {
    pub agent: &'a ureq::Agent,
    pub ends: &'a Endpoints,
    pub label: &'a str,
    pub token: &'a str,
}

impl Api<'_> {
    /// One GET of the user collection (`personal_info`, `daily_sleep`…): Oura's JSON, or what it said.
    pub fn get(&self, what: &str, query: &[(&str, &str)]) -> anyhow::Result<Value> {
        let mut req = self.agent.get(&format!("{}/v2/usercollection/{what}", self.ends.api));
        for (k, v) in query {
            req = req.query(k, v);
        }
        let label = self.label;
        match req.set("Authorization", &format!("Bearer {}", self.token)).call() {
            Ok(r) => serde_json::from_str(&text(r)).map_err(|_| anyhow!("Oura's answer wasn't JSON")),
            Err(ureq::Error::Status(status, r)) => {
                let why = said(&text(r));
                Err(match status {
                    401 => anyhow!("Oura no longer takes oura.{label}'s sign-in: sign in again with /oura add {label}"),
                    403 => anyhow!(
                        "Oura refused it (403 {why}): the sign-in didn't allow {what} (sign in again with /oura add \
                         {label} and allow it), or the Oura membership has lapsed"
                    ),
                    426 => anyhow!("Oura says the Oura app on the phone is too old for the API: update it"),
                    429 => anyhow!("Oura says that's too many calls for now: try again in a few minutes"),
                    _ => anyhow!("Oura said {status}: {why}"),
                })
            }
            Err(ureq::Error::Transport(t)) => Err(anyhow!("no answer from Oura: {t}")),
        }
    }

    /// Every record of a kind between two days (that last day included), following `next_token`: at most 20 pages,
    /// and more is an error that asks for a shorter range.
    pub fn records(&self, kind: &str, from: &str, to: &str) -> anyhow::Result<Vec<Value>> {
        let path = if kind == "vo2_max" { "vO2_max" } else { kind };
        let (fk, tk, start, end, last) = if kind == "heartrate" {
            ("start_datetime", "end_datetime", instant(from, false)?, instant(to, true)?, None)
        } else {
            let (a, b) = (day(from)?, day(to)?);
            // Oura's end_date leaves its day out on some kinds: ask a day more, and drop it after
            ("start_date", "end_date", ymd(a), ymd(b.next_day().unwrap_or(b)), Some(ymd(b)))
        };
        let mut out = Vec::new();
        let mut next = String::new();
        for _ in 0..20 {
            let mut q = vec![(fk, start.as_str()), (tk, end.as_str())];
            if !next.is_empty() {
                q.push(("next_token", next.as_str()));
            }
            let v = self.get(path, &q)?;
            out.extend(v["data"].as_array().cloned().unwrap_or_default());
            next = v["next_token"].as_str().unwrap_or_default().to_string();
            if next.is_empty() {
                break;
            }
        }
        if !next.is_empty() {
            bail!("Oura has more than 20 pages of {kind} from {from} to {to}: ask for a shorter range");
        }
        if let Some(last) = last {
            // a day's records carry `day`; enhanced_tag and rest_mode_period carry `start_day`
            out.retain(|r| r["day"].as_str().or(r["start_day"].as_str()).is_none_or(|d| d <= last.as_str()));
        }
        Ok(out)
    }
}

/// A record shortened for reading: a list over 48 items, or text over 300 characters (a night's stages), says how
/// long it is instead.
pub fn trim(v: &Value) -> Value {
    match v {
        Value::Array(a) if a.len() > 48 => json!(format!("[{} items: full=true for them]", a.len())),
        Value::String(s) if s.len() > 300 => json!(format!("[{} characters: full=true for them]", s.len())),
        Value::Array(a) => Value::Array(a.iter().map(trim).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, v)| (k.clone(), trim(v))).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn days_and_times() {
        assert_eq!(ymd(day("2026-11-20").unwrap()), "2026-11-20");
        assert!(day("20 Nov").unwrap_err().to_string().contains("2026-11-20"));
        assert_eq!(instant("2026-11-20", false).unwrap(), "2026-11-20T00:00:00Z");
        assert_eq!(instant("2026-11-20", true).unwrap(), "2026-11-21T00:00:00Z");
        assert_eq!(instant("2026-11-20T08:00:00+08:00", true).unwrap(), "2026-11-20T08:00:00+08:00");
        // 07:00 at UTC+8 is 23:00 UTC the day before: the wearer's day is the newest
        let woke = OffsetDateTime::parse("2026-11-19T23:00:00Z", &Rfc3339).unwrap();
        assert_eq!(ymd(latest_day(woke)), "2026-11-20");
        assert!(instant("soon", false).is_err());
    }

    #[test]
    fn a_long_series_says_how_long_it_is() {
        let night = json!({"score": 81, "hrv": {"items": vec![40; 100], "interval": 300},
            "sleep_phase_5_min": "4".repeat(400), "contributors": {"rem_sleep": 90}});
        let t = trim(&night);
        assert_eq!(t["score"], 81);
        assert_eq!(t["hrv"]["items"], "[100 items: full=true for them]");
        assert_eq!(t["hrv"]["interval"], 300);
        assert_eq!(t["sleep_phase_5_min"], "[400 characters: full=true for them]");
        assert_eq!(t["contributors"]["rem_sleep"], 90);
    }

    #[test]
    fn a_client_is_its_id_then_its_secret() {
        let c = OAuthClient::parse("ABCDEFGH1234 s3cretVALUE-xyz").unwrap();
        assert_eq!((c.id.as_str(), c.secret.as_str()), ("ABCDEFGH1234", "s3cretVALUE-xyz"));
        assert!(!format!("{c:?}").contains("s3cret"));
        assert!(OAuthClient::parse("short").is_none());
    }
}
