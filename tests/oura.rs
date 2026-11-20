//! The extension's commands under a stand-in node, against a fake Oura on a local port (OURA_API_BASE): sign-ins that
//! come back by redirect with PKCE, with a self-hosted Pointman's own client or through core's shared one; a day's
//! scores; records page by page; and a sign-in that ran out or that Oura no longer takes. No real Oura is called.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use pointman_extension::protocol::{
    oauth_token_request::Grant, OauthSharedClientRequest, OauthSharedClientResponse, OauthTokenRequest,
    OauthTokenResponse,
};
use pointman_extension::testing::StandIn;
use pointman_extension::HostError;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const REDIRECT: &str = "https://board.example.com/oauth/callback";
const CLOUD: &str = "https://api.pointman.ai/v1/oauth/oura/callback";
const CLIENT: &str = "OURACLIENT01 OURAsecret-for-the-tests";
const CODE: &str = "CODEfromOURA0123";
const ACCESS: &str = "ACCESSfromOURA0123456789";
const REFRESH: &str = "REFRESHfromOURA0123";
const FAR: i64 = 4_000_000_000;

/// One request the fake was sent: its path with its query, its token, its form.
#[derive(Debug, Clone)]
struct Req {
    path: String,
    token: String,
    form: HashMap<String, String>,
}

/// A fake Oura: the token endpoint takes CODE (checking its verifier against `challenge`), and the user collection
/// answers each path from `pages` (a list for next_token pages) for the token ACCESS; any other token is a 401.
#[derive(Clone, Default)]
struct Fake {
    url: String,
    seen: Arc<Mutex<Vec<Req>>>,
    challenge: Arc<Mutex<String>>,
}

fn form(body: &str) -> HashMap<String, String> {
    let un = |s: &str| {
        let s = s.replace('+', " ");
        let mut out = Vec::new();
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() + 1 {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8(out).unwrap()
    };
    body.split('&').filter_map(|kv| kv.split_once('=')).map(|(k, v)| (un(k), un(v))).collect()
}

fn page(path: &str) -> Value {
    let day = |d: &str, score: i64| json!({"day": d, "score": score});
    match path.split('?').next().unwrap() {
        "/v2/usercollection/personal_info" => json!({"email": "james@example.com", "age": 33}),
        "/v2/usercollection/daily_sleep" => json!({"data": [day("2026-11-19", 70), day("2026-11-20", 81),
            day("2026-11-21", 99)]}),
        "/v2/usercollection/daily_readiness" => {
            json!({"data": [{"day": "2026-11-20", "score": 77, "temperature_deviation": -0.21}]})
        }
        "/v2/usercollection/daily_activity" => {
            json!({"data": [{"day": "2026-11-20", "score": 90, "steps": 8123, "active_calories": 412,
                "met": {"items": vec![1.2; 1440]}}]})
        }
        "/v2/usercollection/sleep" => json!({"data": [
            {"day": "2026-11-20", "type": "sleep", "total_sleep_duration": 1800},
            {"day": "2026-11-20", "type": "long_sleep", "total_sleep_duration": 26_100, "time_in_bed": 29_000,
             "deep_sleep_duration": 5400, "rem_sleep_duration": 6000, "efficiency": 90, "average_hrv": 48,
             "lowest_heart_rate": 52, "bedtime_start": "2026-11-19T23:10:00+08:00",
             "bedtime_end": "2026-11-20T07:13:00+08:00", "sleep_phase_5_min": "4".repeat(400)}]}),
        "/v2/usercollection/heartrate" if path.contains("next_token=p2") => {
            json!({"data": [{"bpm": 61, "timestamp": "2026-11-20T01:10:00+00:00"}], "next_token": null})
        }
        "/v2/usercollection/heartrate" => json!({"data": [{"bpm": 58, "timestamp": "2026-11-20T01:00:00+00:00"},
            {"bpm": 60, "timestamp": "2026-11-20T01:05:00+00:00"}], "next_token": "p2"}),
        _ => json!({"data": []}),
    }
}

impl Fake {
    fn start() -> Fake {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let fake = Fake { url: format!("http://{}", listener.local_addr().unwrap()), ..Default::default() };
        let f = fake.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let f = f.clone();
                std::thread::spawn(move || {
                    let mut r = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    r.read_line(&mut line).unwrap();
                    let path = line.split_whitespace().nth(1).unwrap_or_default().to_string();
                    let (mut len, mut token) = (0, String::new());
                    loop {
                        let mut h = String::new();
                        if r.read_line(&mut h).unwrap_or(0) == 0 || h.trim().is_empty() {
                            break;
                        }
                        let (k, v) = h.split_once(':').unwrap_or_default();
                        match k.to_ascii_lowercase().as_str() {
                            "content-length" => len = v.trim().parse().unwrap_or(0),
                            "authorization" => token = v.trim().trim_start_matches("Bearer ").to_string(),
                            _ => {}
                        }
                    }
                    let mut body = vec![0; len];
                    r.read_exact(&mut body).unwrap();
                    let req = Req { path: path.clone(), token, form: form(&String::from_utf8_lossy(&body)) };
                    f.seen.lock().unwrap().push(req.clone());
                    let (status, v) = f.answer(&req);
                    let text = v.to_string();
                    let mut s = stream;
                    let _ = write!(
                        s,
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: \
                         close\r\n\r\n{text}",
                        text.len()
                    );
                });
            }
        });
        fake
    }

    fn answer(&self, r: &Req) -> (u16, Value) {
        if r.path == "/oauth/token" {
            let verifier = r.form.get("code_verifier").cloned().unwrap_or_default();
            let ok = r.form.get("code").map(String::as_str) == Some(CODE)
                && r.form.get("client_secret").map(String::as_str) == Some("OURAsecret-for-the-tests")
                && URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes())) == *self.challenge.lock().unwrap();
            return if ok {
                (
                    200,
                    json!({"access_token": ACCESS, "expires_in": 2_592_000, "token_type": "bearer",
                    "refresh_token": REFRESH, "scope": "extapi:email extapi:daily extapi:heartrate"}),
                )
            } else {
                (400, json!({"error": "invalid_grant"}))
            };
        }
        if r.token != ACCESS {
            return (401, json!({"detail": "Invalid token"}));
        }
        (200, page(&r.path))
    }

    fn api(&self) -> Vec<Req> {
        self.seen.lock().unwrap().iter().filter(|r| r.path.starts_with("/v2/")).cloned().collect()
    }
}

fn stand_in(fake: &Fake, secrets: Vec<(&str, String)>) -> StandIn {
    StandIn::new(env!("CARGO_MANIFEST_DIR"))
        .binary(env!("CARGO_BIN_EXE_oura"))
        .secrets(secrets)
        .settings(json!({}))
        .env("OURA_API_BASE", &fake.url)
}

/// A self-hosted Pointman's node: core has no shared client.
fn node(fake: &Fake, secrets: Vec<(&str, String)>) -> StandIn {
    stand_in(fake, secrets)
        .on(|_: OauthSharedClientRequest| Ok(OauthSharedClientResponse { shared: false, ..Default::default() }))
        .start()
        .unwrap()
}

fn signed_in(until: i64) -> Vec<(&'static str, String)> {
    vec![("oura.me", format!("{ACCESS} {until} {REFRESH}"))]
}

fn query_of(url: &str, key: &str) -> String {
    let q = url.split_once('?').unwrap().1;
    q.split('&').find_map(|kv| kv.strip_prefix(&format!("{key}="))).unwrap_or_default().to_string()
}

fn sign_in(node: &StandIn, redirect: &str) -> Value {
    node.call(
        "credentials.sign_in",
        json!({"form": "account", "label": "me", "session": {"id": "sgn_1"}, "redirectUri": redirect}),
    )
    .unwrap()
}

fn code(node: &StandIn) -> Result<Value, pointman_extension::testing::Failed> {
    node.call("credentials.code", json!({"form": "account", "session": {"id": "sgn_1"}, "code": CODE}))
}

#[test]
fn a_sign_in_comes_back_by_redirect_and_keeps_its_token_and_when_it_runs_out() {
    let fake = Fake::start();
    let node = node(&fake, vec![("oura.client", CLIENT.into())]);
    let started = sign_in(&node, REDIRECT);
    let url = started["url"].as_str().unwrap();
    assert!(url.starts_with("https://cloud.ouraring.com/oauth/authorize?"), "{url}");
    assert_eq!(query_of(url, "client_id"), "OURACLIENT01");
    assert_eq!(query_of(url, "code_challenge_method"), "S256");
    assert_eq!(query_of(url, "state"), started["state"].as_str().unwrap());
    *fake.challenge.lock().unwrap() = query_of(url, "code_challenge");

    let value = code(&node).unwrap()["value"].as_str().unwrap().to_string();
    let parts: Vec<&str> = value.split(' ').collect();
    assert_eq!((parts[0], parts[2]), (ACCESS, REFRESH), "{value}");
    let lasts = parts[1].parse::<i64>().unwrap() - time::OffsetDateTime::now_utc().unix_timestamp();
    assert!((2_591_000..=2_592_000).contains(&lasts), "it runs out when Oura says: {lasts}");
    let exchange = fake.seen.lock().unwrap().iter().find(|r| r.path == "/oauth/token").cloned().unwrap();
    assert_eq!(exchange.form["redirect_uri"], REDIRECT, "with the same redirect");
    assert!(code(&node).unwrap_err().message.contains("ended"), "used once");

    let log = node.log();
    for secret in [CODE, ACCESS, REFRESH, "OURAsecret-for-the-tests", exchange.form["code_verifier"].as_str()] {
        assert!(!log.contains(secret), "{secret} in the log: {log}");
    }
}

#[test]
fn a_hosted_pointman_signs_in_through_cores_shared_client() {
    let fake = Fake::start();
    let node = stand_in(&fake, vec![])
        .on(|r: OauthSharedClientRequest| {
            assert_eq!(r.provider, "oura");
            Ok(OauthSharedClientResponse {
                shared: true,
                client_id: "POINTMANOURA".into(),
                redirect_uri: CLOUD.into(),
                ..Default::default()
            })
        })
        .on(|r: OauthTokenRequest| match r.grant {
            Some(Grant::Code(c)) if r.provider == "oura" && c.code == CODE && c.redirect_uri == CLOUD => {
                Ok(OauthTokenResponse {
                    access_token: ACCESS.into(),
                    expires_in: 2_592_000,
                    scope: "daily email".into(),
                    refresh_token: Some(REFRESH.into()),
                    ..Default::default()
                })
            }
            _ => Err(HostError::with_code("Bad Request", "invalid_grant").into()),
        })
        .start()
        .unwrap();
    let e = node
        .call(
            "credentials.sign_in",
            json!({"form": "account", "label": "me", "session": {"id": "sgn_0"},
            "redirectUri": REDIRECT}),
        )
        .unwrap_err();
    assert!(e.message.contains("doesn't come back where"), "never another client after the shared one: {e:?}");
    let url = sign_in(&node, CLOUD)["url"].as_str().unwrap().to_string();
    assert_eq!(query_of(&url, "client_id"), "POINTMANOURA");
    let value = code(&node).unwrap()["value"].as_str().unwrap().to_string();
    assert!(value.starts_with(&format!("{ACCESS} ")) && value.ends_with(REFRESH), "{value}");
    assert!(fake.seen.lock().unwrap().is_empty(), "Oura's token endpoint isn't called by the extension");
}

#[test]
fn a_day_has_its_scores_and_its_main_night() {
    let fake = Fake::start();
    let node = node(&fake, signed_in(FAR));
    let done = node.run("oura.day", json!({"date": "2026-11-20"})).unwrap().result;
    let d = &done["days"][0];
    assert_eq!((d["sleep_score"].as_i64(), d["readiness_score"].as_i64()), (Some(81), Some(77)), "{done}");
    assert_eq!(d["total_sleep"], 26_100, "the long sleep, not the nap");
    assert_eq!(d["steps"], 8123);
    let text = done["text"].as_str().unwrap();
    assert!(text.contains("2026-11-20 (me): sleep 81, readiness 77, activity 90."), "{text}");
    assert!(text.contains("7h15 asleep") && text.contains("HRV 48 ms") && text.contains("-0.2 °C"), "{text}");
    let asked = fake.api().into_iter().find(|r| r.path.contains("daily_sleep")).unwrap().path;
    assert!(asked.contains("start_date=2026-11-20") && asked.contains("end_date=2026-11-21"), "{asked}");
}

#[test]
fn records_come_page_by_page_and_long_series_are_shortened() {
    let fake = Fake::start();
    let node = node(&fake, signed_in(FAR));
    let hr = node.run("oura.data", json!({"kind": "heartrate", "from": "2026-11-20", "to": "2026-11-20"})).unwrap();
    assert_eq!(hr.result["count"], 3, "{}", hr.result);
    let first = fake.api().into_iter().find(|r| r.path.contains("heartrate")).unwrap().path;
    assert!(first.contains("start_datetime=2026-11-20T00") && first.contains("end_datetime=2026-11-21T00"), "{first}");

    let nights = node.run("oura.data", json!({"kind": "sleep", "from": "2026-11-20", "to": "2026-11-20"})).unwrap();
    let text = nights.result["text"].as_str().unwrap();
    assert!(text.contains("[400 characters: full=true for them]"), "{text}");
    let sleep = node.run("oura.data", json!({"kind": "daily_sleep", "from": "2026-11-19", "to": "2026-11-20"}));
    assert_eq!(sleep.unwrap().result["count"], 2, "the day after `to` that Oura may add is dropped");
    let full = node
        .run("oura.data", json!({"kind": "sleep", "from": "2026-11-20", "to": "2026-11-20", "full": true}))
        .unwrap();
    assert!(full.result["text"].as_str().unwrap().contains(&"4".repeat(400)));
}

#[test]
fn a_sign_in_that_ran_out_or_that_oura_refuses_says_to_sign_in_again() {
    let fake = Fake::start();
    let node = node(&fake, signed_in(1_000_000_000));
    let e = node.run("oura.day", json!({})).unwrap_err();
    assert!(e.message.contains("ran out on 2001-09-09") && e.message.contains("/oura add me"), "{e:?}");
    assert!(fake.api().is_empty(), "nothing asked of Oura with a token that ran out");

    let node = self::node(&fake, vec![("oura.me", format!("REVOKEDtoken0123456 {FAR}"))]);
    let e = node.run("oura.data", json!({"kind": "workout", "from": "2026-11-01"})).unwrap_err();
    assert!(e.message.contains("no longer takes oura.me's sign-in") && e.message.contains("/oura add me"), "{e:?}");
}

#[test]
fn accounts_say_whose_each_is_and_until_when() {
    let fake = Fake::start();
    let node = node(&fake, [signed_in(FAR), vec![("oura.client", CLIENT.into())]].concat());
    let done = node.run("oura.accounts", json!({})).unwrap().result;
    assert_eq!(done["accounts"].as_array().unwrap().len(), 1, "the client isn't an account: {done}");
    assert_eq!(done["accounts"][0]["email"], "james@example.com");
    assert!(done["text"].as_str().unwrap().contains("signed in until 2096-10-02"), "{done}");
}
