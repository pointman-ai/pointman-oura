//! The extension's process: the node starts it (`bin/oura`, from the extension's folder) and talks to it over stdin
//! and stdout. It reads Oura accounts' days and records, and signs accounts in from the apps, with Pointman's shared
//! Oura client where core has one and the vault's `oura.client` where it doesn't. It never writes to Oura, and no
//! token or code is ever logged.

use std::sync::Arc;

use anyhow::{anyhow, bail};
use oura::accounts::{self, item};
use oura::api::{self, agent, Api, Endpoints, OAuthClient};
use oura::signin::{Client, SignIns, UPGRADE};
use oura::v1::{
    Account, AccountsParams, AccountsResult, AddParams, AddResult, ClientParams, ClientResult, DataParams, DataResult,
    Day, DayParams, DayResult, Problem, Settings,
};
use oura::{and, CLIENT_ITEM, PROVIDER};
use pointman_extension::protocol::{CredentialsCodeRequest, CredentialsCodeResponse, CredentialsSignInRequest};
use pointman_extension::{Extension, Handle, HostError, Job};
use serde_json::Value;
use time::OffsetDateTime;

/// At most this many records go in a reply's text.
const MOST: usize = 2000;

struct Ext {
    h: Handle,
    agent: ureq::Agent,
    ends: Endpoints,
}

impl Ext {
    fn reads(&self, asked: &str) -> anyhow::Result<Vec<String>> {
        let setting = self.h.typed_settings::<Settings>().map(|s| s.account).unwrap_or_default();
        accounts::for_read(&accounts::labels(self.h.secrets("oura.")?), asked, &setting)
    }

    /// The client a sign-in sent to `redirect` goes through: core's shared one when it has one, and only if that's
    /// where `redirect` points; the vault's `oura.client` when core says it has none. Never one after the other.
    fn sign_in_client(&self, redirect: &str) -> anyhow::Result<Client> {
        let redirect = redirect.trim();
        if redirect.is_empty() {
            bail!(UPGRADE);
        }
        let core = self.h.oauth_shared_client(PROVIDER).map_err(|e| {
            let said = e.downcast_ref::<HostError>().map(|h| h.message.clone()).unwrap_or_else(|| format!("{e:#}"));
            anyhow!("Pointman couldn't say whether it has a shared Oura client, so the sign-in stops: {said}")
        })?;
        if !core.shared {
            let value = self.h.secret(CLIENT_ITEM).map_err(|_| {
                anyhow!(
                    "this Pointman has no shared Oura client, so it needs one of its own: type /oura client in the \
                     app and paste your Oura application's client ID and secret"
                )
            })?;
            let own = OAuthClient::parse(&value)
                .ok_or_else(|| anyhow!("{CLIENT_ITEM} isn't a client ID and secret: add it again with /oura client"))?;
            return Ok(Client::Own(own));
        }
        if core.client_id.trim().is_empty() || core.redirect_uri.trim() != redirect {
            bail!("Pointman's shared Oura client doesn't come back where this sign-in does, so it stops: start again");
        }
        Ok(Client::Shared { id: core.client_id.trim().to_string() })
    }

    /// `f` with an account's API, once its sign-in is there and hasn't run out.
    fn api<T>(&self, label: &str, f: impl FnOnce(&Api) -> anyhow::Result<T>) -> anyhow::Result<T> {
        let (token, until) = accounts::token(label, &self.h.secret(&item(label))?)?;
        if until <= OffsetDateTime::now_utc().unix_timestamp() {
            bail!("oura.{label}'s sign-in ran out on {}: sign in again with /oura add {label}", when(until));
        }
        f(&Api { agent: &self.agent, ends: &self.ends, label, token: &token })
    }
}

fn when(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix).map(|t| api::ymd(t.date())).unwrap_or_default()
}

fn problem(account: &str, e: &anyhow::Error) -> Problem {
    Problem { account: account.to_string(), error: format!("{e:#}"), ..Default::default() }
}

/// Each account's failure in a line, for a read's text.
fn failures(failed: &[Problem]) -> String {
    failed.iter().map(|f| format!("\nCouldn't ask {}: {}", f.account, f.error)).collect()
}

/// A read that asked every account it was given, and every one failed: the error is theirs.
fn all_failed(labels: &[String], failed: &[Problem]) -> anyhow::Result<()> {
    if !labels.is_empty() && failed.len() == labels.len() {
        let each: Vec<String> = failed.iter().map(|f| format!("{}: {}", f.account, f.error)).collect();
        bail!("{}", each.join("; "));
    }
    Ok(())
}

fn int(v: &Value) -> i32 {
    v.as_i64().unwrap_or_default() as i32
}

fn hm(seconds: i32) -> String {
    format!("{}h{:02}", seconds / 3600, seconds % 3600 / 60)
}

fn accounts_list(x: &Ext, _: &Job, _: AccountsParams) -> anyhow::Result<AccountsResult> {
    let have = accounts::labels(x.h.secrets("oura.")?);
    if have.is_empty() {
        return Ok(AccountsResult {
            text: "No Oura account is signed in: /oura add <label> in the app signs one in.".into(),
            ..Default::default()
        });
    }
    let mut out = AccountsResult::default();
    let mut lines = Vec::new();
    for label in &have {
        let mut a = Account { label: label.clone(), ..Default::default() };
        let got = x.api(label, |api| {
            let until = accounts::token(label, &x.h.secret(&item(label))?)?.1;
            Ok((api.get("personal_info", &[])?, until))
        });
        match got {
            Ok((v, until)) => {
                (a.email, a.works) = (v["email"].as_str().unwrap_or_default().to_string(), true);
                a.until = OffsetDateTime::from_unix_timestamp(until)
                    .ok()
                    .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
                    .unwrap_or_default();
                lines.push(format!("{label} ({}, signed in until {})", a.email, when(until)));
            }
            Err(e) => {
                a.error = format!("{e:#}");
                lines.push(format!("{label} (not working: {})", a.error));
            }
        }
        out.accounts.push(a);
    }
    out.text = format!("Oura: {}.", lines.join(", "));
    Ok(out)
}

/// One account's day: the latest with scores when none is named.
fn one_day(api: &Api, label: &str, date: &str) -> anyhow::Result<Option<Day>> {
    let to = if date.is_empty() { api::today() } else { api::day(date)? };
    let from = if date.is_empty() { to - time::Duration::days(3) } else { to };
    let (from, to) = (api::ymd(from), api::ymd(to));
    let get = |kind: &str| api.records(kind, &from, &to);
    let (sleep, ready, active, nights) =
        (get("daily_sleep")?, get("daily_readiness")?, get("daily_activity")?, get("sleep")?);
    let Some(day) = [&sleep, &ready, &active].iter().flat_map(|r| r.iter()).filter_map(|r| r["day"].as_str()).max()
    else {
        return Ok(None);
    };
    let on = |rs: &[Value]| rs.iter().find(|r| r["day"] == day).cloned().unwrap_or(Value::Null);
    let (s, r, a) = (on(&sleep), on(&ready), on(&active));
    // the day's main sleep: its long_sleep, else its longest
    let night = nights
        .iter()
        .filter(|n| n["day"] == day && n["type"] != "deleted" && n["type"] != "rest")
        .max_by_key(|n| (n["type"] == "long_sleep", n["total_sleep_duration"].as_i64()))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(Some(Day {
        account: label.to_string(),
        day: day.to_string(),
        sleep_score: int(&s["score"]),
        readiness_score: int(&r["score"]),
        activity_score: int(&a["score"]),
        total_sleep: int(&night["total_sleep_duration"]),
        time_in_bed: int(&night["time_in_bed"]),
        deep_sleep: int(&night["deep_sleep_duration"]),
        rem_sleep: int(&night["rem_sleep_duration"]),
        efficiency: int(&night["efficiency"]),
        average_hrv: int(&night["average_hrv"]),
        lowest_heart_rate: int(&night["lowest_heart_rate"]),
        bedtime_start: night["bedtime_start"].as_str().unwrap_or_default().to_string(),
        bedtime_end: night["bedtime_end"].as_str().unwrap_or_default().to_string(),
        temperature_deviation: r["temperature_deviation"].as_f64().unwrap_or_default(),
        steps: int(&a["steps"]),
        active_calories: int(&a["active_calories"]),
        ..Default::default()
    }))
}

fn day_line(d: &Day) -> String {
    let score = |n: i32| if n == 0 { "not yet".to_string() } else { n.to_string() };
    let mut t = format!(
        "{} ({}): sleep {}, readiness {}, activity {}.",
        d.day,
        d.account,
        score(d.sleep_score),
        score(d.readiness_score),
        score(d.activity_score)
    );
    if d.total_sleep > 0 {
        t.push_str(&format!(
            "\n  Night: {} asleep of {} in bed ({}% efficient), deep {}, REM {}, {} to {}; HRV {} ms, lowest HR {}.",
            hm(d.total_sleep),
            hm(d.time_in_bed),
            d.efficiency,
            hm(d.deep_sleep),
            hm(d.rem_sleep),
            d.bedtime_start,
            d.bedtime_end,
            d.average_hrv,
            d.lowest_heart_rate
        ));
    }
    if d.readiness_score > 0 {
        t.push_str(&format!("\n  Temperature {:+.1} °C from usual.", d.temperature_deviation));
    }
    if d.steps > 0 {
        t.push_str(&format!("\n  {} steps, {} active kcal.", d.steps, d.active_calories));
    }
    t
}

fn day(x: &Ext, _: &Job, p: DayParams) -> anyhow::Result<DayResult> {
    let labels = x.reads(&p.account)?;
    let mut out = DayResult::default();
    let mut lines = Vec::new();
    for label in &labels {
        match x.api(label, |api| one_day(api, label, p.date.trim())) {
            Ok(Some(d)) => {
                lines.push(day_line(&d));
                out.days.push(d);
            }
            Ok(None) => lines.push(format!(
                "{label}: no scores yet for {}.",
                if p.date.is_empty() { "the last 3 days" } else { p.date.as_str() }
            )),
            Err(e) => out.failed.push(problem(label, &e)),
        }
    }
    all_failed(&labels, &out.failed)?;
    out.text = lines.join("\n") + &failures(&out.failed);
    Ok(out)
}

fn data(x: &Ext, _: &Job, p: DataParams) -> anyhow::Result<DataResult> {
    let to = if p.to.trim().is_empty() { api::ymd(api::today()) } else { p.to.trim().to_string() };
    let labels = x.reads(&p.account)?;
    let mut out = DataResult::default();
    let mut lines = Vec::new();
    for label in &labels {
        match x.api(label, |api| api.records(&p.kind, &p.from, &to)) {
            Ok(records) => {
                for r in records {
                    let mut r = if p.full { r } else { api::trim(&r) };
                    if labels.len() > 1 {
                        r["account"] = Value::from(label.as_str());
                    }
                    lines.push(r.to_string());
                }
            }
            Err(e) => out.failed.push(problem(label, &e)),
        }
    }
    all_failed(&labels, &out.failed)?;
    out.count = lines.len() as i32;
    let more = lines.len().saturating_sub(MOST);
    lines.truncate(MOST);
    let mut text = format!("{} {} records from {} to {to} in {}:", out.count, p.kind, p.from, and(&labels));
    for l in &lines {
        text.push('\n');
        text.push_str(l);
    }
    if more > 0 {
        text.push_str(&format!("\n…and {more} more: ask for a shorter range"));
    }
    out.text = text + &failures(&out.failed);
    Ok(out)
}

fn main() -> anyhow::Result<()> {
    let mut ext = Extension::new()?;
    let x = Arc::new(Ext { h: ext.handle(), agent: agent(), ends: Endpoints::from_env() });
    let signins = Arc::new(SignIns::default());

    let xx = x.clone();
    ext.typed_command(move |job: &Job, p: AccountsParams| accounts_list(&xx, job, p));
    let xx = x.clone();
    ext.typed_command(move |job: &Job, p: DayParams| day(&xx, job, p));
    let xx = x.clone();
    ext.typed_command(move |job: &Job, p: DataParams| data(&xx, job, p));

    // `/oura add` and `/oura client` posted (an agent, an older app): the apps open the forms for them
    ext.typed_command(|_: &Job, _: AddParams| {
        Ok(AddResult {
            text: "An Oura account is signed in from the Pointman app, so its token never goes in a post: type \
                   `/oura add <label>` there and tap Sign in."
                .into(),
            ..Default::default()
        })
    });
    ext.typed_command(|_: &Job, _: ClientParams| {
        Ok(ClientResult {
            text: "A self-hosted Pointman's own Oura application is added in the Pointman app, so its secret never \
                   goes in a post: type `/oura client` there. A hosted Pointman needs none."
                .into(),
            ..Default::default()
        })
    });

    let (xx, si) = (x.clone(), signins.clone());
    ext.on(move |p: CredentialsSignInRequest| {
        if p.form != "account" {
            bail!("oura signs in accounts only (form: account); the client is pasted with /oura client");
        }
        let label = p.label.trim();
        if label == "client" {
            bail!("{CLIENT_ITEM} is the client's place in the vault: call the account something else");
        }
        let session = p.session.as_option().map(|s| s.id.as_str()).unwrap_or_default();
        si.start(&xx.ends, xx.sign_in_client(&p.redirect_uri)?, session, &p.redirect_uri, label)
    });
    let (xx, si) = (x, signins);
    ext.on(move |p: CredentialsCodeRequest| {
        let session = p.session.as_option().map(|s| s.id.as_str()).unwrap_or_default();
        let value = si.code(&xx.h, &xx.agent, &xx.ends, session, &p.code)?;
        Ok(CredentialsCodeResponse { value, ..Default::default() })
    });

    ext.run()
}
