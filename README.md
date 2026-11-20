# oura

A Pointman extension that lets every agent read a person's Oura ring data: sleep, readiness, activity, heart rate,
workouts, stress and the rest of Oura's API v2 user collection, with any number of Oura accounts. Each account is
signed in from the Pointman apps and kept in the vault as `oura.<label>`, so every machine with the extension uses the
same sign-ins. It only reads.

| File | What |
|---|---|
| `SKILL.md` | The agents' guidance: the commands, the kinds of record, privacy |
| `proto/oura/v1/oura.proto` | The commands' params and results, and the settings |
| `src/` | The process: `signin` (authorization code + PKCE, shared or own client), `accounts` (which account a call uses, what the vault keeps), `api` (Oura's HTTP API) |

## Install

```
pointman add pointman-ai/pointman-oura
```

## Sign accounts in

**`/oura add <label>`** in the app (`/oura add me`), and tap Sign in. Oura's page opens; sign in and allow every box.
Pointman finishes the sign-in by itself: nothing to paste.

On a hosted Pointman that's all: the sign-in goes through Pointman's own Oura application, core's shared client, whose
redirect URI is `https://api.pointman.ai/v1/oauth/oura/callback`. The extension never holds that client's secret: it
exchanges the code through core.

The sign-in asks for every read scope (`email personal daily heartrate workout tag session spo2 heart_health`), with
Oura's authorization-code flow and PKCE. It needs node 0.4.12 or later.

**A sign-in lasts 30 days.** Oura's refresh tokens work once each, so each refresh must store the next one, and an
extension can't write to the vault yet. The extension keeps the access token Oura gives (30 days) and when it runs
out, and the refresh token for the day it can store the next one. Until then, sign in again with `/oura add <label>`
once a month; `oura.accounts` says until when each sign-in lasts.

### A self-hosted Pointman: your own Oura application, once

1. At [cloud.ouraring.com/oauth/applications](https://cloud.ouraring.com/oauth/applications), make an application with
   the redirect URI `https://<your Pointman>/oauth/callback`: your core's own callback.
2. **`/oura client`** in the app: paste its client ID, a space, then its secret.

An unreviewed Oura application signs in at most 10 people.

## The commands

| Command | What it does |
|---|---|
| `oura.accounts {}` | Each account's label and address, and until when its sign-in lasts |
| `oura.day {date?, account?}` | One day's sleep, readiness and activity scores and its main night, in a few lines |
| `oura.data {kind, from, to?, account?, full?}` | Oura's records of one kind between two days (that last day included), one line of JSON each |
| `/oura add`, `/oura client` | Open the forms for an account's sign-in and for a self-hosted Pointman's application, in the app |

## Develop

`cargo test` runs the commands under the SDK's stand-in node against a fake Oura on a local port (`tests/oura.rs`): no
real account is called. Change a command's params in the proto, then `pointman-extension manifest write` to write
extension.toml's schemas again; `tests/manifest.rs` fails while they differ. A release is a tag that's
extension.toml's version (`git tag v0.1.0 && git push origin v0.1.0`): `release.yml` builds each platform.
