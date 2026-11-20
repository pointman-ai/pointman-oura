---
name: oura
description: How to read a person's Oura ring data on Pointman (sleep, readiness, activity, heart rate, workouts, stress and the rest), with any number of Oura accounts, through the oura extension's commands. Use it when a task touches their sleep, recovery, activity or health.
---

# Oura

For tasks on the person's Oura data: how they slept, their readiness or activity, heart rate, HRV, workouts. Skip it
otherwise. It only reads: nothing is changed in Oura.

**The commands,** on any machine with the extension: `create_job` (or `/oura <verb>` in a thread).

| For | Command |
|---|---|
| Which accounts are signed in, whose, until when | `oura.accounts {}` |
| One day's scores and its night, in a few lines (the latest day when no `date`) | `oura.day {date?, account?}` |
| Oura's own records of one kind between two days | `oura.data {kind, from, to?, account?, full?}` |

**Start with `oura.day`.** It answers "how did I sleep" and "how's my readiness" in one call: the sleep, readiness and
activity scores, the main night's sleep (asleep, in bed, deep, REM, efficiency, HRV, lowest heart rate), the
temperature deviation, steps. Use `oura.data` for anything else, or a trend over days:

| `kind` | What each record is |
|---|---|
| `daily_sleep`, `daily_readiness`, `daily_activity` | A day's score and its contributors (activity has steps, calories, time per intensity) |
| `sleep` | A sleep period: stages, heart rate and HRV through the night, `type` (`long_sleep` is the main one) |
| `heartrate` | Every reading, about 5 minutes apart: `from` and `to` may be RFC 3339 times. Keep ranges to a day or two |
| `workout`, `session` | Workouts (detected or entered) and the app's guided sessions |
| `daily_spo2`, `daily_stress`, `daily_resilience`, `daily_cardiovascular_age`, `vo2_max` | Those daily measures |
| `sleep_time`, `tag`, `enhanced_tag`, `rest_mode_period` | Bedtime advice, the person's tags, rest mode |

Records come back as one line of JSON each. Long series (a night's 5-minute stages, a day's MET by the minute) say
how long they are; pass `full: true` only when you need them.

**Days are Oura's.** A night counts for the day it ends on, so last night is today's date. Data arrives once the ring
syncs with the phone: a score Oura hasn't made yet shows as "not yet". Durations are seconds.

**Accounts.** Each is a label (`me`): the vault's `oura.<label>`. Without `account`, a read uses the `account`
setting's, else every account, and says which each result came from.

**Health data is private.** Use it to do the task, and post it only when the person asked for it, in the thread
they asked in. Never in a public page, a commit or an issue. Don't draw medical conclusions: say what the numbers are,
and suggest a doctor for anything that worries them.

- **Not signed in?** Ask the person to run `/oura add <label>` in the app (`/oura add me`). A self-hosted Pointman
  needs its own Oura application first (`/oura client`, once); a hosted one uses Pointman's. Never ask for, paste or
  post a token, a code or the client's secret.
- **A sign-in lasts 30 days.** An error that says it ran out or that Oura no longer takes it: ask them to run
  `/oura add <label>` again for that account. `oura.accounts` says until when each one lasts.
