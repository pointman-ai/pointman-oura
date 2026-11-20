//! Oura on Pointman: every agent reads a person's Oura data (`api`), sleep, readiness, activity and heart rate, with
//! any number of Oura accounts, each signed in from the apps by redirect (`signin`) and kept in the vault as
//! `oura.<label>`. Which accounts a call uses is `accounts`'. The commands' params are proto/oura/v1/oura.proto's.
//! On a hosted Pointman, sign-ins use core's shared Oura client, Pointman's own, and exchange through core; a
//! self-hosted one uses its own client, `oura.client`. Nothing here writes to Oura.

pub mod accounts;
pub mod api;
pub mod signin;

/// proto/oura/v1/oura.proto's messages, as buffa builds them (build.rs).
pub mod proto {
    pointman_extension::include_proto!();
}
pub use proto::oura::v1;

/// The vault item with a self-hosted Pointman's own Oura client: every other `oura.<label>` is an account's sign-in.
pub const CLIENT_ITEM: &str = "oura.client";

/// The provider the account form names as its `shared_client`: core's shared client for it is Pointman's own.
pub const PROVIDER: &str = "oura";

/// A list in words: `a`, `a and b`, `a, b and c`.
pub fn and(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}
