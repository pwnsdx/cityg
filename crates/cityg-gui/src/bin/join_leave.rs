//! `join_leave`: drive simulated City-G v0.3 members against a delivery
//! service from the command line.
//!
//! ```text
//! join_leave [server] [invite-link] [alias] [--count=N] [--batch|--watch]
//!            [--leave-order=i,j,...] [--message-burst-count=N]
//!            [--message-burst-interval-ms=MS] [--capacity=N]
//!            [--session-artifact-dir=PATH] [--verbose]
//! ```
//!
//! Without an invite link, the first simulated member creates a new group
//! and invites the others; with one, every simulated member joins through
//! it. The joiners after the first one join together: their requests are
//! committed in one batch. `--batch` joins everyone, sends the message
//! burst and then makes the members leave in `--leave-order`, each
//! departure being committed by a remaining member. `--watch` does the same
//! while every member follows the group log and prints what it receives.

#[cfg(not(test))]
use std::env;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, anyhow};
use cityg_api_client::cityg_core::identity::DeviceIdentity;
use cityg_api_client::{DsClient, InviteLink, Member, SyncReport};
use cityg_config::CityGConfig;
use rand::RngExt;
use serde::Serialize;
use tokio::time::sleep;

const DEFAULT_SERVER_URL: &str = "http://127.0.0.1:8080";
const DEFAULT_CAPACITY: u32 = 64;
const INVITE_TTL_MS: u64 = 24 * 3_600_000;
const INVITE_USES: u64 = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CliOptions {
    server_url: String,
    invite: Option<String>,
    alias_base: String,
    count: usize,
    batch_mode: bool,
    watch_mode: bool,
    verbose: bool,
    leave_order: Option<Vec<usize>>,
    message_burst_count: usize,
    message_burst_interval_ms: u64,
    capacity: u32,
    session_artifact_dir: Option<PathBuf>,
}

fn read_nonempty_env(var: &str) -> Option<String> {
    std::env::var(var)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn configured_cli_server_url() -> Option<String> {
    read_nonempty_env("CITYG_CLI_SERVER_URL").or_else(|| {
        CityGConfig::load()
            .ok()
            .map(|config| config.client.default_server_url)
            .filter(|url| !url.trim().is_empty())
    })
}

fn parse_cli_args(args: impl IntoIterator<Item = String>) -> Result<CliOptions> {
    let mut positional = Vec::new();
    let mut count = 1usize;
    let mut batch_mode = false;
    let mut watch_mode = false;
    let mut verbose = false;
    let mut leave_order_raw: Option<String> = None;
    let mut message_burst_count = 0usize;
    let mut message_burst_interval_ms = 0u64;
    let mut capacity = DEFAULT_CAPACITY;
    let mut session_artifact_dir = None;

    for arg in args {
        if let Some(rest) = arg.strip_prefix("--count=") {
            count = rest
                .parse()
                .map_err(|_| anyhow!("invalid --count value: {rest}"))?;
            if count == 0 {
                return Err(anyhow!("--count must be at least 1"));
            }
        } else if arg == "--batch" {
            batch_mode = true;
        } else if arg == "--watch" {
            watch_mode = true;
            batch_mode = true;
        } else if arg == "--verbose" {
            verbose = true;
        } else if let Some(rest) = arg.strip_prefix("--leave-order=") {
            leave_order_raw = Some(rest.to_string());
        } else if let Some(rest) = arg.strip_prefix("--message-burst-count=") {
            message_burst_count = rest
                .parse()
                .map_err(|_| anyhow!("invalid --message-burst-count value: {rest}"))?;
        } else if let Some(rest) = arg.strip_prefix("--message-burst-interval-ms=") {
            message_burst_interval_ms = rest
                .parse()
                .map_err(|_| anyhow!("invalid --message-burst-interval-ms value: {rest}"))?;
        } else if let Some(rest) = arg.strip_prefix("--capacity=") {
            capacity = rest
                .parse()
                .map_err(|_| anyhow!("invalid --capacity value: {rest}"))?;
        } else if let Some(rest) = arg.strip_prefix("--session-artifact-dir=") {
            if rest.trim().is_empty() {
                return Err(anyhow!("--session-artifact-dir requires a non-empty path"));
            }
            session_artifact_dir = Some(PathBuf::from(rest));
        } else if arg.starts_with("--") {
            return Err(anyhow!("unknown option: {arg}"));
        } else {
            positional.push(arg);
        }
    }
    let mut positional = positional.into_iter();
    let server_url = positional
        .next()
        .or_else(configured_cli_server_url)
        .unwrap_or_else(|| DEFAULT_SERVER_URL.to_string());
    let mut invite = None;
    let mut alias = None;
    for arg in positional {
        if arg.starts_with(cityg_api_client::INVITE_PREFIX) && invite.is_none() {
            invite = Some(arg);
        } else if alias.is_none() {
            alias = Some(arg);
        } else {
            return Err(anyhow!(
                "unexpected extra argument: {arg}. usage: [server] [invite-link] [alias] \
                 [--count=N] [--batch|--watch] [--leave-order=...] [--message-burst-count=N] \
                 [--message-burst-interval-ms=MS] [--capacity=N] [--session-artifact-dir=PATH] \
                 [--verbose]"
            ));
        }
    }
    if !batch_mode && leave_order_raw.is_some() {
        return Err(anyhow!("--leave-order requires --batch"));
    }
    if watch_mode && count < 2 {
        return Err(anyhow!("--watch requires --count >= 2"));
    }
    let leave_order = leave_order_raw
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|entry| !entry.is_empty())
                .map(|entry| {
                    let index: usize = entry
                        .parse()
                        .map_err(|_| anyhow!("invalid leave order entry: {entry}"))?;
                    if index == 0 || index > count {
                        return Err(anyhow!(
                            "leave order index {index} out of range (1..={count})"
                        ));
                    }
                    Ok(index)
                })
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?;
    Ok(CliOptions {
        server_url,
        invite,
        alias_base: alias.unwrap_or_else(|| "cli-member".to_string()),
        count,
        batch_mode,
        watch_mode,
        verbose,
        leave_order,
        message_burst_count,
        message_burst_interval_ms,
        capacity,
        session_artifact_dir,
    })
}

fn alias_for(base: &str, count: usize, index: usize) -> String {
    if count == 1 {
        base.to_string()
    } else {
        format!("{base}-{}", index + 1)
    }
}

/// What a session artifact records (no secret material).
#[derive(Serialize)]
struct SessionArtifact<'a> {
    stage: &'a str,
    alias: &'a str,
    gid: String,
    epoch: u64,
    leaf: u32,
    since: u64,
    members: usize,
    log_seq: u64,
    transcript_fingerprint: String,
}

fn write_artifact(dir: Option<&Path>, stage: &str, alias: &str, member: &Member) -> Result<()> {
    let Some(dir) = dir else {
        return Ok(());
    };
    std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    let session = member.session();
    let artifact = SessionArtifact {
        stage,
        alias,
        gid: hex::encode(session.gid()),
        epoch: session.epoch(),
        leaf: session.me().leaf,
        since: session.me().since,
        members: session.tree().member_count(),
        log_seq: member.log_seq(),
        transcript_fingerprint: hex::encode(session.transcript_fingerprint()),
    };
    let path = dir.join(format!("{alias}-{stage}.json"));
    std::fs::write(&path, serde_json::to_vec_pretty(&artifact)?)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn fresh_identity() -> DeviceIdentity {
    let mut seed = [0u8; 32];
    rand::rng().fill(&mut seed);
    DeviceIdentity::from_seed(&seed)
}

fn print_report(alias: &str, report: &SyncReport, verbose: bool) {
    for message in &report.messages {
        println!(
            "[{alias}] message from leaf {} at {} ms: {}",
            message.sender.leaf,
            message.signed_timestamp_ms,
            String::from_utf8_lossy(&message.plaintext)
        );
    }
    if verbose {
        for commit in &report.commits {
            println!(
                "[{alias}] epoch {} ({:?}): {} removed, {} entered",
                commit.epoch,
                commit.kind,
                commit.removed.len(),
                commit.joined.len() + usize::from(commit.author_entry.is_some())
            );
        }
        if report.rejected > 0 {
            println!("[{alias}] {} envelopes rejected", report.rejected);
        }
    }
}

async fn join_members(options: &CliOptions) -> Result<(Vec<Member>, Vec<String>)> {
    let client = DsClient::new(&options.server_url)?;
    let mut members = Vec::with_capacity(options.count);
    let mut aliases: Vec<String> = (0..options.count)
        .map(|index| alias_for(&options.alias_base, options.count, index))
        .collect();
    let link = match options.invite.as_deref() {
        Some(raw) => InviteLink::parse(raw)?.ok_or(
            cityg_api_client::ClientError::InvalidInvite("not an invite link"),
        )?,
        None => {
            let mut creator =
                Member::create(client.clone(), fresh_identity(), options.capacity).await?;
            let created = creator
                .create_invite_link(&options.server_url, INVITE_TTL_MS, INVITE_USES)
                .await?;
            println!("invite: {}", created.encode());
            members.push(creator);
            created
        }
    };
    // The remaining members join together: one of them commits the batch.
    let joins = (members.len()..options.count)
        .map(|_| Member::join_with_invite(client.clone(), fresh_identity(), &link));
    for joined in futures::future::join_all(joins).await {
        members.push(joined?);
    }
    for (member, alias) in members.iter_mut().zip(aliases.iter_mut()) {
        member.sync().await?;
        member.bind_alias(alias).await?;
        println!(
            "server={} room={} alias={alias}",
            options.server_url,
            hex::encode(member.gid())
        );
        println!(
            "join ok: epoch={} leaf={} members={}",
            member.session().epoch(),
            member.session().my_leaf(),
            member.session().tree().member_count()
        );
        write_artifact(
            options.session_artifact_dir.as_deref(),
            "joined",
            alias,
            member,
        )?;
    }
    for (member, alias) in members.iter_mut().zip(&aliases) {
        let report = member.sync().await?;
        print_report(alias, &report, options.verbose);
    }
    Ok((members, aliases))
}

async fn send_burst(
    members: &mut [Member],
    aliases: &[String],
    options: &CliOptions,
) -> Result<()> {
    for round in 0..options.message_burst_count {
        for (member, alias) in members.iter_mut().zip(aliases) {
            let sent = member
                .send_text(&format!("{alias} message {}", round + 1))
                .await?;
            if options.verbose {
                println!("[{alias}] sent seq={} epoch={}", sent.seq, sent.epoch);
            }
        }
        if options.message_burst_interval_ms > 0 {
            sleep(Duration::from_millis(options.message_burst_interval_ms)).await;
        }
    }
    Ok(())
}

async fn sync_all(
    members: &mut [Member],
    aliases: &[String],
    present: &[bool],
    verbose: bool,
    print: bool,
) -> Result<()> {
    for ((member, alias), here) in members.iter_mut().zip(aliases).zip(present) {
        if !*here {
            continue;
        }
        let report = member.sync().await?;
        if print {
            print_report(alias, &report, verbose);
        }
    }
    Ok(())
}

async fn leave_in_order(
    members: &mut [Member],
    aliases: &[String],
    options: &CliOptions,
) -> Result<()> {
    let default_order: Vec<usize> = (1..=members.len()).collect();
    let order = options.leave_order.clone().unwrap_or(default_order);
    let mut present = vec![true; members.len()];
    for index in order {
        let slot = index - 1;
        if !present[slot] {
            return Err(anyhow!(
                "leave order index {index} repeats a departed member"
            ));
        }
        write_artifact(
            options.session_artifact_dir.as_deref(),
            "pre-leave",
            &aliases[slot],
            &members[slot],
        )?;
        println!("leaving alias={}", aliases[slot]);
        members[slot].leave().await?;
        present[slot] = false;
        if let Some(committer) = present.iter().position(|here| *here) {
            members[committer].sync().await?;
            members[committer].commit_pending().await?;
            sync_all(
                members,
                aliases,
                &present,
                options.verbose,
                options.watch_mode,
            )
            .await?;
            println!("leave ok");
        } else {
            // Nobody is left to commit it: the next joiner will.
            println!("leave ok (recorded; no member left to commit it)");
        }
    }
    Ok(())
}

async fn run_with_options(options: CliOptions) -> Result<()> {
    let (mut members, aliases) = join_members(&options).await?;
    if options.message_burst_count > 0 {
        send_burst(&mut members, &aliases, &options).await?;
        let present = vec![true; members.len()];
        sync_all(&mut members, &aliases, &present, options.verbose, true).await?;
    }
    if options.batch_mode {
        leave_in_order(&mut members, &aliases, &options).await?;
    }
    Ok(())
}

#[cfg(not(test))]
#[tokio::main]
async fn main() -> Result<()> {
    run_with_options(parse_cli_args(env::args().skip(1))?).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use cityg_api::routes::{ServiceState, router};
    use cityg_runtime::{NativeRoomStore, ServiceConfig};
    use std::net::SocketAddr;

    async fn server() -> String {
        let state = ServiceState::new(
            ServiceConfig::default(),
            NativeRoomStore::for_state_path(None).unwrap(),
            64,
        );
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_string()).collect()
    }

    #[test]
    fn options_parse_and_validate() {
        let options = parse_cli_args(args(&[
            "http://srv",
            "alice",
            "--count=3",
            "--batch",
            "--leave-order=2,,3,1",
            "--message-burst-count=2",
            "--message-burst-interval-ms=5",
            "--capacity=16",
            "--session-artifact-dir=/tmp/x",
            "--verbose",
        ]))
        .unwrap();
        assert_eq!(options.server_url, "http://srv");
        assert_eq!(options.alias_base, "alice");
        assert_eq!(options.leave_order, Some(vec![2, 3, 1]));
        assert_eq!(options.capacity, 16);
        assert!(options.batch_mode && options.verbose && !options.watch_mode);
        let watch = parse_cli_args(args(&["http://srv", "--watch", "--count=2"])).unwrap();
        assert!(watch.watch_mode && watch.batch_mode);
        let link = "cityg-invite:{}";
        let with_invite = parse_cli_args(args(&["http://srv", link, "bob"])).unwrap();
        assert_eq!(with_invite.invite.as_deref(), Some(link));
        assert_eq!(with_invite.alias_base, "bob");

        for (bad, needle) in [
            (vec!["--count=0"], "--count must be at least 1"),
            (vec!["--count=x"], "invalid --count"),
            (vec!["--watch"], "--watch requires --count >= 2"),
            (vec!["--leave-order=1"], "--leave-order requires --batch"),
            (
                vec!["--batch", "--count=2", "--leave-order=3"],
                "out of range",
            ),
            (
                vec!["--batch", "--count=2", "--leave-order=a"],
                "invalid leave order",
            ),
            (
                vec!["--message-burst-count=x"],
                "invalid --message-burst-count",
            ),
            (
                vec!["--message-burst-interval-ms=x"],
                "invalid --message-burst-interval-ms",
            ),
            (vec!["--capacity=x"], "invalid --capacity"),
            (vec!["--session-artifact-dir="], "non-empty path"),
            (vec!["--nope"], "unknown option"),
            (vec!["s", "a", "b"], "unexpected extra argument"),
        ] {
            let error = parse_cli_args(args(&bad)).unwrap_err().to_string();
            assert!(error.contains(needle), "{error} lacks {needle}");
        }
        assert_eq!(alias_for("base", 1, 0), "base");
        assert_eq!(alias_for("base", 2, 1), "base-2");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn batch_run_joins_talks_and_leaves() {
        let url = server().await;
        let dir = tempfile::tempdir().unwrap();
        let options = parse_cli_args(vec![
            url.clone(),
            "tester".into(),
            "--count=3".into(),
            "--batch".into(),
            "--leave-order=2,1,3".into(),
            "--message-burst-count=2".into(),
            format!("--session-artifact-dir={}", dir.path().display()),
            "--verbose".into(),
        ])
        .unwrap();
        run_with_options(options).await.unwrap();
        let artifact = std::fs::read_to_string(dir.path().join("tester-2-joined.json")).unwrap();
        assert!(artifact.contains("\"members\": 3"));
        assert!(dir.path().join("tester-3-pre-leave.json").exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn watch_run_and_invite_join() {
        let url = server().await;
        let options = parse_cli_args(vec![
            url.clone(),
            "watcher".into(),
            "--watch".into(),
            "--count=2".into(),
            "--message-burst-count=1".into(),
            "--message-burst-interval-ms=1".into(),
        ])
        .unwrap();
        run_with_options(options).await.unwrap();

        // A second run joins an existing group through an invite link.
        let mut owner = Member::create(DsClient::new(&url).unwrap(), fresh_identity(), 8)
            .await
            .unwrap();
        let link = owner.create_invite_link(&url, 60_000, 2).await.unwrap();
        let options = parse_cli_args(vec![url.clone(), link.encode(), "guest".into()]).unwrap();
        run_with_options(options).await.unwrap();
        let report = owner.sync().await.unwrap();
        assert_eq!(report.commits.len(), 1);
        assert_eq!(owner.session().tree().member_count(), 2);

        let broken = parse_cli_args(vec![url, "cityg-invite:{".into()]).unwrap();
        assert!(run_with_options(broken).await.is_err());
    }
}
