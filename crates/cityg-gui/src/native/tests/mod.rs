//! GUI tests: offline sessions for the UI and handlers, an in-process v3
//! delivery service for the end-to-end flows.

use std::future::Future;

use gpui::{Modifiers, TestAppContext, VisualTestContext};
use tempfile::TempDir;

use super::*;
use cityg_api_client::DsClient;
use cityg_api_client::cityg_core::identity::DeviceIdentity;
use cityg_api_client::cityg_core::session::GroupSession;

mod flows;
mod handlers;
mod persistence;
mod ui;

/// Server URL of offline sessions (nothing listens there).
const OFFLINE_URL: &str = "http://127.0.0.1:9";

/// A temporary GUI configuration directory, active while it lives.
struct ConfigDir {
    _guard: ConfigDirGuard,
    dir: TempDir,
}

impl ConfigDir {
    fn new() -> Self {
        let dir = TempDir::new().expect("create temp dir");
        let guard = set_config_dir_override_for_tests(Some(dir.path().join("cityg").join("gui")));
        Self { _guard: guard, dir }
    }
}

/// The occupancy of leaf `leaf` since epoch 0.
fn mref(leaf: u8) -> MemberRef {
    MemberRef {
        leaf: u32::from(leaf),
        since: 0,
    }
}

fn identity(seed: u8) -> DeviceIdentity {
    DeviceIdentity::from_seed(&[seed; 32])
}

/// Member (and admin) of a single-member room that only exists locally.
fn offline_member(seed: u8) -> Member {
    let identity = identity(seed);
    let (pending, _published) =
        GroupSession::create(&identity, 8, &mut rand_core::OsRng).expect("create group");
    Member::from_session(
        DsClient::new(OFFLINE_URL).expect("client"),
        identity,
        pending.into_session().expect("session"),
        1,
    )
    .expect("member")
}

/// Session of an offline room (not persisted).
fn offline_session(seed: u8, alias: &str) -> AppSession {
    AppSession::new(
        OFFLINE_URL.to_string(),
        alias.to_string(),
        offline_member(seed),
        engine::now_ms(),
    )
}

fn mouse_down(button: MouseButton, click_count: usize) -> MouseDownEvent {
    MouseDownEvent {
        position: point(px(0.0), px(0.0)),
        modifiers: Modifiers::none(),
        button,
        click_count,
        first_mouse: false,
    }
}

fn click() -> MouseDownEvent {
    mouse_down(MouseButton::Left, 1)
}

fn key(text: &str) -> Keystroke {
    Keystroke::parse(text).expect("keystroke")
}

/// Open the app window; `session` becomes the active session.
fn open_window(
    cx: &mut TestAppContext,
    session: Option<AppSession>,
) -> (Entity<AppModel>, &mut VisualTestContext) {
    cx.update(tokio_bridge::init);
    cx.add_window_view(move |window, _| {
        window.resize(size(px(1280.0), px(760.0)));
        let mut model = AppModel::new(CityGConfig::default());
        if let Some(session) = session {
            model.install_session(session);
        }
        model
    })
}

/// Run the app until `done` holds; background work runs on real threads.
fn wait_for(
    cx: &mut VisualTestContext,
    view: &Entity<AppModel>,
    what: &str,
    done: impl Fn(&AppModel) -> bool,
) {
    cx.executor().allow_parking();
    for _ in 0..6000 {
        cx.run_until_parked();
        if view.read_with(cx, |model, _| done(model)) {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("timed out waiting for {what}");
}

/// An in-process v3 delivery service on its own Tokio runtime.
struct TestServer {
    runtime: tokio::runtime::Runtime,
    url: String,
}

impl TestServer {
    fn start() -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("server runtime");
        let url = runtime.block_on(engine::tests::spawn_server());
        Self { runtime, url }
    }

    fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.runtime.block_on(future)
    }

    /// A member created (and admin) on this server, outside the GUI.
    fn create_member(&self, alias: &str) -> SharedMember {
        let member = self
            .block_on(engine::create_room(&self.url, alias, 8))
            .expect("create room");
        Arc::new(tokio::sync::Mutex::new(member))
    }

    /// An invite link to the room of `member`.
    fn invite(&self, member: &SharedMember) -> String {
        self.block_on(engine::create_invite(member))
            .expect("create invite")
    }

    /// A member joining through `invite`, outside the GUI.
    fn join(&self, invite: &str, alias: &str) -> SharedMember {
        let link = InviteLink::parse(invite)
            .expect("parse invite")
            .expect("invite link");
        let member = self
            .block_on(engine::join_room(&link, alias))
            .expect("join room");
        Arc::new(tokio::sync::Mutex::new(member))
    }

    fn sync(&self, member: &SharedMember) -> engine::SyncOutcome {
        self.block_on(engine::sync_room(member)).expect("sync")
    }
}

fn clipboard_text(cx: &mut VisualTestContext) -> Option<String> {
    cx.update(|_, app| app.read_from_clipboard().and_then(|item| item.text()))
}
