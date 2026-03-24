use anyhow::Error;
use gpui::{App, AppContext, Global, Task};
use std::future::Future;
use tokio::{
    runtime::{Builder, Runtime},
    task::AbortHandle,
};

pub fn init(app: &mut App) {
    app.set_global(GlobalTokio::new());
}

struct GlobalTokio {
    runtime: Runtime,
}

impl Global for GlobalTokio {}

impl GlobalTokio {
    #[allow(clippy::expect_used)]
    fn new() -> Self {
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime");
        Self { runtime }
    }
}

struct AbortGuard(Option<AbortHandle>);

impl Drop for AbortGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

pub struct Tokio;

impl Tokio {
    pub fn spawn_result<C, Fut, R>(cx: &C, f: Fut) -> C::Result<Task<anyhow::Result<R>>>
    where
        C: AppContext,
        Fut: Future<Output = anyhow::Result<R>> + Send + 'static,
        R: Send + 'static,
    {
        cx.read_global(|tokio: &GlobalTokio, cx| {
            let join_handle = tokio.runtime.spawn(f);
            let abort_handle = join_handle.abort_handle();
            let cancel = AbortGuard(Some(abort_handle));
            cx.background_spawn(async move {
                let result = join_handle.await;
                drop(cancel);
                result.map_err(Error::from)?
            })
        })
    }
}
