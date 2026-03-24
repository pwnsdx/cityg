#[cfg(test)]
use std::{
    collections::VecDeque,
    fs,
    future::Future,
    path::Path,
    sync::{Mutex, OnceLock},
};

#[cfg(test)]
use anyhow::{Result, anyhow};

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum FaultInjectionCutPoint {
    BeforeSessionEncrypt,
    AfterSessionEncrypt,
    AfterTempWriteFsync,
    BeforeAtomicRename,
    AfterSessionWrite,
    BeforePointerWrite,
    AfterPointerWrite,
    BeforePublishJoinFinalize,
    AfterPublishBeforeReload,
    AfterAuthenticatedAcceptBeforePersist,
    AfterPersistBeforePendingClear,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum FaultInjectionAction {
    Fail(&'static str),
    TruncatePrimary,
    RewritePointerToMissing,
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FaultInjectionStep {
    pub(super) cut_point: FaultInjectionCutPoint,
    pub(super) action: FaultInjectionAction,
}

#[cfg(test)]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct FaultInjectionPlan {
    steps: VecDeque<FaultInjectionStep>,
}

#[cfg(test)]
fn plan_cell() -> &'static Mutex<FaultInjectionPlan> {
    static CELL: OnceLock<Mutex<FaultInjectionPlan>> = OnceLock::new();
    CELL.get_or_init(|| Mutex::new(FaultInjectionPlan::default()))
}

#[cfg(test)]
pub(super) struct FaultInjectionGuard {
    previous: FaultInjectionPlan,
}

#[cfg(test)]
impl Drop for FaultInjectionGuard {
    fn drop(&mut self) {
        let mut guard = plan_cell()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = std::mem::take(&mut self.previous);
    }
}

#[cfg(test)]
pub(super) fn set_fault_injection(steps: Vec<FaultInjectionStep>) -> FaultInjectionGuard {
    let mut guard = plan_cell()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous = std::mem::replace(
        &mut *guard,
        FaultInjectionPlan {
            steps: VecDeque::from(steps),
        },
    );
    FaultInjectionGuard { previous }
}

#[cfg(test)]
pub(super) fn with_fault_injection<T>(steps: Vec<FaultInjectionStep>, f: impl FnOnce() -> T) -> T {
    let _guard = set_fault_injection(steps);
    let result = f();
    assert_fault_plan_consumed();
    result
}

#[cfg(test)]
pub(super) async fn with_fault_injection_async<T, Fut>(
    steps: Vec<FaultInjectionStep>,
    f: impl FnOnce() -> Fut,
) -> T
where
    Fut: Future<Output = T>,
{
    let _guard = set_fault_injection(steps);
    let result = f().await;
    assert_fault_plan_consumed();
    result
}

#[cfg(test)]
pub(super) fn assert_fault_plan_consumed() {
    let guard = plan_cell()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    assert!(
        guard.steps.is_empty(),
        "unconsumed fault injection steps: {:?}",
        guard.steps
    );
}

#[cfg(test)]
pub(super) fn trigger_fault(
    cut_point: FaultInjectionCutPoint,
    primary_path: Option<&Path>,
) -> Result<()> {
    let step = {
        let mut guard = plan_cell()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard
            .steps
            .front()
            .is_some_and(|step| step.cut_point == cut_point)
        {
            guard.steps.pop_front()
        } else {
            None
        }
    };

    let Some(step) = step else {
        return Ok(());
    };

    match step.action {
        FaultInjectionAction::Fail(message) => Err(anyhow!(message)),
        FaultInjectionAction::TruncatePrimary => {
            let path = primary_path.ok_or_else(|| anyhow!("missing primary path for truncate"))?;
            fs::write(path, &[]).map_err(|err| anyhow!("truncate {}: {err}", path.display()))
        }
        FaultInjectionAction::RewritePointerToMissing => {
            let path =
                primary_path.ok_or_else(|| anyhow!("missing primary path for pointer rewrite"))?;
            let contents = serde_json::json!({
                "server_url": "fault://missing",
                "room_id": "fault-pointer-missing",
            });
            fs::write(path, serde_json::to_vec(&contents)?)
                .map_err(|err| anyhow!("rewrite {}: {err}", path.display()))
        }
    }
}
