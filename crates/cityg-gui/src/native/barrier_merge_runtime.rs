use super::barrier_merge_execution_runtime::perform_barrier_merge_inner;
use super::*;

pub(super) async fn perform_pcs_refresh(request: LeaveRequest) -> Result<()> {
    perform_barrier_merge_inner(request, BarrierMergeMode::PcsRefresh, false)
        .await
        .map(|_| ())
}

pub(super) async fn perform_pcs_refresh_inner(
    request: LeaveRequest,
    allow_pending_recovery: bool,
) -> Result<PublishedBarrierMerge> {
    // Heap-allocate the large merge future so callers do not inherit its full async frame.
    Box::pin(perform_barrier_merge_inner(
        request,
        BarrierMergeMode::PcsRefresh,
        allow_pending_recovery,
    ))
    .await
}

pub(super) async fn perform_join_finalize_inner(
    request: LeaveRequest,
) -> Result<PublishedBarrierMerge> {
    // Join-finalize is the heaviest post-join path; boxing keeps exact-test stack usage bounded.
    Box::pin(perform_barrier_merge_inner(
        request,
        BarrierMergeMode::JoinFinalize,
        true,
    ))
    .await
}
