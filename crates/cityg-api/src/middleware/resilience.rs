// Resilience patterns: Circuit Breaker
//
// This module implements the circuit breaker pattern to prevent cascading failures.
// The circuit breaker is integrated into health checks and ready for integration
// into request handlers.
//
// Note: Retry logic at the middleware level is complex with Axum due to request
// body consumption. For production retry logic, consider using tower-http's retry
// middleware or implementing retry at the client level where request cloning is easier.

use std::{
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};
use tracing::{debug, warn};

// RetryLayer placeholder - complex to implement correctly with Axum

pub struct RetryLayer;

impl RetryLayer {
    #[allow(dead_code)]
    pub fn new(_max_retries: u32, _initial_backoff: Duration) -> Self {
        Self
    }
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker for preventing cascading failures
#[derive(Clone)]
pub struct CircuitBreaker {
    state: Arc<RwLock<CircuitBreakerInner>>,
    failure_threshold: u32,
    success_threshold: u32,
    timeout: Duration,
}

struct CircuitBreakerInner {
    state: CircuitBreakerState,
    failure_count: u32,
    success_count: u32,
    last_failure_time: Option<Instant>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: u32, success_threshold: u32, timeout: Duration) -> Self {
        Self {
            state: Arc::new(RwLock::new(CircuitBreakerInner {
                state: CircuitBreakerState::Closed,
                failure_count: 0,
                success_count: 0,
                last_failure_time: None,
            })),
            failure_threshold,
            success_threshold,
            timeout,
        }
    }

    pub fn get_state(&self) -> CircuitBreakerState {
        self.state.read().unwrap().state
    }

    pub fn is_request_allowed(&self) -> bool {
        let mut inner = self.state.write().unwrap();

        match inner.state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => {
                // Check if timeout has elapsed
                if let Some(last_failure) = inner.last_failure_time {
                    if last_failure.elapsed() >= self.timeout {
                        debug!("circuit breaker transitioning from Open to HalfOpen");
                        inner.state = CircuitBreakerState::HalfOpen;
                        inner.success_count = 0;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            CircuitBreakerState::HalfOpen => true,
        }
    }

    pub fn record_success(&self) {
        let mut inner = self.state.write().unwrap();

        match inner.state {
            CircuitBreakerState::Closed => {
                inner.failure_count = 0;
            }
            CircuitBreakerState::HalfOpen => {
                inner.success_count += 1;
                if inner.success_count >= self.success_threshold {
                    debug!("circuit breaker transitioning from HalfOpen to Closed");
                    inner.state = CircuitBreakerState::Closed;
                    inner.failure_count = 0;
                    inner.success_count = 0;
                }
            }
            CircuitBreakerState::Open => {
                // Should not happen, but reset if it does
                inner.failure_count = 0;
            }
        }
    }

    pub fn record_failure(&self) {
        let mut inner = self.state.write().unwrap();

        match inner.state {
            CircuitBreakerState::Closed => {
                inner.failure_count += 1;
                if inner.failure_count >= self.failure_threshold {
                    warn!(
                        failure_count = inner.failure_count,
                        "circuit breaker opening due to failures"
                    );
                    inner.state = CircuitBreakerState::Open;
                    inner.last_failure_time = Some(Instant::now());
                }
            }
            CircuitBreakerState::HalfOpen => {
                warn!("circuit breaker reopening after failure in HalfOpen state");
                inner.state = CircuitBreakerState::Open;
                inner.last_failure_time = Some(Instant::now());
                inner.success_count = 0;
            }
            CircuitBreakerState::Open => {
                inner.last_failure_time = Some(Instant::now());
            }
        }
    }

    pub fn get_metrics(&self) -> CircuitBreakerMetrics {
        let inner = self.state.read().unwrap();
        CircuitBreakerMetrics {
            state: inner.state,
            failure_count: inner.failure_count,
            success_count: inner.success_count,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CircuitBreakerMetrics {
    pub state: CircuitBreakerState,
    pub failure_count: u32,
    pub success_count: u32,
}
