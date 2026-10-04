use std::thread::sleep;
use std::time::Duration;

/// Configuration for automated network retry with exponential backoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_factor: u32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 500,
            max_delay_ms: 8000,
            backoff_factor: 2,
        }
    }
}

impl RetryConfig {
    /// Fast configuration for unit tests avoiding unnecessary test sleep duration.
    pub fn for_test() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 1,
            max_delay_ms: 10,
            backoff_factor: 2,
        }
    }

    /// Computes delay for a given attempt index (0-indexed).
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let multiplier = self.backoff_factor.saturating_pow(attempt) as u64;
        let delay_ms = (self.initial_delay_ms.saturating_mul(multiplier)).min(self.max_delay_ms);
        Duration::from_millis(delay_ms)
    }
}

/// Determines whether an HTTP status code represents a transient error that should be retried.
pub fn is_transient_status(status_code: u16) -> bool {
    matches!(
        status_code,
        408 | // Request Timeout
        429 | // Too Many Requests (Rate limit / Quota burst)
        500 | // Internal Server Error
        502 | // Bad Gateway
        503 | // Service Unavailable
        504 // Gateway Timeout
    )
}

/// Determines whether a reqwest error represents a transient network fault.
pub fn is_transient_error(err: &reqwest::Error) -> bool {
    if err.is_timeout() || err.is_connect() {
        return true;
    }
    if let Some(status) = err.status() {
        return is_transient_status(status.as_u16());
    }
    false
}

/// Executes a synchronous operation with automated exponential backoff retry.
///
/// Calls `operation()` up to `config.max_attempts` times. If the result is an `Err`,
/// `is_retryable(&err)` is evaluated. If retryable and attempts remain, the thread sleeps
/// with exponential backoff before the next attempt.
pub fn execute_with_retry<T, E, F, R>(
    config: &RetryConfig,
    operation_name: &str,
    mut operation: F,
    is_retryable: R,
) -> Result<T, E>
where
    F: FnMut() -> Result<T, E>,
    R: Fn(&E) -> bool,
    E: std::fmt::Display,
{
    let mut attempt = 0;
    loop {
        attempt += 1;
        match operation() {
            Ok(val) => return Ok(val),
            Err(err) => {
                if attempt >= config.max_attempts || !is_retryable(&err) {
                    return Err(err);
                }

                let delay = config.delay_for_attempt(attempt - 1);
                eprintln!(
                    "[Retry] '{}' attempt {}/{} failed ({}), retrying in {:?}...",
                    operation_name, attempt, config.max_attempts, err, delay
                );
                sleep(delay);
            }
        }
    }
}
