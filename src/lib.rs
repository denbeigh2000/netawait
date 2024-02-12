// NOTE: for clean experiences,
// #[allow(dead_code)]
// mod bindings;
mod socket;

mod bindings;

pub struct TimeoutError;

pub type TimeoutResult<E> = Result<E, TimeoutError>;

#[derive(thiserror::Error, Debug)]
pub enum WaitError {
    #[error("timed out")]
    Timeout,
    #[error("IO error: {0}")]
    Error(#[from] std::io::Error),
}

pub fn wait_for_default_route() -> Result<(), WaitError> {
    Ok(())
}
