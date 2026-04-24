#[macro_export]
macro_rules! trace {
    (target: $target:expr, $($args:tt)*) => {
        $crate::tracing::trace!(target: $target, $($args)*)
    };
    ($($args:tt)*) => {
        $crate::tracing::trace!($($args)*)
    };
}

#[macro_export]
macro_rules! debug {
    (target: $target:expr, $($args:tt)*) => {
        $crate::tracing::debug!(target: $target, $($args)*)
    };
    ($($args:tt)*) => {
        $crate::tracing::debug!($($args)*)
    };
}

#[macro_export]
macro_rules! info {
    (target: $target:expr, $($args:tt)*) => {
        $crate::tracing::info!(target: $target, $($args)*)
    };
    ($($args:tt)*) => {
        $crate::tracing::info!($($args)*)
    };
}

#[macro_export]
macro_rules! warn {
    (target: $target:expr, $($args:tt)*) => {
        $crate::tracing::warn!(target: $target, $($args)*)
    };
    ($($args:tt)*) => {
        $crate::tracing::warn!($($args)*)
    };
}

#[macro_export]
macro_rules! error {
    (target: $target:expr, $($args:tt)*) => {
        $crate::tracing::error!(target: $target, $($args)*)
    };
    ($($args:tt)*) => {
        $crate::tracing::error!($($args)*)
    };
}
