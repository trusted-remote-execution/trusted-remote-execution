/// Executes a closure while ensuring privilege drop always occurs afterward.
///
/// Wraps the closure in `catch_unwind` to catch panics, then calls the provided
/// drop function. If the drop function returns an error, returns a structured error
#[macro_export]
macro_rules! execute_with_privilege_drop {
    ($closure:expr, $drop_fn:expr, $drop_fail_msg:expr, $panic_error:expr, $drop_fail_error:expr) => {{
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe($closure));

        if $drop_fn.is_err() {
            if let Err(ref panic_payload) = result {
                let msg = panic_payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".to_string());
                tracing::error!("Panic occurred during privileged execution: {}", msg);
            }
            let drop_msg = $drop_fail_msg;
            tracing::error!("{}", drop_msg);
            return Err($drop_fail_error(drop_msg));
        }

        match result {
            Ok(r) => r,
            Err(panic_payload) => {
                let msg = panic_payload
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown panic".to_string());
                Err($panic_error(msg))
            }
        }
    }};
}
