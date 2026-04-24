//! This module provides helper functions to convert Rhai types to Rust types
//! used by the `ExecuteOptions` API.

use caps::Capability;
use rhai::{Array, EvalAltResult, Map};
use std::str::FromStr;

/// Converts Rhai Array to `ExecuteOptions` args format: `Vec<(String, Option<String>)>`
pub(crate) fn parse_execute_args(
    args: Array,
) -> Result<Vec<(String, Option<String>)>, Box<EvalAltResult>> {
    args.into_iter()
        .enumerate()
        .map(
            |(index, arg)| -> Result<(String, Option<String>), Box<EvalAltResult>> {
                if let Some(flag) = arg.clone().try_cast::<String>() {
                    Ok((flag, None))
                } else if let Some(arr) = arg.try_cast::<Array>() {
                    match arr.len() {
                        0 => {
                            return Err(
                                format!("Argument array at index {index} cannot be empty").into()
                            );
                        }
                        len if len > 2 => {
                            return Err(format!(
                                "Argument array at index {index} cannot have more than 2 elements"
                            )
                            .into());
                        }
                        _ => {}
                    }

                    let key = arr
                        .first()
                        .ok_or_else(|| format!("Argument array at index {index} is empty"))?
                        .clone()
                        .into_string()
                        .map_err(|_| "Argument key must be a string".to_string())?;

                    let value = arr
                        .get(1)
                        .map(|v| {
                            v.clone()
                                .into_string()
                                .map_err(|_| "Argument value must be a string".to_string())
                        })
                        .transpose()?;

                    Ok((key, value))
                } else {
                    Err(format!("Argument at index {index} must be a string or an array").into())
                }
            },
        )
        .collect()
}

/// Converts Rhai Map to `Vec<(String, String)>` for environment variables
pub(crate) fn parse_execute_env(env: Map) -> Result<Vec<(String, String)>, Box<EvalAltResult>> {
    env.into_iter()
        .map(
            |(key, value)| -> Result<(String, String), Box<EvalAltResult>> {
                value
                    .into_string()
                    .map(|val| (key.to_string(), val))
                    .map_err(|_| {
                        format!("Environment variable value for key '{key}' must be a string")
                            .into()
                    })
            },
        )
        .collect()
}

/// Converts Rhai Array of capability strings to `Vec<Capability>`
pub(crate) fn parse_execute_capabilities(
    caps: Array,
) -> Result<Vec<Capability>, Box<EvalAltResult>> {
    caps.into_iter()
        .enumerate()
        .map(|(index, cap)| -> Result<Capability, Box<EvalAltResult>> {
            let cap_str = cap
                .into_string()
                .map_err(|_| format!("Capability at index {index} must be a string"))?;

            Capability::from_str(&cap_str)
                .map_err(|_| format!("Invalid capability format: '{cap_str}'").into())
        })
        .collect()
}
