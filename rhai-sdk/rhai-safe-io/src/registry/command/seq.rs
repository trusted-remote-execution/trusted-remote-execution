//! Rhai registration for the `seq` command

use crate::command;
use crate::command::SeqFlag;
use rhai::plugin::Engine;
use rhai::{Array, EvalAltResult, Module, NativeCallContext};

pub(super) fn register(engine: &mut Engine) {
    register_types(engine);
    register_functions(engine);
}

fn register_types(engine: &mut Engine) {
    engine.register_type_with_name::<SeqFlag>("SeqFlag");
    engine.register_static_module("seq", {
        let mut module = Module::new();
        module.set_native_fn("step", |n: i64| Ok(SeqFlag::Step(n)));
        module.into()
    });
}

fn register_functions(engine: &mut Engine) {
    // seq(start, end)
    engine.register_fn("seq", {
        move |ctx: NativeCallContext, start: i64, end: i64| -> Result<Array, Box<EvalAltResult>> {
            let _guard = crate::registry::common::get_rhai_context_guard(&ctx);
            match command::seq(start, end) {
                Ok(nums) => Ok(nums.into_iter().map(rhai::Dynamic::from).collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });

    // seq(flags, start, end)
    engine.register_fn("seq", {
        move |ctx: NativeCallContext,
              flags: Array,
              start: i64,
              end: i64|
              -> Result<Array, Box<EvalAltResult>> {
            let _guard = crate::registry::common::get_rhai_context_guard(&ctx);
            match command::seq_with_flags(start, end, &flags) {
                Ok(nums) => Ok(nums.into_iter().map(rhai::Dynamic::from).collect()),
                Err(e) => crate::errors::convert_to_rhai_error(&e),
            }
        }
    });
}
