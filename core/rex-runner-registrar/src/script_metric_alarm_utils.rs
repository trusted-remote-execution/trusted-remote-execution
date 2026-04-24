#[macro_export]
macro_rules! register_type_with_name {
    ($engine:expr, $(($type:ty, $name:expr)),+) => {
        $(
            $engine.register_type_with_name::<$type>($name);
        )+
    };
}

#[macro_export]
macro_rules! register_derive_builder_setter {
    ($engine:expr, $builder_type:ty, $method_name:expr, $param_type:ty, $method:ident) => {
        $engine.register_fn(
            $method_name,
            |mut builder: $builder_type, param: $param_type| -> $builder_type {
                builder.$method(param);
                builder
            },
        );
    };
}

#[macro_export]
macro_rules! register_derive_builder_option_setter {
    ($engine:expr, $builder_type:ty, $method_name:expr, $param_type:ty, $method:ident) => {
        $engine.register_fn(
            $method_name,
            |mut builder: $builder_type, param: $param_type| -> $builder_type {
                builder.$method(Some(param));
                builder
            },
        );
    };
}

#[macro_export]
macro_rules! register_derive_builder_key_value_setter {
    ($engine:expr, $builder_type:ty, $method_name:expr, $method:ident) => {
        $engine.register_fn(
            $method_name,
            |builder: $builder_type, key: String, value: String| -> $builder_type {
                builder.$method(key, value)
            },
        );
    };
}

#[macro_export]
macro_rules! register_derive_builder {
    (
        $engine:expr,
        ($builder_type:ty, $builder_name:expr),
        ($built_type:ty, $built_name:expr),
        setters: [$(($method_name:expr, $param_type:ty, $method:ident)),*],
        option_setters: [$(($opt_method_name:expr, $opt_param_type:ty, $opt_method:ident)),*]
        $(, registry: $registry:expr, add_fn: $add_fn:ident)?
    ) => {
        // Register the builder type with name and constructor

        register_type_with_name!($engine,
            ($builder_type, $builder_name),
            ($built_type, $built_name)
        );

        $engine.register_fn($builder_name, <$builder_type>::default);

        // Register all setter methods
        $(
            register_derive_builder_setter!($engine, $builder_type, $method_name, $param_type, $method);
        )*

        // Register all option setter methods
        $(
            register_derive_builder_option_setter!($engine, $builder_type, $opt_method_name, $opt_param_type, $opt_method);
        )*

        // Register publish method that builds and adds metric/alarm to the registry
        $(
            let registry = $registry.clone();
            $engine.register_fn(
                "publish",
                move |builder: &mut $builder_type| -> Result<(), Box<rhai::EvalAltResult>> {
                    builder.build()
                        .map_err(|e| format!("{e:#}").into())
                        .map(|built| {
                            registry.borrow_mut().$add_fn(built);
                        })
                },
            );
        )?
    };

    // Pattern for builders with key-value setter methods
    (
        $engine:expr,
        ($builder_type:ty, $builder_name:expr),
        ($built_type:ty, $built_name:expr),
        key_value_setters: [$(($method_name:expr, $method:ident)),*]
    ) => {
        register_type_with_name!($engine,
            ($builder_type, $builder_name),
            ($built_type, $built_name)
        );

        $engine.register_fn($builder_name, <$builder_type>::default);

        // Register key_value setter methods
        $(
            register_derive_builder_key_value_setter!($engine, $builder_type, $method_name, $method);
        )*

        $engine.register_fn(
            "build",
            |builder: $builder_type| -> $built_type {
                builder.build()
           }
        );
    };
}
