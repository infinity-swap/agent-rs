pub mod agent;
pub mod export;
pub mod request_id;

pub use ic_types;
pub use ic_types::hash_tree;

use candid::parser::typing::TypeEnv;
use candid::types::{Function, Type};
use candid::{parser::value::IDLValue, IDLArgs};

/// The type to represent DFX results.
pub type DfxResult<T = ()> = anyhow::Result<T>;

/// The type to represent DFX errors.
pub type DfxError = anyhow::Error;

#[macro_export]
macro_rules! error_invalid_argument {
    ($($args:tt)*) => {
        anyhow::anyhow!("Invalid argument: {}", format_args!($($args)*))
    }
}

#[macro_export]
macro_rules! error_invalid_data {
    ($($args:tt)*) => {
        anyhow::anyhow!("Invalid data: {}", format_args!($($args)*))
    }
}

#[macro_export]
macro_rules! error_unknown {
    ($($args:tt)*) => {
        anyhow::anyhow!("Unknown error: {}", format_args!($($args)*))
    }
}

pub fn blob_from_arguments(
    arguments: Option<&str>,
    arg_type: Option<&str>,
    method_type: &Option<(TypeEnv, Function)>,
) -> DfxResult<Vec<u8>> {
    let arg_type = arg_type.unwrap_or("idl");
    match arg_type {
        "idl" => {
            let typed_args = match method_type {
                None => {
                    let arguments = arguments.unwrap_or("()");
                    candid::pretty_parse::<IDLArgs>("Candid argument", arguments)
                        .map_err(|e| error_invalid_argument!("Invalid Candid values: {}", e))?
                        .to_bytes()
                }
                Some((env, func)) => {
                    if let Some(arguments) = arguments {
                        let first_char = arguments.chars().next();
                        let is_candid_format = first_char.map_or(false, |c| c == '(');
                        // If parsing fails and method expects a single value, try parsing as IDLValue.
                        // If it still fails, and method expects a text type, send arguments as text.
                        let args = arguments.parse::<IDLArgs>().or_else(|_| {
                            if func.args.len() == 1 && !is_candid_format {
                                let is_quote = first_char.map_or(false, |c| c == '"');
                                if candid::types::Type::Text == func.args[0] && !is_quote {
                                    Ok(IDLValue::Text(arguments.to_string()))
                                } else {
                                    candid::pretty_parse::<IDLValue>("Candid argument", arguments)
                                }
                                .map(|v| IDLArgs::new(&[v]))
                            } else {
                                candid::pretty_parse::<IDLArgs>("Candid argument", arguments)
                            }
                        });
                        args.map_err(|e| error_invalid_argument!("Invalid Candid values: {}", e))?
                            .to_bytes_with_types(env, &func.args)
                    } else if func.args.is_empty() {
                        use candid::Encode;
                        Encode!()
                    } else if func.args.iter().all(|t| matches!(t, Type::Opt(_))) {
                        // If the user provided no arguments, and if all the expected arguments are
                        // optional, then use null values.
                        let nulls = vec![IDLValue::Null; func.args.len()];
                        let args = IDLArgs::new(&nulls);
                        args.to_bytes_with_types(env, &func.args)
                    } else {
                        return Err(error_invalid_data!("Expected arguments but found none."));
                    }
                }
            }
            .map_err(|e| error_invalid_data!("Unable to serialize Candid values: {}", e))?;
            Ok(typed_args)
        }
        v => Err(error_unknown!("Invalid type: {}", v)),
    }
}
