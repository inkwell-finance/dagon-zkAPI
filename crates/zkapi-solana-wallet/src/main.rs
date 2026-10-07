//! zkapi-solana-wallet: the native-SOL wallet helper that zkapi-clientd drives over stdin/stdout.
//!
//! Each stdin line is a JSON command `{"id":N,"command":"...",...}`; stdout carries only JSON replies
//! `{"id":N,"ok":true,"result":...}` or `{"id":N,"ok":false,"error":"...","code":"..."}`. Every proof and note transition is
//! the same pure browser-SDK code (`zkapi-browser`); the chain commands talk only to the RPC named by `connect`.
//! Start with `zkapi-solana-wallet SETUP_DIRECTORY` (the directory holding `request.pk` and `withdrawal.pk`);
//! the first command a client should send is `handshake`.

mod chain;
#[cfg(feature = "dev")]
mod dev;
mod driver;

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};
use std::{
    io::{self, BufRead, Write},
    path::PathBuf,
};

use chain::Coded;
use driver::{WalletDriver, PROTOCOL};

/// Derived Solana chain IDs are exact u64s that routinely exceed 2^53. The Rust public-input structs serialize them as JSON
/// numbers, which a JavaScript client would round (the server then reports `protocol_mismatch`), so reply with decimal
/// strings exactly as the browser SDK's WASM layer does. The Rust side reads either form.
fn stringify_chain_ids(value: &mut Value) {
    match value {
        Value::Object(object) => {
            if let Some(chain_id) = object.get_mut("chain_id") {
                if let Some(number) = chain_id.as_u64() {
                    *chain_id = Value::String(number.to_string());
                }
            }
            object.values_mut().for_each(stringify_chain_ids);
        }
        Value::Array(values) => values.iter_mut().for_each(stringify_chain_ids),
        _ => {}
    }
}

fn version_line() -> String {
    format!(
        "zkapi-solana-wallet {} (protocol {PROTOCOL}{})",
        env!("CARGO_PKG_VERSION"),
        if cfg!(feature = "dev") { ", DEV BUILD: test-only commands" } else { "" }
    )
}

const USAGE: &str = "usage: zkapi-solana-wallet SETUP_DIRECTORY | --version";

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let first = args.next().context(USAGE)?;
    if first == "--version" || first == "-V" {
        println!("{}", version_line());
        return Ok(());
    }
    ensure!(first != "--help" && first != "-h", USAGE);
    ensure!(args.next().is_none(), USAGE);
    let mut driver = WalletDriver::new(PathBuf::from(first))?;
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        let (id, result) = match serde_json::from_str::<Value>(&line) {
            Ok(command) => (command.get("id").cloned().unwrap_or(Value::Null), driver.handle(&command)),
            Err(error) => (Value::Null, Err(error.into())),
        };
        let reply = match result {
            Ok(mut result) => {
                stringify_chain_ids(&mut result);
                json!({"id": id, "ok": true, "result": result})
            }
            Err(error) => {
                let code = error.downcast_ref::<Coded>().map(|coded| coded.code);
                json!({"id": id, "ok": false, "error": format!("{error:#}"), "code": code})
            }
        };
        serde_json::to_writer(&mut stdout, &reply)?;
        writeln!(stdout)?;
        stdout.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_ids_are_replied_as_decimal_strings_at_any_depth() {
        let mut value = json!({"chain_id": 18446744073709551615u64, "inner": [{"chain_id": 7, "note_id": 3}]});
        stringify_chain_ids(&mut value);
        assert_eq!(value["chain_id"], "18446744073709551615");
        assert_eq!(value["inner"][0]["chain_id"], "7");
        assert_eq!(value["inner"][0]["note_id"], 3);
    }

    #[test]
    fn the_version_line_names_the_protocol_and_flags_dev_builds() {
        let line = version_line();
        assert!(line.starts_with(&format!("zkapi-solana-wallet {} (protocol {PROTOCOL}", env!("CARGO_PKG_VERSION"))));
        assert_eq!(line.contains("DEV BUILD"), cfg!(feature = "dev"));
    }
}
