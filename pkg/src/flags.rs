use std::str::FromStr;

use clap::Parser;
use lazy_static::lazy_static;

lazy_static! {
    static ref FLAG_VARIANTS: [WaitConditionFlag; 3] = [
        WaitConditionFlag::DefaultRouteExists,
        WaitConditionFlag::InterfaceHasRoute("en0".to_string()),
        WaitConditionFlag::InterfaceHasAddress("en0".to_string()),
    ];
}

#[derive(Parser)]
pub struct Args {
    /// If specified, waits for this interface to be up AND assigned a route OR address.
    #[arg(short, long)]
    pub wait_condition: WaitConditionFlag,
}

#[derive(Clone)]
pub enum WaitConditionFlag {
    DefaultRouteExists,
    InterfaceHasAddress(String),
    InterfaceHasRoute(String),
}

impl FromStr for WaitConditionFlag {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let mut parts = input.split_terminator(&['=', ' ', ':']);
        let key = parts.next();
        match key {
            Some("default-route") => Ok(Self::DefaultRouteExists),
            Some("if-gets-address") | Some("if-gets-route") => {
                let if_name = parts
                    .next()
                    .ok_or("missing interface value for wait condition")?
                    .to_string();
                Ok(match key.unwrap() {
                    "if-gets-address" => WaitConditionFlag::InterfaceHasAddress(if_name),
                    "if-gets-route" => WaitConditionFlag::InterfaceHasRoute(if_name),
                    _ => unreachable!(),
                })
            }
            Some(s) => Err(format!("invalid value for wait condition: {s}")),
            None => Err("missing value for wait condition".to_string()),
        }
    }
}
