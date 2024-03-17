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

/// Waits for a network condition to be met.
#[derive(Parser)]
pub struct Args {
    /// Specifes the exit condition:
    /// - A global default route is available (default-route)
    /// - A specific interface receives a non-link-local address (if-gets-address=<eth0>)
    /// - A specific interface receives a non-local route (if-gets-route=<eth0>)

    #[arg(
        short,
        long,
        default_value = "default-route",
        env = "NETAWAIT_WAIT_CONDITION",
        verbatim_doc_comment
    )]
    pub wait_condition: WaitConditionFlag,

    /// If specified, will only wait this long for our condition to be met.
    #[arg(short, long, env = "NETAWAIT_TIMEOUT")]
    pub timeout: Option<i32>,

    /// Log level to display output at
    #[arg(short, long, env = "NETAWAIT_LOG_LEVEL", default_value = "warn")]
    pub log_level: log::LevelFilter,
}

#[derive(Clone)]
pub enum WaitConditionFlag {
    DefaultRouteExists,
    InterfaceHasAddress(String),
    InterfaceHasRoute(String),
}

impl Default for WaitConditionFlag {
    fn default() -> Self {
        Self::DefaultRouteExists
    }
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
