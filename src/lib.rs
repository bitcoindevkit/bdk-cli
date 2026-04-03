// Copyright (c) 2020-2025 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

#![doc = include_str!("../README.md")]
#![doc(html_logo_url = "https://github.com/bitcoindevkit/bdk/raw/master/static/bdk.png")]

pub mod commands;
mod config;
pub mod error;
pub mod handlers;
#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "cbf",
    feature = "rpc"
))]
mod payjoin;
#[cfg(any(feature = "sqlite", feature = "redb"))]
mod persister;
pub mod utils;

pub use commands::CliOpts;
pub use handlers::handle_command;
