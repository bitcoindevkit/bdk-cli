// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! The Backend
//!
//! This module defines the Backend struct and associated operations

#[allow(dead_code)]
// Different Backend types activated with `regtest-*` mode.
// If `regtest-*` feature not activated, then default is `None`.
pub enum Backend {
    None,
    Bitcoin { rpc_url: String, rpc_auth: String },
    Electrum { electrum_url: String },
    Esplora { esplora_url: String },
}
