// SPDX-License-Identifier: Apache-2.0

#![no_std]
#![allow(clippy::unreadable_literal)]

include!(concat!(env!("OUT_DIR"), "/source_profile.rs"));

pub const SYNC_COMMITTEE_BITS_BYTES: usize = SYNC_COMMITTEE_SIZE.div_ceil(8);
