// SPDX-License-Identifier: Apache-2.0

#![no_main]

use prividium_public_values::StrictAbiCodec;
use prividium_types::TrustUpdateWitness;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let witness: TrustUpdateWitness = sp1_zkvm::io::read();
    let Ok(public) = prividium_program_logic::verify_trust_update(&witness) else {
        sp1_zkvm::lib::halt_invalid_hint()
    };
    sp1_zkvm::io::commit_slice(&public.abi_encode());
}
