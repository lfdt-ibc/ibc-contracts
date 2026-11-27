// SPDX-License-Identifier: Apache-2.0

#![no_main]

use prividium_public_values::StrictAbiCodec;
use prividium_types::NonMembershipWitness;
use prividium_zksync_native::NativeProofBatch;

sp1_zkvm::entrypoint!(main);

pub fn main() {
    let witness: NonMembershipWitness<NativeProofBatch> = sp1_zkvm::io::read();
    let Ok(public) = prividium_program_logic::verify_non_membership(&witness) else {
        sp1_zkvm::lib::halt_invalid_hint()
    };
    sp1_zkvm::io::commit_slice(&public.abi_encode());
}
