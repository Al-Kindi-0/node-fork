//! Compatibility shims for current golden-rs adapter behavior.
//!
//! This module should stay small. Anything here is a candidate for deletion once the pinned
//! golden-rs dependency is replaced by an upstream fix or a patched vendor crate.

use std::collections::HashMap;

use ark_bls12_381::G1Affine;
use golden_dkg::error::DkgError;
use golden_dkg::types::{DkgConfig, NodeId, Round0Msg, Scalar};
use golden_dkg::{dkg, zk_evrf};
use miden_node_private_tx::ThresholdError;

// Factorial proof retries are only acceptable for PoC-sized groups. Six recipients means at most
// 720 verification attempts for a failed batch proof; larger groups should use a patched golden-rs
// verifier that sorts by NodeId before constructing batch public inputs.
const MAX_BATCH_PROOF_ORDER_RECIPIENTS: usize = 6;

pub(crate) fn verify_dealing(
    round0: &Round0Msg,
    peers: &HashMap<NodeId, G1Affine>,
    config: &DkgConfig,
) -> Result<(), ThresholdError> {
    match dkg::verify_dealing(round0, peers, config) {
        Ok(()) => Ok(()),
        Err(DkgError::ProofError(_)) if round0.batch_evrf_proof.is_some() => {
            verify_batch_proof_in_any_order(round0, peers, config.beta)
        },
        Err(_) => Err(ThresholdError::VerificationFailed),
    }
}

fn verify_batch_proof_in_any_order(
    round0: &Round0Msg,
    peers: &HashMap<NodeId, G1Affine>,
    beta: Scalar,
) -> Result<(), ThresholdError> {
    let proof = round0.batch_evrf_proof.as_ref().ok_or(ThresholdError::VerificationFailed)?;
    let sender_public_key = peers
        .get(&round0.dkg_header.from)
        .copied()
        .ok_or(ThresholdError::VerificationFailed)?;
    let mut statements = round0
        .dkg_header
        .ciphertexts
        .iter()
        .map(|(&node_id, ciphertext)| {
            let public_key =
                peers.get(&node_id).copied().ok_or(ThresholdError::VerificationFailed)?;
            Ok((node_id, public_key, ciphertext.r_commitment))
        })
        .collect::<Result<Vec<_>, ThresholdError>>()?;

    if statements.len() > MAX_BATCH_PROOF_ORDER_RECIPIENTS {
        return Err(ThresholdError::VerificationFailed);
    }

    if verify_statement_permutations(sender_public_key, &mut statements, beta, proof)? {
        Ok(())
    } else {
        Err(ThresholdError::VerificationFailed)
    }
}

fn verify_statement_permutations(
    sender_public_key: G1Affine,
    statements: &mut [(NodeId, G1Affine, G1Affine)],
    beta: Scalar,
    proof: &zk_evrf::EVRFProof,
) -> Result<bool, ThresholdError> {
    fn visit(
        index: usize,
        sender_public_key: G1Affine,
        statements: &mut [(NodeId, G1Affine, G1Affine)],
        beta: Scalar,
        proof: &zk_evrf::EVRFProof,
    ) -> Result<bool, ThresholdError> {
        if index == statements.len() {
            let peers = statements
                .iter()
                .map(|(node_id, public_key, _)| (*node_id, *public_key))
                .collect::<Vec<_>>();
            let pad_commitments = statements
                .iter()
                .map(|(node_id, _, commitment)| (*node_id, *commitment))
                .collect::<Vec<_>>();
            return zk_evrf::verify_evrf_batch(
                sender_public_key,
                &peers,
                &pad_commitments,
                beta,
                proof,
            )
            .map_err(|_| ThresholdError::VerificationFailed);
        }

        for candidate in index..statements.len() {
            statements.swap(index, candidate);
            if visit(index + 1, sender_public_key, statements, beta, proof)? {
                statements.swap(index, candidate);
                return Ok(true);
            }
            statements.swap(index, candidate);
        }

        Ok(false)
    }

    visit(0, sender_public_key, statements, beta, proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::UniformRand;
    use rand08::rngs::OsRng;

    #[test]
    fn batch_proof_permutation_fallback_accepts_reordered_inputs() {
        let mut rng = OsRng;
        let sender_secret = Scalar::rand(&mut rng);
        let sender_public_key = (G1Affine::generator() * sender_secret).into_affine();
        let peer_2_public_key = (G1Affine::generator() * Scalar::rand(&mut rng)).into_affine();
        let peer_3_public_key = (G1Affine::generator() * Scalar::rand(&mut rng)).into_affine();
        let beta = Scalar::rand(&mut rng);
        let peer_2_pad = Scalar::rand(&mut rng);
        let peer_3_pad = Scalar::rand(&mut rng);
        let peer_2_commitment = (G1Affine::generator() * peer_2_pad).into_affine();
        let peer_3_commitment = (G1Affine::generator() * peer_3_pad).into_affine();
        let proof = zk_evrf::prove_evrf_batch(
            sender_secret,
            sender_public_key,
            &[(2, peer_2_public_key), (3, peer_3_public_key)],
            &[(2, peer_2_pad, peer_2_commitment), (3, peer_3_pad, peer_3_commitment)],
            beta,
        )
        .unwrap();

        let reordered_peers = [(3, peer_3_public_key), (2, peer_2_public_key)];
        let reordered_commitments = [(3, peer_3_commitment), (2, peer_2_commitment)];
        assert!(
            !zk_evrf::verify_evrf_batch(
                sender_public_key,
                &reordered_peers,
                &reordered_commitments,
                beta,
                &proof,
            )
            .unwrap()
        );

        let mut statements = vec![
            (3, peer_3_public_key, peer_3_commitment),
            (2, peer_2_public_key, peer_2_commitment),
        ];
        assert!(
            verify_statement_permutations(sender_public_key, &mut statements, beta, &proof)
                .unwrap()
        );
    }
}
