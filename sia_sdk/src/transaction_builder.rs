//! V2 Transaction Builder
//!
//! Builder pattern for constructing, signing, and finalizing Sia V2 transactions.
//! Adapted from [GLEECBTC/sia-rust](https://github.com/GLEECBTC/sia-rust).

use crate::consensus::{ChainState, BLAKE2B_256_PARAMS, REPLAY_PREFIX_V2};
use crate::signing::PrivateKey;
use crate::types::v2::{self, SatisfiedPolicy, SpendPolicy};
use crate::types::{Address, Currency, Hash256, SiacoinOutput, SiafundOutput};

/// Builder for V2 siacoin transactions.
///
/// Construct a transaction step-by-step: add inputs (UTXOs), outputs
/// (recipients), set the miner fee, then sign and build.
///
/// ```ignore
/// let mut builder = V2TransactionBuilder::new();
/// builder
///     .add_siacoin_input(utxo_element, SpendPolicy::PublicKey(pk))
///     .add_siacoin_output(SiacoinOutput { value: amount, address: recipient })
///     .miner_fee(Currency::new(10_000_000_000_000_000_000));
/// builder.sign_simple(&[&private_key]);
/// let txn = builder.build();
/// ```
#[derive(Debug, Clone)]
pub struct V2TransactionBuilder {
    pub siacoin_inputs: Vec<v2::SiacoinInput>,
    pub siacoin_outputs: Vec<SiacoinOutput>,
    pub siafund_inputs: Vec<v2::SiafundInput>,
    pub siafund_outputs: Vec<SiafundOutput>,
    pub file_contracts: Vec<v2::FileContract>,
    pub file_contract_revisions: Vec<v2::FileContractRevision>,
    pub file_contract_resolutions: Vec<v2::FileContractResolution>,
    pub attestations: Vec<v2::Attestation>,
    pub arbitrary_data: Vec<u8>,
    pub new_foundation_address: Option<Address>,
    pub miner_fee: Currency,
}

impl V2TransactionBuilder {
    pub fn new() -> Self {
        Self {
            siacoin_inputs: Vec::new(),
            siacoin_outputs: Vec::new(),
            siafund_inputs: Vec::new(),
            siafund_outputs: Vec::new(),
            file_contracts: Vec::new(),
            file_contract_revisions: Vec::new(),
            file_contract_resolutions: Vec::new(),
            attestations: Vec::new(),
            arbitrary_data: Vec::new(),
            new_foundation_address: None,
            miner_fee: Currency::zero(),
        }
    }

    /// Add a siacoin input (UTXO) with its spend policy.
    /// The policy's signatures/preimages are left empty — call [`sign_simple`]
    /// (or [`sign_simple_v1`] with a [`ChainState`]) after all inputs/outputs are added.
    pub fn add_siacoin_input(
        &mut self,
        parent: v2::SiacoinElement,
        policy: SpendPolicy,
    ) -> &mut Self {
        self.siacoin_inputs.push(v2::SiacoinInput {
            parent,
            satisfied_policy: SatisfiedPolicy {
                policy,
                signatures: Vec::new(),
                preimages: Vec::new(),
            },
        });
        self
    }

    /// Add a siacoin output (recipient).
    pub fn add_siacoin_output(&mut self, output: SiacoinOutput) -> &mut Self {
        self.siacoin_outputs.push(output);
        self
    }

    /// Set all siacoin inputs at once (replaces any previously added).
    pub fn siacoin_inputs(&mut self, inputs: Vec<v2::SiacoinInput>) -> &mut Self {
        self.siacoin_inputs = inputs;
        self
    }

    /// Set all siacoin outputs at once (replaces any previously added).
    pub fn siacoin_outputs(&mut self, outputs: Vec<SiacoinOutput>) -> &mut Self {
        self.siacoin_outputs = outputs;
        self
    }

    /// Set pre-signed attestations to include in the transaction.
    pub fn attestations(&mut self, attestations: Vec<v2::Attestation>) -> &mut Self {
        self.attestations = attestations;
        self
    }

    /// Set the miner fee.
    pub fn miner_fee(&mut self, fee: Currency) -> &mut Self {
        self.miner_fee = fee;
        self
    }

    /// Set arbitrary data (e.g. encrypted manifest pointer).
    pub fn arbitrary_data(&mut self, data: Vec<u8>) -> &mut Self {
        self.arbitrary_data = data;
        self
    }

    /// Set the new foundation address (rarely used).
    pub fn new_foundation_address(&mut self, address: Address) -> &mut Self {
        self.new_foundation_address = Some(address);
        self
    }

    /// Compute the signature hash using the replay prefix from [`ChainState`].
    /// Correct across all hardfork eras; use this when `ChainState` is available.
    pub fn input_sig_hash_v1(&self, cs: &ChainState) -> Hash256 {
        self.to_transaction().input_sig_hash(cs)
    }

    /// Compute the signature hash with the hardcoded V2 replay prefix (`2`).
    /// Only valid after the v2 hardfork has activated. Use [`input_sig_hash_v1`]
    /// if you need correct behavior across hardfork boundaries.
    pub fn input_sig_hash(&self) -> Hash256 {
        let txn = self.to_transaction();
        let mut state = BLAKE2B_256_PARAMS.to_state();
        state.update(b"sia/sig/input|");
        state.update(REPLAY_PREFIX_V2);
        txn.encode_semantics(&mut state)
            .expect("encode_semantics writes to blake2b State, which is infallible");
        state.finalize().into()
    }

    /// Sign all inputs using the replay prefix from [`ChainState`].
    /// Handles pre- and post-hardfork eras correctly. Use this when you have a
    /// [`ChainState`] available (e.g. in a full node or syncer context).
    /// Each key is matched against each input's policy by public key comparison.
    /// Duplicate keys are ignored to prevent double-signing inputs.
    #[allow(deprecated)]
    pub fn sign_simple_v1(&mut self, cs: &ChainState, keys: &[&PrivateKey]) -> &mut Self {
        let sig_hash = self.input_sig_hash_v1(cs);
        let mut seen = std::collections::HashSet::new();
        let unique_keys: Vec<&&PrivateKey> = keys
            .iter()
            .filter(|k| seen.insert(k.public_key().as_ref().to_vec()))
            .collect();
        for key in unique_keys {
            let pk = key.public_key();
            let sig = key.sign(sig_hash.as_ref());
            for input in &mut self.siacoin_inputs {
                match &input.satisfied_policy.policy {
                    SpendPolicy::PublicKey(input_pk) if *input_pk == pk => {
                        input.satisfied_policy.signatures.push(sig.clone());
                    }
                    SpendPolicy::UnlockConditions(uc) => {
                        for unlock_key in &uc.public_keys {
                            // Compare the raw key bytes against our public key
                            if unlock_key.key.as_slice() == pk.as_ref() {
                                input.satisfied_policy.signatures.push(sig.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        self
    }

    /// Sign all inputs using the hardcoded V2 replay prefix (`2`).
    /// Use this for post-v2-hardfork transactions when [`ChainState`] is not
    /// available (e.g. WASM light clients). For full nodes or any context
    /// spanning hardfork boundaries, use [`sign_simple_v1`] instead.
    /// Each key is matched against each input's policy by public key comparison.
    #[allow(deprecated)]
    pub fn sign_simple(&mut self, keys: &[&PrivateKey]) -> &mut Self {
        let sig_hash = self.input_sig_hash();
        // Deduplicate keys to avoid adding multiple signatures to inputs
        // that share the same public key (e.g. multiple UTXOs from one address)
        let mut seen = std::collections::HashSet::new();
        let unique_keys: Vec<&&PrivateKey> = keys.iter()
            .filter(|k| seen.insert(k.public_key().as_ref().to_vec()))
            .collect();
        for key in unique_keys {
            let pk = key.public_key();
            let sig = key.sign(sig_hash.as_ref());
            for input in &mut self.siacoin_inputs {
                match &input.satisfied_policy.policy {
                    SpendPolicy::PublicKey(input_pk) if *input_pk == pk => {
                        input.satisfied_policy.signatures.push(sig.clone());
                    }
                    SpendPolicy::UnlockConditions(uc) => {
                        for unlock_key in &uc.public_keys {
                            if unlock_key.key.as_slice() == pk.as_ref() {
                                input.satisfied_policy.signatures.push(sig.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        self
    }

    /// Consume the builder and produce a finalized `v2::Transaction`.
    pub fn build(self) -> v2::Transaction {
        v2::Transaction {
            siacoin_inputs: self.siacoin_inputs,
            siacoin_outputs: self.siacoin_outputs,
            siafund_inputs: self.siafund_inputs,
            siafund_outputs: self.siafund_outputs,
            file_contracts: self.file_contracts,
            file_contract_revisions: self.file_contract_revisions,
            file_contract_resolutions: self.file_contract_resolutions,
            attestations: self.attestations,
            arbitrary_data: self.arbitrary_data,
            new_foundation_address: self.new_foundation_address,
            miner_fee: self.miner_fee,
        }
    }

    /// Create a temporary transaction (for hashing). Does not consume the builder.
    fn to_transaction(&self) -> v2::Transaction {
        v2::Transaction {
            siacoin_inputs: self.siacoin_inputs.clone(),
            siacoin_outputs: self.siacoin_outputs.clone(),
            siafund_inputs: self.siafund_inputs.clone(),
            siafund_outputs: self.siafund_outputs.clone(),
            file_contracts: self.file_contracts.clone(),
            file_contract_revisions: self.file_contract_revisions.clone(),
            file_contract_resolutions: self.file_contract_resolutions.clone(),
            attestations: self.attestations.clone(),
            arbitrary_data: self.arbitrary_data.clone(),
            new_foundation_address: self.new_foundation_address.clone(),
            miner_fee: self.miner_fee,
        }
    }
}

impl Default for V2TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}
