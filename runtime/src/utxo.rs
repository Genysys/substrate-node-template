use primitives::{Signature, H256};
use rstd::collections::btree_map::BTreeMap;
use runtime_io::ed25519_verify;
use runtime_primitives::traits::{BlakeTwo256, Hash};
use srml_support::{
	dispatch::{Result, Vec},
	StorageMap,
};
use system::ensure_inherent;

pub trait Trait: system::Trait {
	type Event: From<Event> + Into<<Self as system::Trait>::Event>;
}

/// Single transaction to be dispatched
#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash)]
pub struct Transaction {
	/// Existing UTXOs to be used as inputs for current transaction
	pub inputs: Vec<TransactionInput>,

	/// UTXOs to be created as a result of current transaction dispatch
	pub outputs: Vec<TransactionOutput>,
}

/// Single transaction input that refers to one existing UTXO
#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash)]
pub struct TransactionInput {
	/// Reference to an existing UTXO to be spent
	pub parent_output: H256,

	/// Proof that transaction owner is authorized to spend referred UTXO
	pub signature: Signature,
}

/// Single transaction output to create upon transaction dispatch
#[cfg_attr(feature = "std", derive(Serialize, Deserialize, Debug))]
#[derive(Default, PartialEq, Eq, PartialOrd, Ord, Clone, Encode, Decode, Hash)]
pub struct TransactionOutput {
	/// Value associated with this output
	pub value: u128,

	/// Public key associated with this output. In order to spend this output
	/// owner must provide a proof by hashing whole `TransactionOutput` and
	/// signing it with a corresponding private key.
	pub pubkey: H256,

	/// Unique (potentially random) value used to distinguish this
	/// particular output from others addressed to the same public
	/// key with the same value. Prevents potential replay attacks.
	pub salt: u32,
}

decl_module! {
	pub struct Module<T: Trait> for enum Call where origin: T::Origin {
		pub fn execute(origin, transaction: Transaction) -> Result {
			//ensure_inherent(origin)?;

			Self::check_transaction(&transaction)?;
			Self::update_storage(&transaction);

			Self::deposit_event(Event::TransactionExecuted(transaction));

			Ok(())
		}
	}
}

decl_storage! {
	trait Store for Module<T: Trait> as Utxo {
		/// All valid unspent transaction outputs are stored in this map.
		pub UnspentOutputs build(|config: &GenesisConfig<T>| {
			config.initial_utxo
				.iter()
				.cloned()
				.map(|u| (BlakeTwo256::hash_of(&u), u))
				.collect::<Vec<_>>()
		}): map H256 => Option<TransactionOutput>;
	}

	add_extra_genesis {
		config(initial_utxo): Vec<TransactionOutput>;
	}
}

decl_event!(
	pub enum Event {
		/// Transaction was executed successfully
		TransactionExecuted(Transaction),
	}
);

impl<T: Trait> Module<T> {
	/// Check transaction for validity.
	///
	/// Ensures that:
	/// - inputs and outputs are not empty
	/// - all inputs match to existing and unspent outputs
	/// - each unspent output is used exactly once
	/// - each output is defined exactly once and has nonzero value
	/// - total output value must not exceed total input value
	/// - new outputs do not collide with existing ones
	/// - provided signatures are valid
	fn check_transaction(transaction: &Transaction) -> Result {
		ensure!(!transaction.inputs.is_empty(), "no inputs");
		ensure!(!transaction.outputs.is_empty(), "no outputs");

		{
			let input_set: BTreeMap<_, ()> = transaction
				.inputs
				.iter()
				.map(|input| (input, ()))
				.collect();

			ensure!(
				input_set.len() == transaction.inputs.len(),
				"each input must be used only once"
			);
		}

		{
			let output_set: BTreeMap<_, ()> = transaction
				.outputs
				.iter()
				.map(|output| (output, ()))
				.collect();

			ensure!(
				output_set.len() == transaction.outputs.len(),
				"each output must be defined only once"
			);
		}

		let total_input = transaction.inputs.iter().fold(Ok(0u128), |sum, input| {
			sum.and_then(|sum| {
				// Fetch UTXO from the storage
				let output = <UnspentOutputs<T>>::get(&input.parent_output)
					.ok_or("all parent outputs must exist and be unspent")?;

				// Check that we're authorized to use it
				ensure!(
					ed25519_verify(
						input.signature.as_fixed_bytes(),
						input.parent_output.as_fixed_bytes(),
						&output.pubkey
					),
					"signature must be valid"
				);

				// Add the value to the input total
				sum.checked_add(output.value).ok_or("input value overflow")
			})
		})?;

		let total_output = transaction.outputs.iter().fold(Ok(0u128), |sum, output| {
			sum.and_then(|sum| {
				ensure!(output.value != 0, "output value must be nonzero");

				let hash = BlakeTwo256::hash_of(output);
				ensure!(!<UnspentOutputs<T>>::exists(hash), "output already exists");

				sum.checked_add(output.value).ok_or("output value overflow")
			})
		})?;

		ensure!(
			total_input >= total_output,
			"output value must not exceed input value"
		);

		Ok(())
	}

	/// Update storage to reflect changes made by transaction
	fn update_storage(transaction: &Transaction) {
		// Remove all used UTXO to mark them as spent
		for input in &transaction.inputs {
			<UnspentOutputs<T>>::remove(input.parent_output);
		}

		// Add new UTXO to be used by future transactions
		for output in &transaction.outputs {
			let hash = BlakeTwo256::hash_of(output);
			<UnspentOutputs<T>>::insert(hash, output);
		}
	}

	fn deposit_event(event: Event) {
		let event = <T as Trait>::Event::from(event).into();
		<system::Module<T>>::deposit_event(event);
	}

	/// DANGEROUS! Adds specified output to the storage potentially overwriting existing one.
	/// Does not perform any checks. Must only be used for testing purposes.
	#[cfg(test)]
	fn insert_utxo(output: TransactionOutput) -> H256 {
		let hash = BlakeTwo256::hash_of(&output);
		<UnspentOutputs<T>>::insert(hash, output);
		hash
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use primitives::ed25519::Pair;
	use primitives::Blake2Hasher;
	use runtime_io::with_externalities;

	use runtime_primitives::{
		testing::{Digest, DigestItem, Header},
		traits::BlakeTwo256,
		BuildStorage,
	};

	use Runtime;

	impl_outer_origin! {
		pub enum Origin for Test {}
	}

	#[derive(Clone, Eq, PartialEq)]
	pub struct Test;

	impl system::Trait for Test {
		type Origin = Origin;
		type Index = u64;
		type BlockNumber = u64;
		type Hash = H256;
		type Hashing = BlakeTwo256;
		type Digest = Digest;
		type AccountId = u64;
		type Header = Header;
		type Event = ();
		type Log = DigestItem;
	}

	impl Trait for Test {
		type Event = Event;
	}

	type Utxo = Module<Test>;

	fn alice_utxo() -> (H256, TransactionOutput) {
		let transaction = TransactionOutput {
			value: u128::max_value(),
			pubkey: Pair::from_seed(b"Alice                           ").public().0.into(),
			salt: 0,
		};

		(BlakeTwo256::hash_of(&transaction), transaction)
	}

	fn new_test_ext() -> runtime_io::TestExternalities<Blake2Hasher> {
		let mut config = system::GenesisConfig::<Test>::default().build_storage().unwrap().0;

		config.extend(
			GenesisConfig::<Runtime> {
				initial_utxo: vec![alice_utxo().1],
				..Default::default()
			}
			.build_storage()
			.unwrap()
			.0,
		);

		config.into()
	}

	#[test]
	fn empty() {
		with_externalities(&mut new_test_ext(), || {
			assert_err!(
				Utxo::execute(Origin::INHERENT, Transaction::default()),
				"no inputs"
			);

			assert_err!(
				Utxo::execute(
					Origin::INHERENT,
					Transaction {
						inputs: vec![TransactionInput::default()],
						outputs: vec![],
					}
				),
				"no outputs"
			);
		});
	}

	#[test]
	fn valid_transaction() {
		with_externalities(&mut new_test_ext(), || {
			let keypair = Pair::from_seed(b"Alice                           ");
			let (parent_hash, _) = alice_utxo();

			let transaction = Transaction {
				inputs: vec![
					TransactionInput {
						parent_output: parent_hash,
						signature: keypair.sign(parent_hash.as_fixed_bytes()),
					}
				],
				outputs: vec![
					TransactionOutput {
						value: 100,
						pubkey: 0.into(),
						salt: 0,
					}
				],
			};

			let output_hash = BlakeTwo256::hash_of(&transaction.outputs[0]);

			assert_ok!(Utxo::execute(Origin::INHERENT, transaction));
			assert!(!<UnspentOutputs<Test>>::exists(parent_hash));
			assert!(<UnspentOutputs<Test>>::exists(output_hash));
		});
	}
}
