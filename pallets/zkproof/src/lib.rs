// We make sure this pallet uses `no_std` for compiling to Wasm.
#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::BoundedVec;
pub use pallet::*;
pub use scale_info::prelude::vec::Vec;

// All pallet logic is defined in its own module and must be annotated by the `pallet` attribute.
#[frame_support::pallet]
pub mod pallet {
    // Import various useful types required by all FRAME pallets.
    use super::*;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    /// The pallet's configuration trait.
    ///
    /// All our types and constants a pallet depends on must be declared here.
    /// These types are defined generically and made concrete when the pallet is declared in the
    /// `runtime/src/lib.rs` file of your chain.
    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type MaxJsonLength: Get<u32>;
    }

    //pub type ZkProofData<T: Config> = StorageValue<_, BoundedVec<u8, T::MaxJsonLength>, ValueQuery>;
    #[pallet::storage]
    pub type ZkProofData<T: Config> = StorageMap<_, Twox64Concat, T::Hash, BoundedVec<u8, T::MaxJsonLength>, OptionQuery>;

    #[pallet::event]
    #[pallet::generate_deposit(pub (super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Un événement pour notifier que des données JSON ont été stockées.
        ZkProofStored {
            json: BoundedVec<u8, T::MaxJsonLength>,
            who: T::AccountId,
            hash: T::Hash,
        },

        ZkProofRetrieved(T::Hash, Vec<u8>),
    }

    #[pallet::error]
    pub enum Error<T> {
        ZkProofTooLarge,
        InvalidProof,
    }

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        #[pallet::weight(10_000)]
        pub fn store_zk_proof(origin: OriginFor<T>, json: Vec<u8>) -> DispatchResult {
            let who = ensure_signed(origin)?;

            use frame_support::sp_runtime::traits::Hash;
            let proof_hash = T::Hashing::hash(&json);

            ensure!(proof_is_valid(&json), Error::<T>::InvalidProof);

            let bounded_json = BoundedVec::try_from(json).map_err(|_| Error::<T>::ZkProofTooLarge)?;

            ZkProofData::<T>::insert(proof_hash, bounded_json.clone());

            Self::deposit_event(Event::ZkProofStored { json: bounded_json, who, hash: proof_hash });

            Ok(())
        }

        #[pallet::weight(10_000)]
        pub fn retrieve_all_zk_proofs(origin: OriginFor<T>) -> DispatchResultWithPostInfo {
            let _who = ensure_signed(origin)?;

            for (proof_hash, zk_proof) in ZkProofData::<T>::iter() {
                Self::deposit_event(Event::ZkProofRetrieved(proof_hash, zk_proof.to_vec()));
            }

            Ok(().into())
        }
    }
}

fn proof_is_valid(proof_data: &[u8]) -> bool {
    match core::str::from_utf8(proof_data) {
        Ok(proof_str) => {
            log::info!("Checking zkproof: {}", proof_str);
        },
        Err(e) => {
            log::error!("Invalid zk proof provided: {:?}", e);
            return false;
        }
    }
    true
}