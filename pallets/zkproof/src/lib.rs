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

            ensure!(pallet_verify_proof(&json), Error::<T>::InvalidProof);

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

extern crate alloc;
extern crate core;

use alloc::string::String;
use core::str::FromStr;
use serde::{Deserialize, Serialize};
use serde_json::{self, from_str, to_string};

use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr, FrConfig, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::prepare_g2;
use ark_ff::{Field, Fp256, MontBackend, Zero};
use ark_groth16::{Groth16, Proof, VerifyingKey, PreparedVerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, CanonicalSerializeWithFlags};
use ark_std::rand::Rng;
use base64::Engine;
use hex;
use base64::{decode};
use log::error;

fn decode_base64(data: String) -> Vec<u8> {
    return decode(data).unwrap();
}

fn parse_g1_point(point: G1Point) -> G1Affine {
    let x_bytes = decode_base64(point.x);
    let y_bytes = decode_base64(point.y);

    let x_fq = Fq::deserialize_compressed_unchecked(&*x_bytes).unwrap();
    let y_fq = Fq::deserialize_compressed_unchecked(&*y_bytes).unwrap();

    return G1Affine::new(x_fq, y_fq);
}

fn parse_g2_point(point: G2Point) -> G2Affine {
    let x_c0_bytes = decode_base64(point.x.c0);
    let x_c1_bytes = decode_base64(point.x.c1);
    let y_c0_bytes = decode_base64(point.y.c0);
    let y_c1_bytes = decode_base64(point.y.c1);

    let x_c0_fq = Fq::deserialize_compressed_unchecked(&*x_c0_bytes).unwrap();
    let x_c1_fq = Fq::deserialize_compressed_unchecked(&*x_c1_bytes).unwrap();
    let y_c0_fq = Fq::deserialize_compressed_unchecked(&*y_c0_bytes).unwrap();
    let y_c1_fq = Fq::deserialize_compressed_unchecked(&*y_c1_bytes).unwrap();

    let x_fq2 = Fq2::new(x_c0_fq, x_c1_fq);
    let y_fq2 = Fq2::new(y_c0_fq, y_c1_fq);

    return G2Affine::new(x_fq2, y_fq2);
}

fn parse_verifying_key(json_vk: String) -> PreparedVerifyingKey<Bls12_381> {
    let vk_bytes = decode_base64(json_vk);
    PreparedVerifyingKey::<Bls12_381>::deserialize_compressed_unchecked(&*vk_bytes).unwrap_or_else(|e| {
        log::error!("vk error prepare: {:?}", e);
        PreparedVerifyingKey::<Bls12_381>::default()
    })
}

fn parse_proof(proof: JsonProof) -> Proof<Bls12_381> {
    let a = parse_g1_point(proof.a);
    let b = parse_g2_point(proof.b);
    let c = parse_g1_point(proof.c);
    return Proof { a, b, c };
}

fn parse_public_inputs(public_hash: String) -> Fp256<MontBackend<FrConfig, 4>> {
    let public_hash_bytes = decode_base64(public_hash);
    return Fr::from_random_bytes(public_hash_bytes.as_slice()).unwrap_or_default();
}

fn verify_proof(json_proof: JsonProof, public_inputs: &[Fr]) -> bool {
    let vk = parse_verifying_key(json_proof.verifying_key.clone());
    let proof = parse_proof(json_proof);
    Groth16::<Bls12_381>::verify_proof(&vk, &proof, public_inputs).unwrap_or(true)
}

fn pallet_verify_proof(proof_data: &[u8]) -> bool {
    return match core::str::from_utf8(proof_data) {
        Ok(proof_str) => {
            let json_proof: JsonProof = from_str(proof_str).unwrap();
            let public_inputs = parse_public_inputs(json_proof.public_hash.clone());

            verify_proof(json_proof, &[public_inputs])
        }
        Err(e) => {
            log::error!("Invalid UTF-8 in zk proof data: {:?}", e);
            false
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonProof {
    a: G1Point,
    b: G2Point,
    c: G1Point,
    public_hash: String,
    verifying_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct G1Point {
    x: String,
    y: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct G2Point {
    x: G2Coordinates,
    y: G2Coordinates,
}

#[derive(Serialize, Deserialize, Debug)]
struct G2Coordinates {
    c0: String,
    c1: String,
}
