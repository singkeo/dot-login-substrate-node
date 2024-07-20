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

use alloc::string::String;
use serde::{Deserialize, Serialize};
use serde_json::{self, from_str};

use ark_bls12_381::{Bls12_381, Fq, Fq2, Fr, FrConfig, G1Affine, G2Affine};
use ark_ff::{Field, Fp256, MontBackend};
use ark_groth16::{Groth16, Proof, PreparedVerifyingKey};
use ark_serialize::{CanonicalDeserialize};
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

            let jwt_token = json_proof.jwt_token.clone();
            return if verify_proof(json_proof, &[public_inputs]) {
                return if validate_jwt(jwt_token) {
                    true
                } else {
                    error!("FAIL VERIFICATION TOKEN JWT");
                    false
                }
            } else {
                error!("FAIL VERIFICATION ZK PROOF");
                false
            }
        }
        Err(e) => {
            log::error!("Invalid UTF-8 in zk proof data: {:?}", e);
            false
        }
    };
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonProof {
    a: G1Point,
    b: G2Point,
    c: G1Point,
    public_hash: String,
    verifying_key: String,
    jwt_token: String,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    iss: String,
    // L'émetteur du token
    azp: String,
    // L'ID client autorisé
    aud: String,
    // Le destinataire du token, doit correspondre à l'ID client
    sub: String,
    // L'identifiant unique de l'utilisateur
    nonce: String,
    // Une chaîne utilisée pour associer une session client à un ID Token
    nbf: i64,
    // La date/heure avant laquelle le token n'est pas accepté (Not Before)
    iat: i64,
    // L'heure d'émission du token (Issued At)
    exp: i64,
    // L'heure d'expiration du token (Expire)
    jti: String,
    // Un identifiant unique pour le token (JWT ID)
    email: String,
}

#[derive(Debug, Deserialize)]
struct GoogleJwks {
    keys: Vec<Jwk>,
}

#[derive(Debug, Deserialize)]
struct Jwk {
    n: String,
    #[serde(rename = "use")]
    k_use: String,
    kid: String,
    alg: String,
    kty: String,
    e: String,
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let mut input = input.replace('-', "+").replace('_', "/");
    while input.len() % 4 != 0 {
        input.push('=');
    }
    base64::decode(&input)
}
fn validate_jwt(token: String) -> bool {
    let jwks: GoogleJwks = get_google_jwks();

    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    let header_part = parts[0];
    let payload_part = parts[1];
    let signature_part = parts[2];

    let header_bytes = match base64_url_decode(header_part) {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };

    let header_str = match core::str::from_utf8(&header_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let header: serde_json::Value = match from_str(header_str) {
        Ok(h) => h,
        Err(_) => return false,
    };

    let kid = match header.get("kid") {
        Some(k) => k.as_str().unwrap_or(""),
        None => return false,
    };

    let jwk = match jwks.keys.iter().find(|k| k.kid == kid) {
        Some(jwk) => jwk,
        None => return false,
    };

    //TODO @Ahmed verify the last signature part with RSA

    return true
}

//TODO @Ahmed to be retrieved from on off chain worker as JWK may be rotated.
fn get_google_jwks() -> GoogleJwks {
    let mut keys = Vec::new();

    keys.push(Jwk {
        alg: String::from("RS256"),
        n: String::from("rv95jmy91hibD7cb_BCA25jv5HrX7WoqHv-fh8wrOR5aYcM8Kvsc3mbzs2w1vCUlMRv7NdEGVBEnOZ6tHvUzGLon4ythd5XsX-wTvAtIHPkyHdo5zGpTgATO9CEn78Y-f1E8By63ttv14kXe_RMjt5aKttK4yqqUyzWUexSs7pET2zWiigd0_bGhJGYYEJlEk_JsOBFvloIBaycMfDjK--kgqnlRA8SWUkP3pEJIAo9oHzmvX6uXZTEJK10a1YNj0JVR4wZY3k60NaUX-KCroreU85iYgnecyxSdL-trpKdkg0-2OYks-_2Isymu7jPX-uKVyi-zKyaok3N64mERRQ"),
        e: String::from("AQAB"),
        kty: String::from("RSA"),
        k_use: String::from("sig"),
        kid: String::from("0e345fd7e4a97271dffa991f5a893cd16b8e0827"),
    });

    keys.push(Jwk {
        alg: String::from("RS256"),
        n: String::from("zaUomGGU1qSBxBHOQRk5fF7rOVVzG5syHhJYociRyyvvMOM6Yx_n7QFrwKxW1Gv-YKPDsvs-ksSN5YsozOTb9Y2HlPsOXrnZHQTQIdjWcfUz-TLDknAdJsK3A0xZvq5ud7ElIrXPFS9UvUrXDbIv5ruv0w4pvkDrp_Xdhw32wakR5z0zmjilOHeEJ73JFoChOaVxoRfpXkFGON5ZTfiCoO9o0piPROLBKUtIg_uzMGzB6znWU8Yfv3UlGjS-ixApSltsXZHLZfat1sUvKmgT03eXV8EmNuMccrhLl5AvqKT6E5UsTheSB0veepQgX8XCEex-P3LCklisnen3UKOtLw"),
        e: String::from("AQAB"),
        kty: String::from("RSA"),
        k_use: String::from("sig"),
        kid: String::from("f2e11986282de93f27b264fd2a4de192993dcb8c"),
    });

    GoogleJwks { keys }
}