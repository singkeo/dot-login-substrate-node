use crate::{mock::*, Error};
use frame_support::{assert_ok, assert_noop, BoundedVec};

#[test]
fn store_zk_proof_works() {
    new_test_ext().execute_with(|| {
        let json_data = vec![1, 2, 3, 4, 5];
        let result = ZkProofModule::store_zk_proof(Origin::signed(1), json_data.clone());
        assert_ok!(result);

        let proof_hash = <Test as frame_system::Config>::Hashing::hash(&json_data);
        let stored_data = pallet_zk_proof::ZkProofData::<Test>::get(proof_hash).unwrap();
        assert_eq!(stored_data, BoundedVec::try_from(json_data).unwrap());

        let expected_event = Event::ZkProofModule(crate::Event::ZkProofStored {
            json: BoundedVec::try_from(vec![1, 2, 3, 4, 5]).unwrap(),
            who: 1,
            hash: proof_hash,
        });
        frame_system::Pallet::<Test>::assert_last_event(expected_event.into());
    });
}

#[test]
fn store_zk_proof_too_large() {
    new_test_ext().execute_with(|| {
        let json_data = vec![0; 2048]; // Larger than MaxJsonLength
        let result = ZkProofModule::store_zk_proof(Origin::signed(1), json_data);
        assert_noop!(result, Error::<Test>::ZkProofTooLarge);
    });
}

#[test]
fn retrieve_all_zk_proofs_works() {
    new_test_ext().execute_with(|| {
        let json_data_1 = vec![1, 2, 3, 4, 5];
        let json_data_2 = vec![6, 7, 8, 9, 10];

        // Store the first proof
        assert_ok!(ZkProofModule::store_zk_proof(Origin::signed(1), json_data_1.clone()));
        // Store the second proof
        assert_ok!(ZkProofModule::store_zk_proof(Origin::signed(1), json_data_2.clone()));

        // Retrieve all proofs
        let result = ZkProofModule::retrieve_all_zk_proofs(Origin::signed(1));
        assert_ok!(result);

        let proof_hash_1 = <Test as frame_system::Config>::Hashing::hash(&json_data_1);
        let proof_hash_2 = <Test as frame_system::Config>::Hashing::hash(&json_data_2);

        let expected_event_1 = Event::ZkProofModule(crate::Event::ZkProofRetrieved(proof_hash_1, json_data_1));
        let expected_event_2 = Event::ZkProofModule(crate::Event::ZkProofRetrieved(proof_hash_2, json_data_2));

        frame_system::Pallet::<Test>::assert_has_event(expected_event_1.into());
        frame_system::Pallet::<Test>::assert_last_event(expected_event_2.into());
    });
}
