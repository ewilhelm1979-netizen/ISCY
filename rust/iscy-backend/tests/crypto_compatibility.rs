//! Fixed compatibility outputs, not application credentials.
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

fn from_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn new_mac(key: &[u8]) -> Hmac<Sha256> {
    // The same test source can also exercise the legacy dependency stack.
    <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(key).unwrap()
}

#[test]
fn sha256_known_answers_and_chunk_boundaries() {
    for (message, expected) in [
        (
            Vec::new(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            b"abc".to_vec(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq".to_vec(),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
        (
            vec![b'a'; 1_000_000],
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        ),
    ] {
        let expected = from_hex(expected);
        assert_eq!(&Sha256::digest(&message)[..], expected);
        for size in [1, 7, 55, 56, 63, 64, 65] {
            let mut digest = Sha256::new();
            for chunk in message.chunks(size) {
                digest.update(chunk);
            }
            assert_eq!(&digest.finalize()[..], expected);
        }
    }
}

#[test]
fn hmac_sha256_matches_rfc4231_full_length_vectors() {
    // https://www.rfc-editor.org/rfc/rfc4231.html sections 4.2-4.5, 4.7-4.8.
    for (key, message, expected) in [
        (vec![0x0b; 20], b"Hi There".to_vec(),
         "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"),
        (b"Jefe".to_vec(), b"what do ya want for nothing?".to_vec(),
         "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        (vec![0xaa; 20], vec![0xdd; 50],
         "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
        ((1_u8..=25).collect(), vec![0xcd; 50],
         "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b"),
        (vec![0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First".to_vec(),
         "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"),
        (vec![0xaa; 131], b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.".to_vec(),
         "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"),
    ] {
        let expected = from_hex(expected);
        let mut mac = new_mac(&key);
        mac.update(&message);
        assert_eq!(&mac.clone().finalize().into_bytes()[..], expected);
        assert!(mac.verify_slice(&expected).is_ok());
        let mut streamed = new_mac(&key);
        for chunk in message.chunks(7) {
            streamed.update(chunk);
        }
        assert_eq!(&streamed.finalize().into_bytes()[..], expected);
    }
}

#[test]
fn hmac_verification_rejects_mutations_wrong_keys_and_tag_lengths() {
    let expected = from_hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    let mut mac = new_mac(&[0x0b; 20]);
    mac.update(b"Hi There");
    assert!(mac.clone().verify_slice(&expected).is_ok());
    for index in 0..expected.len() {
        let mut changed = expected.clone();
        changed[index] ^= 1;
        assert!(mac.clone().verify_slice(&changed).is_err());
    }
    for length in [0, 1, 15, 16, 31, 33, 64] {
        let mut invalid = expected.clone();
        invalid.resize(length, 0);
        assert!(mac.clone().verify_slice(&invalid).is_err());
    }
    let mut wrong_key = new_mac(&[0x0c; 20]);
    wrong_key.update(b"Hi There");
    assert!(wrong_key.verify_slice(&expected).is_err());
    let mut wrong_message = new_mac(&[0x0b; 20]);
    wrong_message.update(b"Hi There!");
    assert!(wrong_message.verify_slice(&expected).is_err());

    // RFC 4231 case 5 is truncated; ISCY must still require a full tag.
    let mut truncated_case = new_mac(&[0x0c; 20]);
    truncated_case.update(b"Test With Truncation");
    let truncated = from_hex("a3b6167473100ee06e0c796c2955552b");
    assert_eq!(
        &truncated_case.clone().finalize().into_bytes()[..16],
        truncated
    );
    assert!(truncated_case.verify_slice(&truncated).is_err());
}
