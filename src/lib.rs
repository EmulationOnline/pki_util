// Utilities for working with signatures from the
// chiplab.
pub mod trace;


pub fn sign(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    use p256::ecdsa::{SigningKey, VerifyingKey, signature::{Signer, Verifier}, Signature};
    let signer = match SigningKey::from_slice(key) {
        Err(e) => {
            return Err(format!("Bad signing key: {e:?}"));
        },
        Ok(v) => v,
    };
    let sig : Signature = signer.sign(data);
    Ok(sig.to_bytes().as_slice().to_vec())
}

pub fn new_privkey() -> Result<Vec<u8>, String> {
    use p256::ecdsa::{SigningKey, VerifyingKey, signature::{Signer, Verifier}, Signature};
    let mut rng = rand::thread_rng();
    let signer = SigningKey::random(&mut rng);
    Ok(signer.to_bytes().as_slice().to_vec())
}


pub fn to_pubkey(key: &[u8]) -> Result<Vec<u8>, String> {
    use p256::ecdsa::{SigningKey, VerifyingKey, signature::{Signer, Verifier}, Signature};
    let signer = match SigningKey::from_slice(key) {
        Err(e) => {
            return Err(format!("Bad signing key: {e:?}"));
        },
        Ok(v) => v,
    };
    let verifier = signer.verifying_key();
    Ok(verifier.to_sec1_bytes().to_vec())
}


pub fn verify(data: &[u8], sig: &[u8], pubkey: &[u8])
    -> Result<(), String> {
    use p256::ecdsa::{SigningKey, VerifyingKey, signature::{Signer, Verifier}, Signature};
    let key = match p256::PublicKey::from_sec1_bytes(pubkey) {
        Err(e) => {
            return Err(format!("bad pubkey bytes: {e}"));
        },
        Ok(v) => v,
    };
    let sig = match Signature::from_slice(sig) {
        Err(e) => {
            return Err(format!("bad signature: {e}"));
        },
        Ok(v) => v,
    };
    let checker = VerifyingKey::from(key);
    match checker.verify(data, &sig) {
        Ok(v) => Ok(()),
        Err(e) => {
            Err(format!("Verification failed: {e}"))
        }
    }
}

pub fn sha256_b64(input: &[u8]) -> String {
    use sha2::{Sha256, Digest};
    let mut hash = Sha256::new();
    hash.update(input);
    let checksum = hash.finalize();
    base64::encode(checksum)
}

#[cfg(test)]
mod test {
    use super::*;
    use p256::ecdsa::{SigningKey, VerifyingKey, signature::{Signer, Verifier}, Signature};


    #[test]
    fn test_roundtrip() {
        // let mut rng = rand::thread_rng();
        // let signer = SigningKey::random(&mut rng);
        // signer.to_bytes().as_slice()
        let key : Vec<u8> = vec![
            216, 236, 135, 35, 44, 192, 17, 167, 131, 252, 241, 10, 115, 239, 254, 68, 44, 90, 147,
            15, 173, 109, 215, 224, 128, 144, 204, 34, 252, 80, 116, 168
        ];
        let signer = SigningKey::from_slice(&key).unwrap();
        let data = "Hello world!";
        let data = data.as_bytes();
        let sig : Signature = signer.sign(data);

        let checker = signer.verifying_key();
        assert!(checker.verify(data, &sig).is_ok());

        let bad_data = "Goodbye world!";
        assert!(
            checker.verify(bad_data.as_bytes(), &sig).is_err());

    }
    #[test]
    fn test_bytes_api() {
        let key : Vec<u8> = vec![
            216, 236, 135, 35, 44, 192, 17, 167, 131, 252, 241, 10, 115, 239, 254, 68, 44, 90, 147,
            15, 173, 109, 215, 224, 128, 144, 204, 34, 252, 80, 116, 168
        ];
        let data = b"hello world";
        let signature = sign(data, &key).unwrap();
        let pubkey = to_pubkey(&key).unwrap();

        assert!(
            verify(&data[..], &signature, &pubkey).is_ok());
        let bad_data = b"goodbye";
        assert!(
            verify(bad_data, &signature, &pubkey).is_err());
    }

    #[test]
    fn test_checksums() {
        let a = sha256_b64("hello".as_bytes());
        let b = sha256_b64("world".as_bytes());
        assert!(a != b);

        // 256 bit checksum
        // base64 emits a character per 6 bits
        // 256/6 = 42.66, output padded to multiple of 4 -> 44
        assert_eq!(44, a.len());
        assert_eq!(44, b.len());
    }
}
