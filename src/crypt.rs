use aes_gcm_siv::aead::generic_array::GenericArray;
use aes_gcm_siv::aead::rand_core::RngCore;
/// Provides for default en/decryption utilities.
/// Uses AES-GCM-SIV with 256 bit keys, and 96 bit nonce.
/// Current implementation assumes no AAD usage.
use aes_gcm_siv::{
    aead::{Aead, KeyInit, OsRng, Payload},
    Aes256GcmSiv, Nonce,
};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;

pub struct Envelope {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    /// Generate a new instance, random, for the type.
    pub fn new(key: [u8; 32], clear: Vec<u8>) -> Result<Self, aes_gcm_siv::Error> {
        let mut nonce = [0u8; 12]; // 96-bits; unique per message
        OsRng.fill_bytes(&mut nonce);
        let payload = Payload {
            msg: clear.as_ref(),
            aad: b"".as_ref(),
        };
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key));
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), payload)?;
        Ok(Self { nonce, ciphertext })
    }

    /// Use the key to return the clear field.
    pub fn decrypt(&self, key: [u8; 32]) -> Result<Vec<u8>, aes_gcm_siv::Error> {
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key));
        let nonce = Nonce::from_slice(&self.nonce);
        let payload = Payload {
            msg: self.ciphertext.as_ref(),
            aad: b"".as_ref(),
        };
        cipher.decrypt(nonce, payload)
    }

    pub fn serialize(&self) -> String {
        let nonce = BASE64_STANDARD.encode(self.nonce);
        let ciphertext = BASE64_STANDARD.encode(&self.ciphertext);
        format!("{}:{}", nonce, ciphertext)
    }

    pub fn deserialize(s: &str) -> Result<Self, ()> {
        let parts: Vec<&str> = s.split(':').collect();
        let result = BASE64_STANDARD.decode(parts[0]).expect("nonce: bad decode");
        let nonce: [u8; 12] = *slice_as_array!(result.as_slice(), [u8; 12])
            .expect("nonce: bad hash length");
        let ciphertext = BASE64_STANDARD
            .decode(parts[1])
            .expect("ciphertext: bad decode");
        Ok(Self { nonce, ciphertext })
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn envelope_serialize_test() {
        let mut key = [0u8; 32];
        let clear: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7];
        OsRng.fill_bytes(&mut key);
        let envelope = Envelope::new(key, clear.clone()).unwrap();
        let s = envelope.serialize();
        let envelope2 = Envelope::deserialize(&s).unwrap();
        assert_eq!(envelope2.nonce, envelope.nonce);
        assert_eq!(envelope2.ciphertext, envelope.ciphertext);
    }

    /// Test our Envelope implementation.
    #[test]
    fn envelope_test() {
        let mut key = [0u8; 32];
        let clear: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7];
        OsRng.fill_bytes(&mut key);
        let envelope = Envelope::new(key, clear.clone()).unwrap();
        assert_ne!(envelope.ciphertext, clear);

        let clear2 = envelope.decrypt(key).unwrap();
        assert_eq!(clear2, clear);
    }

    /// Test the AES/GCM/SIV implementation.
    #[test]
    fn it_works() {
        let key = Aes256GcmSiv::generate_key(&mut OsRng);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Nonce::from_slice(b"unique nonce"); // 96-bits; unique per message
        let ciphertext = cipher
            .encrypt(nonce, b"cleartext message".as_ref())
            .expect("encryption failure!");
        let cleartext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .expect("decryption failure!");
        assert_eq!(&cleartext, b"cleartext message");
    }
}
