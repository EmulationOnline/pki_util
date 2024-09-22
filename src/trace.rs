// The lab takes either a binary, or source, and
// runs it on the chip.
// Output is of the form
// ===BEGIN SIGNED===
// version:[versionline]
// input_sha256:[sha256 base64]
// [trace lines]
// ===END SIGNED===
// Signature=[signature base64]

// Validates that a given trace has been
// signed by the chiplab.
// The chiplab uses a ECDSA p256 using its private
// key to sign all outputs, to make it easy
// for model repositories to assert that traces
// came from the lab hardware.
const PREFIX : &str = 
    "===BEGIN SIGNED DATA===\n";
const SUFFIX : &str = 
    "===END SIGNED DATA===\n";
// The signature line is expected to follow the 
// signed data, and will be base64 encoded.
const SIGNATURE_PREFIX : &str =
    "Signature=";


// TraceChecker is used by tests, to ensure that all traces
// in the repo are verifiably from the chiplab server.
pub struct TraceChecker {
    pubkey: Vec<u8>,
}

impl TraceChecker {
    pub fn new(pubkey: &[u8]) -> TraceChecker {
        TraceChecker {
            pubkey: pubkey.to_vec(),
        }
    }


    pub fn verify_trace(&self, trace: &str) ->
        Result<(), String> {
        // The body that was signed is between PREFIX and SUFFIX.
        // The signature is the first Signature= line after the suffix.
        let prefix_start =
            trace.find(PREFIX).ok_or(format!("Missing prefix."))?;
        let trace = &trace[prefix_start + PREFIX.len() ..];

        let suffix_start =
            trace.find(SUFFIX).ok_or(format!("Missing suffix."))?;
        let message = &trace[.. suffix_start];
        let after = &trace[suffix_start + SUFFIX.len() .. ];

        // Find the signature, between SIGNATURE_PREFIX and \n
        let sig_start =
            after.find(SIGNATURE_PREFIX).ok_or(format!("Missing signature."))?;
        let after = &after[sig_start + SIGNATURE_PREFIX.len() ..];
        let sig_end = after.find("\n").ok_or("No newline after signature.")?;
        let sig = &after[ .. sig_end];

        // base64 decode
        let sig = base64::decode(sig.as_bytes())
            .or(Err("Invalid base64".to_string()))?;

        // Finally verify
        crate::verify(message.as_bytes(), &sig, &self.pubkey)
    }
}

// TraceSigner is used by the chiplab, to produce signed trace
// output that can be used in by the model repositories.
#[derive(Clone)]
pub struct TraceSigner {
    privkey: Vec<u8>,
}

impl TraceSigner {
    pub fn from(privkey: &[u8]) -> Result<TraceSigner, String> {
        // sign a dummy message to ensure the key is working
        crate::sign(b"test message", privkey)?;
        Ok(TraceSigner {
            privkey: privkey.to_vec(),
        })
    }

    // Produce packaged, signed data for the given input message.
    pub fn signed(&self, message: &str) -> Result<String, String> {
        let sig = crate::sign(message.as_bytes(), &self.privkey)?;
        let sig = base64::display::Base64Display::new(&sig, 
            &base64::engine::general_purpose::STANDARD);
        Ok(format!("{PREFIX}{message}{SUFFIX}Signature={sig}\n"))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    struct TestKeys {
        pubkey: Vec<u8>,
        privkey: Vec<u8>,
    }
    fn test_keys() -> TestKeys {
        let privkey = crate::new_privkey().unwrap();
        TestKeys {
            pubkey: crate::to_pubkey(&privkey).unwrap(),
            privkey, 
        }
    }

    const TEST_MESSAGE : &str = r#"6502_v1
a=0xFFFC sync=0
a=0xFFFD sync=0
a=0xDEAD sync=1
a=0xDEAE sync=0
a=0xFFFD sync=0"#;

    #[test]
    fn test_sign() {
        let keys = test_keys();
        let signer = TraceSigner::from(&keys.privkey).unwrap();
        let signed = signer.signed(TEST_MESSAGE).unwrap();

        // input should be present
        assert!(signed.find(TEST_MESSAGE).is_some());
        // should have a signature line
        assert!(signed.find("Signature=").is_some());
    }

    #[test]
    fn test_verify() {
        let keys = test_keys();
        let signer = TraceSigner::from(&keys.privkey).unwrap();
        let mut signed = signer.signed(TEST_MESSAGE).unwrap().to_string();
        let checker = TraceChecker::new(&keys.pubkey);

        // Message should verify
        assert_eq!(Ok(()), checker.verify_trace(&signed));
        // Message should fail after mangling the signature
        let sig_pos = signed.find(SIGNATURE_PREFIX).unwrap() + SIGNATURE_PREFIX.len();
        signed.replace_range(sig_pos .. sig_pos+3, "A");
        assert!(checker.verify_trace(&signed).is_err());

    }
}

