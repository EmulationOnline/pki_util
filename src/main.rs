use pki_util as crt;
use std::io::Write;

fn main() {
    let argv :Vec<String> = std::env::args().collect();
    if argv.len() != 2 {
        println!(
r#"Usage: {} out_prefix
Generates ecdsa public and private keypairs as raw bytes.
Writes to out_prefix.bin.pub and out_prefix.bin.priv"#,
        argv[0]);
        std::process::exit(1);
    }

    let prefix = &argv[1];
    let private_path = format!("{prefix}.bin.priv");
    let public_path = format!("{prefix}.bin.pub");
    println!("Using:\npriv={private_path}\npub={public_path}");

    let mut private = std::fs::File::create(
        private_path).expect("Cannot create file for privkey");
    let mut public = std::fs::File::create(
        public_path).expect("Cannot create file for pubkey");

    let privkey = crt::new_privkey()
        .expect("failed to generate private key");


    private.write_all(&privkey);
    let pubkey = crt::to_pubkey(&privkey)
        .expect("failed to derive pubkey from privkey.");
    public.write_all(&pubkey);
    println!("Done writing.");
}

