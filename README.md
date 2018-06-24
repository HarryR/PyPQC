# PyPQC - Python Post-Quantum Cryptography Wrappers

This project provides Python and command-line wrappers for the NIST Post-Quantum Cryptography submissions, see: https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Round-1-Submissions 

It serves to make the Round 1 submissions more accessible to developers, and should allow you to experiment and prototype with them very quickly in Python or other languages, without having to write C code, create shared objects or DLLs or lock yourself into one specific algorithm (e.g. when Round 2 happens).


## Build

[![Build Status](https://travis-ci.org/HarryR/PyPQC.svg?branch=master)](https://travis-ci.org/HarryR/PyPQC)

Required packages:

  * `openssl-devel` or `libssl-dev` to get `libcrypto.so`

Then build with:

```
make
```

## Example

The two classes, `PQCKEM` and `PQCSign`, provide an interface to the `pqc_cli` executable. You must provide it with the full path of the executable as the constructor argument. Each submission is modified slightly to build its own `pqc_cli` executable.

If the algorithm supports both Key Exchange and Signing, it's not guaranteed that key pairs generated for one are compatible with the other.


### Key Exchange

Creates a shared secret for the owner of a designated key pair. Only the holder of the secret component of the key pair can decode the shared secret from the cipher text.

The shared secret is randomly generated, the `encaps` method returns the cipher text and the shared secret. Pass the cipher text to the key pair owner. They can then decrypt the cipher text by providing their secret key, resulting in the same shared secret.

```
x = PQCKEM(kem_path)
pk, sk = x.keypair()
ct, ss = x.encaps(pk)
check_ss = x.decaps(ct, sk)
assert ss == check_ss
```

### Message Signing

Allows the owner of a key pair to create a signed message which can only be opened if the decrypter knows the public key. An alternative interpretation is that with knowledge of a public key the authenticity of a signed message can be verified as having been created by the holder of the secret key.

```
x = PQCSign(sign_path)
pk, sk = x.keypair()
msg = os.urandom(128)
smsg = x.sign(sk, msg)
cmsg = x.open(pk, smsg)
assert msg == cmsg
```

## Supporting Additional Algorithms

The `pqc_cli_api.c` file provides a consistent interface to the native code, this is the entry point for the `pqc_cli` executable and links against the source code for the algorithm.

To add support for an additional algorithm, follow these steps:

 1. Download and extract the submission into the same directory as this projects source code
 2. Symlink `pqc_cli_api.c` into the source directory
 3. Modify the Makefile to build `pqc_cli_api.c` as `pqc_cli`
 4. Define `-DBUILD_KEM` or `-DBUILD_SIGN` or both, when compiling `pqc_cli_api.c` to turn-on the CLI API for those features.
 5. Add the path of the resulting `pqc_cli` file to `pqcalgos.py`


## Notes

 * https://cryptojedi.org/peter/data/nancy-20180219.pdf (Peter Schwabe)
 * https://csrc.nist.gov/CSRC/media/Presentations/PostQuantum-RSA/images-media/PostQuantumRSA-April2018.pdf


## Talking Points

From a [recent slashdot article](https://it.slashdot.org/story/18/05/19/200225/ibm-warns-quantum-computing-will-break-encryption) 

> "What I wonder is, if encryption can be 'instantly broken,' does this also mean that remaining crypto-coins can be instantly discovered?"

The following whitepaper attempts to answer some of these questions: https://github.com/theQRL/Whitepaper/blob/master/QRL_whitepaper.pdf
