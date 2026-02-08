
import os, binascii, sys, secrets
# This is a FILE-BASED stub keygen for CI in case Rust isn't compiled yet.
# WARNING: Not cryptographically sound; for CI demo only.
sk = os.urandom(32)
# Deriving pk here would need curve ops; leave to Rust keygen in build steps.
open("keys/ed25519.sk","wb").write(sk)
print("Wrote keys/ed25519.sk (pk will be derived by Rust keygen in build stage)")
