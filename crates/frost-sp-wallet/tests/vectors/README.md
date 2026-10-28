# Test vectors

`bip-0352/send_and_receive_test_vectors.json` fetched from bitcoin/bips `master` on 2026-10-28.
Last commit touching the file: `3c68d3f3a19b9ed3ee1e9129147541a15f1603cb`.

BIP 374 / BIP 375 vectors are not used by W1 (DLEQ and sending are W2).

`bip-0374/test_vectors_{generate,verify}_proof.csv` fetched from bitcoin/bips `master` on 2026-10-28.
Last commit touching `bip-0374`: `afaa856630058b87188648111da5dab0dd311bf7`.
Vectors with a non-standard generator are skipped (rust-dleq supports only G). BIP 375 vectors are not used (no PSBT in W2).
