# Mesh registration vouch vector

`oracle.py` uses independent CBOR construction, hashlib and OpenSSL Ed25519 signing;
it does not import the control implementation. Run it from the repository root:

```sh
python3 crates/control/tests/fixtures/mesh-vouch-v1/oracle.py
```

Compare its output byte-for-byte with `vectors.json`. Seeds 11, 12 and 14 are
synthetic fixture material. The vector binds a live registration to a current
member with incarnation 3 and a retained eviction watermark of 2, at seq 9.
The issuer is the current administrator. Both signed envelopes, the inner vouch
signature, UDP/WSS framing, canonical state and digest are fixed independently.
NS consumers must use the same vector; successful verification does not change
membership or establish that a disaster-recovery snapshot is trustworthy.
