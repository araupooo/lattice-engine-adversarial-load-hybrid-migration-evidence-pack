# Citations

Primary sources only. Every spec claim in this pack traces to one of
these; measured claims trace to the logs listed in `evidence-index.md`.

## TLS 1.3

- **RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3**
  (Rescorla, Aug 2018). https://datatracker.ietf.org/doc/html/rfc8446
  - §2 (protocol overview, 1-RTT full handshake).
  - §4.1.2 (ClientHello: `legacy_version`, `random`, `cipher_suites`,
    `extensions`).
  - §4.2.7 (supported_versions extension), §4.2.8 (key_share extension).
  - §4.2.10 (signature_algorithms extension).
  - §6 (alert protocol: 40 `handshake_failure`, 70 `protocol_version`,
    71 `insufficient_security`; fatal alerts close the connection).

## Post-quantum key exchange in TLS

- **draft-ietf-tls-mlkem — ML-KEM in TLS 1.3** (TLS Working Group
  draft, draft-ietf-tls-mlkem-07 at time of writing).
  https://datatracker.ietf.org/doc/draft-ietf-tls-mlkem/
  - Defines the ML-KEM-768 key exchange and the hybrid
    X25519MLKEM768 group (code point 0x11ec): the key_share entry is
    the 32-byte X25519 public key concatenated with the 1184-byte
    ML-KEM-768 encapsulation key (1216 bytes total) — confirmed by the
    measured trace in this pack (ClientHello key_share 1216 bytes,
    group 0x11ec; see `evidence-index.md` C8).

## ML-KEM

- **FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism
  Standard** (NIST, Aug 2024).
  https://csrc.nist.gov/pubs/fips/203/final
  - §8, Table 3: ML-KEM-768 parameter set — encapsulation key 1184
    bytes, decapsulation key 2400 bytes, ciphertext 1088 bytes,
    shared secret 32 bytes, NIST security category 3. Verified
    against the liboqs implementation in `outputs/bench-kem-run*.log`
    (see `evidence-index.md` C1).
  - §7.3 (implicit rejection): decapsulation of an invalid ciphertext
    returns a pseudorandom shared secret rather than failing — the
    basis of the separate implicit-rejection assessment; not re-tested
    here.

## Implementations

- **OpenSSL 3.0.13** — https://www.openssl.org/ — the TLS stack used
  for the test deployment (`openssl s_server` / `s_client`). Provider
  model and `openssl.cnf` configuration as documented at
  https://www.openssl.org/docs/man3.0/man7/provider.html.
- **liboqs 0.16.0** — https://github.com/open-quantum-safe/liboqs —
  the library implementing ML-KEM-768. Version string printed in
  `outputs/bench-kem-run*.log` (`liboqs version: 0.16.0`).
- **oqs-provider 0.12.0** — https://github.com/open-quantum-safe/oqs-provider —
  the OpenSSL 3 provider exposing the hybrid groups to `s_server` /
  `s_client`. Version string visible in `openssl list -providers`
  (`oqsprovider 0.12.0`).

## Notes on sources

- RFC 8446 and FIPS 203 were fetched and read during research for this
  pack; the draft-ietf-tls-mlkem group code point (0x11ec) was
  confirmed independently by the measured ClientHello trace, not taken
  on trust from the draft alone.
- No secondary sources (blogs, vendor pages, summaries) are cited for
  any claim in this pack.
