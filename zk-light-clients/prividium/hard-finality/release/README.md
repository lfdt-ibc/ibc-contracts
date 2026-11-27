# Release artifacts

The release process and evidence requirements are documented in
[`../docs/RELEASE.md`](../docs/RELEASE.md). This directory is reserved for
reviewed manifests. Generated ELFs and proofs belong under ignored build or
artifact storage.

Release artifacts are profile-specific. Never reuse an ELF, VKey, proof, or
manifest after changing the SourceProfile or guest source.

Install Docker before building. The guest build uses the immutable official
SP1 v6.7.0 linux/amd64 image pinned in `scripts/sp1-container.env`:

```bash
PRIVIDIUM_SOURCE_PROFILE=profiles/example.synthetic.json scripts/build-sp1.sh
```

SP1 SDK v6.7.0 embeds circuit version v6.1.0. Its Groth16 proofs therefore use
the v6.1.0 verifier hash and `0x4388a21c` gateway selector. Treat the SDK
version, circuit version, verifier hash, ELF hash, and program VKey as separate
release metadata fields.

From a clean committed tree, verify two independent guest builds:

```bash
scripts/reproducible-guests.sh profiles/example.synthetic.json
```

Generate the four ELF hashes and VKeys together:

```bash
mkdir -p target/deployment-artifacts
scripts/generate-vkeys.sh \
  profiles/example.synthetic.json \
  target/deployment-artifacts/program-vkeys.synthetic.json
```

Generate and immediately revalidate the corresponding development manifest:

```bash
scripts/release-workflow.sh all \
  profiles/example.synthetic.json \
  target/deployment-artifacts/program-vkeys.synthetic.json \
  target/deployment-artifacts/manifest.synthetic.json
```

The synthetic output is development evidence only. A production
`expected-vkeys.json` and release manifest must not be created until the
production SourceProfile and the remaining SPEC Section 24 inputs are frozen
and independently reviewed.
