# darkroom-verify

`darkroom-verify` checks the integrity of a Darkroom export package without Darkroom
or network access.

## Build

Install the current stable Rust toolchain, then build from the repository root:

```sh
cargo build --release --locked
```

The executable is written to `target/release/darkroom-verify`.

## Use

Pass the directory that contains `manifest.json`:

```sh
./target/release/darkroom-verify /path/to/export-package
```

The verifier prints the SHA-256 and BLAKE3 hashes of the exact manifest bytes, followed
by one result for each record content, Seal, and original-file check.

Exit status:

- `0` - every check verified.
- `1` - verification completed, but one or more checks failed.
- `2` - the arguments or package structure could not be accepted.

## Checks

The verifier:

- accepts manifest schema version `1` and rejects unknown record types;
- validates UUIDs, table content, source bindings, and source declarations;
- recomputes canonical record-content hashes;
- rebuilds each record Seal preimage and compares both stored digests;
- compares both digests for each original declared by a record source; and
- rejects unexpected, duplicate, non-file, and symbolic-link entries in `originals/`.

The reported manifest hashes can be compared with an external integrity document or
package identifier. The verifier does not provide that external trust anchor.

## What verification means

A successful run confirms that the package contents match the hashes and Seals declared
inside that package. It does not establish authorship, source truth, or a trustworthy
export time.

## macOS artifacts

The macOS workflow builds separate executables for Apple Silicon and Intel, targeting
macOS 12 or later. Each workflow artifact contains a compressed executable and its
SHA-256 file:

- `darkroom-verify-aarch64-apple-darwin`
- `darkroom-verify-x86_64-apple-darwin`

Extract the archive for your Mac, then run the executable:

```sh
tar -xzf darkroom-verify-aarch64-apple-darwin.tar.gz
./darkroom-verify /path/to/export-package
```

Rust and third-party dependencies are linked into each executable. macOS system
libraries remain dynamically linked as required by the platform.

## Windows artifacts

The Windows workflow builds an x64 executable with the MSVC toolchain. The
`darkroom-verify-x86_64-pc-windows-msvc` artifact contains a ZIP archive and its
SHA-256 file.

Extract the archive, then run the executable in PowerShell:

```powershell
Expand-Archive darkroom-verify-x86_64-pc-windows-msvc.zip -DestinationPath darkroom-verify
.\darkroom-verify\darkroom-verify.exe C:\path\to\export-package
```

## Development

```sh
cargo test --locked
cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
```
