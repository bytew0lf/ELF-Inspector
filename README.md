# ELF-Inspector

ELF parser and reporter for ELF32 and ELF64 binaries (.so, executables, etc.).

## Features

* ELF32 and ELF64 (little/big endian)
* Data-source parsing: InMemory, Stream, MemoryMapped (mmap)
* Large-file core with `ulong` offset addressing (>2GB offsets without a global `int` buffer)
* Sections and program headers
* Symbol tables including versioning
* Relocations (REL/RELA/RELR)
* Dynamic section plus imports/exports
* GNU/SYSV hash tables
* Notes
* Security/loader features in the report (PIE, RELRO, NX, BIND_NOW, canary/FORTIFY hints)

<!-- COVERAGE_MAP_START -->
## Current Coverage Map (auto-generated)

Status legend:
* `full`: Implemented and covered by unit/matrix tests
* `partial`: Implemented, but only partially covered by tests
* `open`: Not implemented yet

### Parser/Report Coverage

| Area | Status | Current coverage |
|---|---|---|
| ELF Header | full | ELF32/ELF64, endianness, type, machine, entry point |
| Section Headers | full | Standard + extended numbering, section name resolution |
| Section special cases | full | `SHF_COMPRESSED` (ZLIB + ZSTD), GNU `.zdebug*` (ZLIB + ZSTD), `SHT_GROUP`/COMDAT |
| Program Headers | full | PT_LOAD/PT_DYNAMIC/PT_INTERP/PT_NOTE including interpreter resolution |
| Dynamic | full | DT_NEEDED, SONAME, RPATH/RUNPATH, FLAGS/FLAGS_1, REL/RELA/RELR tags, GNU version tags |
| Symbol Tables | full | `.symtab`/`.dynsym`, fallback without section header table, import/export classification |
| Symbol versioning | full | `DT_VERSYM`, `DT_VERNEED`, `DT_VERDEF` including library/version mapping |
| Relocations | full | REL/RELA/RELR from sections and dynamic tags, symbol/section mapping in report |
| Relocation type names per architecture | full | i386, x86_64, ARM, AArch64, MIPS, PPC/PPC64, S390x, SPARC, RISC-V with extended type-name maps |
| Hash Tables | full | `DT_HASH` and `DT_GNU_HASH` (buckets/chains/bloom), configurable lookup-path evaluation |
| Notes | full | `SHT_NOTE`/`PT_NOTE`, GNU/FDO/Go/FreeBSD/NetBSD/OpenBSD/Android/Linux named plus basic decoding |
| Unwind | full | `.eh_frame`/`.eh_frame_hdr`, CIE/FDE parsing, CFA rules, basic stack walk for core cases |
| DWARF/Debug | full | Index + partial semantics for `.debug_info/.abbrev/.line/.str/.ranges/.addr/.str_offsets/.rnglists/.loclists` including robust partial decoding |
| ET_CORE | full | `PT_NOTE`-based process/thread/register/signal evaluation plus thread-unwind branch in report |
| Security/Loader features | full | PIE, RELRO (partial/full), NX (GNU_STACK), BIND_NOW, canary/FORTIFY hints |
| Text report | full | Deterministic output, structured sections including hash/security |
<!-- COVERAGE_MAP_END -->

Update coverage map:

```bash
scripts/generate_coverage_map.sh --write-readme
```

### Architecture sample coverage (`samples/`)

| Architecture | Samples |
|---|---|
| x86_64 | `hello_x86_64` |
| i386 | `hello_i686` |
| ARM64 | `hello_arm64`, `nano` |
| ARM32 | `hello_armhf` |
| MIPS family | `hello_mips`, `hello_mipsel`, `hello_mips64`, `hello_mips64el`, `hello_mipsisa32r6el`, `hello_mipsisa32r6`, `hello_mipsisa64r6`, `hello_mipsisa64r6el` |
| PowerPC | `hello_ppc`, `hello_ppc64le` |
| S390x | `hello_s390x` |
| SPARC64 | `hello_sparc64` |
| RISC-V | `hello_riscv64` |
| Additional real-world binaries | `busybox`, `nano` |

### Test coverage

| Level | Status | Execution |
|---|---|---|
| Unit tests (xUnit) | full | `scripts/run_unit_tests.sh` |
| Negative parser tests | full | in unit tests + `scripts/run_p3_test_matrix.sh` |
| Golden report regression | full | `scripts/verify_golden_reports.sh` |
| Feature matrix (RELR/flags/mapping) | full | `scripts/run_p4_test_matrix.sh` |
| Local CI gate | full | `scripts/run_ci_gate.sh` |

### Intentionally out of current scope

* No disassembly/instruction analysis
* No complete coverage of all architecture-specific relocation subtypes
* No symbolic runtime binding like a real dynamic loader
* No full DWARF semantic evaluation (all DIE types/attributes, full query engine)
* No complete cross-architecture unwind simulation for arbitrary CFI instruction sets

## Build samples with Docker

The `build-samples_with_docker.sh` script builds architecture samples in `samples/` and additionally extracts `nano` (Debian) and `busybox` (Alpine).

Default call:

```bash
./build-samples_with_docker.sh
```

Optional environment variables:

* `SAMPLES_DIR`: target directory for generated samples (default: `<repo>/samples`)
* `DEBIAN_IMAGE`: Debian image for cross compilers + `nano` (default: `debian:trixie`)
* `ALPINE_IMAGE`: Alpine image for `busybox` (default: `alpine:latest`)

Example with overridden images:

```bash
SAMPLES_DIR="$PWD/samples" \
DEBIAN_IMAGE="debian:latest" \
ALPINE_IMAGE="alpine:latest" \
./build-samples_with_docker.sh
```

## Usage

If `samples/nano` or other sample binaries are missing, run `./build-samples_with_docker.sh` first (see section `Build samples with Docker`).

```bash
dotnet run --project ELF-Inspector.csproj -- \
  --file samples/nano \
  --output report.txt \
  --output-path samples
```

Optional for reproducible output:

```bash
dotnet run --project ELF-Inspector.csproj -- \
  --file samples/nano \
  --output report.txt \
  --output-path samples \
  --deterministic
```

Optional for permissive header validation (legacy/non-conforming ELF headers):

```bash
dotnet run --project ELF-Inspector.csproj -- \
  --file samples/nano \
  --output report.txt \
  --output-path samples \
  --compat-header-validation
```

## Golden Reports (P0)

Generate baseline reports:

```bash
scripts/generate_golden_reports.sh
```

The script auto-discovers ELF binaries in `samples/` and writes `report-<sample>.txt` files to `samples/golden/`.

Verify generated output against the baseline:

```bash
scripts/verify_golden_reports.sh
```

## P3 Test Matrix

Run positive/negative parser hardening checks:

```bash
scripts/run_p3_test_matrix.sh
```

## P4 Test Matrix

Run advanced feature checks (RELR, relocation mapping, dynamic flag decoding):

```bash
scripts/run_p4_test_matrix.sh
```

## P0 Conformance Matrix

Run strict/compat header conformance and deterministic mutation smoke checks:

```bash
scripts/run_p0_conformance_matrix.sh
```

## Unit Tests

Run parser unit tests (positive sample sweep + negative sample-based mutations):

```bash
scripts/run_unit_tests.sh
```

## CI Gate

Run the full quality gate locally (unit tests + P3 + P4):

```bash
scripts/run_ci_gate.sh
```
