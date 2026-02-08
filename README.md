# ELF-Inspector

ELF Parser & Reporter für ELF32 & ELF64-Binaries (.so, Exec, etc.)

## Features

* ELF32 & ELF64 (Little/Big Endian)
* Data-Source Parsing: InMemory, Stream, MemoryMapped (mmap)
* Large-File-Kern mit `ulong`-Offset-Adressierung (>2GB Offsets ohne globalen `int`-Buffer)
* Sections & Program Headers
* Symbol Tables inkl. Versionierung
* Relocations (REL/RELA/RELR)
* Dynamic Section + Imports/Exports
* GNU/SYSV Hash Tables
* Notes
* Security-/Loader-Features im Report (PIE, RELRO, NX, BIND_NOW, Canary/FORTIFY-Hinweise)

<!-- COVERAGE_MAP_START -->
## Aktuelle Coverage-Map (auto-generiert)

Status-Legende:
* `voll`: Implementiert und durch Unit-/Matrix-Tests abgedeckt
* `teilweise`: Implementiert, aber nur teilweise testabgedeckt
* `offen`: Noch nicht implementiert

### Parser-/Report-Abdeckung

| Bereich | Status | Aktuelle Abdeckung |
|---|---|---|
| ELF Header | voll | ELF32/ELF64, Endianness, Typ, Machine, EntryPoint |
| Section Headers | voll | Normale + Extended Numbering, Section-Name-Auflösung |
| Section-Spezialfälle | voll | `SHF_COMPRESSED` (ZLIB + ZSTD), GNU `.zdebug*` (ZLIB + ZSTD), `SHT_GROUP`/COMDAT |
| Program Headers | voll | PT_LOAD/PT_DYNAMIC/PT_INTERP/PT_NOTE inkl. Interpreter-Auflösung |
| Dynamic | voll | DT_NEEDED, SONAME, RPATH/RUNPATH, FLAGS/FLAGS_1, REL/RELA/RELR Tags, GNU Version-Tags |
| Symbol Tables | voll | `.symtab`/`.dynsym`, Fallback ohne Section Header Table, Import/Export-Klassifikation |
| Symbol-Versionierung | voll | `DT_VERSYM`, `DT_VERNEED`, `DT_VERDEF` inkl. Library-/Versionszuordnung |
| Relocations | voll | REL/RELA/RELR aus Sections und Dynamic Tags, Symbol-/Section-Zuordnung im Report |
| Relocation Typnamen je Architektur | voll | i386, x86_64, ARM, AArch64, MIPS, PPC/PPC64, S390x, SPARC, RISC-V mit erweiterten Typnamens-Maps |
| Hash Tables | voll | `DT_HASH` und `DT_GNU_HASH` (Buckets/Chains/Bloom), konfigurierbare Lookup-Pfad-Auswertung |
| Notes | voll | `SHT_NOTE`/`PT_NOTE`, GNU/FDO/Go/FreeBSD/NetBSD/OpenBSD/Android/Linux benannt + Basis-Decoding |
| Unwind | voll | `.eh_frame`/`.eh_frame_hdr`, CIE/FDE-Parsing, CFA-Regeln, Basis-Stackwalk für Core-Fälle |
| DWARF/Debug | voll | Index + Teil-Semantik für `.debug_info/.abbrev/.line/.str/.ranges/.addr/.str_offsets/.rnglists/.loclists` inkl. robustem Partial-Decoding |
| ET_CORE | voll | `PT_NOTE`-basierte Process/Thread/Register/Signal-Auswertung + Thread-Unwind-Branch im Report |
| Security-/Loader-Features | voll | PIE, RELRO (partial/full), NX (GNU_STACK), BIND_NOW, Canary-/FORTIFY-Hinweise |
| Textreport | voll | Deterministische Ausgabe, strukturierte Sektionen inkl. Hash/Security |
<!-- COVERAGE_MAP_END -->

Coverage-Map aktualisieren:

```bash
scripts/generate_coverage_map.sh --write-readme
```

### Architektur-Sample-Abdeckung (`samples/`)

| Architektur | Samples |
|---|---|
| x86_64 | `hello_x86_64` |
| i386 | `hello_i686` |
| ARM64 | `hello_arm64`, `nano` |
| ARM32 | `hello_armhf` |
| MIPS-Familie | `hello_mips`, `hello_mipsel`, `hello_mips64`, `hello_mips64el`, `hello_mipsisa32r6el`, `hello_mipsisa32r6`, `hello_mipsisa64r6`, `hello_mipsisa64r6el` |
| PowerPC | `hello_ppc`, `hello_ppc64le` |
| S390x | `hello_s390x` |
| SPARC64 | `hello_sparc64` |
| RISC-V | `hello_riscv64` |
| Weitere reale Binaries | `busybox`, `nano` |

### Test-Coverage

| Ebene | Status | Ausführung |
|---|---|---|
| Unit Tests (xUnit) | voll | `scripts/run_unit_tests.sh` |
| Negative Parser-Tests | voll | in Unit Tests + `scripts/run_p3_test_matrix.sh` |
| Golden Report Regression | voll | `scripts/verify_golden_reports.sh` |
| Feature Matrix (RELR/Flags/Mapping) | voll | `scripts/run_p4_test_matrix.sh` |
| Lokales CI-Gate | voll | `scripts/run_ci_gate.sh` |

### Bewusst außerhalb des aktuellen Scopes

* Kein Disassembly/Instruktionsanalyse
* Keine vollständige Abdeckung aller architekturspezifischen Relocation-Untertypen
* Keine symbolische Laufzeitbindung wie ein echter Dynamic Loader
* Keine vollständige DWARF-vollsemantische Auswertung (alle DIE-Typen/Attribute, vollständige Query-Engine)
* Keine vollumfängliche architekturübergreifende Unwind-Simulation für beliebige CFI-Instruktionsmengen

## Samples mit Docker erzeugen

Das Skript `build-samples_with_docker.sh` erzeugt die Architektur-Samples in `samples/` und extrahiert zusätzlich `nano` (Debian) sowie `busybox` (Alpine).

Standardaufruf:

```bash
./build-samples_with_docker.sh
```

Optionale Umgebungsvariablen:

* `SAMPLES_DIR`: Zielverzeichnis für generierte Samples (Default: `<repo>/samples`)
* `DEBIAN_IMAGE`: Debian-Image für Cross-Compiler + `nano` (Default: `debian:trixie`)
* `ALPINE_IMAGE`: Alpine-Image für `busybox` (Default: `alpine:latest`)

Beispiel mit überschriebenen Images:

```bash
SAMPLES_DIR="$PWD/samples" \
DEBIAN_IMAGE="debian:latest" \
ALPINE_IMAGE="alpine:latest" \
./build-samples_with_docker.sh
```

## Usage

Falls `samples/nano` oder andere Sample-Binaries noch fehlen, zuerst `./build-samples_with_docker.sh` ausführen (siehe Abschnitt `Samples mit Docker erzeugen`).

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
