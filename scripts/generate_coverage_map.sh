#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
README_FILE="$ROOT_DIR/README.md"
TEST_FILE="$ROOT_DIR/tests/ELFInspector.UnitTests/Program.cs"
START_MARKER="<!-- COVERAGE_MAP_START -->"
END_MARKER="<!-- COVERAGE_MAP_END -->"

has_parser_pattern() {
	local pattern="$1"
	rg -q --no-messages "$pattern" "$ROOT_DIR/Parser" "$ROOT_DIR/Reporting" "$ROOT_DIR/Library"
}

has_test_pattern() {
	local pattern="$1"
	rg -q --no-messages "$pattern" "$TEST_FILE"
}

resolve_status() {
	local parser_pattern="$1"
	local test_pattern="$2"

	if ! has_parser_pattern "$parser_pattern"; then
		printf "open"
		return
	fi

	if [[ -n "$test_pattern" ]] && ! has_test_pattern "$test_pattern"; then
		printf "partial"
		return
	fi

	printf "full"
}

print_matrix() {
	local elf_header_status section_headers_status section_special_status program_headers_status dynamic_status
	local symbols_status symbol_version_status relocations_status relocation_arch_status hash_status notes_status
	local unwind_status dwarf_status core_status security_status textreport_status

	elf_header_status="$(resolve_status "ValidateHeaderPrefix|ValidateHeaderPostParse|Parse32|Parse64" "Parse_InvalidEiVersion_StrictRejects_CompatAllows|Parse_InvalidHeaderVersion_StrictRejects_CompatAllows")"
	section_headers_status="$(resolve_status "ParseSectionHeaders|SectionHeader" "Parse_WithoutSectionHeaderTable_StillResolvesDynamicData|StripSectionHeaderTable")"
	section_special_status="$(resolve_status "ParseSectionSpecialCases|SHF_COMPRESSED|SHT_GROUP" "ParseDwarfIndex_ShfCompressedZstdSection_IsDecoded|ParseDwarfIndex_GnuZdebugZstdSection_IsDecoded")"
	program_headers_status="$(resolve_status "ParseProgramHeaders|ElfProgramHeader" "Parse_WithoutSectionHeaderTable_StillParsesNotesFromProgramHeaders|Parse_HelloX64_ContainsExpectedSecurityFeatures")"
	dynamic_status="$(resolve_status "ParseDynamic|DT_|DynamicEntries" "Parse_DynamicTags_ExposeStructuredDecodedSemantics|Parse_DynamicTags_AArch64AndSparc_ProcessorSpecificTags_AreNamedAndStructured")"
	symbols_status="$(resolve_status "ParseSymbolTables|ImportedSymbols|ExportedSymbols" "Parse_WithoutSectionHeaderTable_StillResolvesDynamicData|Parse_WithoutSectionHeaderTable_ResolvesVersionedImportsViaDynamicTables")"
	symbol_version_status="$(resolve_status "ParseVersion.*|VERNEED|VERDEF|VERSYM" "Parse_WithoutSectionHeaderTable_ResolvesVersionedImportsViaDynamicTables")"
	relocations_status="$(resolve_status "ParseRelocations|RELR|RELA|REL" "Parse_Busybox_ContainsRelrRelocations|Parse_HelloX64_Relocations_ExposeLoaderPathClassification")"
	relocation_arch_status="$(resolve_status "GetRelocationTypeName|R_ARM_|R_MIPS_|R_PPC_|R_390_|R_SPARC_|R_RISCV_" "Parse_MultiArchSamples_UseArchitectureSpecificRelocationNames|Parse_MultiArchSamples_Relocations_AvoidRawFallbackTypeNames")"
	hash_status="$(resolve_status "ParseHashTables|DT_GNU_HASH|DT_HASH|BuildHashLookupPaths" "Report_Nano_ParsesGnuHashTablesAndLookupPaths|Report_HelloX64_GnuHashLookupPaths_CanResolveMatches|Parse_HashLookupPaths_SymbolLimit_IsConfigurable")"
	notes_status="$(resolve_status "ParseNotes|ElfNote|NT_" "ParseNotes_SyntheticGnuExtendedTypes_AreNamedAndDecoded|ParseNotes_SyntheticVendorTypes_AreNamedAndDecoded")"
	unwind_status="$(resolve_status "ParseUnwindData|EhFrame|CFA|ParseEhFrame" "Parse_HelloX64_ParsesUnwindSections|ParseUnwindData_SyntheticEhFrame_ParsesCieFdeRules")"
	dwarf_status="$(resolve_status "ParseDwarfIndex|ParseDwarfSemantics|debug_rnglists|debug_loclists|ElfDwarf" "ParseDwarfIndex_SemanticModel_ParsesDieTreeAndSymbolMappings|ParseDwarfIndex_DwarfV5Tables_EnableRnglistsAndLoclistsSymbolMappings|ParseDwarfIndex_SemanticModel_UnknownAttributeForm_IsPreservedWithFallbackValue")"
	core_status="$(resolve_status "ParseCoreDumpInfo|ElfCoreDump|NT_PRSTATUS" "Parse_CoreTypedSample_InitializesCoreReportBranch|Parse_CoreNotes_X86_64_PrStatus_UsesStructuredLayout")"
	security_status="$(resolve_status "CreateSecurityFeatures|PT_GNU_STACK|PT_GNU_RELRO|DF_BIND_NOW|FORTIFY" "Report_Nano_ContainsExpectedSecurityFeatures|Report_HelloX64_ContainsExpectedSecurityFeatures")"
	textreport_status="$(resolve_status "BuildTextReport|RunWithArgs" "ExampleUsage_ReturnsErrorCode_ForMalformedElf|ExampleUsage_CompatHeaderValidation_AllowsLegacyHeaderVariants")"

	cat <<EOF
## Current Coverage Map (auto-generated)

Status legend:
* \`full\`: Implemented and covered by unit/matrix tests
* \`partial\`: Implemented, but only partially covered by tests
* \`open\`: Not implemented yet

### Parser/Report Coverage

| Area | Status | Current coverage |
|---|---|---|
| ELF Header | $elf_header_status | ELF32/ELF64, endianness, type, machine, entry point |
| Section Headers | $section_headers_status | Standard + extended numbering, section name resolution |
| Section special cases | $section_special_status | \`SHF_COMPRESSED\` (ZLIB + ZSTD), GNU \`.zdebug*\` (ZLIB + ZSTD), \`SHT_GROUP\`/COMDAT |
| Program Headers | $program_headers_status | PT_LOAD/PT_DYNAMIC/PT_INTERP/PT_NOTE including interpreter resolution |
| Dynamic | $dynamic_status | DT_NEEDED, SONAME, RPATH/RUNPATH, FLAGS/FLAGS_1, REL/RELA/RELR tags, GNU version tags |
| Symbol Tables | $symbols_status | \`.symtab\`/\`.dynsym\`, fallback without section header table, import/export classification |
| Symbol versioning | $symbol_version_status | \`DT_VERSYM\`, \`DT_VERNEED\`, \`DT_VERDEF\` including library/version mapping |
| Relocations | $relocations_status | REL/RELA/RELR from sections and dynamic tags, symbol/section mapping in report |
| Relocation type names per architecture | $relocation_arch_status | i386, x86_64, ARM, AArch64, MIPS, PPC/PPC64, S390x, SPARC, RISC-V with extended type-name maps |
| Hash Tables | $hash_status | \`DT_HASH\` and \`DT_GNU_HASH\` (buckets/chains/bloom), configurable lookup-path evaluation |
| Notes | $notes_status | \`SHT_NOTE\`/\`PT_NOTE\`, GNU/FDO/Go/FreeBSD/NetBSD/OpenBSD/Android/Linux named plus basic decoding |
| Unwind | $unwind_status | \`.eh_frame\`/\`.eh_frame_hdr\`, CIE/FDE parsing, CFA rules, basic stack walk for core cases |
| DWARF/Debug | $dwarf_status | Index + partial semantics for \`.debug_info/.abbrev/.line/.str/.ranges/.addr/.str_offsets/.rnglists/.loclists\` including robust partial decoding |
| ET_CORE | $core_status | \`PT_NOTE\`-based process/thread/register/signal evaluation plus thread-unwind branch in report |
| Security/Loader features | $security_status | PIE, RELRO (partial/full), NX (GNU_STACK), BIND_NOW, canary/FORTIFY hints |
| Text report | $textreport_status | Deterministic output, structured sections including hash/security |
EOF
}

write_readme() {
	if [[ ! -f "$README_FILE" ]]; then
		echo "README not found: $README_FILE" >&2
		exit 1
	fi

	if ! rg -q "^${START_MARKER}$" "$README_FILE"; then
		echo "Missing coverage start marker in README: $START_MARKER" >&2
		exit 1
	fi
	if ! rg -q "^${END_MARKER}$" "$README_FILE"; then
		echo "Missing coverage end marker in README: $END_MARKER" >&2
		exit 1
	fi

	local generated_file tmp_file
	generated_file="$(mktemp)"
	tmp_file="$(mktemp)"
	trap 'rm -f "$generated_file" "$tmp_file"' EXIT

	print_matrix >"$generated_file"

	awk -v start="$START_MARKER" -v end="$END_MARKER" -v repl="$generated_file" '
	$0 == start {
		print
		while ((getline line < repl) > 0)
			print line
		in_block = 1
		next
	}
	$0 == end {
		in_block = 0
		print
		next
	}
	!in_block { print }
	' "$README_FILE" >"$tmp_file"

	mv "$tmp_file" "$README_FILE"
}

if [[ "${1:-}" == "--write-readme" ]]; then
	write_readme
else
	print_matrix
fi
