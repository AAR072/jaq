// Package pe provides a deterministic, read-only parser for Portable
// Executable files.  It treats every byte and extracted string as hostile
// data: no returned value is executed, resolved, or contacted.
package pe

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/jaq-project/jaq/internal/evidence"
)

const (
	// MaxPEFileSize bounds the file helper. AnalyzeBytes has no implicit copy or
	// allocation proportional to malformed declared sizes, but callers should
	// still apply their own input policy before passing untrusted bytes.
	MaxPEFileSize   = 512 << 20
	MaxSections     = 96
	MaxDirectories  = 16
	MaxStrings      = 10000
	MaxStringLength = 4096
	MaxImports      = 65536
	MaxResources    = 4096
	MaxExports      = 65536
)

var (
	// ErrNotPE means the input does not begin with a recognizable PE envelope.
	ErrNotPE = errors.New("input is not a Portable Executable")
	// ErrMalformedPE means the input claims to be a PE but has inconsistent or
	// out-of-bounds structures.
	ErrMalformedPE = errors.New("malformed Portable Executable")
)

// DataDirectory is one IMAGE_DATA_DIRECTORY entry.  VirtualAddress is an RVA
// except for the security directory (index 4), where PE specifies a file
// offset.
type DataDirectory struct {
	Index          int    `json:"index"`
	VirtualAddress uint32 `json:"virtual_address"`
	Size           uint32 `json:"size"`
}

// Headers contains the PE/DOS/COFF/optional-header values needed for static
// triage.  It deliberately excludes pointers that could be interpreted as
// executable addresses.
type Headers struct {
	DOSMagic                string          `json:"dos_magic"`
	PEOffset                uint32          `json:"pe_offset"`
	Machine                 uint16          `json:"machine"`
	SectionCount            uint16          `json:"section_count"`
	TimeDateStamp           uint32          `json:"time_date_stamp"`
	PointerToSymbolTable    uint32          `json:"pointer_to_symbol_table"`
	NumberOfSymbols         uint32          `json:"number_of_symbols"`
	Characteristics         uint16          `json:"characteristics"`
	OptionalMagic           uint16          `json:"optional_magic"`
	Is64Bit                 bool            `json:"is_64_bit"`
	LinkerMajor             uint8           `json:"linker_major"`
	LinkerMinor             uint8           `json:"linker_minor"`
	SizeOfCode              uint32          `json:"size_of_code"`
	SizeOfInitializedData   uint32          `json:"size_of_initialized_data"`
	SizeOfUninitializedData uint32          `json:"size_of_uninitialized_data"`
	AddressOfEntryPoint     uint32          `json:"address_of_entry_point"`
	BaseOfCode              uint32          `json:"base_of_code"`
	ImageBase               uint64          `json:"image_base"`
	SectionAlignment        uint32          `json:"section_alignment"`
	FileAlignment           uint32          `json:"file_alignment"`
	SizeOfImage             uint32          `json:"size_of_image"`
	SizeOfHeaders           uint32          `json:"size_of_headers"`
	Checksum                uint32          `json:"checksum"`
	Subsystem               uint16          `json:"subsystem"`
	DLLCharacteristics      uint16          `json:"dll_characteristics"`
	NumberOfRvaAndSizes     uint32          `json:"number_of_rva_and_sizes"`
	Directories             []DataDirectory `json:"directories"`
}

// Section is an IMAGE_SECTION_HEADER with a safe file-backed range.
type Section struct {
	Name            string `json:"name"`
	VirtualSize     uint32 `json:"virtual_size"`
	VirtualAddress  uint32 `json:"virtual_address"`
	RawSize         uint32 `json:"raw_size"`
	RawOffset       uint32 `json:"raw_offset"`
	Characteristics uint32 `json:"characteristics"`
}

// String is an inert ASCII or UTF-16LE byte sequence with its file location.
type String struct {
	Value    string `json:"value"`
	Encoding string `json:"encoding"`
	Offset   uint64 `json:"offset"`
	Length   uint64 `json:"length"`
}

// Import is one imported symbol.  Ordinal is nonzero for ordinal imports; a
// name import has Name and Hint populated instead.
type Import struct {
	DLL     string `json:"dll"`
	Name    string `json:"name,omitempty"`
	Ordinal uint16 `json:"ordinal,omitempty"`
	Hint    uint16 `json:"hint,omitempty"`
	NameRVA uint32 `json:"name_rva,omitempty"`
	IATRVA  uint32 `json:"iat_rva,omitempty"`
}

// Function is an exported function discovered without executing code.  The
// parser does not guess internal functions or decompile bytes.
type Function struct {
	Name       string `json:"name,omitempty"`
	Ordinal    uint32 `json:"ordinal"`
	RVA        uint32 `json:"rva"`
	FileOffset uint64 `json:"file_offset"`
}

// Reference and CallRelationship are schema placeholders for richer static
// tool evidence. Lightweight parsing never invents relationships.
type Reference struct {
	FromRVA uint32 `json:"from_rva"`
	ToRVA   uint32 `json:"to_rva"`
	Kind    string `json:"kind"`
}

type CallRelationship struct {
	CallerRVA  uint32 `json:"caller_rva"`
	CalleeRVA  uint32 `json:"callee_rva"`
	CalleeName string `json:"callee_name,omitempty"`
}

// ResourceEntry records a resource leaf without exposing or interpreting its
// payload as a document or executable.
type ResourceEntry struct {
	TypeID     uint32 `json:"type_id"`
	NameID     uint32 `json:"name_id"`
	LanguageID uint32 `json:"language_id"`
	TypeName   string `json:"type_name,omitempty"`
	Name       string `json:"name,omitempty"`
	DataRVA    uint32 `json:"data_rva"`
	DataSize   uint32 `json:"data_size"`
	CodePage   uint32 `json:"code_page"`
}

type ResourceSummary struct {
	Present       bool            `json:"present"`
	DirectoryRVA  uint32          `json:"directory_rva,omitempty"`
	DirectorySize uint32          `json:"directory_size,omitempty"`
	Entries       []ResourceEntry `json:"entries,omitempty"`
}

// CapabilityHint is a deterministic, low-confidence grouping of imported API
// names.  It is a lead for an investigator, never proof of behavior.
type CapabilityHint struct {
	Capability     string   `json:"capability"`
	MatchedImports []string `json:"matched_imports"`
	Confidence     string   `json:"confidence"`
}

// Analysis is the complete deterministic lightweight package.
type Analysis struct {
	SchemaVersion     string             `json:"schema_version"`
	Size              int64              `json:"size"`
	Hashes            evidence.Hashes    `json:"hashes"`
	Format            string             `json:"format"`
	Headers           Headers            `json:"headers"`
	Sections          []Section          `json:"sections"`
	Strings           []String           `json:"strings"`
	Imports           []Import           `json:"imports"`
	Exports           []Function         `json:"exports"`
	Functions         []Function         `json:"functions"`
	References        []Reference        `json:"references"`
	CallRelationships []CallRelationship `json:"call_relationships"`
	Resources         ResourceSummary    `json:"resources"`
	CapabilityHints   []CapabilityHint   `json:"capability_hints"`
}

// PE is a compatibility alias for Analysis.
type PE = Analysis

// Compatibility aliases make the lightweight result convenient for callers
// that use terminology from the PE specification.
type PEHeaders = Headers
type SectionHeader = Section
type ExtractedString = String
type ImportEntry = Import
type Resource = ResourceSummary

// AnalyzeFile opens and reads a regular input file as inert bytes.  It never
// hands the path to a process, loader, or network client.
func AnalyzeFile(path string) (*Analysis, error) {
	if path == "" {
		return nil, errors.New("empty PE path")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open PE: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat PE: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("PE input is not a regular file")
	}
	if info.Size() > MaxPEFileSize {
		return nil, fmt.Errorf("PE input exceeds %d-byte limit", MaxPEFileSize)
	}
	data, err := io.ReadAll(io.LimitReader(file, MaxPEFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read PE: %w", err)
	}
	if len(data) > MaxPEFileSize {
		return nil, fmt.Errorf("PE input exceeds %d-byte limit", MaxPEFileSize)
	}
	return AnalyzeBytes(data)
}

// ParseFile is an alias for AnalyzeFile.
func ParseFile(path string) (*Analysis, error) { return AnalyzeFile(path) }

// AnalyzeBytes parses a complete in-memory PE without executing any bytes.
func AnalyzeBytes(data []byte) (*Analysis, error) {
	parsed, err := parse(data)
	if err != nil {
		return nil, err
	}
	parsed.Size = int64(len(data))
	parsed.Hashes = evidence.HashBytes(data)
	parsed.Strings = extractStrings(data)
	parsed.Imports, err = parseImports(data, parsed)
	if err != nil {
		return nil, err
	}
	parsed.Exports, err = parseExports(data, parsed)
	if err != nil {
		return nil, err
	}
	parsed.Resources, err = parseResources(data, parsed)
	if err != nil {
		return nil, err
	}
	parsed.CapabilityHints = capabilityHints(parsed.Imports)
	// Lightweight parsing supplies no guessed internal relationships.  Make
	// the slices non-nil so JSON output remains stable across empty analyses.
	if parsed.Sections == nil {
		parsed.Sections = []Section{}
	}
	if parsed.Strings == nil {
		parsed.Strings = []String{}
	}
	if parsed.Imports == nil {
		parsed.Imports = []Import{}
	}
	if parsed.Exports == nil {
		parsed.Exports = []Function{}
	}
	if parsed.Functions == nil {
		parsed.Functions = []Function{}
	}
	if parsed.References == nil {
		parsed.References = []Reference{}
	}
	if parsed.CallRelationships == nil {
		parsed.CallRelationships = []CallRelationship{}
	}
	if parsed.CapabilityHints == nil {
		parsed.CapabilityHints = []CapabilityHint{}
	}
	return parsed, nil
}

// Analyze and Parse are concise aliases used by controller integrations.
func Analyze(data []byte) (*Analysis, error) { return AnalyzeBytes(data) }
func Parse(data []byte) (*Analysis, error)   { return AnalyzeBytes(data) }

// ExtractPE is a descriptive alias for AnalyzeBytes.
func ExtractPE(data []byte) (*Analysis, error) { return AnalyzeBytes(data) }

// ExtractStrings exposes the bounded inert string scanner for focused parser
// tests and callers that already validated their PE envelope.
func ExtractStrings(data []byte) []String { return extractStrings(data) }

// DetectCapabilities maps exact imported API names to low-confidence hints.
func DetectCapabilities(imports []Import) []CapabilityHint { return capabilityHints(imports) }

// Extract returns a value rather than a pointer for callers that prefer value
// semantics.  It is otherwise identical to AnalyzeBytes.
func Extract(data []byte) (Analysis, error) {
	result, err := AnalyzeBytes(data)
	if err != nil {
		return Analysis{}, err
	}
	return *result, nil
}

func parse(data []byte) (*Analysis, error) {
	if len(data) < 64 || data[0] != 'M' || data[1] != 'Z' {
		return nil, ErrNotPE
	}
	peOffset, err := u32(data, 0x3c)
	if err != nil {
		return nil, malformed("DOS header", err)
	}
	if peOffset < 64 || !hasRange(data, uint64(peOffset), 4) {
		return nil, malformed("PE header offset", nil)
	}
	if string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		return nil, ErrNotPE
	}
	coff := uint64(peOffset) + 4
	if !hasRange(data, coff, 20) {
		return nil, malformed("COFF header", nil)
	}
	machine, _ := u16(data, coff)
	sectionCount, _ := u16(data, coff+2)
	if sectionCount == 0 || sectionCount > MaxSections {
		return nil, malformed("section count", nil)
	}
	timestamp, _ := u32(data, coff+4)
	ptrSymbols, _ := u32(data, coff+8)
	numSymbols, _ := u32(data, coff+12)
	sizeOptional, _ := u16(data, coff+16)
	characteristics, _ := u16(data, coff+18)
	optional := coff + 20
	if sizeOptional < 2 || !hasRange(data, optional, uint64(sizeOptional)) {
		return nil, malformed("optional header", nil)
	}
	magic, _ := u16(data, optional)
	is64 := magic == 0x20b
	if magic != 0x10b && !is64 {
		return nil, malformed("optional header magic", nil)
	}
	minimumOptional := uint64(96)
	if is64 {
		minimumOptional = 112
	}
	if uint64(sizeOptional) < minimumOptional {
		return nil, malformed("optional header size", nil)
	}
	get8 := func(at uint64) (uint8, error) {
		if at >= optional+uint64(sizeOptional) || !hasRange(data, at, 1) {
			return 0, ErrMalformedPE
		}
		return data[at], nil
	}
	get16 := func(at uint64) (uint16, error) { return u16(data, at) }
	get32 := func(at uint64) (uint32, error) { return u32(data, at) }
	get64 := func(at uint64) (uint64, error) { return u64(data, at) }
	majorLinker, err := get8(optional + 2)
	if err != nil {
		return nil, malformed("optional linker version", err)
	}
	minorLinker, err := get8(optional + 3)
	if err != nil {
		return nil, malformed("optional linker version", err)
	}
	sizeCode, err := get32(optional + 4)
	if err != nil {
		return nil, malformed("optional code size", err)
	}
	sizeInit, err := get32(optional + 8)
	if err != nil {
		return nil, malformed("optional initialized data size", err)
	}
	sizeUninit, err := get32(optional + 12)
	if err != nil {
		return nil, malformed("optional uninitialized data size", err)
	}
	entry, err := get32(optional + 16)
	if err != nil {
		return nil, malformed("optional entry point", err)
	}
	baseCode, err := get32(optional + 20)
	if err != nil {
		return nil, malformed("optional base of code", err)
	}
	var imageBase uint64
	if is64 {
		imageBase, err = get64(optional + 24)
	} else {
		var base32 uint32
		base32, err = get32(optional + 28)
		imageBase = uint64(base32)
	}
	if err != nil {
		return nil, malformed("optional image base", err)
	}
	sectionAlignment, err := get32(optional + 32)
	if err != nil {
		return nil, malformed("optional section alignment", err)
	}
	fileAlignment, err := get32(optional + 36)
	if err != nil {
		return nil, malformed("optional file alignment", err)
	}
	sizeImage, err := get32(optional + 56)
	if err != nil {
		return nil, malformed("optional image size", err)
	}
	sizeHeaders, err := get32(optional + 60)
	if err != nil {
		return nil, malformed("optional header size", err)
	}
	checksum, err := get32(optional + 64)
	if err != nil {
		return nil, malformed("optional checksum", err)
	}
	subsystem, err := get16(optional + 68)
	if err != nil {
		return nil, malformed("optional subsystem", err)
	}
	dllCharacteristics, err := get16(optional + 70)
	if err != nil {
		return nil, malformed("optional DLL characteristics", err)
	}
	countOffset := optional + 92
	directoryOffset := optional + 96
	if is64 {
		countOffset = optional + 108
		directoryOffset = optional + 112
	}
	directoryCount, err := get32(countOffset)
	if err != nil {
		return nil, malformed("data-directory count", err)
	}
	if sectionAlignment == 0 || fileAlignment == 0 {
		return nil, malformed("optional alignment", nil)
	}
	if uint64(sizeHeaders) > uint64(len(data)) {
		return nil, malformed("optional header file bounds", nil)
	}
	availableDirectories := (optional + uint64(sizeOptional) - directoryOffset) / 8
	if directoryCount > uint32(availableDirectories) && directoryCount <= MaxDirectories {
		return nil, malformed("truncated data directories", nil)
	}
	directoryLimit := directoryCount
	if directoryLimit > MaxDirectories {
		directoryLimit = MaxDirectories
	}
	if uint64(directoryLimit) > availableDirectories {
		return nil, malformed("data-directory bounds", nil)
	}
	directories := make([]DataDirectory, 0, directoryLimit)
	for i := uint32(0); i < directoryLimit; i++ {
		at := directoryOffset + uint64(i)*8
		rva, _ := u32(data, at)
		size, _ := u32(data, at+4)
		directories = append(directories, DataDirectory{Index: int(i), VirtualAddress: rva, Size: size})
	}
	sectionsAt := optional + uint64(sizeOptional)
	sectionTableSize := uint64(sectionCount) * 40
	if !hasRange(data, sectionsAt, sectionTableSize) {
		return nil, malformed("section table", nil)
	}
	sections := make([]Section, 0, sectionCount)
	for i := uint64(0); i < uint64(sectionCount); i++ {
		at := sectionsAt + i*40
		nameBytes := data[at : at+8]
		name := strings.TrimRight(string(nameBytes), "\x00")
		virtualSize, _ := u32(data, at+8)
		virtualAddress, _ := u32(data, at+12)
		rawSize, _ := u32(data, at+16)
		rawOffset, _ := u32(data, at+20)
		characteristics, _ := u32(data, at+36)
		if rawSize > 0 && !hasRange(data, uint64(rawOffset), uint64(rawSize)) {
			return nil, malformed(fmt.Sprintf("section %q raw bounds", name), nil)
		}
		if rawSize == 0 && uint64(rawOffset) > uint64(len(data)) {
			return nil, malformed(fmt.Sprintf("section %q raw offset", name), nil)
		}
		sections = append(sections, Section{
			Name: name, VirtualSize: virtualSize, VirtualAddress: virtualAddress,
			RawSize: rawSize, RawOffset: rawOffset, Characteristics: characteristics,
		})
	}
	result := &Analysis{
		SchemaVersion: evidence.SchemaVersion,
		Format:        "PE32+",
		Headers: Headers{
			DOSMagic: "MZ", PEOffset: peOffset, Machine: machine,
			SectionCount: sectionCount, TimeDateStamp: timestamp,
			PointerToSymbolTable: ptrSymbols, NumberOfSymbols: numSymbols,
			Characteristics: characteristics, OptionalMagic: magic, Is64Bit: is64,
			LinkerMajor: majorLinker, LinkerMinor: minorLinker,
			SizeOfCode: sizeCode, SizeOfInitializedData: sizeInit,
			SizeOfUninitializedData: sizeUninit, AddressOfEntryPoint: entry,
			BaseOfCode: baseCode, ImageBase: imageBase, SectionAlignment: sectionAlignment,
			FileAlignment: fileAlignment, SizeOfImage: sizeImage, SizeOfHeaders: sizeHeaders,
			Checksum: checksum, Subsystem: subsystem, DLLCharacteristics: dllCharacteristics,
			NumberOfRvaAndSizes: directoryCount, Directories: directories,
		},
		Sections: sections,
	}
	if !is64 {
		result.Format = "PE32"
	}
	// Validate every parsed directory's file-backed bounds before any specialized
	// parser (imports, resources, debug/export) dereferences it.
	for _, directory := range directories {
		if directory.VirtualAddress == 0 || directory.Size == 0 {
			continue
		}
		if directory.Index == 4 { // IMAGE_DIRECTORY_ENTRY_SECURITY uses file offset.
			if !hasRange(data, uint64(directory.VirtualAddress), uint64(directory.Size)) {
				return nil, malformed("security directory bounds", nil)
			}
			continue
		}
		if _, ok := rvaToOffset(result, directory.VirtualAddress, directory.Size, len(data)); !ok {
			return nil, malformed(fmt.Sprintf("data directory %d bounds", directory.Index), nil)
		}
	}
	return result, nil
}

func malformed(context string, cause error) error {
	if cause == nil {
		return fmt.Errorf("%w: %s", ErrMalformedPE, context)
	}
	return fmt.Errorf("%w: %s: %v", ErrMalformedPE, context, cause)
}

func hasRange(data []byte, offset, size uint64) bool {
	return offset <= uint64(len(data)) && size <= uint64(len(data))-offset
}

func u16(data []byte, offset uint64) (uint16, error) {
	if !hasRange(data, offset, 2) {
		return 0, ErrMalformedPE
	}
	return uint16(data[offset]) | uint16(data[offset+1])<<8, nil
}

func u32(data []byte, offset uint64) (uint32, error) {
	if !hasRange(data, offset, 4) {
		return 0, ErrMalformedPE
	}
	return uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24, nil
}

func u64(data []byte, offset uint64) (uint64, error) {
	if !hasRange(data, offset, 8) {
		return 0, ErrMalformedPE
	}
	var value uint64
	for i := uint64(0); i < 8; i++ {
		value |= uint64(data[offset+i]) << (8 * i)
	}
	return value, nil
}

func rvaToOffset(analysis *Analysis, rva, size uint32, dataLen int) (uint64, bool) {
	if size == 0 {
		return uint64(rva), uint64(rva) <= uint64(dataLen)
	}
	if rva < analysis.Headers.SizeOfHeaders {
		offset := uint64(rva)
		return offset, offset <= uint64(dataLen) && uint64(size) <= uint64(dataLen)-offset
	}
	for _, section := range analysis.Sections {
		start := uint64(section.VirtualAddress)
		fileStart := uint64(section.RawOffset)
		rawSize := uint64(section.RawSize)
		if rawSize == 0 || uint64(rva) < start || uint64(rva)-start >= rawSize {
			continue
		}
		offset := fileStart + (uint64(rva) - start)
		if offset < fileStart || uint64(size) > rawSize-(uint64(rva)-start) {
			return 0, false
		}
		if offset > uint64(dataLen) || uint64(size) > uint64(dataLen)-offset {
			return 0, false
		}
		return offset, true
	}
	return 0, false
}

func readCString(data []byte, offset uint64, max int) (string, int, error) {
	if offset >= uint64(len(data)) {
		return "", 0, ErrMalformedPE
	}
	end := offset
	for end < uint64(len(data)) && int(end-offset) < max {
		if data[end] == 0 {
			return string(data[offset:end]), int(end - offset), nil
		}
		end++
	}
	return "", 0, ErrMalformedPE
}

func parseImports(data []byte, analysis *Analysis) ([]Import, error) {
	directory := directoryAt(analysis, 1)
	if directory.Size == 0 || directory.VirtualAddress == 0 {
		return []Import{}, nil
	}
	offset, ok := rvaToOffset(analysis, directory.VirtualAddress, directory.Size, len(data))
	if !ok || directory.Size < 20 {
		return nil, malformed("import directory bounds", nil)
	}
	result := make([]Import, 0)
	terminated := false
	for index := uint32(0); index < MaxImports/16; index++ {
		descriptorOffset := offset + uint64(index)*20
		if !hasRange(data, descriptorOffset, 20) || descriptorOffset-offset >= uint64(directory.Size) {
			break
		}
		originalFirstThunk, _ := u32(data, descriptorOffset)
		nameRVA, _ := u32(data, descriptorOffset+12)
		firstThunk, _ := u32(data, descriptorOffset+16)
		if originalFirstThunk == 0 && nameRVA == 0 && firstThunk == 0 {
			terminated = true
			break
		}
		if nameRVA == 0 {
			return nil, malformed("import descriptor missing DLL name", nil)
		}
		nameOffset, ok := rvaToOffset(analysis, nameRVA, 1, len(data))
		if !ok {
			return nil, malformed("import DLL name bounds", nil)
		}
		dll, _, err := readCString(data, nameOffset, 512)
		if err != nil {
			return nil, malformed("import DLL name", err)
		}
		thunkRVA := originalFirstThunk
		if thunkRVA == 0 {
			thunkRVA = firstThunk
		}
		if thunkRVA == 0 {
			return nil, malformed("import descriptor missing thunk table", nil)
		}
		width := uint64(4)
		ordinalMask := uint64(0x80000000)
		if analysis.Headers.Is64Bit {
			width = 8
			ordinalMask = uint64(0x8000000000000000)
		}
		thunkTerminated := false
		for thunkIndex := uint32(0); thunkIndex < MaxImports; thunkIndex++ {
			entryRVA64 := uint64(thunkRVA) + uint64(thunkIndex)*width
			if entryRVA64 > uint64(^uint32(0)) {
				return nil, malformed("import thunk RVA overflow", nil)
			}
			entryRVA := uint32(entryRVA64)
			entryOffset, ok := rvaToOffset(analysis, entryRVA, uint32(width), len(data))
			if !ok {
				return nil, malformed("import thunk bounds", nil)
			}
			var value uint64
			if width == 8 {
				value, _ = u64(data, entryOffset)
			} else {
				entry, _ := u32(data, entryOffset)
				value = uint64(entry)
			}
			if value == 0 {
				thunkTerminated = true
				break
			}
			iatRVA64 := uint64(firstThunk) + uint64(thunkIndex)*width
			if iatRVA64 > uint64(^uint32(0)) {
				return nil, malformed("import IAT RVA overflow", nil)
			}
			item := Import{DLL: dll, IATRVA: uint32(iatRVA64)}
			if value&ordinalMask != 0 {
				item.Ordinal = uint16(value & 0xffff)
			} else {
				nameRVA := uint32(value & 0x7fffffff)
				if nameRVA == 0 {
					return nil, malformed("import symbol missing name RVA", nil)
				}
				item.NameRVA = nameRVA
				nameOffset, ok := rvaToOffset(analysis, nameRVA, 2, len(data))
				if !ok {
					return nil, malformed("import symbol name bounds", nil)
				}
				item.Hint, _ = u16(data, nameOffset)
				item.Name, _, err = readCString(data, nameOffset+2, 1024)
				if err != nil {
					return nil, malformed("import symbol name", err)
				}
			}
			result = append(result, item)
			if len(result) >= MaxImports {
				return nil, malformed("too many imports", nil)
			}
		}
		if !thunkTerminated {
			return nil, malformed("unterminated import thunk table", nil)
		}
	}
	if !terminated {
		return nil, malformed("unterminated import descriptor table", nil)
	}
	sort.SliceStable(result, func(i, j int) bool {
		if strings.ToLower(result[i].DLL) != strings.ToLower(result[j].DLL) {
			return strings.ToLower(result[i].DLL) < strings.ToLower(result[j].DLL)
		}
		if result[i].Name != result[j].Name {
			return result[i].Name < result[j].Name
		}
		return result[i].Ordinal < result[j].Ordinal
	})
	return result, nil
}

func parseExports(data []byte, analysis *Analysis) ([]Function, error) {
	directory := directoryAt(analysis, 0)
	if directory.Size == 0 || directory.VirtualAddress == 0 {
		return []Function{}, nil
	}
	offset, ok := rvaToOffset(analysis, directory.VirtualAddress, 40, len(data))
	if !ok || directory.Size < 40 {
		return nil, malformed("export directory bounds", nil)
	}
	base, _ := u32(data, offset+16)
	numberFunctions, _ := u32(data, offset+20)
	numberNames, _ := u32(data, offset+24)
	functionsRVA, _ := u32(data, offset+28)
	namesRVA, _ := u32(data, offset+32)
	ordinalsRVA, _ := u32(data, offset+36)
	if numberFunctions > MaxExports || numberNames > MaxExports {
		return nil, malformed("export count limit", nil)
	}
	if numberFunctions == 0 {
		return []Function{}, nil
	}
	functionOffset, ok := rvaToOffset(analysis, functionsRVA, numberFunctions*4, len(data))
	if !ok {
		return nil, malformed("export address table bounds", nil)
	}
	nameByIndex := make(map[uint32]string, numberNames)
	if numberNames > 0 {
		nameOffsets, ok := rvaToOffset(analysis, namesRVA, numberNames*4, len(data))
		ordinalOffsets, ordOK := rvaToOffset(analysis, ordinalsRVA, numberNames*2, len(data))
		if !ok || !ordOK {
			return nil, malformed("export name table bounds", nil)
		}
		for i := uint32(0); i < numberNames; i++ {
			nameRVA, _ := u32(data, nameOffsets+uint64(i)*4)
			nameOffset, ok := rvaToOffset(analysis, nameRVA, 1, len(data))
			if !ok {
				return nil, malformed("export name bounds", nil)
			}
			name, _, err := readCString(data, nameOffset, 1024)
			if err != nil {
				return nil, malformed("export name", err)
			}
			ordinalIndex, _ := u16(data, ordinalOffsets+uint64(i)*2)
			if uint32(ordinalIndex) >= numberFunctions {
				return nil, malformed("export ordinal index", nil)
			}
			nameByIndex[uint32(ordinalIndex)] = name
		}
	}
	result := make([]Function, 0, numberFunctions)
	for i := uint32(0); i < numberFunctions; i++ {
		functionRVA, _ := u32(data, functionOffset+uint64(i)*4)
		if functionRVA == 0 {
			continue
		}
		fileOffset, ok := rvaToOffset(analysis, functionRVA, 1, len(data))
		if !ok {
			// A forwarder RVA points to an ASCII name inside the export directory;
			// it is still a valid export but has no file-backed code location.
			fileOffset = 0
		}
		result = append(result, Function{Name: nameByIndex[i], Ordinal: base + i, RVA: functionRVA, FileOffset: fileOffset})
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].RVA != result[j].RVA {
			return result[i].RVA < result[j].RVA
		}
		return result[i].Name < result[j].Name
	})
	return result, nil
}

func directoryAt(analysis *Analysis, index int) DataDirectory {
	if index < 0 || index >= len(analysis.Headers.Directories) {
		return DataDirectory{Index: index}
	}
	return analysis.Headers.Directories[index]
}

func extractStrings(data []byte) []String {
	result := make([]String, 0)
	for offset := 0; offset < len(data) && len(result) < MaxStrings; {
		if !isPrintableASCII(data[offset]) {
			offset++
			continue
		}
		start := offset
		for offset < len(data) && offset-start < MaxStringLength && isPrintableASCII(data[offset]) {
			offset++
		}
		if offset-start >= 4 {
			result = append(result, String{Value: string(data[start:offset]), Encoding: "ascii", Offset: uint64(start), Length: uint64(offset - start)})
		}
	}
	for offset := 0; offset+1 < len(data) && len(result) < MaxStrings; {
		if !isPrintableASCII(data[offset]) || data[offset+1] != 0 {
			offset++
			continue
		}
		start := offset
		units := make([]uint16, 0, 32)
		for offset+1 < len(data) && len(units) < MaxStringLength && isPrintableASCII(data[offset]) && data[offset+1] == 0 {
			units = append(units, uint16(data[offset]))
			offset += 2
		}
		if len(units) >= 4 {
			result = append(result, String{Value: string(utf16.Decode(units)), Encoding: "utf-16le", Offset: uint64(start), Length: uint64(len(units) * 2)})
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		if result[i].Offset != result[j].Offset {
			return result[i].Offset < result[j].Offset
		}
		if result[i].Encoding != result[j].Encoding {
			return result[i].Encoding < result[j].Encoding
		}
		return result[i].Value < result[j].Value
	})
	return result
}

func isPrintableASCII(value byte) bool { return value >= 0x20 && value <= 0x7e }

type resourceKey struct {
	ID   uint32
	Name string
}

func parseResources(data []byte, analysis *Analysis) (ResourceSummary, error) {
	directory := directoryAt(analysis, 2)
	if directory.Size == 0 || directory.VirtualAddress == 0 {
		return ResourceSummary{Present: false, Entries: []ResourceEntry{}}, nil
	}
	if directory.Size < 16 {
		return ResourceSummary{}, malformed("resource directory bounds", nil)
	}
	if _, ok := rvaToOffset(analysis, directory.VirtualAddress, directory.Size, len(data)); !ok {
		return ResourceSummary{}, malformed("resource directory bounds", nil)
	}
	result := ResourceSummary{Present: true, DirectoryRVA: directory.VirtualAddress, DirectorySize: directory.Size, Entries: []ResourceEntry{}}
	stack := map[uint32]bool{}
	var walk func(uint32, []resourceKey, int) error
	walk = func(relative uint32, path []resourceKey, depth int) error {
		if depth > 8 {
			return malformed("resource directory depth", nil)
		}
		if relative >= directory.Size || directory.Size-relative < 16 {
			return malformed("resource subdirectory bounds", nil)
		}
		if stack[relative] {
			return malformed("resource directory cycle", nil)
		}
		stack[relative] = true
		defer delete(stack, relative)
		if relative > ^uint32(0)-directory.VirtualAddress {
			return malformed("resource subdirectory RVA overflow", nil)
		}
		dirRVA := directory.VirtualAddress + relative
		dirOffset, ok := rvaToOffset(analysis, dirRVA, 16, len(data))
		if !ok {
			return malformed("resource subdirectory file bounds", nil)
		}
		named, _ := u16(data, dirOffset+12)
		ids, _ := u16(data, dirOffset+14)
		count := uint64(named) + uint64(ids)
		if count > MaxResources || 16+count*8 > uint64(directory.Size-relative) {
			return malformed("resource entry bounds", nil)
		}
		entriesOffset := dirOffset + 16
		for index := uint64(0); index < count; index++ {
			entryOffset := entriesOffset + index*8
			nameOrID, _ := u32(data, entryOffset)
			childOrData, _ := u32(data, entryOffset+4)
			key := resourceKey{}
			if nameOrID&0x80000000 != 0 {
				nameRelative := nameOrID & 0x7fffffff
				name, err := readResourceName(data, analysis, directory.VirtualAddress, nameRelative, directory.Size)
				if err != nil {
					return err
				}
				key.Name = name
			} else {
				key.ID = nameOrID
			}
			newPath := append(append([]resourceKey(nil), path...), key)
			if childOrData&0x80000000 != 0 {
				if err := walk(childOrData&0x7fffffff, newPath, depth+1); err != nil {
					return err
				}
				continue
			}
			dataRelative := childOrData
			if dataRelative >= directory.Size || directory.Size-dataRelative < 16 {
				return malformed("resource data entry bounds", nil)
			}
			if dataRelative > ^uint32(0)-directory.VirtualAddress {
				return malformed("resource data RVA overflow", nil)
			}
			dataRVAForEntry := directory.VirtualAddress + dataRelative
			dataOffset, ok := rvaToOffset(analysis, dataRVAForEntry, 16, len(data))
			if !ok {
				return malformed("resource data entry file bounds", nil)
			}
			payloadRVA, _ := u32(data, dataOffset)
			payloadSize, _ := u32(data, dataOffset+4)
			codePage, _ := u32(data, dataOffset+8)
			if payloadSize > 0 {
				if _, ok := rvaToOffset(analysis, payloadRVA, payloadSize, len(data)); !ok {
					return malformed("resource payload bounds", nil)
				}
			}
			entry := ResourceEntry{DataRVA: payloadRVA, DataSize: payloadSize, CodePage: codePage}
			if len(newPath) > 0 {
				entry.TypeID, entry.TypeName = newPath[0].ID, newPath[0].Name
			}
			if len(newPath) > 1 {
				entry.NameID, entry.Name = newPath[1].ID, newPath[1].Name
			}
			if len(newPath) > 2 {
				entry.LanguageID = newPath[2].ID
			}
			result.Entries = append(result.Entries, entry)
			if len(result.Entries) > MaxResources {
				return malformed("resource count limit", nil)
			}
		}
		return nil
	}
	if err := walk(0, nil, 0); err != nil {
		return ResourceSummary{}, err
	}
	sort.SliceStable(result.Entries, func(i, j int) bool {
		if result.Entries[i].TypeID != result.Entries[j].TypeID {
			return result.Entries[i].TypeID < result.Entries[j].TypeID
		}
		if result.Entries[i].NameID != result.Entries[j].NameID {
			return result.Entries[i].NameID < result.Entries[j].NameID
		}
		return result.Entries[i].LanguageID < result.Entries[j].LanguageID
	})
	return result, nil
}

func readResourceName(data []byte, analysis *Analysis, rootRVA, relative, directorySize uint32) (string, error) {
	if relative >= directorySize || directorySize-relative < 2 {
		return "", malformed("resource name bounds", nil)
	}
	if relative > ^uint32(0)-rootRVA {
		return "", malformed("resource name RVA overflow", nil)
	}
	rva := rootRVA + relative
	offset, ok := rvaToOffset(analysis, rva, 2, len(data))
	if !ok {
		return "", malformed("resource name file bounds", nil)
	}
	length, _ := u16(data, offset)
	if uint32(length) > (directorySize-relative-2)/2 {
		return "", malformed("resource name length", nil)
	}
	units := make([]uint16, length)
	for i := range units {
		units[i], _ = u16(data, offset+2+uint64(i)*2)
	}
	return string(utf16.Decode(units)), nil
}

type capabilityRule struct {
	Capability string
	Confidence string
	Patterns   []string
}

var capabilityRules = []capabilityRule{
	{Capability: "network_communication", Confidence: "low", Patterns: []string{"internetopen", "internetconnect", "internetreadfile", "httpsendrequest", "winhttp", "wsasocket", "getaddrinfo", "connect", "socket", "urldownloadtofile"}},
	{Capability: "file_system", Confidence: "low", Patterns: []string{"createfile", "readfile", "writefile", "deletefile", "movefile", "copyfile", "findfirstfile"}},
	{Capability: "process_execution", Confidence: "low", Patterns: []string{"createprocess", "winexec", "shellexecute", "openprocess"}},
	{Capability: "registry_access", Confidence: "low", Patterns: []string{"regopen", "regquery", "regsetvalue", "regcreate", "regdelete"}},
	{Capability: "service_management", Confidence: "low", Patterns: []string{"openscmanager", "createservice", "startservice", "controlservice"}},
	{Capability: "cryptography", Confidence: "low", Patterns: []string{"crypt", "bcrypt", "cryptprotect", "cryptunprotect"}},
	{Capability: "remote_process_injection", Confidence: "low", Patterns: []string{"virtualallocex", "writeprocessmemory", "createremotethread"}},
	{Capability: "dynamic_library_loading", Confidence: "low", Patterns: []string{"loadlibrary", "getprocaddress"}},
}

func capabilityHints(imports []Import) []CapabilityHint {
	result := make([]CapabilityHint, 0)
	for _, rule := range capabilityRules {
		matched := make([]string, 0)
		seen := map[string]struct{}{}
		for _, imported := range imports {
			name := strings.ToLower(imported.Name)
			for _, pattern := range rule.Patterns {
				if strings.Contains(name, pattern) {
					label := imported.DLL + "!"
					if imported.Name != "" {
						label += imported.Name
					} else {
						label += fmt.Sprintf("#%d", imported.Ordinal)
					}
					if _, ok := seen[label]; !ok {
						seen[label] = struct{}{}
						matched = append(matched, label)
					}
					break
				}
			}
		}
		if len(matched) == 0 {
			continue
		}
		sort.Strings(matched)
		result = append(result, CapabilityHint{Capability: rule.Capability, MatchedImports: matched, Confidence: rule.Confidence})
	}
	sort.SliceStable(result, func(i, j int) bool { return result[i].Capability < result[j].Capability })
	return result
}
