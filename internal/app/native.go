package app

import (
	"fmt"
	"strings"

	"github.com/jaq-project/jaq/internal/evidence"
	peinfo "github.com/jaq-project/jaq/internal/pe"
)

const nativeAnalyzerVersion = "0.1.0"

func nativeObservations(result *peinfo.Analysis, configHash string) []evidence.Observation {
	analyzer := evidence.AnalyzerIdentity{
		Name:       "jaq-pe",
		Version:    nativeAnalyzerVersion,
		ConfigHash: configHash,
	}
	provenance := func(source string) evidence.Provenance {
		return evidence.Provenance{
			Source:      source,
			Stage:       "deterministic-pe-extraction",
			InputSHA256: result.Hashes.SHA256,
		}
	}
	location := func(offset, length int64) evidence.ArtifactLocation {
		return evidence.ArtifactLocation{Artifact: "sample", Offset: offset, Length: length}
	}
	var observations []evidence.Observation
	add := func(typ string, raw, normalized any, loc evidence.ArtifactLocation, source string) {
		observations = append(observations, evidence.NewObservation(
			typ, raw, normalized, loc, analyzer, provenance(source),
		))
	}

	for algorithm, value := range map[string]string{
		"md5": result.Hashes.MD5, "sha1": result.Hashes.SHA1,
		"sha256": result.Hashes.SHA256, "sha512": result.Hashes.SHA512,
	} {
		add("artifact.hash."+algorithm, value, strings.ToLower(value), location(0, result.Size), "artifact-hasher")
	}
	add("pe.metadata.headers", result.Headers, result.Headers, location(0, int64(result.Headers.SizeOfHeaders)), "pe-headers")

	for _, section := range result.Sections {
		add("pe.section", section, map[string]any{
			"name": section.Name, "virtual_address": section.VirtualAddress,
			"virtual_size": section.VirtualSize, "raw_size": section.RawSize,
			"characteristics": section.Characteristics,
		}, location(int64(section.RawOffset), int64(section.RawSize)), "pe-section-table")
	}
	for _, value := range result.Strings {
		add("pe.string."+strings.ToLower(value.Encoding), value.Value, value.Value,
			location(int64(value.Offset), int64(value.Length)), "bounded-string-scan")
	}
	for _, imported := range result.Imports {
		name := imported.Name
		if name == "" {
			name = fmt.Sprintf("ordinal:%d", imported.Ordinal)
		}
		add("pe.import", imported, strings.ToLower(imported.DLL+"!"+name),
			location(0, 0), "pe-import-directory")
	}
	for _, exported := range result.Exports {
		add("pe.export", exported, map[string]any{
			"name": exported.Name, "ordinal": exported.Ordinal, "rva": exported.RVA,
		}, location(int64(exported.FileOffset), 0), "pe-export-directory")
	}
	if result.Resources.Present {
		add("pe.resource.summary", result.Resources, map[string]any{
			"present": true, "entry_count": len(result.Resources.Entries),
			"directory_rva": result.Resources.DirectoryRVA,
		}, location(0, 0), "pe-resource-directory")
		for _, resource := range result.Resources.Entries {
			add("pe.resource.entry", resource, resource, location(0, int64(resource.DataSize)), "pe-resource-directory")
		}
	}
	for _, hint := range result.CapabilityHints {
		add("capability.hint", hint, map[string]any{
			"capability": hint.Capability, "matched_imports": hint.MatchedImports,
			"confidence": hint.Confidence,
		}, location(0, 0), "deterministic-import-rule")
	}
	return observations
}
