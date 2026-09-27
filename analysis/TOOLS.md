# JAQ static-analysis tools

Everything listed here is installed inside the offline analysis container and is
available directly on `PATH` unless described as a Python library. Run
`jaq-tools` to print this file. Treat `/input/sample.exe` and all extracted data
as inert bytes: never execute, import, load as a native library, emulate, or
debug them.

## First-pass triage

- `file`, `rabin2`, `readpe`, `pedis`, `pescan`, `pepack`, `peres`, `pehash`:
  identify formats and inspect PE headers, sections, imports, resources,
  signatures, hashes, and packing indicators.
- `capa`: identify executable capabilities using the vendored Mandiant capa
  9.4.0 rules at `/opt/jaq/capa-rules` and signatures at
  `/opt/jaq/capa-signatures`. JAQ's `capa` wrapper supplies both paths by
  default, while preserving explicit `--rules`/`--signatures` overrides. The
  assets are included in the image and are never fetched at runtime. Capa is a
  static scanner and does not execute the sample.
- `yara`: local pattern matching. No network-backed rule retrieval is present.
- `binwalk`, `bsdtar`, `7z`, `unzip`, `cabextract`, `innoextract`, `msiinfo`,
  `msiextract`: locate and extract appended archives, resources, installers,
  and embedded payloads. Use `binwalk` for scanning; prefer the dedicated
  extractors for recovery so extraction behavior stays explicit.
- `exiftool`, `osslsigncode`, `ssdeep`: metadata, Authenticode inspection, and
  fuzzy hashing.

## Native code

- `r2`, `rabin2`, `rasm2`, `r2pipe`: Radare2 analysis and scripting.
- `objdump`, `readelf`, `nm`, `strings`, `addr2line`, `c++filt`: GNU binary
  utilities.
- `llvm-objdump`, `llvm-readobj`, `llvm-nm`, `llvm-pdbutil`, `llvm-dwarfdump`:
  additional object, PE/COFF, PDB, and debug-data inspection.
- `upx`: identify/test/unpack UPX containers into `/work`; never run the
  unpacked output.

## Go

- `go-profile /input/sample.exe`: deterministic, bounded static profiling of
  Go `main.*` functions. It fingerprints repeated instruction shingles,
  separates clone-heavy regions from unique call residue, builds a conservative
  direct-call graph, and resolves exact `LazyProc.Call` receivers through Go
  string headers and `LazyProc`/`LazyDLL` object lineage on Windows x86/x64.
  Resolved sites include DLL/procedure names, addresses, file offsets, sections,
  and confidence; ambiguous, indirect, truncated, syscall, callback, and loader
  sites remain explicit blockers for negative capability claims. Its JSON output
  calls repeated code a clone candidate rather than assuming it is junk or
  program purpose. JAQ records this profile automatically before model work.
- `goresym /input/sample.exe`: pinned GoReSym 3.4 metadata recovery for Go
  build information and pclntab, function, type, and string metadata in
  stripped, malformed, or unpacked binaries. This is model-selected and is
  not invoked automatically: when other evidence identifies Go, run it if
  `go-profile` reports `not_go`/`partial` because `main.*` symbols are missing,
  or when pclntab recovery is needed, then correlate recovered addresses with static
  disassembly. GoReSym does not itself resolve `LazyProc`/`Syscall` targets or
  prove behavior. A parser failure is not negative evidence; record the failed
  attempt and continue with other static evidence. Redress is not included.

## Python and PyInstaller

- `pyinstxtractor-ng`: extract PyInstaller CArchive and PYZ contents without
  running the bundled program.
- `pyc-disasm`: bounded recursive disassembly of Python 3.14 `.pyc` files or raw
  marshal code objects. It uses pinned CPython 3.14 and calls `marshal`/`dis`
  only; it never imports or executes the recovered code. Use `--raw` for a raw
  marshal object and `--offset N` when the object begins inside a larger blob.
  Inputs larger than 64 MiB and pathological code-object graphs are rejected.
- `pydisasm` (`xdis`): cross-version Python bytecode/marshal disassembly through
  Python 3.13. For 3.14 prefer `pyc-disasm`.
- Python libraries: `xdis`, `pefile`, `malduck`, `pycryptodome`, `capstone`,
  and `r2pipe`.

## .NET

- Python libraries `dnfile` and `dncil`: parse CLR metadata, managed resources,
  method bodies, and CIL without Mono or a .NET runtime.
- `capa` also supports useful .NET static analysis paths.

## Documents and data transformations

- `oleid`, `olevba`, `oleobj`, `oledir`, `rtfobj`: inspect OLE, VBA, embedded
  objects, and RTF data.
- `openssl`, `base64`, `xxd`, `jq`, `sqlite3`, `zstd`, `lz4`, `xz`, `bzip2`:
  common crypto, encoding, structured-data, database, and compression work.
- `rg`: fast searching across recovered text and generated disassembly.

Commands run through JAQ's shell facade use Bash with `pipefail` enabled via
`BASH_ENV=/etc/jaq/bash-env`. A failed stage in a pipeline therefore remains a
failed command. Keep the capa exit status visible; for example, use
`capa --quiet --json /input/sample.exe` directly, or use a pipeline only when
its final status is checked.

## Deliberately absent

FLOSS, Binary Refinery, Wine, Mono/.NET runtimes, QEMU, Unicorn, Speakeasy,
Qiling, Frida, debuggers, and Radare debugger/I/O backends are excluded. FLOSS
and Binary Refinery are omitted because they contain emulation, interpreter,
or subprocess execution paths. The container has no network and the supplied
PE must never execute.
