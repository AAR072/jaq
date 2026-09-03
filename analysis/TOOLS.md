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
- `capa`: identify executable capabilities using Mandiant capa rules.
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

## Deliberately absent

FLOSS, Binary Refinery, Wine, Mono/.NET runtimes, QEMU, Unicorn, Speakeasy,
Qiling, Frida, debuggers, and Radare debugger/I/O backends are excluded. FLOSS
and Binary Refinery are omitted because they contain emulation, interpreter,
or subprocess execution paths. The container has no network and the supplied
PE must never execute.
