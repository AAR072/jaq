# JAQ

JAQ is an autonomous static-analysis tool for investigating Windows executables. It combines LLM-guided reverse engineering with offline analysis tools to turn PE files into evidence-backed intelligence reports.

## Features

- **Autonomous investigation** — Uses Radare2 and specialized analysis tools to uncover application behavior, communication paths, and embedded assets.
- **Isolated static analysis** — Inspects samples in a disposable, network-disabled Docker container without executing the supplied binary.
- **Broad analysis toolkit** — Includes tooling for native PE, .NET, Go, PyInstaller, Java/Kotlin, and Electron code.
- **Evidence-backed reports** — Produces readable Markdown reports and structured JSON, with findings linked to persisted analysis evidence.
- **Quality checks** — Validates findings, tracks coverage gaps, and marks incomplete investigations as partial.
- **Budget controls and recovery** — Supports configurable cost limits, durable findings, and recovery from saved evidence without additional model calls.

See [instructions.md](instructions.md) for setup, configuration, usage, and recovery.
