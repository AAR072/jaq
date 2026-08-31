"""Module entry point for ``python -m jaq_investigator``."""

from .cli import main


if __name__ == "__main__":  # pragma: no cover - exercised by process wrapper
    raise SystemExit(main())
