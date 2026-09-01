"""Deterministic operational-asset candidate extraction from inert evidence."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit


_URL = re.compile(r"https?://[^\s\"'<>]{4,2048}", re.IGNORECASE)
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b", re.IGNORECASE)
_IP = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_TOKEN = re.compile(r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,255}|xox[baprs]-[A-Za-z0-9-]{10,255}|sk-[A-Za-z0-9_-]{16,255}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b")
_WALLET = re.compile(r"\b(?:bc1[a-zA-HJ-NP-Z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|0x[a-fA-F0-9]{40})\b")
_PEM = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_PEM_BLOCK = re.compile(r"-----BEGIN (?P<label>(?:(?:RSA|EC|OPENSSH) )?PRIVATE KEY|CERTIFICATE)-----[A-Za-z0-9+/=\r\n]{16,65536}-----END (?P=label)-----")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|co|info|biz|top|xyz|onion)\b", re.I)
_CONNECTION = re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|jdbc:[a-z0-9]+)://[^\s\"'<>]{3,2048}", re.I)
_PIPE = re.compile(r"\\\\\.\\pipe\\[^\s\"']{1,256}", re.I)
_REGISTRY = re.compile(r"\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER)|HKLM|HKCU|SOFTWARE|SYSTEM)\\[^\r\n\"']{2,512}", re.I)
_HASH = re.compile(r"\b[a-fA-F0-9]{64}\b")
_LABELED_SECRET = re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|bearer|password|passwd|secret)\s*[:=]\s*([A-Za-z0-9._~+/=-]{8,512})")
_COMMAND_START = re.compile(r"(?i)^(?:cmd\.exe\s+/c|powershell(?:\.exe)?\b|wmic\b|vssadmin\b|bcdedit\b|reagentc\b)")


@dataclass(frozen=True)
class Candidate:
    id: str
    type: str
    value: str
    normalized_value: str
    role: str
    evidence_ids: tuple[str, ...]
    confidence: float = 0.95

    def to_dict(self) -> dict[str, Any]:
        return {**self.__dict__, "evidence_ids": list(self.evidence_ids)}


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item)


def extract_candidates(observations: Iterable[Any], limit: int = 500) -> list[Candidate]:
    found: dict[tuple[str, str], set[str]] = {}
    values: dict[tuple[str, str], tuple[str, str, float]] = {}
    for observation in observations:
        observation_id = getattr(observation, "id", None)
        if not isinstance(observation_id, str):
            continue
        provenance = getattr(observation, "provenance", {})
        if isinstance(provenance, Mapping) and provenance.get("stage") == "agent-tool-request":
            continue
        for text in _strings([getattr(observation, "raw_value", None), getattr(observation, "normalized_value", None)]):
            for url in _URL.findall(text):
                clean = url.rstrip(".,);]}")
                parts = urlsplit(clean)
                normalized = urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path, parts.query, ""))
                role = "remote_payload_reference" if re.search(r"\.(?:exe|dll|bin|dat|zip|rar|7z)(?:$|\?)", normalized, re.I) else "network_infrastructure"
                key = ("url", normalized)
                values[key] = (clean, role, 0.98)
                found.setdefault(key, set()).add(observation_id)
                if parts.hostname:
                    domain_key = ("domain", parts.hostname.lower())
                    values[domain_key] = (parts.hostname, "network_infrastructure", 0.97)
                    found.setdefault(domain_key, set()).add(observation_id)
            for email in _EMAIL.findall(text):
                key = ("email", email.lower())
                values[key] = (email, "contact_or_account", 0.98)
                found.setdefault(key, set()).add(observation_id)
                domain = email.rsplit("@", 1)[1].lower()
                domain_key = ("domain", domain)
                values[domain_key] = (domain, "network_infrastructure", 0.95)
                found.setdefault(domain_key, set()).add(observation_id)
            for raw_ip in _IP.findall(text):
                try:
                    address = ipaddress.ip_address(raw_ip)
                except ValueError:
                    continue
                if address.is_unspecified or address.is_loopback:
                    continue
                key = ("ip_address", str(address))
                values[key] = (raw_ip, "network_infrastructure", 0.95)
                found.setdefault(key, set()).add(observation_id)
            for token in _TOKEN.findall(text):
                asset_type = "bearer_token" if token.startswith("eyJ") else "api_key"
                key = (asset_type, token)
                values[key] = (token, "embedded_credential", 0.99)
                found.setdefault(key, set()).add(observation_id)
            for wallet in _WALLET.findall(text):
                key = ("crypto_wallet", wallet)
                values[key] = (wallet, "payment_infrastructure", 0.97)
                found.setdefault(key, set()).add(observation_id)
            for domain in _DOMAIN.findall(text):
                key = ("domain", domain.lower().rstrip("."))
                values[key] = (domain, "network_infrastructure", 0.9)
                found.setdefault(key, set()).add(observation_id)
            for connection in _CONNECTION.findall(text):
                key = ("database_connection", connection)
                values[key] = (connection, "embedded_credential_or_configuration", 0.98)
                found.setdefault(key, set()).add(observation_id)
            for pipe in _PIPE.findall(text):
                key = ("named_pipe", pipe.lower())
                values[key] = (pipe, "interprocess_communication", 0.95)
                found.setdefault(key, set()).add(observation_id)
            for registry in _REGISTRY.findall(text):
                normalized_registry = registry.lower()
                if normalized_registry.startswith(("software\\", "system\\")):
                    normalized_registry = "hklm\\" + normalized_registry
                key = ("registry_path", normalized_registry)
                values[key] = (registry, "configuration_or_persistence", 0.9)
                found.setdefault(key, set()).add(observation_id)
            for digest in _HASH.findall(text):
                key = ("payload_hash", digest.lower())
                values[key] = (digest, "artifact_identifier", 0.95)
                found.setdefault(key, set()).add(observation_id)
            for label, secret in _LABELED_SECRET.findall(text):
                if secret.lower() in {"example", "changeme", "password", "redacted"}:
                    continue
                asset_type = "username_password" if label.lower() in {"password", "passwd"} else "api_key"
                key = (asset_type, secret)
                values[key] = (secret, "embedded_credential", 0.96)
                found.setdefault(key, set()).add(observation_id)
            for line in text.splitlines():
                stripped = line.strip()
                numbered = re.match(r"^\d+\s+(['\"])(.*)\1$", stripped)
                command = numbered.group(2) if numbered else stripped
                if not _COMMAND_START.match(command):
                    continue
                normalized = " ".join(command.split())
                key = ("command", normalized)
                values[key] = (command, "execution_or_sabotage_command", 0.95)
                found.setdefault(key, set()).add(observation_id)
            if _PEM.search(text) and not _PEM_BLOCK.search(text):
                marker = _PEM.search(text).group(0)
                key = ("private_key", marker)
                values[key] = (marker, "embedded_credential", 0.99)
                found.setdefault(key, set()).add(observation_id)
            for block in _PEM_BLOCK.finditer(text):
                value = block.group(0)
                asset_type = "certificate" if block.group("label") == "CERTIFICATE" else "private_key"
                key = (asset_type, value)
                values[key] = (value, "embedded_credential", 1.0)
                found.setdefault(key, set()).add(observation_id)
    if len(found) > limit:
        raise ValueError(f"operational candidate inventory exceeds {limit} entries")
    candidates = []
    for key in sorted(found):
        value, role, confidence = values[key]
        digest = hashlib.sha256((key[0] + "\0" + key[1]).encode()).hexdigest()[:20]
        candidates.append(Candidate(f"candidate-{digest}", key[0], value, key[1], role, tuple(sorted(found[key])), confidence))
    return candidates
