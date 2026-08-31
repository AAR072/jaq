"""Read-only access to the controller-created observation package.

``EvidenceStore`` opens exactly one path supplied by the controller at
construction time.  No operation accepts a path, URL, shell expression, or
model-provided locator.  Queries operate on validated IDs and bounded literal
search terms only.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import json
from pathlib import Path
from typing import Any

from .schemas import Observation, SchemaError, as_observation


class EvidenceError(ValueError):
    """Raised when the evidence package cannot be loaded or queried safely."""


class EvidenceStore:
    """A small, immutable-in-use index over ``observations.jsonl``."""

    MAX_SEARCH_CHARS = 256
    MAX_RESULTS = 100
    DEFAULT_RESULTS = 20

    def __init__(self, observations_path: str | Path) -> None:
        if not isinstance(observations_path, (str, Path)):
            raise EvidenceError("observations_path must be supplied by the controller")
        path = Path(observations_path)
        if not path.is_file():
            raise EvidenceError(f"observations file does not exist: {path}")
        self._observations_path = path
        observations: list[Observation] = []
        by_id: dict[str, Observation] = {}
        try:
            with path.open("r", encoding="utf-8", newline="") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.strip():
                        continue
                    try:
                        decoded = json.loads(line)
                    except json.JSONDecodeError as exc:
                        raise EvidenceError(
                            f"invalid observations JSON at line {line_number}"
                        ) from exc
                    try:
                        observation = as_observation(decoded)
                    except SchemaError as exc:
                        raise EvidenceError(
                            f"invalid observation at line {line_number}: {exc}"
                        ) from exc
                    if observation.id in by_id:
                        raise EvidenceError(f"duplicate observation ID: {observation.id}")
                    observations.append(observation)
                    by_id[observation.id] = observation
        except OSError as exc:
            raise EvidenceError(f"could not read observations file: {path}") from exc
        self._observations = tuple(sorted(observations, key=lambda item: item.id))
        self._by_id = by_id

    @classmethod
    def from_observations(cls, observations: Iterable[Observation | Mapping[str, Any]]) -> "EvidenceStore":
        """Build an in-memory store for tests and controller adapters.

        This helper does not accept a path and therefore cannot broaden the
        model's filesystem access.  Production callers should construct the
        store with the controller-selected observations file.
        """

        instance = cls.__new__(cls)
        normalized = [as_observation(item) for item in observations]
        by_id: dict[str, Observation] = {}
        for observation in normalized:
            if observation.id in by_id:
                raise EvidenceError(f"duplicate observation ID: {observation.id}")
            by_id[observation.id] = observation
        instance._observations_path = None
        instance._observations = tuple(sorted(normalized, key=lambda item: item.id))
        instance._by_id = by_id
        return instance

    @property
    def observations(self) -> list[Observation]:
        """Return a fresh list; callers cannot mutate the store's index."""

        return list(self._observations)

    def list_observations(
        self,
        type: str | None = None,
        *,
        limit: int | None = None,
        cursor: str | None = None,
    ) -> list[Observation]:
        """List observations, optionally filtered by exact type.

        ``limit`` and ``cursor`` are controller-facing pagination conveniences;
        the core operation still returns only validated observations.  A
        cursor is an exact ID and never a prefix or path.
        """

        if type is not None and (not isinstance(type, str) or not type.strip()):
            raise EvidenceError("type must be a nonempty string or null")
        values = list(self._observations) if type is None else [
            item for item in self._observations if item.type == type
        ]
        if cursor is not None:
            if not isinstance(cursor, str):
                raise EvidenceError("cursor must be an exact observation ID or null")
            if cursor not in self._by_id:
                return []
            values = [item for item in values if item.id > cursor]
        if limit is None:
            return values
        return values[: self._validate_limit(limit)]

    # A concise alias is useful when exposing this object as a typed tool.
    list = list_observations

    def list_types(self) -> list[str]:
        return sorted({item.type for item in self._observations})

    def list_observation_types(self) -> list[str]:
        """Compatibility spelling for the investigator's typed tool adapter."""

        return self.list_types()

    def get(self, observation_id: str) -> Observation | None:
        """Get by exact ID; no prefix, path, or fuzzy lookup is performed."""

        if not isinstance(observation_id, str):
            raise EvidenceError("observation_id must be a string")
        return self._by_id.get(observation_id)

    def get_observation(
        self,
        observation_id: str | None = None,
        *,
        id: str | None = None,
    ) -> Observation | None:
        """Get by exact ID, accepting the tool adapter's ``id=`` spelling."""

        if observation_id is not None and id is not None:
            raise EvidenceError("supply observation_id or id, not both")
        selected = observation_id if observation_id is not None else id
        if selected is None:
            raise EvidenceError("observation ID is required")
        return self.get(selected)

    def require(self, observation_id: str) -> Observation:
        observation = self.get(observation_id)
        if observation is None:
            raise KeyError(observation_id)
        return observation

    @staticmethod
    def _normalized_text(value: Any) -> str:
        if isinstance(value, str):
            return value
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @classmethod
    def _validate_limit(cls, limit: int) -> int:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise EvidenceError("limit must be an integer")
        if limit < 1 or limit > cls.MAX_RESULTS:
            raise EvidenceError(f"limit must be between 1 and {cls.MAX_RESULTS}")
        return limit

    def search(
        self,
        literal: str,
        limit: int = DEFAULT_RESULTS,
        *,
        type: str | None = None,
    ) -> list[Observation]:
        """Case-insensitive literal search over type and normalized values.

        Raw values are intentionally excluded: model-facing search should not
        turn untrusted binary strings or comments into an instruction channel.
        The query is never treated as a regular expression or shell fragment.
        """

        if not isinstance(literal, str):
            raise EvidenceError("search literal must be a string")
        if len(literal) > self.MAX_SEARCH_CHARS:
            raise EvidenceError(f"search literal is limited to {self.MAX_SEARCH_CHARS} characters")
        limit = self._validate_limit(limit)
        if type is not None and (not isinstance(type, str) or not type.strip()):
            raise EvidenceError("type must be a nonempty string or null")
        if literal == "":
            return []
        needle = literal.casefold()
        matches: list[Observation] = []
        for observation in self._observations:
            if type is not None and observation.type != type:
                continue
            haystacks = (
                observation.type,
                self._normalized_text(observation.normalized_value),
            )
            if any(needle in haystack.casefold() for haystack in haystacks):
                matches.append(observation)
                if len(matches) >= limit:
                    break
        return matches

    def search_observations(
        self,
        *,
        query: str,
        type: str | None = None,
        limit: int = DEFAULT_RESULTS,
    ) -> dict[str, Any]:
        """Return the same bounded search as a JSON-tool-shaped result."""

        matches = self.search(query, limit=limit, type=type)
        return {"observations": [item.to_dict() for item in matches]}

    @staticmethod
    def _cited_ids(value: str | Iterable[str]) -> tuple[str, ...]:
        if isinstance(value, str):
            values = (value,)
        else:
            try:
                values = tuple(value)
            except TypeError as exc:
                raise EvidenceError("observation IDs must be strings") from exc
        result: list[str] = []
        for item in values:
            if not isinstance(item, str) or not item.strip():
                raise EvidenceError("observation IDs must be nonempty strings")
            if item not in result:
                result.append(item)
        return tuple(result)

    @staticmethod
    def _validate_direction(direction: str) -> str:
        if direction not in {"out", "in", "both"}:
            raise EvidenceError("direction must be out, in, or both")
        return direction

    def _edges(self, relation: str = "all") -> list[tuple[str, str]]:
        """Build edges solely from structured observation relationship fields."""

        relation_key = relation.casefold() if isinstance(relation, str) else ""
        if relation_key not in {
            "all",
            "relationship",
            "relationships",
            "call",
            "calls",
            "reference",
            "references",
        }:
            raise EvidenceError("relation must be all, calls, or references")
        edges: list[tuple[str, str]] = []
        for observation in self._observations:
            if relation_key in {"call", "calls"}:
                targets = observation.relation_ids("calls")
            elif relation_key in {"reference", "references"}:
                targets = observation.relation_ids("references")
            else:
                targets = observation.relation_ids("all")
            for target in targets:
                if target in self._by_id and target != observation.id:
                    edges.append((observation.id, target))

            # Some analyzers encode one relationship observation with explicit
            # endpoints.  These are structured IDs, not text to be parsed.
            if relation_key in {"all", "relationship", "relationships"}:
                endpoint_source = self._endpoint_ids(observation, "source")
                endpoint_target = self._endpoint_ids(observation, "target")
                for source in endpoint_source:
                    for target in endpoint_target:
                        if source in self._by_id and target in self._by_id and source != target:
                            edges.append((source, target))
        return list(dict.fromkeys(edges))

    @staticmethod
    def _endpoint_ids(observation: Observation, endpoint: str) -> tuple[str, ...]:
        names = (
            ("source_id", "source", "from", "caller_id", "caller")
            if endpoint == "source"
            else ("target_id", "target", "to", "callee_id", "callee")
        )
        values: list[str] = []
        for container in (observation.relationships, observation.metadata, observation.extra):
            for name in names:
                value = container.get(name)
                if isinstance(value, str) and value.strip():
                    values.append(value)
                elif isinstance(value, (list, tuple)):
                    values.extend(item for item in value if isinstance(item, str) and item.strip())
        return tuple(dict.fromkeys(values))

    def relationship_edges(self, relation: str = "all") -> list[tuple[str, str]]:
        """Return a deterministic copy of structured relationship edges."""

        return sorted(self._edges(relation), key=lambda edge: (edge[0], edge[1]))

    def neighbors(
        self,
        observation_ids: str | Iterable[str],
        *,
        relation: str = "all",
        direction: str = "both",
        limit: int = DEFAULT_RESULTS,
    ) -> list[Observation]:
        """Return call/reference neighbors of cited observations.

        Source IDs are exact.  Unknown source IDs simply have no neighbors;
        they cannot cause a filesystem access or a fuzzy search.
        """

        cited = self._cited_ids(observation_ids)
        direction = self._validate_direction(direction)
        limit = self._validate_limit(limit)
        edge_list = self._edges(relation)
        cited_set = set(cited)
        result_ids: set[str] = set()
        for source, target in edge_list:
            if direction in {"out", "both"} and source in cited_set:
                result_ids.add(target)
            if direction in {"in", "both"} and target in cited_set:
                result_ids.add(source)
        result_ids.difference_update(cited_set)
        return [self._by_id[item] for item in sorted(result_ids)[:limit]]

    def call_neighbors(
        self,
        observation_ids: str | Iterable[str],
        *,
        direction: str = "both",
        limit: int = DEFAULT_RESULTS,
    ) -> list[Observation]:
        return self.neighbors(observation_ids, relation="calls", direction=direction, limit=limit)

    def reference_neighbors(
        self,
        observation_ids: str | Iterable[str],
        *,
        direction: str = "both",
        limit: int = DEFAULT_RESULTS,
    ) -> list[Observation]:
        return self.neighbors(observation_ids, relation="references", direction=direction, limit=limit)

    def get_neighbors(self, *, id: str, limit: int = DEFAULT_RESULTS) -> list[dict[str, Any]]:
        """Return JSON-shaped call/reference neighbors for a typed tool call."""

        return [item.to_dict() for item in self.neighbors(id, limit=limit)]

    # Names used by a few typed-tool adapters.
    get_call_neighbors = call_neighbors
    get_reference_neighbors = reference_neighbors
    relationship_neighbors = neighbors

    def supports_reachability(
        self,
        entrypoints: Iterable[str],
        path_evidence_ids: Iterable[str],
        cited_evidence_ids: Iterable[str] = (),
    ) -> bool:
        """Check that structured relationship evidence supports a path.

        Entry points may be exact observation IDs or exact normalized string
        values.  A path must contain at least one relationship edge and all
        path IDs must exist.  This deliberately refuses to infer reachability
        from raw strings, comments, decompiler output, or names alone.
        """

        try:
            starts = self._cited_ids(entrypoints)
            path = self._cited_ids(path_evidence_ids)
            cited = self._cited_ids(cited_evidence_ids) if cited_evidence_ids else ()
        except EvidenceError:
            return False
        if not starts or not path or any(item not in self._by_id for item in path):
            return False
        allowed = set(path) | {item for item in cited if item in self._by_id}
        # Path records may be explicit relationship records whose endpoint IDs
        # are stored in structured metadata rather than as path nodes.  Include
        # those exact endpoints in the bounded graph when they exist.
        for path_id in path:
            path_observation = self._by_id[path_id]
            allowed.update(
                item
                for item in (
                    path_observation.relation_ids("all")
                    + self._endpoint_ids(path_observation, "source")
                    + self._endpoint_ids(path_observation, "target")
                )
                if item in self._by_id
            )
        allowed.update(item for item in starts if item in self._by_id)
        if not allowed:
            return False

        edges = self._edges("all")
        adjacency: dict[str, set[str]] = {item: set() for item in allowed}
        for source, target in edges:
            if source in allowed and target in allowed:
                adjacency[source].add(target)

        resolved_starts: set[str] = set()
        for start in starts:
            if start in self._by_id:
                resolved_starts.add(start)
                continue
            for observation in self._observations:
                if observation.id not in allowed:
                    continue
                if isinstance(observation.normalized_value, str) and observation.normalized_value == start:
                    resolved_starts.add(observation.id)
        if not resolved_starts:
            return False

        # A relationship edge must leave an entry point and lead to another
        # cited/path observation.  Merely citing an entrypoint or naming a
        # function is not enough to claim it is reachable.
        pending = [item for item in resolved_starts if item in allowed]
        visited = set(pending)
        traversed_from_path = False
        while pending:
            current = pending.pop(0)
            for target in sorted(adjacency.get(current, ())):
                if target not in visited:
                    visited.add(target)
                    pending.append(target)
                if current in set(path) or target in set(path):
                    traversed_from_path = True
        if bool((visited & set(path)) - resolved_starts):
            return True
        if traversed_from_path:
            return True

        # Explicit relationship records can connect IDs without themselves
        # being graph nodes.  Check their source/target fields directly while
        # keeping both endpoints exact and controller-provided.
        start_ids = set(resolved_starts)
        for path_id in path:
            relationship = self._by_id[path_id]
            sources = set(self._endpoint_ids(relationship, "source"))
            targets = set(self._endpoint_ids(relationship, "target"))
            if sources & start_ids and targets & (set(path) | set(cited)):
                return True
        return False


__all__ = ["EvidenceError", "EvidenceStore"]
