"""Keep a prompt template describing the schema its answers are checked against.

Every field an answer must carry is written down twice: in ``config/*.json``,
where it is enforced, and in ``templates/*.md``, where it is explained to
whoever answers the prompt. Nothing held the two together. A schema could pin a
type, or add a required field, that the template never mentioned — and the
prompt would go on describing the old shape, so an answer failed validation for
a reason the prompt had never stated.

That failure mode is expensive in a way a normal bug is not. There is no way to
discover it except by sending a prompt and reading the rejection, and a
rejection names one field at a time: a live run found four of these across four
round trips, fixing one and surfacing the next. A block of bullets in the
template now declares the schema it describes, and this module checks the two
still agree — every required field named, every declared type stated, every
enum value spelled out — so the whole class is caught at once, before a call.

The markers are addressed to this check, not to the reviewer; `strip_markers`
takes them back out at render time.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .paths import root

#: Opens a block of field bullets and binds it to the schema that enforces
#: them. ``#name`` addresses a nested object: the properties of ``name``, or of
#: its ``items`` when it is an array.
_OPEN = re.compile(
    r"^<!--\s*fields:\s*(?P<schema>[A-Za-z0-9_.-]+\.json)(?:#(?P<path>[a-z_]+))?\s*-->$"
)
_CLOSE = re.compile(r"^<!--\s*end fields\s*-->$")
#: Digits are part of a field name — ``scenario_prompt_sha256`` is one — and a
#: name class that omits them silently drops the bullet instead of checking it,
#: which reads downstream as "the template never names this field".
_BULLET = re.compile(r"^-\s+`(?P<name>[a-z0-9_]+)`")
_MARKER_LINE = re.compile(
    r"^[ \t]*<!--\s*(?:fields:[^>]*|end fields)\s*-->[ \t]*\r?\n", re.MULTILINE
)

#: Type words a bullet may use to name what the schema declares. Anything the
#: schema declares outside this set is not something a prompt can usefully
#: state, so it is not demanded.
_TYPE_WORDS = frozenset(
    {"string", "array", "object", "integer", "number", "boolean"}
)


def strip_markers(text: str) -> str:
    """Remove the binding markers, whole lines and all.

    Placed directly against the bullets they wrap, dropping the lines leaves
    the surrounding blank lines exactly as they were, so the rendered prompt is
    the template a reader sees minus two comments.
    """
    return _MARKER_LINE.sub("", text)


@dataclass
class _Bullet:
    name: str
    text: str
    line: int


@dataclass
class _Block:
    schema: str
    path: str
    line: int
    closed: bool = False
    bullets: list[_Bullet] = field(default_factory=list)

    @property
    def where(self) -> str:
        return f"{self.schema}#{self.path}" if self.path else self.schema


def _blocks(text: str) -> list[_Block]:
    blocks: list[_Block] = []
    current: _Block | None = None
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        opened = _OPEN.match(stripped)
        if opened:
            current = _Block(opened.group("schema"), opened.group("path") or "", number)
            blocks.append(current)
            continue
        if current is None:
            continue
        if _CLOSE.match(stripped):
            current.closed = True
            current = None
            continue
        bullet = _BULLET.match(line)
        if bullet:
            current.bullets.append(_Bullet(bullet.group("name"), stripped, number))
        elif current.bullets and stripped and line[:1] in " \t":
            # a wrapped bullet: the type word may be on the continuation line
            current.bullets[-1].text += " " + stripped
    return blocks


def _declared_types(spec: dict[str, Any]) -> set[str]:
    """Every type word this property may legitimately be described as."""
    words: set[str] = set()
    declared = spec.get("type")
    if isinstance(declared, str):
        words.add(declared)
    elif isinstance(declared, list):
        words.update(str(item) for item in declared)
    for key in ("oneOf", "anyOf"):
        for branch in spec.get(key, []):
            if isinstance(branch, dict):
                words.update(_declared_types(branch))
    return words & _TYPE_WORDS


def _enum_values(spec: dict[str, Any]) -> list[str]:
    return [value for value in spec.get("enum", []) if isinstance(value, str)]


def _resolve(schema: dict[str, Any], path: str) -> dict[str, Any]:
    """The object whose properties a block describes."""
    if not path:
        return schema
    node = schema.get("properties", {}).get(path)
    if not isinstance(node, dict):
        raise KeyError(path)
    while isinstance(node.get("items"), dict):
        node = node["items"]
    return node


def _says(text: str, word: str) -> bool:
    return re.search(rf"\b{re.escape(word)}\b", text, re.IGNORECASE) is not None


def _block_errors(label: str, block: _Block, schema: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    try:
        node = _resolve(schema, block.path)
    except KeyError:
        return [
            f"{label}:{block.line}: {block.schema} defines no `{block.path}` "
            "for this block to describe"
        ]
    properties = node.get("properties", {})
    if not isinstance(properties, dict):
        properties = {}
    described = {bullet.name for bullet in block.bullets}
    for name in node.get("required", []):
        if name not in described:
            errors.append(
                f"{label}:{block.line}: {block.where} requires `{name}`, "
                "which this block never names"
            )
    for bullet in block.bullets:
        spec = properties.get(bullet.name)
        if not isinstance(spec, dict):
            errors.append(
                f"{label}:{bullet.line}: `{bullet.name}` is described here but "
                f"{block.where} does not define it"
            )
            continue
        types = _declared_types(spec)
        if types and not any(_says(bullet.text, word) for word in types):
            errors.append(
                f"{label}:{bullet.line}: `{bullet.name}` is "
                f"{' or '.join(sorted(types))} in {block.where}, "
                "and the bullet does not say so"
            )
        values = _enum_values(spec)
        missing = [value for value in values if not _says(bullet.text, value)]
        if missing:
            errors.append(
                f"{label}:{bullet.line}: `{bullet.name}` accepts only "
                f"{', '.join(values)} in {block.where}, "
                f"and the bullet omits {', '.join(missing)}"
            )
    return errors


def template_contract_errors(base: Path | None = None) -> list[str]:
    """Disagreements between every marked template block and its schema."""
    base = base or root()
    schemas: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for template in sorted((base / "templates").glob("*.md")):
        label = f"templates/{template.name}"
        for block in _blocks(template.read_text(encoding="utf-8")):
            if not block.closed:
                errors.append(
                    f"{label}:{block.line}: field block for {block.schema} "
                    "is never closed"
                )
            if block.schema not in schemas:
                source = base / "config" / block.schema
                try:
                    schemas[block.schema] = json.loads(
                        source.read_text(encoding="utf-8")
                    )
                except Exception as exc:
                    errors.append(f"{label}:{block.line}: cannot read {block.schema}: {exc}")
                    continue
            errors.extend(_block_errors(label, block, schemas[block.schema]))
    return errors
