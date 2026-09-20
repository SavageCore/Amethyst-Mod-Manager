"""Support for Vortex ``vortex_override_instructions.json`` (Vortex >= 1.14).

Honors ``setmodtype`` (reroutes the payload to a known mod-type destination
such as NMS ``Binaries/``) and ``copy`` (per-file remap under that root).
``generatefile`` / ``unsupported`` / ``error`` are dropped; ``submodule`` /
``iniedit`` / ``attribute`` / ``rule`` are logged and ignored. The override
file itself is never installed. Applies to manual and collection installs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


OVERRIDE_FILENAME = "vortex_override_instructions.json"

# Refused by Vortex itself (potentially malicious).
_DROPPED_TYPES = frozenset({"generatefile", "unsupported", "error"})

# No Amethyst equivalent (logged + ignored).
_IGNORED_TYPES = frozenset(
    {"submodule", "iniedit", "attribute", "rule", "enableallplugins"})

# Mod-type id -> game-root-relative destination ("" = game root itself).
MODTYPE_GAME_ROOT_DESTS = {
    "nomanssky-binaries": "Binaries",
    "nomanssky-deprecated-pak": "GAMEDATA/PCBANKS/MODS",
    "dinput": "",
}

# Only valid for No Man's Sky (Vortex checks support per game).
_NMS_ONLY_MODTYPES = frozenset(
    {"nomanssky-binaries", "nomanssky-deprecated-pak"})


@dataclass
class OverrideSpec:
    """Parsed override: one mod type + per-file copy remaps."""
    modtype: str | None = None
    copies: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    dropped_unsafe: int = 0


def find_override_file(search_root: str | Path) -> Path | None:
    """Find the override JSON at the root or one folder down (wrapped mods)."""
    root = Path(search_root)
    if not root.is_dir():
        return None
    direct = _child_named(root, OVERRIDE_FILENAME)
    if direct is not None:
        return direct
    try:
        children = list(root.iterdir())
    except OSError:
        return None
    if len(children) == 1 and children[0].is_dir():
        return _child_named(children[0], OVERRIDE_FILENAME)
    return None


def _child_named(directory: Path, name: str) -> Path | None:
    lowered = name.lower()
    try:
        for child in directory.iterdir():
            if child.is_file() and child.name.lower() == lowered:
                return child
    except OSError:
        return None
    return None


def _clean_rel(value, *, label: str) -> str:
    """Normalise a relative path, rejecting absolute or escaping values."""
    raw = value if isinstance(value, str) else os_fspath_str(value)
    if "\x00" in raw or "\n" in raw or "\r" in raw:
        raise ValueError(f"{label} contains an invalid character: {raw!r}")
    normalised = raw.replace("\\", "/").strip()
    if not normalised or normalised.startswith("/") or (
            len(normalised) >= 2 and normalised[1] == ":"):
        raise ValueError(f"{label} is not a relative path: {raw!r}")
    parts: list[str] = []
    for part in normalised.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise ValueError(f"{label} escapes the mod root: {raw!r}")
        parts.append(part)
    if not parts:
        raise ValueError(f"{label} is empty: {raw!r}")
    return "/".join(parts)


def os_fspath_str(value) -> str:
    import os
    raw = os.fspath(value)
    return raw if isinstance(raw, str) else os.fsdecode(raw)


def parse_override_instructions(raw_text: str) -> OverrideSpec:
    """Parse override JSON. Raises ValueError on malformed content."""
    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    if not isinstance(data, list):
        raise ValueError("top level must be an array of instructions")
    spec = OverrideSpec()
    for entry in data:
        if not isinstance(entry, dict):
            spec.warnings.append("skipped a non-object instruction entry")
            continue
        itype = str(entry.get("type", "")).strip().lower()
        if itype in _DROPPED_TYPES:
            spec.dropped_unsafe += 1
            continue
        if itype == "setmodtype":
            value = str(entry.get("value", "")).strip()
            if not value:
                spec.warnings.append("skipped an empty setmodtype instruction")
                continue
            if spec.modtype is None:
                spec.modtype = value
            else:
                spec.warnings.append(
                    f"multiple setmodtype entries - keeping "
                    f"'{spec.modtype}', ignoring '{value}'")
        elif itype == "copy":
            try:
                src = _clean_rel(entry.get("source", ""), label="copy source")
                dst = _clean_rel(entry.get("destination", ""),
                                 label="copy destination")
            except (ValueError, TypeError) as exc:
                spec.warnings.append(f"skipped a copy instruction ({exc})")
                continue
            spec.copies.append((src, dst))
        elif itype == "mkdir":
            continue  # implied by copy destinations
        elif itype in _IGNORED_TYPES:
            spec.warnings.append(
                f"ignoring unsupported instruction type '{itype}'")
        elif not itype:
            spec.warnings.append("skipped an instruction with no type")
        else:
            spec.warnings.append(
                f"ignoring unknown instruction type '{itype}'")
    return spec


def _game_texts(game) -> str:
    """Lowercased identifying text for *game* (best effort)."""
    bits: list[str] = []
    for attr in ("name", "game_id", "exe_name"):
        try:
            value = getattr(game, attr, "")
        except Exception:
            continue
        if value:
            bits.append(str(value))
    try:
        defn = getattr(game, "_defn", None)
    except Exception:
        defn = None
    if isinstance(defn, dict):
        for key in ("name", "game_id", "exe_name", "mod_data_path",
                    "nexus_game_domain"):
            value = defn.get(key, "")
            if value:
                bits.append(str(value))
    try:
        data_path = game.get_mod_data_path()
    except Exception:
        data_path = None
    if data_path is not None:
        bits.append(str(data_path))
    return "\n".join(bits).lower()


def looks_like_nms(game) -> bool:
    """True when *game* looks like No Man's Sky."""
    text = _game_texts(game)
    return ("nomanssky" in text or "no man" in text
            or "nms.exe" in text or "gamedata/mods" in text)


def resolve_modtype_dest(game, value: str) -> tuple[str | None, str | None]:
    """Map a setmodtype value to a game-root-relative dest ("" = game root).

    Returns (dest, None), or (None, reason) when unknown/unsupported.
    """
    key = (value or "").strip().lower()
    if key not in MODTYPE_GAME_ROOT_DESTS:
        return None, f"unknown mod type '{value}'"
    if key in _NMS_ONLY_MODTYPES and not looks_like_nms(game):
        return None, f"mod type '{value}' is for No Man's Sky"
    return MODTYPE_GAME_ROOT_DESTS[key], None


def _norm_src(rel: str) -> str:
    return rel.replace("\\", "/").strip().strip("/").lower()


def apply_override_to_file_list(game, stage_root: str,
                                file_list: list[tuple[str, str, bool]],
                                log_fn=None) -> tuple[list, str | None]:
    """Apply an on-disk override to a staged *file_list*.

    Returns (new_file_list, redirect_dest); redirect_dest is None when
    nothing was redirected (caller must not set the root-folder flag).
    The override file entry itself is always dropped.
    """
    _log = log_fn or (lambda _m: None)
    override_path = find_override_file(stage_root)
    if override_path is None:
        return file_list, None
    try:
        rel_override = _norm_src(
            str(override_path.relative_to(Path(stage_root))))
    except ValueError:
        rel_override = OVERRIDE_FILENAME
    try:
        spec = parse_override_instructions(
            override_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _log(f"Vortex override: ignoring unreadable "
             f"{OVERRIDE_FILENAME} ({exc}).")
        return _drop_override_entries(file_list, rel_override), None

    if spec.dropped_unsafe:
        _log(f"Vortex override: dropped {spec.dropped_unsafe} unsafe "
             f"instruction(s) (generatefile/unsupported/error).")
    for warning in spec.warnings:
        _log(f"Vortex override: {warning}.")

    remaining = _drop_override_entries(file_list, rel_override)
    if spec.modtype is None and not spec.copies:
        _log("Vortex override: file has no usable instructions - ignored.")
        return remaining, None

    dest: str | None = None
    if spec.modtype is not None:
        resolved, reason = resolve_modtype_dest(game, spec.modtype)
        if resolved is None:
            _log(f"Vortex override: {reason} - mod type ignored.")
        else:
            dest = resolved
            label = dest if dest else "game root"
            _log(f"Vortex override: setmodtype '{spec.modtype}' "
                 f"-> {label}.")

    if spec.modtype is not None and dest is None and not spec.copies:
        return remaining, None

    # Case-insensitive source index; falls back to an unambiguous
    # trailing-suffix match for wrapper-folder offsets.
    by_src: dict[str, list[int]] = {}
    for idx, (src_rel, _dst, _folder) in enumerate(remaining):
        by_src.setdefault(_norm_src(src_rel), []).append(idx)

    def _match(source: str) -> int | None:
        key = _norm_src(source)
        hits = by_src.get(key)
        if hits:
            return hits[0]
        suffix = "/" + key
        candidates = [idx for norm, idxs in by_src.items()
                      for idx in idxs if norm.endswith(suffix)]
        if len(candidates) == 1:
            return candidates[0]
        return None

    new_list = list(remaining)
    matched: set[int] = set()
    if spec.copies:
        for source, destination in spec.copies:
            idx = _match(source)
            if idx is None:
                _log(f"Vortex override: copy source '{source}' not found "
                     f"in archive - skipped.")
                continue
            src_rel, _dst, is_folder = new_list[idx]
            staged = f"{dest}/{destination}" if dest else destination
            new_list[idx] = (src_rel, staged, is_folder)
            matched.add(idx)
        if dest:
            # Copy destinations are relative to the mod-type root, so the
            # rest of the payload moves under it too.
            for idx, (src_rel, dst_rel, is_folder) in enumerate(new_list):
                if idx not in matched:
                    new_list[idx] = (src_rel, _prefixed(dest, dst_rel),
                                     is_folder)
            rerouted = len(new_list)
        else:
            rerouted = len(matched)
        if rerouted:
            label = dest if dest else "game root"
            _log(f"Vortex override: rerouted {rerouted} file(s) under "
                 f"{label}.")
    elif dest is not None and spec.modtype is not None:
        # Pure setmodtype: move the whole payload under the mod-type root.
        for idx, (src_rel, dst_rel, is_folder) in enumerate(new_list):
            new_list[idx] = (src_rel, _prefixed(dest or "", dst_rel),
                             is_folder)
        rerouted = len(new_list)
        _log(f"Vortex override: rerouted {rerouted} file(s) under "
             f"{dest if dest else 'game root'}.")

    redirect = dest if (rerouted and spec.modtype is not None) else None
    if spec.modtype is None:
        redirect = None
    return new_list, redirect


def _prefixed(base: str, dst_rel: str) -> str:
    if not base:
        return dst_rel
    trailing = dst_rel.endswith("/") or dst_rel.endswith("\\")
    stripped = dst_rel.replace("\\", "/").strip("/")
    return f"{base}/{stripped}" + ("/" if trailing else "")


def _drop_override_entries(file_list: list[tuple[str, str, bool]],
                           rel_override: str) -> list:
    """Drop the override file's own staging entries."""
    result = []
    for entry in file_list:
        src_rel = entry[0]
        norm = _norm_src(src_rel)
        if norm == rel_override or (
                Path(norm).name == OVERRIDE_FILENAME
                and str(Path(norm).parent) == str(Path(rel_override).parent)):
            continue
        result.append(entry)
    return result


def apply_override_to_staged_tree(game, payload_root: str,
                                  dest_root: Path,
                                  log_fn=None) -> str | None:
    """Apply an override to an already-staged tree (FOMOD path).

    Whole-mod ``setmodtype`` only; per-file ``copy`` entries can't map back
    through FOMOD renames. Returns the redirect dest ("" = game root) or None.
    """
    _log = log_fn or (lambda _m: None)
    override_path = find_override_file(payload_root)
    if override_path is None:
        return None
    try:
        spec = parse_override_instructions(
            override_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        _log(f"Vortex override: ignoring unreadable "
             f"{OVERRIDE_FILENAME} ({exc}).")
        return None
    if spec.dropped_unsafe:
        _log(f"Vortex override: dropped {spec.dropped_unsafe} unsafe "
             f"instruction(s) (generatefile/unsupported/error).")
    for warning in spec.warnings:
        _log(f"Vortex override: {warning}.")
    if spec.modtype is None:
        if spec.copies:
            _log("Vortex override: per-file copy entries can't be mapped "
                 "onto FOMOD output - ignored.")
        else:
            _log("Vortex override: file has no usable instructions - ignored.")
        return None
    dest, reason = resolve_modtype_dest(game, spec.modtype)
    if dest is None:
        _log(f"Vortex override: {reason} - ignored.")
        return None
    label = dest if dest else "game root"
    _log(f"Vortex override: setmodtype '{spec.modtype}' -> {label}.")
    if spec.copies:
        _log("Vortex override: per-file copy entries folded into the "
             "whole-mod redirect.")

    for child in Path(dest_root).rglob("*"):
        try:
            if child.is_file() and child.name.lower() == OVERRIDE_FILENAME:
                child.unlink()
        except OSError:
            pass
    if dest:
        target = Path(dest_root) / dest
        try:
            target.mkdir(parents=True, exist_ok=True)
            for child in list(Path(dest_root).iterdir()):
                if child == target or child.name == "meta.ini":
                    continue
                child.rename(target / child.name)
        except OSError as exc:
            _log(f"Vortex override: reroute failed ({exc}) - ignored.")
            return None
    return dest
