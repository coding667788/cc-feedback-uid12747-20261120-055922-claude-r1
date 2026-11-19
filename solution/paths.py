"""Protected-path canonicalization.

Windows semantics: paths are case-insensitive, ``\\`` and ``/`` are the same
separator, ``.`` segments and duplicate separators collapse.  The canonical
form folds case (drive letter upper-cased, the rest lower-cased) so that
``C:\\App\\A.EXE`` and ``c:/app/a.exe`` denote the same protected path.
"""


def canon_path(path: str) -> str:
    """Return the canonical (case-folded, separator-normalized) path."""
    if not isinstance(path, str):
        raise TypeError("path must be a string")
    p = path.strip().replace("\\", "/")
    parts = [seg for seg in p.split("/") if seg not in ("", ".")]
    drive = ""
    if parts and len(parts[0]) == 2 and parts[0][1] == ":" and parts[0][0].isalpha():
        drive = parts[0].upper()
        parts = parts[1:]
    folded = "/".join(seg.lower() for seg in parts)
    return f"{drive}/{folded}" if drive else folded
