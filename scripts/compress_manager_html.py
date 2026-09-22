#!/usr/bin/env python3
# pyright: reportMissingImports=false, reportUndefinedVariable=false
import gzip
import pathlib
import sys


def compress_html(target, source, env):
    src_path = pathlib.Path(str(source[0]))
    tgt_path = pathlib.Path(str(target[0]))

    if not src_path.exists():
        print(f"[compress_manager_html] Quelle fehlt: {src_path}", file=sys.stderr)
        return 1

    data = src_path.read_bytes()
    compressed = gzip.compress(data, compresslevel=9, mtime=0)
    tgt_path.write_bytes(compressed)
    saved_percent = 100 - (len(compressed) * 100 // len(data))
    print(
        f"[compress_manager_html] {src_path.name}: {len(data)} -> {len(compressed)} Byte (-{saved_percent}%)"
    )
    return 0


# If invoked via SCons / PlatformIO
try:
    Import("env")

    # Only register build hooks if not generating IDE metadata
    clt = [str(t) for t in COMMAND_LINE_TARGETS]  # noqa: F821
    if not (getattr(env, "IsBuildDump", lambda: False)() or any("ide" in t for t in clt)):
        repo_root = pathlib.Path(env["PROJECT_DIR"]).resolve()
        src_file = repo_root / "src" / "manager" / "manager.html"
        gz_file = repo_root / "src" / "manager" / "manager.html.gz"

        # Register manager.html.gz as a real dependency of $PROGPATH (the binary build)
        html_target = env.Command(
            str(gz_file),
            str(src_file),
            env.Action(compress_html, "Compressing $SOURCE -> $TARGET"),
        )
        # Ensure compression runs before compiling any sources
        env.Requires(env.File("$PROGPATH"), html_target)

except NameError:
    # Standalone execution: python3 scripts/compress_manager_html.py
    root = pathlib.Path(__file__).resolve().parent.parent
    src = root / "src" / "manager" / "manager.html"
    tgt = root / "src" / "manager" / "manager.html.gz"
    compress_html([tgt], [src], None)