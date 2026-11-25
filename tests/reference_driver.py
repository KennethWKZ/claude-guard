"""Run a Python hook's main() in-process for many hook inputs: one JSON line in ({"input": <raw stdin>}), one out.
Test harness for the differential tests only.
Not Rust: it drives the Python reference hooks, which can only be called from Python. Loading the module once
keeps thousands of cases fast; the differential tests also spot-check it against real `python3 -I` runs.

Usage: /usr/bin/python3 -I reference_driver.py bash <guard-bash.py>
         out: {"stdout": ..., "error": <exception name or null>}
       /usr/bin/python3 -I reference_driver.py read <guard-read-keys.py>
         out: {"code": <exit code>, "stderr": ...}   (as its __main__ block: a crash exits 2)
       /usr/bin/python3 -I reference_driver.py prompt <guard-prompt.py>
         in:  {"input": <raw stdin>, "args": [<hook arguments>]}
         out: {"stdout": ...}   (as its __main__ block: an exception prints the fail-open warning)
       /usr/bin/python3 -I reference_driver.py web <web-guard.py>
         in/out as prompt (web-guard.py's own fail-open warning)
       /usr/bin/python3 -I reference_driver.py repo-bash <a repo's PreToolUse Bash hook>
         out: {"code": <exit code>, "stdout": ..., "stderr": ..., "crash": <main() raised, which the hook logs and allows>}
"""
import importlib.util
import io
import json
import os
import sys
import tempfile
import traceback

mode, ref = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("hook_reference", ref)
g = importlib.util.module_from_spec(spec)
spec.loader.exec_module(g)
if hasattr(g, "CRASH_LOG"):
    g.CRASH_LOG = os.path.join(tempfile.mkdtemp(prefix="hook-ref-"), "crash.log")



def clean(text):
    """Unpaired surrogates (from a "\\ud800" in the input) as U+FFFD, so the line is valid JSON for serde."""
    return text.encode("utf-16", "surrogatepass").decode("utf-16", "replace")


real = (sys.stdin, sys.stdout, sys.stderr)
for line in real[0]:
    request = json.loads(line)
    raw = request["input"]
    out, err = io.StringIO(), io.StringIO()
    sys.stdin, sys.stdout, sys.stderr = io.StringIO(raw), out, err
    result = {}
    try:
        if mode == "bash":
            error = None
            try:
                g.main()
            except BaseException as e:  # what would have ended the real process (exit 1, no decision)
                error = type(e).__name__
            result = {"stdout": clean(out.getvalue()), "error": error}
        elif mode == "repo-bash":
            code, crash = 0, False
            try:
                g.main()
            except SystemExit as e:
                code = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
            except Exception:
                crash = True
            result = {"code": code, "stdout": clean(out.getvalue()), "stderr": clean(err.getvalue()), "crash": crash}
        elif mode in ("prompt", "web"):
            sys.argv = [ref] + request.get("args", [])
            name = "guard-prompt.py" if mode == "prompt" else "web-guard.py"
            what = "prompt" if mode == "prompt" else "call"
            try:
                g.main()
            except SystemExit:
                pass
            except Exception as e:
                print(json.dumps({"systemMessage": f"{name} failed ({type(e).__name__}); {what} allowed unchecked."}))
            result = {"stdout": clean(out.getvalue())}
        else:
            try:
                code = g.main()
            except Exception:
                print("guard-read-keys.py crashed, so the read is blocked:\n" + traceback.format_exc(), file=sys.stderr)
                code = 2
            result = {"code": code if isinstance(code, int) else 0, "stderr": clean(err.getvalue())}
    finally:
        sys.stdin, sys.stdout, sys.stderr = real
    real[1].write(json.dumps(result) + "\n")
real[1].flush()
