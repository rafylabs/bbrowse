#!/usr/bin/env python3
"""
bbrowse - Chrome DevTools Protocol browser automation for offensive security research.

Why a real browser: genuine TLS fingerprint, real header ordering, complete cookie jar,
and true client-side JavaScript execution.
"""
import argparse
import base64
import json
import os
import sys
import time
import urllib.parse

import bbcdp

CDP_PORT = int(os.environ.get("BBROWSE_CDP_PORT", "9333"))
BASE_DIR = os.environ.get("BBROWSE_HOME", os.getcwd())
PROFILE = os.environ.get("BBROWSE_PROFILE", os.path.join(BASE_DIR, "browser-profile"))
EVIDENCE = os.path.join(BASE_DIR, "evidence")
LOGS = os.path.join(BASE_DIR, "logs")


def heal_profile():
    """Remove stale locks and reset crashed profile markers."""
    for name in ("SingletonLock", "SingletonSocket", "SingletonCookie"):
        try:
            os.remove(os.path.join(PROFILE, name))
        except OSError:
            pass
    prefs = os.path.join(PROFILE, "Default", "Preferences")
    if os.path.exists(prefs):
        try:
            d = json.load(open(prefs))
            prof = d.setdefault("profile", {})
            if prof.pop("exit_type", None) or prof.pop("exited_cleanly", None):
                prof["exit_type"] = "Normal"
                prof["exited_cleanly"] = True
                json.dump(d, open(prefs, "w"))
        except Exception:
            pass


def ensure_scope(url, allow_any):
    """Validate target scope if scope verification module is available."""
    host = urllib.parse.urlsplit(url).hostname or ""
    if host in ("127.0.0.1", "localhost", "::1"):
        return "localhost-test"
    if allow_any:
        return "authorized-test"
    try:
        import bbx

        verdict, program, note = bbx.scope_verdict(url)
        if verdict != "IN-SCOPE":
            print(f"[-] REJECTED: {url} -> {verdict} ({note})")
            sys.exit(2)
        return program
    except ImportError:
        return "target"


def main():
    parser = argparse.ArgumentParser(description="CDP browser automation for security research")
    parser.add_argument("url", help="Target URL to navigate")
    parser.add_argument("--shot", help="Save PNG screenshot to evidence/<name>.png")
    parser.add_argument("--dom", help="Save rendered DOM to evidence/<name>.html")
    parser.add_argument("--net", help="Save network log to evidence/<name>.jsonl")
    parser.add_argument(
        "--wait", type=float, default=3.0, help="Wait time after loadEventFired in seconds"
    )
    parser.add_argument(
        "--click", action="append", default=[], help="CSS selector to click (can repeat)"
    )
    parser.add_argument(
        "--fill", action="append", default=[], help="CSS selector=value to fill (can repeat)"
    )
    parser.add_argument("--js", help="Evaluate JavaScript expression and capture output")
    parser.add_argument("--cookies", help="Path to Netscape cookies.txt or JSON cookie file")
    parser.add_argument(
        "--any", action="store_true", help="Bypass scope verification (for lab testing)"
    )
    parser.add_argument(
        "--reuse", action="store_true", help="Attach to an already running Chrome session"
    )
    parser.add_argument(
        "--keep-open", action="store_true", help="Keep Chrome running after navigation"
    )
    parser.add_argument(
        "--cdp", type=int, default=CDP_PORT, help="CDP remote debugging port (default: 9333)"
    )
    args = parser.parse_args()

    program = ensure_scope(args.url, args.any)

    steps = []
    for spec in args.fill:
        sel, _, val = spec.partition("=")
        steps.append({"action": "fill", "selector": sel, "value": val, "settle": 0.8})
    for sel in args.click:
        steps.append({"action": "click", "selector": sel, "settle": max(1.0, args.wait / 2)})
    if args.js:
        steps.append({"action": "js", "expr": args.js, "settle": 0.5})

    proc = None
    reuse = False
    if args.reuse and bbcdp.is_up(args.cdp):
        reuse = True
        print(f"[*] Attaching to running Chrome session on port {args.cdp}")
    if not reuse:
        print(f"[*] Launching isolated Chrome session (profile: {PROFILE}) ...")
        os.makedirs(PROFILE, exist_ok=True)
        heal_profile()
        proc, _ = bbcdp.launch(args.cdp, profile=PROFILE)
        if not bbcdp.wait_ready(args.cdp):
            print("[-] Chrome failed to initialize. Check logs/chrome-*.log")
            sys.exit(4)

    print(f"[*] Navigating to: {args.url}")
    cookies = None
    if args.cookies:
        cookies = bbcdp.load_cookies(args.cookies)
        print(f"[*] Loaded {len(cookies)} cookies from {args.cookies}")

    result = bbcdp.browse(
        args.cdp,
        args.url,
        wait=args.wait,
        want_dom=True,
        want_shot=True,
        steps=steps,
        cookies=cookies,
    )

    print(f"[+] Title: {result['title'][:90]}")
    print(f"[+] Final URL: {result['final_url'][:110]}")
    print(f"[+] DOM size: {result['dom_len']:,} chars | {len(result['net'])} network requests")

    if result.get("cookies_set"):
        print(f"[+] Injected cookies: {result['cookies_set']}")
    if result.get("cookies_error"):
        print(f"[-] Cookie injection error: {result['cookies_error']}")

    for step in result.get("steps", []):
        print(f"    Step: {step['action']:5s} {str(step.get('selector') or '')[:28]:28s} -> {step['result']}")

    if result.get("screenshot_error"):
        print(f"[-] Screenshot error: {result['screenshot_error']}")

    os.makedirs(EVIDENCE, exist_ok=True)
    if args.dom:
        dom_path = os.path.join(EVIDENCE, args.dom if args.dom.endswith(".html") else args.dom + ".html")
        open(dom_path, "w", encoding="utf-8").write(result["dom"])
        print(f"[+] Saved DOM -> {dom_path}")

    if args.shot and result.get("screenshot_b64"):
        shot_path = os.path.join(EVIDENCE, args.shot if args.shot.endswith(".png") else args.shot + ".png")
        open(shot_path, "wb").write(base64.b64decode(result["screenshot_b64"]))
        print(f"[+] Saved screenshot -> {shot_path} ({os.path.getsize(shot_path):,} bytes)")

    if args.net:
        net_path = os.path.join(EVIDENCE, args.net if args.net.endswith(".jsonl") else args.net + ".jsonl")
        with open(net_path, "w", encoding="utf-8") as f:
            for item in result["net"]:
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
        print(f"[+] Saved network log -> {net_path} ({len(result['net'])} requests)")

    # Audit log entry
    os.makedirs(LOGS, exist_ok=True)
    with open(os.path.join(LOGS, "browse.jsonl"), "a", encoding="utf-8") as f:
        f.write(
            json.dumps({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "url": args.url,
                "final_url": result["final_url"],
                "program": program,
                "title": result["title"][:200],
                "dom_len": result["dom_len"],
                "requests": len(result["net"]),
                "steps": result.get("steps", []),
            })
            + "\n"
        )

    if proc and not args.keep_open:
        bbcdp.kill_chrome(profile=PROFILE, port=args.cdp)
        print("[*] Chrome session closed.")
    elif proc:
        print(f"[*] Chrome session running on port {args.cdp} (PID: {proc.pid})")


if __name__ == "__main__":
    main()
