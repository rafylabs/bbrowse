#!/usr/bin/env python3
"""
bbcdp - Lightweight Chrome DevTools Protocol (CDP) client directly over websockets.

No Playwright or Puppeteer overhead: every step is explicit (target creation, navigation,
DOM capture, screenshot generation, and network logging). Auditable, predictable, and fast.
"""
import asyncio
import json
import os
import shutil
import subprocess
import time
import urllib.request

DEFAULT_PORT = 9333


def http(port, path, method="GET", body=None):
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method, data=body)
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.read().decode("utf-8", "replace")
    try:
        return json.loads(raw)
    except Exception:
        return {"raw": raw}


def version(port=DEFAULT_PORT):
    return http(port, "/json/version")


def is_up(port=DEFAULT_PORT):
    try:
        v = version(port)
        return bool(v.get("Browser"))
    except Exception:
        return False


def find_chrome():
    env_path = os.environ.get("CHROME_PATH")
    if env_path and os.path.exists(env_path):
        return env_path
    candidates = [
        shutil.which("google-chrome"),
        shutil.which("google-chrome-stable"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        "/usr/bin/google-chrome",
        "/usr/bin/google-chrome-stable",
        "/usr/bin/chromium",
        "/usr/bin/chromium-browser",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return "google-chrome"


CHROME = find_chrome()

# Robust launch flags for containerized/headless environments
LAUNCH_FLAGS = [
    "--headless=new",
    "--no-sandbox",
    "--single-process",
    "--no-zygote",
    "--disable-gpu-sandbox",
    "--disable-gpu",
    "--disable-software-rasterizer",
    "--disable-dev-shm-usage",
    "--disable-crash-reporter",
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-sync",
    "--disable-extensions",
    "--remote-allow-origins=*",
    # Anti-headless detection flags
    "--disable-blink-features=AutomationControlled",
    "--window-size=1920,1080",
    "--force-device-scale-factor=1",
    "--lang=en-US",
    "--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]


def chrome_pids(profile=None, port=None):
    """Find managed Chrome pids from /proc without killing unrelated processes."""
    out = []
    if not os.path.exists("/proc"):
        return out
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            cmd = open(f"/proc/{d}/cmdline", "rb").read().decode("utf-8", "replace")
        except OSError:
            continue
        if "chrome" not in cmd and "chromium" not in cmd:
            continue
        if profile and profile not in cmd:
            continue
        if port is not None and f"remote-debugging-port={port}" not in cmd:
            continue
        out.append(int(d))
    return out


def kill_chrome(profile=None, port=None, sig=15):
    pids = chrome_pids(profile, port)
    for pid in pids:
        try:
            os.kill(pid, sig)
        except OSError:
            pass
    return pids


def launch(port=DEFAULT_PORT, profile=None, extra=None):
    """Launch Chrome with dedicated profile directory and remote debugging port."""
    base_dir = os.environ.get("BBROWSE_HOME", os.getcwd())
    profile = profile or os.environ.get("BBROWSE_PROFILE", os.path.join(base_dir, "browser-profile"))
    os.makedirs(profile, exist_ok=True)
    kill_chrome(profile=profile, port=port)
    time.sleep(1.0)
    args = [CHROME] + LAUNCH_FLAGS + (extra or []) + [
        f"--user-data-dir={profile}",
        f"--remote-debugging-port={port}",
        "about:blank",
    ]
    logdir = os.path.join(base_dir, "logs")
    os.makedirs(logdir, exist_ok=True)
    log = open(os.path.join(logdir, f"chrome-{port}.log"), "ab")
    return subprocess.Popen(args, stdout=log, stderr=log, start_new_session=True), profile


def wait_ready(port=DEFAULT_PORT, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        if is_up(port):
            return True
        time.sleep(0.5)
    return False


def targets(port=DEFAULT_PORT):
    return http(port, "/json/list")


def new_target(port=DEFAULT_PORT, url="about:blank"):
    return http(port, f"/json/new?{url}", method="PUT")


def close_target(port, tid):
    try:
        return http(port, f"/json/close/{tid}")
    except Exception:
        return None


class Session:
    """Active WebSocket connection to a single Chrome target tab."""

    def __init__(self, ws):
        self.ws = ws
        self._id = 0
        self.events = []

    async def send(self, method, **params):
        self._id += 1
        mid = self._id
        await self.ws.send(json.dumps({"id": mid, "method": method, "params": params}))
        while True:
            msg = json.loads(await asyncio.wait_for(self.ws.recv(), timeout=30))
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"{method} -> {msg['error']}")
                return msg.get("result", {})
            if "method" in msg:
                self.events.append(msg)

    async def drain(self, seconds, until=None):
        """Drain incoming events until a specific event or timeout occurs."""
        loop = asyncio.get_event_loop()
        end = loop.time() + seconds
        while True:
            left = end - loop.time()
            if left <= 0:
                return
            try:
                msg = json.loads(await asyncio.wait_for(self.ws.recv(), timeout=left))
            except asyncio.TimeoutError:
                return
            if "method" in msg:
                self.events.append(msg)
                if until and msg["method"] == until:
                    return


def _net_summary(events):
    """Summarize Network.responseReceived events into a compact list."""
    out, seen = [], set()
    for e in events:
        if e.get("method") != "Network.responseReceived":
            continue
        p = e.get("params", {})
        r = p.get("response", {})
        url = r.get("url", "")
        key = (r.get("status"), url)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "status": r.get("status"),
            "mime": r.get("mimeType"),
            "type": p.get("type"),
            "url": url[:300],
        })
    return out


def _console(events):
    out = []
    for e in events:
        if e.get("method") == "Runtime.consoleAPICalled":
            args = [a.get("value", a.get("description", "")) for a in e.get("params", {}).get("args", [])]
            out.append({"type": e["params"].get("type"), "args": [str(a)[:200] for a in args]})
        elif e.get("method") == "Runtime.exceptionThrown":
            d = e["params"].get("exceptionDetails", {})
            out.append({
                "type": "exception",
                "args": [
                    str(d.get("text"))[:200],
                    str((d.get("exception") or {}).get("description"))[:400],
                ],
            })
    return out


def _clean_cookie(c):
    """Remove empty fields to satisfy CDP requirements."""
    return {k: v for k, v in c.items() if v is not None and v != ""}


def load_cookies(path):
    """Parse cookie export file (Netscape cookies.txt or Cookie-Editor JSON) into CDP dicts."""
    txt = open(path, encoding="utf-8", errors="replace").read()
    out = []

    stripped = txt.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(txt)
        except Exception as e:
            raise RuntimeError(f"Corrupt JSON cookies: {e}")
        if isinstance(data, dict):
            data = data.get("cookies", [])
        for c in data:
            if not c.get("name"):
                continue
            out.append({
                "name": c["name"],
                "value": c.get("value", ""),
                "domain": c.get("domain", ""),
                "path": c.get("path", "/"),
                "secure": bool(c.get("secure", False)),
                "httpOnly": bool(c.get("httpOnly", False)),
                "sameSite": (c.get("sameSite") or "Lax")
                .replace("no_restriction", "None")
                .replace("lax", "Lax")
                .replace("strict", "Strict"),
                "expires": float(c.get("expirationDate") or c.get("expires") or 0) or None,
            })
        return out

    # Netscape format: domain \t includeSub \t path \t secure \t expires \t name \t value
    for line in txt.splitlines():
        line = line.rstrip("\n")
        if not line.strip() or line.startswith("# ") and "Netscape" not in line:
            continue
        http_only = False
        if line.startswith("#HttpOnly_"):
            http_only = True
            line = line[len("#HttpOnly_"):]
        elif line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        domain, _sub, path, secure, expires, name, value = [p.strip() for p in parts[:7]]
        if not name:
            continue
        try:
            exp = float(expires)
        except ValueError:
            exp = 0.0
        out.append({
            "name": name,
            "value": value,
            "domain": domain,
            "path": path or "/",
            "secure": secure.strip().upper() == "TRUE",
            "httpOnly": http_only,
            "sameSite": "Lax",
            "expires": exp if exp > 0 else None,
        })
    return out


async def _browse(port, url, wait, want_dom, want_shot, script, vw, vh, steps, cookies=None):
    t = new_target(port, "about:blank")
    tid = t.get("id")
    ws_url = t.get("webSocketDebuggerUrl")
    if not ws_url:
        raise RuntimeError(f"Failed to create new target: {t}")

    import websockets

    out = {"target_id": tid, "url": url}
    async with websockets.connect(ws_url, max_size=96 * 1024 * 1024) as ws:
        s = Session(ws)
        await s.send("Page.enable")
        await s.send("Network.enable")
        try:
            await s.send("Network.setCacheDisabled", cacheDisabled=True)
        except Exception:
            pass
        await s.send("Runtime.enable")

        # Inject session cookies before navigation
        if cookies:
            try:
                cleaned = [_clean_cookie(c) for c in cookies]
                await s.send("Network.setCookies", cookies=cleaned)
                out["cookies_set"] = len(cleaned)
            except Exception as e:
                out["cookies_error"] = f"{type(e).__name__}: {str(e)[:120]}"

        try:
            await s.send(
                "Emulation.setDeviceMetricsOverride",
                width=vw,
                height=vh,
                deviceScaleFactor=1,
                mobile=False,
                screenWidth=vw,
                screenHeight=vh,
                screenOrientation={"type": "landscapePrimary", "angle": 0},
            )
        except Exception:
            pass

        await s.send("Page.navigate", url=url)
        await s.drain(30, until="Page.loadEventFired")
        await s.drain(wait)

        r = await s.send("Runtime.evaluate", expression="document.title", returnByValue=True)
        out["title"] = (r.get("result") or {}).get("value") or ""

        r = await s.send(
            "Runtime.evaluate", expression="document.documentElement.outerHTML", returnByValue=True
        )
        dom = (r.get("result") or {}).get("value") or ""
        out["dom_len"] = len(dom)
        if want_dom:
            out["dom"] = dom

        r = await s.send("Runtime.evaluate", expression="document.location.href", returnByValue=True)
        out["final_url"] = (r.get("result") or {}).get("value") or ""

        if script:
            try:
                r = await s.send(
                    "Runtime.evaluate", expression=script, returnByValue=True, awaitPromise=True
                )
                out["script_result"] = (r.get("result") or {}).get("value")
            except Exception as e:
                out["script_result"] = f"ERROR: {e}"

        # Interactive steps
        out["steps"] = []
        for st in steps or []:
            act = st.get("action")
            if act == "wait":
                await s.drain(st.get("seconds", 1.0))
                out["steps"].append({"action": "wait", "result": "ok"})
                continue
            if act == "fill":
                sel, val = st["selector"], st["value"]
                expr = (
                    f"(() => {{ const e = document.querySelector({json.dumps(sel)});"
                    f" if (!e) return 'ELEMENT_NOT_FOUND';"
                    f" const d = Object.getOwnPropertyDescriptor(e.constructor.prototype,'value');"
                    f" if (d && d.set) d.set.call(e, {json.dumps(val)}); else e.value = {json.dumps(val)};"
                    f" e.dispatchEvent(new Event('input',{{bubbles:true}}));"
                    f" e.dispatchEvent(new Event('change',{{bubbles:true}}));"
                    f" return 'ok:' + String(e.value).slice(0,40); }})()"
                )
            elif act == "click":
                sel = st["selector"]
                expr = (
                    f"(() => {{ const e = document.querySelector({json.dumps(sel)});"
                    f" if (!e) return 'ELEMENT_NOT_FOUND';"
                    f" e.scrollIntoView({{block:'center'}}); e.click();"
                    f" return 'ok:' + String(e.innerText || e.tagName).slice(0,40); }})()"
                )
            elif act == "js":
                expr = st["expr"]
            else:
                out["steps"].append({"action": act, "result": "UNKNOWN_ACTION"})
                continue
            try:
                r = await s.send(
                    "Runtime.evaluate", expression=expr, returnByValue=True, awaitPromise=True
                )
                res = (r.get("result") or {}).get("value")
                if r.get("exceptionDetails"):
                    res = f"EXC: {r['exceptionDetails'].get('text')}"
            except Exception as e:
                res = f"ERROR: {type(e).__name__}"
            out["steps"].append({
                "action": act,
                "selector": st.get("selector"),
                "result": res,
            })
            await s.drain(st.get("settle", 1.0))

        if want_shot:
            try:
                r = await s.send(
                    "Page.captureScreenshot",
                    format="png",
                    captureBeyondViewport=False,
                    fromSurface=False,
                )
                out["screenshot_b64"] = r.get("data", "")
                if not out["screenshot_b64"]:
                    out["screenshot_error"] = "empty"
            except Exception as e:
                out["screenshot_error"] = f"{type(e).__name__}: {str(e)[:80]}"
                out["screenshot_b64"] = ""

        out["net"] = _net_summary(s.events)
        out["console"] = _console(s.events)
        out["doc_request"] = next(
            (
                {
                    "url": e["params"]["request"]["url"][:200],
                    "method": e["params"]["request"].get("method"),
                    "headers": e["params"]["request"].get("headers", {}),
                }
                for e in s.events
                if e.get("method") == "Network.requestWillBeSent"
                and e["params"].get("type") == "Document"
            ),
            {},
        )
    if tid:
        close_target(port, tid)
    return out


def browse(
    port=DEFAULT_PORT,
    url="about:blank",
    wait=3.0,
    want_dom=False,
    want_shot=False,
    script=None,
    vw=1920,
    vh=1080,
    steps=None,
    cookies=None,
):
    return asyncio.run(
        _browse(port, url, wait, want_dom, want_shot, script, vw, vh, steps, cookies)
    )


if __name__ == "__main__":
    import sys

    p = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    r = browse(p, sys.argv[1], want_dom=True)
    print(json.dumps({k: v for k, v in r.items() if k != "dom"}, indent=2, ensure_ascii=False))
    print("DOM snippet (300 char):", r["dom"][:300])
