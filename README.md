# bbrowse

Chrome DevTools Protocol (CDP) browser automation for offensive security research.

Drive a real Chrome instance via CDP — not header spoofing, not Playwright abstraction. Every step is explicit: create tab, navigate, capture DOM, record traffic, screenshot. Thin, auditable, no hidden layers.

## Why

Security research needs a browser that behaves like a real user's browser: identical TLS fingerprint, real header ordering, actual cookie jar, and genuine JavaScript execution. `bbrowse` uses Chrome's own DevTools Protocol to drive an actual browser process with full visibility into network traffic, console output, and DOM state.

## Features

- **Real Chrome via CDP** — not spoofed headers, an actual browser process
- **SPA crawling** — waits for `Page.loadEventFired`, drains events, captures final DOM after client-side rendering
- **Network capture** — records all `Network.responseReceived` events with status, MIME type, and URL
- **Console & exception capture** — `Runtime.consoleAPICalled` and `Runtime.exceptionThrown` events collected automatically
- **Cookie injection** — load Netscape `cookies.txt` or Cookie-Editor JSON before navigation for authenticated sessions
- **Interactive steps** — fill forms, click elements, run arbitrary JS with settle delays
- **Screenshot capture** — PNG via `Page.captureScreenshot`
- **Request fingerprint evidence** — captures the exact headers Chrome sent for the document request
- **Stealth-aware launch flags** — disables `AutomationControlled`, sets real viewport and user-agent
- **Cache disabled** — `Network.setCacheDisabled` prevents stale DOM from producing false recon results

## Requirements

- Python 3.10+
- `websockets>=12.0`
- Chrome or Chromium installed (`google-chrome`, `chromium`, or `CHROME_PATH`)

## Quick Start

```bash
# Clone repository
git clone https://github.com/rafylabs/bbrowse.git
cd bbrowse

# Install dependencies
pip install -r requirements.txt

# Browse a target URL
python bbrowse.py https://example.com --dom example.html --shot example.png
```

## CLI Usage

```bash
python bbrowse.py <url> [options]

Options:
  --shot NAME      Save screenshot to evidence/NAME.png
  --dom NAME       Save rendered DOM to evidence/NAME.html
  --net NAME       Save network log to evidence/NAME.jsonl
  --wait SECONDS   Extra drain time after page load (default: 3.0)
  --cookies FILE   Inject cookies before navigation (Netscape or JSON)
  --click SEL      Click element matching CSS selector (repeatable)
  --fill SEL=VAL   Fill input matching CSS selector with value (repeatable)
  --js EXPR        Evaluate JavaScript expression and print result
  --reuse          Attach to already-running Chrome session
  --cdp PORT       CDP port (default: 9333)
```

## Python Library Usage

```python
from bbcdp import browse, load_cookies

result = browse(
    port=9333,
    url="https://example.com/login",
    wait=5.0,
    want_dom=True,
    want_shot=True,
    cookies=load_cookies("cookies.txt"),
    steps=[
        {"action": "fill", "selector": "#username", "value": "testuser"},
        {"action": "click", "selector": "#login-btn"},
        {"action": "wait", "seconds": 2.0},
        {"action": "js", "expr": "document.title"},
    ],
)

print("Title:", result["title"])
print("Final URL:", result["final_url"])
print("Requests recorded:", len(result["net"]))
```

## License

MIT © [Rafylabs](https://rafylabs.com)
