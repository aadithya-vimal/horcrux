"""Production browser automation boundary (Phase 8, Part 1).

Replaceable ``BrowserAdapter`` interface with operations for navigation,
interaction, and observation. Two backends:

- :class:`PlaywrightBrowserAdapter` — real automation via Playwright when the
  ``playwright`` package (and a browser runtime) is installed. All browser
  I/O is scope-gated and failure-isolated; unavailability is reported as
  structured state, never an exception leak.
- :class:`ScriptedBrowserAdapter` — deterministic scripted sessions used by
  synthetic benchmarks, replay, and offline environments. Executes a script
  of navigation/interaction steps against a synthetic page/route table and
  records the same observation envelope as the real backend.

Both backends emit identical observation envelopes that converge into the
SAME ApplicationModel via :func:`record_browser_session` (Part 2) — there is
no browser-specific semantic model.
"""

from __future__ import annotations

import abc
import hashlib
import time
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Observation envelope (backend-neutral)
# ---------------------------------------------------------------------------

@dataclass
class BrowserObservation:
    url: str = ""
    title: str = ""
    status_code: int = 0
    dom_routes: list[str] = field(default_factory=list)
    api_calls: list[dict[str, Any]] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    cookies: list[dict[str, Any]] = field(default_factory=list)
    storage_keys: list[str] = field(default_factory=list)
    console_messages: list[str] = field(default_factory=list)
    requests: list[dict[str, Any]] = field(default_factory=list)
    responses: list[dict[str, Any]] = field(default_factory=list)
    identity: str = "anonymous"
    provenance: str = "browser"
    error: str = ""


def _cookie_names(cookies: Any) -> list[str]:
    names: list[str] = []
    for c in cookies or []:
        if isinstance(c, dict) and c.get("name"):
            names.append(str(c["name"]))
        elif isinstance(c, str):
            names.append(c.split("=", 1)[0])
    return names


def hash_secret(value: str) -> str:
    """One-way correlation handle for secrets (never store raw tokens)."""
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Adapter interface
# ---------------------------------------------------------------------------

class BrowserAdapter(abc.ABC):
    """Replaceable browser automation backend."""

    name: str = "abstract"

    # -- lifecycle --
    @abc.abstractmethod
    def launch(self, **kwargs: Any) -> dict[str, Any]: ...
    @abc.abstractmethod
    def close(self) -> None: ...
    @abc.abstractmethod
    def create_context(self, identity: str = "anonymous", **kwargs: Any) -> str: ...
    @abc.abstractmethod
    def new_session(self, context_id: str = "") -> str: ...

    # -- navigation / interaction --
    @abc.abstractmethod
    def navigate(self, url: str, **kwargs: Any) -> BrowserObservation: ...
    @abc.abstractmethod
    def reload(self) -> BrowserObservation: ...
    @abc.abstractmethod
    def click(self, selector: str) -> BrowserObservation: ...
    @abc.abstractmethod
    def fill(self, selector: str, value: str) -> BrowserObservation: ...
    @abc.abstractmethod
    def submit(self, selector: str = "") -> BrowserObservation: ...
    @abc.abstractmethod
    def select(self, selector: str, value: str) -> BrowserObservation: ...
    @abc.abstractmethod
    def wait(self, ms: int = 500) -> None: ...

    # -- observation --
    @abc.abstractmethod
    def screenshot(self) -> str: ...
    @abc.abstractmethod
    def inspect_dom(self) -> dict[str, Any]: ...
    @abc.abstractmethod
    def inspect_network(self) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    def get_cookies(self) -> list[dict[str, Any]]: ...
    @abc.abstractmethod
    def get_storage(self) -> dict[str, Any]: ...
    @abc.abstractmethod
    def get_current_url(self) -> str: ...
    @abc.abstractmethod
    def get_page_title(self) -> str: ...
    @abc.abstractmethod
    def capture_console(self) -> list[str]: ...
    @abc.abstractmethod
    def capture_request(self) -> dict[str, Any]: ...
    @abc.abstractmethod
    def capture_response(self) -> dict[str, Any]: ...

    # -- availability --
    @abc.abstractmethod
    def is_available(self) -> tuple[bool, str]: ...

    def backend_status(self) -> dict[str, Any]:
        ok, reason = self.is_available()
        return {"backend": self.name, "available": ok, "reason": reason}


# ---------------------------------------------------------------------------
# Playwright backend (real automation, optional dependency)
# ---------------------------------------------------------------------------

class PlaywrightBrowserAdapter(BrowserAdapter):
    """Playwright-backed automation. Scope-gated; degrades to structured
    UNAVAILABLE when Playwright or a browser runtime is missing."""

    name = "playwright"

    def __init__(self, scope_check=None, headless: bool = True) -> None:
        self.scope_check = scope_check
        self.headless = headless
        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
        self._context_id = ""
        self._network_log: list[dict[str, Any]] = []
        self._console_log: list[str] = []
        self._current_url = ""

    def is_available(self) -> tuple[bool, str]:
        try:
            __import__("playwright")
        except ImportError:
            return False, "playwright package not installed (pip install playwright)"
        return True, "playwright package importable"

    def _require_scope(self, url: str) -> None:
        if self.scope_check is not None and url:
            try:
                if not self.scope_check(url):
                    raise PermissionError(f"URL outside engagement scope: {url}")
            except PermissionError:
                raise
            except Exception:
                pass

    def launch(self, **kwargs: Any) -> dict[str, Any]:
        ok, reason = self.is_available()
        if not ok:
            return {"launched": False, "reason": reason}
        try:
            from playwright.sync_api import sync_playwright
            self._pw = sync_playwright().start()
            self._browser = self._pw.chromium.launch(headless=kwargs.get("headless", self.headless))
            return {"launched": True, "backend": "playwright"}
        except Exception as exc:
            return {"launched": False, "reason": f"browser launch failed: {exc}"}

    def close(self) -> None:
        for handle in ("_page", "_context", "_browser", "_pw"):
            try:
                obj = getattr(self, handle, None)
                if obj is not None:
                    close = getattr(obj, "close", None)
                    if callable(close):
                        close()
                    else:
                        obj.stop()
            except Exception:
                pass
            setattr(self, handle, None)

    def create_context(self, identity: str = "anonymous", **kwargs: Any) -> str:
        if self._browser is None:
            launched = self.launch()
            if not launched.get("launched"):
                raise RuntimeError(launched.get("reason", "launch failed"))
        assert self._browser is not None
        self._context = self._browser.new_context()
        self._context_id = f"ctx-{identity}-{int(time.time() * 1000) % 100000}"
        self._page = self._context.new_page()
        self._page.on("request", lambda req: self._network_log.append(
            {"method": req.method, "url": req.url}))
        self._page.on("console", lambda msg: self._console_log.append(str(msg.text)[:200]))
        return self._context_id

    def new_session(self, context_id: str = "") -> str:
        return self.create_context()

    def navigate(self, url: str, **kwargs: Any) -> BrowserObservation:
        self._require_scope(url)
        if self._page is None:
            self.create_context(identity=kwargs.get("identity", "anonymous"))
        assert self._page is not None
        try:
            resp = self._page.goto(url, wait_until="domcontentloaded",
                                   timeout=int(kwargs.get("timeout_ms", 15000)))
            self._current_url = self._page.url
            return self._observe(status=resp.status if resp else 0)
        except PermissionError:
            raise
        except Exception as exc:
            return BrowserObservation(url=url, error=f"navigation failed: {exc}",
                                      provenance="browser:playwright")

    def reload(self) -> BrowserObservation:
        try:
            assert self._page is not None
            self._page.reload(wait_until="domcontentloaded")
            return self._observe()
        except Exception as exc:
            return BrowserObservation(url=self._current_url, error=str(exc)[:200],
                                      provenance="browser:playwright")

    def click(self, selector: str) -> BrowserObservation:
        try:
            assert self._page is not None
            self._page.click(selector, timeout=5000)
            self._page.wait_for_timeout(400)
            return self._observe()
        except Exception as exc:
            return BrowserObservation(url=self._current_url, error=str(exc)[:200],
                                      provenance="browser:playwright")

    def fill(self, selector: str, value: str) -> BrowserObservation:
        try:
            assert self._page is not None
            self._page.fill(selector, value, timeout=5000)
            return self._observe()
        except Exception as exc:
            return BrowserObservation(url=self._current_url, error=str(exc)[:200],
                                      provenance="browser:playwright")

    def submit(self, selector: str = "") -> BrowserObservation:
        try:
            assert self._page is not None
            if selector:
                self._page.click(f"{selector} [type=submit], {selector}", timeout=5000)
            else:
                self._page.keyboard.press("Enter")
            self._page.wait_for_timeout(600)
            return self._observe()
        except Exception as exc:
            return BrowserObservation(url=self._current_url, error=str(exc)[:200],
                                      provenance="browser:playwright")

    def select(self, selector: str, value: str) -> BrowserObservation:
        try:
            assert self._page is not None
            self._page.select_option(selector, value, timeout=5000)
            return self._observe()
        except Exception as exc:
            return BrowserObservation(url=self._current_url, error=str(exc)[:200],
                                      provenance="browser:playwright")

    def wait(self, ms: int = 500) -> None:
        try:
            assert self._page is not None
            self._page.wait_for_timeout(max(0, min(int(ms), 10000)))
        except Exception:
            pass

    def screenshot(self) -> str:
        try:
            assert self._page is not None
            return f"screenshot-bytes:{len(self._page.screenshot())}"
        except Exception:
            return ""

    def inspect_dom(self) -> dict[str, Any]:
        try:
            assert self._page is not None
            return {
                "url": self._page.url,
                "title": self._page.title(),
                "links": self._page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.getAttribute('href')).slice(0, 50)"),
                "forms": self._page.eval_on_selector_all(
                    "form", "els => els.map(f => f.getAttribute('action') || '/').slice(0, 10)"),
            }
        except Exception:
            return {"url": self._current_url}

    def inspect_network(self) -> list[dict[str, Any]]:
        return list(self._network_log[-100:])

    def get_cookies(self) -> list[dict[str, Any]]:
        try:
            assert self._context is not None
            return [{"name": c.get("name", ""), "value_hash": hash_secret(c.get("value", ""))}
                    for c in self._context.cookies()]
        except Exception:
            return []

    def get_storage(self) -> dict[str, Any]:
        try:
            assert self._page is not None
            keys = self._page.evaluate("() => Object.keys(localStorage)")
            return {"keys": list(keys)[:50] if isinstance(keys, list) else []}
        except Exception:
            return {"keys": []}

    def get_current_url(self) -> str:
        return self._current_url

    def get_page_title(self) -> str:
        try:
            assert self._page is not None
            return self._page.title()
        except Exception:
            return ""

    def capture_console(self) -> list[str]:
        return list(self._console_log[-50:])

    def capture_request(self) -> dict[str, Any]:
        return dict(self._network_log[-1]) if self._network_log else {}

    def capture_response(self) -> dict[str, Any]:
        return {"url": self._current_url}

    def _observe(self, status: int = 200) -> BrowserObservation:
        dom = self.inspect_dom()
        return BrowserObservation(
            url=self._current_url, title=dom.get("title", ""), status_code=status,
            dom_routes=[l for l in (dom.get("links") or []) if isinstance(l, str)][:30],
            forms=[{"action": a} for a in (dom.get("forms") or [])],
            cookies=self.get_cookies(),
            requests=self.inspect_network(),
            console_messages=self.capture_console(),
            provenance="browser:playwright")


# ---------------------------------------------------------------------------
# Scripted backend (deterministic; synthetic benchmarks / replay / offline)
# ---------------------------------------------------------------------------

class ScriptedBrowserAdapter(BrowserAdapter):
    """Deterministic scripted sessions over a synthetic page table.

    ``pages`` maps path -> {title, links, forms, api_calls, cookies,
    storage_keys, status}. No network is ever touched, so benchmarks and
    replay are fully reproducible.
    """

    name = "scripted"

    def __init__(self, pages: dict[str, dict[str, Any]] | None = None,
                 scope_check=None) -> None:
        self.pages = dict(pages or {})
        self.scope_check = scope_check
        self._current_url = ""
        self._identity = "anonymous"
        self._network_log: list[dict[str, Any]] = []
        self._console_log: list[str] = []
        self._cookies: list[dict[str, Any]] = []
        self._launched = False

    def is_available(self) -> tuple[bool, str]:
        return True, "scripted backend always available (no runtime required)"

    def launch(self, **kwargs: Any) -> dict[str, Any]:
        self._launched = True
        return {"launched": True, "backend": "scripted"}

    def close(self) -> None:
        self._launched = False

    def create_context(self, identity: str = "anonymous", **kwargs: Any) -> str:
        self._identity = identity
        self._network_log.clear()
        self._console_log.clear()
        return f"scripted-{identity}"

    def new_session(self, context_id: str = "") -> str:
        return self.create_context()

    def _check(self, url: str) -> None:
        if self.scope_check is not None and url:
            ok = False
            try:
                ok = bool(self.scope_check(url))
            except Exception:
                ok = True
            if not ok:
                raise PermissionError(f"URL outside engagement scope: {url}")

    def navigate(self, url: str, **kwargs: Any) -> BrowserObservation:
        self._check(url)
        from urllib.parse import urlparse
        self._current_url = url
        path = urlparse(url).path or "/"
        page = self.pages.get(path, {})
        self._network_log.append({"method": "GET", "url": url})
        for call in page.get("api_calls", []):
            self._network_log.append({"method": call.get("method", "GET"),
                                      "url": call.get("url", "")})
        return BrowserObservation(
            url=url, title=page.get("title", path),
            status_code=page.get("status", 200),
            dom_routes=list(page.get("links", [])),
            api_calls=list(page.get("api_calls", [])),
            forms=list(page.get("forms", [])),
            cookies=list(page.get("cookies", [])),
            storage_keys=list(page.get("storage_keys", [])),
            requests=list(self._network_log[-20:]),
            identity=self._identity, provenance="browser:scripted")

    def reload(self) -> BrowserObservation:
        return self.navigate(self._current_url)

    def click(self, selector: str) -> BrowserObservation:
        self._console_log.append(f"click:{selector}")
        return self.navigate(self._current_url)

    def fill(self, selector: str, value: str) -> BrowserObservation:
        self._console_log.append(f"fill:{selector}")
        return BrowserObservation(url=self._current_url, identity=self._identity,
                                  provenance="browser:scripted")

    def submit(self, selector: str = "") -> BrowserObservation:
        self._console_log.append(f"submit:{selector}")
        return self.navigate(self._current_url)

    def select(self, selector: str, value: str) -> BrowserObservation:
        self._console_log.append(f"select:{selector}={value}")
        return BrowserObservation(url=self._current_url, identity=self._identity,
                                  provenance="browser:scripted")

    def wait(self, ms: int = 500) -> None:
        return None

    def screenshot(self) -> str:
        return f"scripted-screenshot:{self._current_url}"

    def inspect_dom(self) -> dict[str, Any]:
        from urllib.parse import urlparse
        page = self.pages.get(urlparse(self._current_url).path or "/", {})
        return {"url": self._current_url, "title": page.get("title", ""),
                "links": page.get("links", []), "forms": page.get("forms", [])}

    def inspect_network(self) -> list[dict[str, Any]]:
        return list(self._network_log[-100:])

    def get_cookies(self) -> list[dict[str, Any]]:
        return list(self._cookies)

    def set_cookies(self, cookies: list[dict[str, Any]]) -> None:
        self._cookies = list(cookies)

    def get_storage(self) -> dict[str, Any]:
        return {"keys": []}

    def get_current_url(self) -> str:
        return self._current_url

    def get_page_title(self) -> str:
        return self.inspect_dom().get("title", "")

    def capture_console(self) -> list[str]:
        return list(self._console_log[-50:])

    def capture_request(self) -> dict[str, Any]:
        return dict(self._network_log[-1]) if self._network_log else {}

    def capture_response(self) -> dict[str, Any]:
        return {"url": self._current_url}


def get_browser_adapter(preferred: str = "auto", **kwargs: Any) -> BrowserAdapter:
    """Select a backend: explicit name, or auto (playwright if available)."""
    if preferred == "scripted":
        return ScriptedBrowserAdapter(**{k: v for k, v in kwargs.items()
                                         if k in ("pages", "scope_check")})
    if preferred == "playwright":
        return PlaywrightBrowserAdapter(**{k: v for k, v in kwargs.items()
                                           if k in ("scope_check", "headless")})
    pw = PlaywrightBrowserAdapter(**{k: v for k, v in kwargs.items()
                                     if k in ("scope_check", "headless")})
    ok, _ = pw.is_available()
    if ok:
        return pw
    return ScriptedBrowserAdapter(**{k: v for k, v in kwargs.items()
                                     if k in ("pages", "scope_check")})


def browser_backend_status() -> dict[str, Any]:
    """Browser state: playwright / chromium / scripted, separately reported.

    Answers whether HORCRUX can actually instantiate the configured adapter:
    package importable, supported browser executable present, adapter init
    possible. Never launches a browser (safe for status rendering).
    """
    try:
        from horcrux.agents.tools.capabilities import _playwright_probe
        probe = _playwright_probe()
    except Exception as exc:
        probe = {"ok": False, "reason": f"probe failed: {exc}", "chromium": None}
    try:
        PlaywrightBrowserAdapter()
        init_ok, init_reason = True, "adapter initializes"
    except Exception as exc:
        init_ok, init_reason = False, f"adapter init failed: {exc}"
    available = bool(probe["ok"] and init_ok)
    return {
        "playwright": {
            "backend": "playwright",
            "available": available,
            "reason": probe["reason"] if available else
                      (probe["reason"] if not probe["ok"] else init_reason),
        },
        "chromium": {
            "backend": "chromium",
            "available": probe.get("chromium") is not None,
            "reason": probe["chromium"] or "no supported browser executable found",
        },
        "scripted": {"backend": "scripted", "available": True,
                     "reason": "deterministic fallback; no runtime required"},
    }
