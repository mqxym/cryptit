import os
import sys
import asyncio
import logging
import http.server
import socketserver
import threading
import time
import unittest
from contextlib import asynccontextmanager, contextmanager
from pyppeteer import launch

# This script does not work as expected right now

# ──────────────────────────────────────────────────────────────────────────────
# Logging
# ──────────────────────────────────────────────────────────────────────────────
LOG_LEVEL = os.environ.get("E2E_LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s.%(msecs)03d %(levelname)-7s %(name)s | %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("e2e")

if LOG_LEVEL != "DEBUG":
    logging.getLogger("websockets").setLevel(logging.WARNING)
    logging.getLogger("pyppeteer").setLevel(logging.INFO)


# ──────────────────────────────────────────────────────────────────────────────
# Static server (adds wasm MIME)
# ──────────────────────────────────────────────────────────────────────────────
class WasmHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=".", **kwargs)

    def do_GET(self):
        path = self.path.lstrip("/")
        if self.path.endswith(".wasm"):
            try:
                with open(path, "rb") as f:
                    data = f.read()
                self.send_response(200)
                self.send_header("Content-type", "application/wasm")
                self.end_headers()
                self.wfile.write(data)
                self.log_message("200 %s (%d bytes, wasm)", self.path, len(data))
            except Exception as e:
                self.send_error(404, "WASM not found")
                self.log_message("404 %s (wasm) error=%s", self.path, e)
        else:
            super().do_GET()

    def log_message(self, fmt, *args):
        logging.getLogger("e2e.http").info(
            "%s - %s", self.address_string(), fmt % args
        )


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


# ──────────────────────────────────────────────────────────────────────────────
# Step helpers
# ──────────────────────────────────────────────────────────────────────────────
@contextmanager
def step(name: str):
    t0 = time.time()
    log.info("▶ %s", name)
    try:
        yield
        log.info("✔ %s (%.1f ms)", name, (time.time() - t0) * 1000)
    except Exception:
        log.exception("✖ %s failed", name)
        raise


@asynccontextmanager
async def astep(name: str):
    t0 = time.time()
    log.info("▶ %s", name)
    try:
        yield
        log.info("✔ %s (%.1f ms)", name, (time.time() - t0) * 1000)
    except Exception:
        log.exception("✖ %s failed", name)
        raise


def is_headless() -> bool:
    return os.environ.get("E2E_HEADLESS", "1") != "0"


async def attach_page_logging(page, label="page"):
    """Wire browser console/network errors to Python logging."""
    p_log = logging.getLogger(f"e2e.{label}")

    async def _on_console(msg):
        try:
            txt = msg.text
        except Exception:
            txt = str(msg)
        p_log.info("console.%s: %s", msg.type, txt)

    async def _on_page_error(err):
        p_log.error("pageerror: %s", err)

    async def _on_req_failed(req):
        p_log.warning("requestfailed: %s %s (%s)", req.method, req.url, req.failure)

    async def _on_response(resp):
        try:
            if resp.status >= 400:
                p_log.warning("response %s %d", resp.url, resp.status)
        except Exception:
            pass

    page.on("console", _on_console)
    page.on("pageerror", _on_page_error)
    page.on("requestfailed", _on_req_failed)
    page.on("response", _on_response)


# ──────────────────────────────────────────────────────────────────────────────
# Tests
# ──────────────────────────────────────────────────────────────────────────────
class CryptitTextE2ETests(unittest.IsolatedAsyncioTestCase):
    SERVER_PORT = int(os.environ.get("E2E_PORT", "8081"))
    SERVER_URL = f"http://localhost:{SERVER_PORT}"

    TEST_TEXT = "This is a test."
    XSS_PAYLOAD = "<script>alert('xss')</script>"
    MALFORMED_CIPHERTEXT = "this is not a valid ciphertext"

    # Conservative timeouts for slow CI/arm64/wasm
    SHORT_TIMEOUT = 30_000
    MED_TIMEOUT = 120_000
    LONG_TIMEOUT = 300_000  # new: allow heavy Argon2id runs to finish

    @classmethod
    def setUpClass(cls):
        with step("start HTTP static server"):
            cls.httpd = ReusableTCPServer(("", cls.SERVER_PORT), WasmHandler)
            cls.server_thread = threading.Thread(
                target=cls.httpd.serve_forever, daemon=True
            )
            cls.server_thread.start()
            log.info("server at %s", cls.SERVER_URL)

    @classmethod
    def tearDownClass(cls):
        with step("shutdown HTTP static server"):
            cls.httpd.shutdown()
            cls.httpd.server_close()
            cls.server_thread.join()

    async def asyncSetUp(self):
        args = [
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-features=site-per-process",
        ]
        exe = os.environ.get("PUPPETEER_EXECUTABLE_PATH") or os.environ.get("CHROME")

        launch_kwargs = {
            "headless": is_headless(),
            "args": args,
            "dumpio": True,  # stream Chrome output into our stdio
            "handleSIGINT": False,
            "handleSIGTERM": False,
            "handleSIGHUP": False,
        }
        if exe:
            launch_kwargs["executablePath"] = exe

        async with astep("launch browser"):
            self.browser = await launch(**launch_kwargs)

        async with astep("new page"):
            self.page = await self.browser.newPage()
            await attach_page_logging(self.page)
            # setCacheEnabled may exist depending on Chromium; guard it
            try:
                await self.page.setCacheEnabled(False)
            except Exception:
                pass
            # pyppeteer has setDefaultNavigationTimeout; keep guarded
            try:
                self.page.setDefaultNavigationTimeout(self.SHORT_TIMEOUT)
            except Exception:
                pass

    async def asyncTearDown(self):
        async with astep("teardown page/browser"):
            try:
                if getattr(self, "page", None):
                    try:
                        await self.page.evaluate("console.log('teardown begin')")
                    except Exception:
                        pass
                    await self.page.close()
            except Exception as e:
                log.warning("page.close failed: %s", e)

            try:
                if getattr(self, "browser", None):
                    try:
                        await asyncio.wait_for(self.browser.close(), timeout=5)
                    except asyncio.TimeoutError:
                        log.warning("browser.close timed out; killing process")
                        proc = None
                        try:
                            proc = (
                                self.browser.process()
                                if callable(getattr(self.browser, "process", None))
                                else None
                            )
                        except Exception:
                            proc = None
                        if proc and proc.poll() is None:
                            proc.terminate()
            except Exception as e:
                log.warning("browser teardown ignored error: %s", e)

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────
    async def _goto_text_page(self):
        url = f"{self.SERVER_URL}/examples/text-encryption.html"
        async with astep(f"goto {url}"):
            await self.page.goto(url, {"waitUntil": "domcontentloaded"})

        # Ensure DOM is ready and controls are present
        await self.page.waitForSelector("#inputText", {"timeout": self.SHORT_TIMEOUT})
        await self.page.waitForSelector("#outputText", {"timeout": self.SHORT_TIMEOUT})
        await self.page.waitForSelector("#secret", {"timeout": self.SHORT_TIMEOUT})
        await self.page.waitForSelector("#encryptBtn", {"timeout": self.SHORT_TIMEOUT})
        await self.page.waitForSelector("#decryptBtn", {"timeout": self.SHORT_TIMEOUT})
        await self.page.waitForSelector("#errorMsg", {"timeout": self.SHORT_TIMEOUT})

        async with astep("wait for window.createCryptit"):
            await self.page.waitForFunction(
                "window.createCryptit !== undefined", {"timeout": self.SHORT_TIMEOUT}
            )

        # Ensure error banner starts hidden/empty
        await self.page.evaluate(
            """
            (function(){
              const e = document.querySelector('#errorMsg');
              if (e) { e.classList.add('d-none'); e.textContent=''; }
            })()
            """
        )

        # Quick sanity: ensure Argon2 loader exists here
        has_loader = await self.page.evaluate(
            "typeof window.loadArgon2WasmBinary === 'function'"
        )
        log.info("has loadArgon2WasmBinary: %s", has_loader)

    async def _wait_output_has_value(self, selector="#outputText", timeout=None):
        if timeout is None:
            timeout = self.MED_TIMEOUT
        await self.page.waitForFunction(
            f"document.querySelector('{selector}').value && document.querySelector('{selector}').value.length > 0",
            {"timeout": timeout},
        )

    async def _wait_error_visible(self, selector="#errorMsg", timeout=None):
        if timeout is None:
            timeout = self.SHORT_TIMEOUT
        await self.page.waitForFunction(
            f"(function(){{const e=document.querySelector('{selector}'); return e && !e.classList.contains('d-none');}})()",
            {"timeout": timeout},
        )

    async def _wait_idle_or_result(self, button_sel, out_sel="#outputText", err_sel="#errorMsg", timeout=None):
        """
        Robust guard for long-running crypto:
        resolves when (output has text) OR (error visible) OR (button is enabled again).
        """
        if timeout is None:
            timeout = self.LONG_TIMEOUT
        await self.page.waitForFunction(
            """
            (btnSel, outSel, errSel) => {
              const b = document.querySelector(btnSel);
              const out = document.querySelector(outSel);
              const err = document.querySelector(errSel);

              const hasOut = !!(out && out.value && out.value.length > 0);
              const hasErr = !!(err && !err.classList.contains('d-none'));
              const idle = !!(b && !b.disabled);

              return hasOut || hasErr || idle;
            }
            """,
            {"timeout": timeout},
            button_sel,
            out_sel,
            err_sel,
        )

    # ──────────────────────────────────────────────────────────────────────
    # Tests
    # ──────────────────────────────────────────────────────────────────────
    async def test_text_encryption_and_decryption(self):
        log.info("==== test_text_encryption_and_decryption ====")
        await self._goto_text_page()

        async with astep("prepare inputs"):
            await self.page.evaluate(
                """
                document.querySelector('#inputText').value='';
                document.querySelector('#outputText').value='';
                document.querySelector('#secret').value='password';
                """
            )

        async with astep("encrypt plaintext"):
            await self.page.type("#inputText", self.TEST_TEXT)
            await self.page.click("#encryptBtn")
            # Wait until encryption either produced output or the button returned to idle
            await self._wait_idle_or_result("#encryptBtn", timeout=self.LONG_TIMEOUT)
            await self._wait_output_has_value("#outputText", timeout=self.LONG_TIMEOUT)
            encrypted = await self.page.evaluate(
                "document.querySelector('#outputText').value"
            )
            log.info("encrypted length=%d", len(encrypted))
            self.assertNotEqual(encrypted, self.TEST_TEXT)

        async with astep("decrypt produced ciphertext"):
            await self.page.evaluate(
                """
                document.querySelector('#inputText').value='';
                document.querySelector('#outputText').value='';
                """
            )
            await self.page.type("#inputText", encrypted)
            await self.page.click("#decryptBtn")
            await self._wait_idle_or_result("#decryptBtn", timeout=self.LONG_TIMEOUT)
            await self._wait_output_has_value("#outputText", timeout=self.LONG_TIMEOUT)
            decrypted = await self.page.evaluate(
                "document.querySelector('#outputText').value"
            )
            log.info("decrypted: %r", decrypted)
            self.assertEqual(decrypted, self.TEST_TEXT)

    async def test_xss_vulnerability_text_decoding(self):
        log.info("==== test_xss_vulnerability_text_decoding ====")
        await self._goto_text_page()

        async with astep("encrypt XSS payload"):
            await self.page.evaluate(
                """
                document.querySelector('#inputText').value='';
                document.querySelector('#outputText').value='';
                document.querySelector('#secret').value='password';
                """
            )
            await self.page.type("#inputText", self.XSS_PAYLOAD)
            await self.page.click("#encryptBtn")
            await self._wait_idle_or_result("#encryptBtn", timeout=self.LONG_TIMEOUT)
            await self._wait_output_has_value("#outputText", timeout=self.LONG_TIMEOUT)
            encrypted = await self.page.evaluate(
                "document.querySelector('#outputText').value"
            )
            log.info("cipher for XSS payload length=%d", len(encrypted))

        # Trap dialogs (alert/prompt/confirm)
        state = {"hit": False}

        async def on_dialog(dlg):
            state["hit"] = True
            log.error("Dialog triggered: %s", dlg.message)
            await dlg.dismiss()

        self.page.on("dialog", on_dialog)

        async with astep("decrypt XSS ciphertext"):
            await self.page.evaluate(
                """
                document.querySelector('#inputText').value='';
                document.querySelector('#outputText').value='';
                """
            )
            await self.page.type("#inputText", encrypted)
            await self.page.click("#decryptBtn")

            # New: wait for decrypt to finish (output, error, or button idle)
            await self._wait_idle_or_result("#decryptBtn", timeout=self.LONG_TIMEOUT)

            # If neither output nor error after idle, surface a better failure than a raw timeout
            out = await self.page.evaluate("document.querySelector('#outputText').value")
            has_err = await self.page.evaluate(
                "(function(){const e=document.querySelector('#errorMsg'); return e && !e.classList.contains('d-none');})()"
            )

            if not out and not has_err:
                # Collect some quick diagnostics
                btn_disabled = await self.page.evaluate("!!document.querySelector('#decryptBtn')?.disabled")
                ready_state = await self.page.evaluate("document.readyState")
                log.error("decrypt finished idle without output/error (btn_disabled=%s, readyState=%s)", btn_disabled, ready_state)
                self.fail("Decrypt finished without producing output or showing an error")

            if has_err:
                # Make failures clear if the page surfaced an error
                err_text = await self.page.evaluate("document.querySelector('#errorMsg').textContent")
                self.fail(f"Decrypt showed error banner: {err_text.strip()}")

            # Normal path: we got output; assert payload preserved and no dialogs fired
            log.info("decrypted output contains payload? %s", self.XSS_PAYLOAD in out)
            self.assertIn(self.XSS_PAYLOAD, out)
            self.assertFalse(state["hit"], "XSS alert was triggered!")

    async def test_exception_not_rendered_as_html(self):
        log.info("==== test_exception_not_rendered_as_html ====")
        await self._goto_text_page()

        async with astep("feed malformed ciphertext and decrypt"):
            await self.page.evaluate(
                """
                document.querySelector('#inputText').value='';
                document.querySelector('#outputText').value='';
                document.querySelector('#secret').value='password';
                """
            )
            await self.page.type("#inputText", self.MALFORMED_CIPHERTEXT)
            await self.page.click("#decryptBtn")
            # Wait either for an error to show or for decrypt to finish and then assert error
            await self._wait_idle_or_result("#decryptBtn", timeout=self.LONG_TIMEOUT)
            await self._wait_error_visible("#errorMsg", timeout=self.MED_TIMEOUT)
            msg = await self.page.evaluate(
                "document.querySelector('#errorMsg').textContent"
            )
            log.info("error banner: %r", msg.strip())
            self.assertNotIn("<", msg)
            self.assertNotIn(">", msg)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    except KeyboardInterrupt:
        log.warning("KeyboardInterrupt received")
        try:
            for h in logging.getLogger().handlers:
                h.flush()
        except Exception:
            pass
        sys.exit(130)