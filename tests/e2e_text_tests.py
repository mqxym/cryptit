import asyncio
import http.server
import socketserver
import threading
import time
from pyppeteer import launch
import unittest

class WasmHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=".", **kwargs)

    def do_GET(self):
        if self.path.endswith('.wasm'):
            self.send_response(200)
            self.send_header('Content-type', 'application/wasm')
            self.end_headers()
            with open(self.path[1:], 'rb') as f:
                self.wfile.write(f.read())
        else:
            super().do_GET()

class CryptitTextE2ETests(unittest.TestCase):
    SERVER_PORT = 8081
    SERVER_URL = f"http://localhost:{SERVER_PORT}"
    TEST_TEXT = "This is a test."
    XSS_PAYLOAD = "<script>alert('xss')</script>"
    MALFORMED_CIPHERTEXT = "this is not a valid ciphertext"

    @classmethod
    def setUpClass(cls):
        cls.httpd = socketserver.TCPServer(("", cls.SERVER_PORT), WasmHandler)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        time.sleep(1)

        cls.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(cls.loop)
        cls.browser = cls.loop.run_until_complete(launch(headless=True, args=['--no-sandbox', '--disable-dev-shm-usage']))

    @classmethod
    def tearDownClass(cls):
        cls.loop.run_until_complete(cls.browser.close())
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.server_thread.join()
        cls.loop.close()

    def test_text_encryption_and_decryption(self):
        async def _test(self):
            page = None
            try:
                page = await self.browser.newPage()
                await page.goto(f"{self.SERVER_URL}/examples/text-encryption.html", {'waitUntil' : 'networkidle0'})

                await page.type("#inputText", self.TEST_TEXT)
                await page.type("#secret", "password")
                await page.click("#encryptBtn")

                await page.waitForSelector("#outputText:not([value=''])")
                encrypted_text = await page.evaluate('document.querySelector("#outputText").value')
                self.assertNotEqual(encrypted_text, self.TEST_TEXT)

                await page.goto(f"{self.SERVER_URL}/examples/text-decoding.html", {'waitUntil' : 'networkidle0'})

                await page.type("#cipherInput", encrypted_text)
                await page.click("#dataBtn")
                await asyncio.sleep(1) # Give time for decryption to start

                await page.waitForSelector("#resultBox:not(:empty)", {'timeout': 120000})
                decoded_text_json = await page.evaluate('document.querySelector("#resultBox").textContent')
                import json
                decoded_text = json.loads(decoded_text_json)
                self.assertEqual(decoded_text['text'], self.TEST_TEXT)
            finally:
                if page:
                    await page.close()
        self.loop.run_until_complete(_test(self))

    def test_xss_vulnerability_text_decoding(self):
        async def _test(self):
            page = None
            try:
                page = await self.browser.newPage()
                await page.goto(f"{self.SERVER_URL}/examples/text-encryption.html", {'waitUntil' : 'networkidle0'})

                await page.type("#inputText", self.XSS_PAYLOAD)
                await page.type("#secret", "password")
                await page.click("#encryptBtn")

                await page.waitForSelector("#outputText:not([value=''])")
                encrypted_xss = await page.evaluate('document.querySelector("#outputText").value')

                await page.goto(f"{self.SERVER_URL}/examples/text-decoding.html", {'waitUntil' : 'networkidle0'})
                await page.type("#cipherInput", encrypted_xss)
                await page.click("#dataBtn")

                await page.waitForSelector("#resultBox:not(:empty)", {'timeout': 120000})
                output_text = await page.evaluate('document.querySelector("#resultBox").textContent')
                self.assertIn(self.XSS_PAYLOAD, output_text)

                dialog_triggered = False
                def handle_dialog(dialog):
                    nonlocal dialog_triggered
                    dialog_triggered = True
                    asyncio.ensure_future(dialog.dismiss())
                page.on('dialog', handle_dialog)
                await asyncio.sleep(1)
                self.assertFalse(dialog_triggered, "XSS alert was triggered!")
            finally:
                if page:
                    await page.close()
        self.loop.run_until_complete(_test(self))

    def test_exception_not_rendered_as_html(self):
        async def _test(self):
            page = None
            try:
                page = await self.browser.newPage()
                await page.goto(f"{self.SERVER_URL}/examples/text-decoding.html", {'waitUntil' : 'networkidle0'})

                await page.type("#cipherInput", self.MALFORMED_CIPHERTEXT)
                await page.click("#dataBtn")

                await page.waitForSelector("#errBox:not(.d-none)")
                error_text = await page.evaluate('document.querySelector("#errBox").textContent')
                self.assertNotIn("<", error_text)
                self.assertNotIn(">", error_text)
            finally:
                if page:
                    await page.close()
        self.loop.run_until_complete(_test(self))

if __name__ == "__main__":
    unittest.main()
