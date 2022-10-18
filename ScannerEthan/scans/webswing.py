from .scan import Scan
import aiohttp
import traceback

class Webswing(Scan):
    async def scan(self, session : aiohttp.ClientSession):
        vulns = []
        data = {}

        try:
            async with session.get(**{"url":str(self.ping.url)+"javascript/webswing-selector.js"}, **self.request_args, timeout=2) as resp:
                if resp.status == 200:
                    text = (await resp.text())
                    if "webswingLang" in text:
                        vulns.append("webswing")
        except Exception as e:
            pass

        return vulns, data