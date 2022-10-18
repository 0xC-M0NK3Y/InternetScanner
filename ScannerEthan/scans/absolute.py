from .scan import Scan
import aiohttp
import traceback

class Absolute(Scan):
    async def scan(self, session : aiohttp.ClientSession):
        vulns = []
        data = {}

        try:
            async with session.get(**{"url":str(self.ping.url)+"/etc/passwd"}, **self.request_args, timeout=2) as resp:
                if resp.status == 200:
                    text = (await resp.text())
                    if ":root:" in text:
                        vulns.append("absolute")
        except Exception as e:
            pass

        return vulns, data