from .scan import Scan
import aiohttp
import traceback

class Git(Scan):
    async def scan(self, session : aiohttp.ClientSession):
        vulns = []
        data = {}

        try:
            async with session.get(**{"url":str(self.ping.url)+".git/HEAD"}, **self.request_args, timeout=2) as resp:
                if resp.status == 200:
                    text = (await resp.text())
                    if text.startswith("ref: "):
                        vulns.append("EXPOSED_GIT")
                        data["EXPOSED_GIT"] = {"data": text}
        except Exception as e:
            pass

        return vulns, data