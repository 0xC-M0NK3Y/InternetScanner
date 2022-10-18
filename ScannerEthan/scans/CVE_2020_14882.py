from .scan import Scan
import aiohttp
import traceback

class CVE_2018_8880(Scan):
    async def scan(self, session : aiohttp.ClientSession):
        vulns = []
        data = {}
        try:
            async with session.get(**{"url":str(self.ping.url)+"console/css/%252e%252e%252fconsole.portal"}, **self.request_args, timeout=2) as resp:
                if resp.status == 200:
                    vulns.append("CVE-2020-14882")
                    data["CVE-2020-14882"] = {"data": text}
                    self.mkdir(["CVE-2020-14882"])
                    with open("scan-outputs/CVE-2020-14882/"+self.ping.host+".ini", "w") as fp:
                        fp.write(text)
        except Exception as e:
            pass

        return vulns, data
