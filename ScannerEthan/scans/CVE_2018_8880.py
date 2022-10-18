from .scan import Scan
import aiohttp
import traceback

class CVE_2018_8880(Scan):
    async def scan(self, session : aiohttp.ClientSession):
        vulns = []
        data = {}
        try:
            async with session.get(**{"url":str(self.ping.url)+"deviceIP"}, **self.request_args, timeout=2) as resp:
                if resp.status == 200:
                    text = (await resp.text())
                    if "MacAddr" in text:
                        vulns.append("CVE-2018-8880")
                        data["CVE-2018-8880"] = {"data": text}
                        self.mkdir(["CVE-2018-8880"])
                        with open("scan-outputs/CVE-2018-8880/"+self.ping.host+".ini", "w") as fp:
                            fp.write(text)
        except Exception as e:
            pass

        return vulns, data
