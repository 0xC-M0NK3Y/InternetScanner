from .scan import Scan
import aiohttp
import traceback

class CVE_2018_16672(Scan):
    async def scan(self, session : aiohttp.ClientSession):
        vulns = []
        data = {}
        try:
            async with session.get(**{"url":str(self.ping.url)+"deviceIP"}, **self.request_args, timeout=2) as resp:
                if resp.status == 200:
                    text = (await resp.text()).encode('utf8')
                    print "Parsing data..."
                    todo =  r.split("\n")
                    wifi = todo[5].split("=")
                    if wifi[1]==1:
                        vulns.append("CVE-2018-11653")
                        data["CVE-2018-11653"] = {"data": text}
                        self.mkdir(["CVE-2018-11653"])
                        with open("scan-outputs/CVE-2018-11653/"+self.ping.host+".ini", "w") as fp:
                            fp.write(text)
        except Exception as e:
            pass

        return vulns, data
