from .scan import Scan
import aiohttp
import traceback

class Xmlrpc(Scan):
	async def scan(self, session : aiohttp.ClientSession):
		vulns = []
		data = {}

		try:
			async with session.get(**{"url":str(self.ping.url)+"xmlrpc.php"}, **self.request_args, timeout=2) as resp:
				if resp.status == 405:
					text = (await resp.text())
					if "XML-RPC server accepts POST requests only." in text:
						vulns.append("xmlrpc")
		except Exception as e:
			pass

		return vulns, data