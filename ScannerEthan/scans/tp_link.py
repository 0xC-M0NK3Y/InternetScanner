from .scan import Scan
import aiohttp
import traceback

class TPLink(Scan):
	def preCheck(self):
		return True if "WWW-Authenticate" in self.ping.headers.keys() and "TP-LINK" in self.ping.headers["WWW-Authenticate"].upper() else False

	async def scan(self, session : aiohttp.ClientSession):
		return ["TP-Link"].copy(), {}.copy()