from ..scan import Scan
import aiohttp
import traceback

TO_FIND = [
	"<h1>Index of /</h1>", # Apache
	"<h1>Directory listing for /</h1>" # Python (SimpleHTTP)
]

class NoIndex(Scan):
	async def scan(self, session : aiohttp.ClientSession):
		tags = []
		data = {}

		try:
			async with session.get(**{"url":str(self.ping.url)}, **self.request_args, timeout=2) as resp:
				if resp.status == 200:
					text = (await resp.text())
					for find in TO_FIND:
						if find in text:
							tags.append("NO_INDEX")
							break
		except Exception as e:
			pass

		return tags, data