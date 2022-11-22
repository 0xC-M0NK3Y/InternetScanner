import aiohttp
import json
from config import DISCORD_WEBHOOK, NOTIFY

class Report(object):
	tags = []
	data = {}

	def __init__(self, ping_response : aiohttp.ClientResponse):
		self.target = ping_response.host
		self.status = ping_response.status
		self.headers = dict(ping_response.headers)
		self.tags = [].copy()
		self.data = {}.copy()

	def parse_server(self, server):
		return server

	def add_scan(self, tags : list, data : dict):
		self.tags += tags
		self.data = {**self.data, **data}

	async def export(self):
		data = {
			"target": self.target,
			"response": {
				"status": self.status,
				"headers": self.headers
			},
			"tags": self.tags,
			"data": self.data
		}
		if "Server" in self.headers.keys():
				data["response"]["server"] = self.parse_server(self.headers["Server"])
		
		with open("./result.json", "a+") as fp:
			json.dump(data, fp)
			fp.write("\n")

		if DISCORD_WEBHOOK is not None:
			for k in NOTIFY:
				if k in data["tags"]:
					async with aiohttp.ClientSession() as session:
						async with session.post(DISCORD_WEBHOOK, json={"content": f"{data['tags']} on {data['target']}"}):
							pass
					break