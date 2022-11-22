import aiohttp
import os

class Scan(object):
	ping : aiohttp.ClientResponse
	request_args : dict

	def __init__(self, ping : aiohttp.ClientResponse, request_args : dict):
		self.ping = ping
		self.request_args = request_args

	def preCheck(self):
		return True

	def mkdir(self, keys : list):
		keys = ["scan-outputs"] + keys
		path = "./"

		for key in keys:
			try:
				os.mkdir(path+key)
			except:
				pass
			path += key+"/"

	async def scan(self, session : aiohttp.ClientSession):
		return [], {}