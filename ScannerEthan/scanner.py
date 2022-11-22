import asyncio
import aiohttp
from addrs import get_random_address
from config import SESSION_SETTINGS, REQUEST_SETTINGS, SCANS
from report import Report

async def scanner(loop):
	async with aiohttp.ClientSession(**SESSION_SETTINGS) as session:

		while True:
			
			t = get_random_address()
			if t is None:
				return
			baseurl=f"http://"+t+"/"
			_resp = None

			try:
				async with session.get(**{"url":baseurl}, **REQUEST_SETTINGS) as resp:
					reporter = Report(resp)

					for _scan in SCANS:
						try:
							scan = _scan(resp, REQUEST_SETTINGS)
							if scan.preCheck():
								tags, data = await scan.scan(session)
								reporter.add_scan(tags, data)
						except Exception as e:
							print(e)
							continue

					await reporter.export()

			except Exception as e:
				continue