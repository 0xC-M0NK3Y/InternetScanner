import aiohttp

aioclient_timeout = aiohttp.ClientTimeout(total=5)

async def do_get_req(url):
	async with aiohttp.ClientSession(timeout=aioclient_timeout) as session:
		async with session.get(url, allow_redirects=False) as response:
			return response, await response.text()

