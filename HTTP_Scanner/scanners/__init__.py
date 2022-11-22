import aiohttp

aioclient_timeout = aiohttp.ClientTimeout(total=5)

# bonjour '-'
async def do_get_req(url, session_args: dict = {}, request_args: dict = {}):
	async with aiohttp.ClientSession(**{"timeout": aioclient_timeout, **session_args}) as session:
		async with session.get(url, **{"allow_redirects": False, **request_args}) as response:
			return response
			