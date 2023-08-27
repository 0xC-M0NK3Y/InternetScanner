from . import do_get_req

async def func(addr):
	try:
		response, _ = await do_get_req(f"http://{addr}")
		return [response.headers['Server']], True
	except:
		return [], False
