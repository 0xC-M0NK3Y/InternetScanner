from . import do_get_req

async def func(addr):
	try:
		response, text = await do_get_req(f"http://{addr}//etc/passwd")
		if "root:x:0:0:root:" in text:
			return [], True
		return [], False
	except:
		return [], False
