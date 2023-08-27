from . import do_get_req

async def func(addr):
	try:
		response, text = await do_get_req(f"http://{addr}")
		tmp = text.lower()
		if tmp.find('index of') > 0 or tmp.find('directory listing for') > 0:
			return [], True
		return [], False
	except:
		return [], False
