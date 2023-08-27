from . import do_get_req

CREDS = ["credentials.json", ".git", ".env"]

async def func(addr):
	ret = []
	for cred in CREDS:
		try:
			response, text = await do_get_req(f"http://{addr}/{cred}")
			if response.status == 200 and len(text) > 0:
				ret.append((cred, text))
		except:
			pass
	if len(ret) > 0:
		return ret, True
	return [], False
