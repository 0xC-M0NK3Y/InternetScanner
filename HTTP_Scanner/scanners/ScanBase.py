
# vuv on a notre classe de base
class ScanBase(object):
	def __init__(self):
		pass

	def get_scan_name(self):
		raise NotImplementedError
	
	def get_scan_description(self):
		raise NotImplementedError

	def pre_scan(self, addr, home_req):
		raise NotImplementedError

	async def scan(self, addr, home_req):
		raise NotImplementedError
