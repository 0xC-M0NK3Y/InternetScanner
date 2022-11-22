from .ScanBase import ScanBase
from . import do_get_req

class ScanTraversalPath(ScanBase):
	def __init__(self):
		pass

	def get_scan_name(self):
		return "Traversal Path Scanner"

	def get_scan_description(self):
		return "Scanning for traversal path"

	def pre_scan(self, addr, home_req):
		return True


	async def scan(self, addr, home_req):
		response = do_get_req(f"http://{addr}/"+("../"*100)+"etc/passwd")
		# TODO: trouver un truc pour windows (et les autres OS, y'a peut-être pas /etc/passwd)
		if "root:x:0:0:root:" in response.text:
			return ["traversal_path"], {}
		return [], {}