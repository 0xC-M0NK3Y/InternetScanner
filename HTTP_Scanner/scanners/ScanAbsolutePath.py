from .ScanBase import ScanBase
from . import do_get_req

class ScanAbsolutePath(ScanBase):
	def __init__(self):
		pass

	def get_scan_name(self):
		return "Absolute Path Scanner"

	def get_scan_description(self):
		return "Scanning for absolute path"

	def pre_scan(self, addr, home_req):
		return True

	async def scan(self, addr, home_req):
		response = do_get_req(f"http://{addr}//etc/passwd")
		if "root:x:0:0:root:" in response.text:
			return ["absolute_path"], {}
		return [], {}