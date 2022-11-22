from aiohttp import ClientTimeout
from scans.netwave import Netwave
from scans.git import Git
from scans.CVE_2017_9841 import Cve_2017_9841
from scans.CVE_2020_5902 import Cve_2020_5902
from scans.no_index import NoIndex
from scans.webswing import Webswing
from scans.tp_link import TPLink
from scans.xmlrpc import Xmlrpc

SIMULTANEOUS_SCAN=500
TIMEOUT=0.5
PROXIES=None
DISCORD_WEBHOOK=None
NOTIFY=["CVE-2018-11653", "webswing"]
ORDERED_SCAN=False
SCANS=[
	Netwave,
	Git,
	# Cve_2017_9841,
	# Cve_2020_5902,
	Xmlrpc,
	NoIndex,
	Webswing,
	TPLink
]

# SIMPLIFY PYTHON CODE
SESSION_SETTINGS={
	"timeout": ClientTimeout(total=TIMEOUT),
	"headers": {}
}
REQUEST_SETTINGS={
	"proxy": PROXIES,
	"allow_redirects": False
}