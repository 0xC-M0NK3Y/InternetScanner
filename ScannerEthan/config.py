from aiohttp import ClientTimeout
from scans.netwave import Netwave
from scans.git import Git
from scans.CVE_2017_9841 import Cve_2017_9841
from scans.CVE_2020_5902 import Cve_2020_5902
from scans.CVE_2018_8880 import CVE_2018_8880
from scans.no_index import NoIndex
from scans.webswing import Webswing
from scans.tp_link import TPLink
from scans.xmlrpc import Xmlrpc
from scans.absolute import Absolute
from scans.traversal_path import TraversalPath

SIMULTANEOUS_SCAN=800
TIMEOUT=0.5
PROXIES=None
DISCORD_WEBHOOK="https://discord.com/api/webhooks/803729224816787506/Lc3uhrpDOI6qB86-sGzO3vIAlC0taQCS8zaP1YI_cE5O_JNMaq0uGkhwk6DIr5G-PMcK"
NOTIFY=["CVE-2018-11653", "CVE-2020-5902", "CVE-2017-9841", "CVE-2018-8880", "webswing", "traversal_path", "absolute"]
ORDERED_SCAN=False
SCANS=[
	#Netwave,
	Git,
	#Cve_2017_9841,
	#Cve_2020_5902,
	#CVE_2018_8880,
	#NoIndex,
	#Webswing,
	#TPLink,
	#Xmlrpc,
	Absolute,
	TraversalPath
]

SESSION_SETTINGS={
	"timeout": ClientTimeout(total=TIMEOUT),
	"headers": {}
}
REQUEST_SETTINGS={
	"proxy": PROXIES,
	"allow_redirects": False
}
