from . import scan_credentials
from . import scan_absolute_path
from . import scan_traversal_path
from . import scan_index_of
from . import scan_server_info

lst = {"server info": scan_server_info.func,
		#"credentials": scan_credentials.func,
		"absolute path": scan_absolute_path.func,
		"traversal path": scan_traversal_path.func,
		"index of": scan_index_of.func}

file_output = ["credentials"]
