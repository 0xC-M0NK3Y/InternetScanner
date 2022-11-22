import asyncio
from scanner import scanner
from config import SIMULTANEOUS_SCAN

async def main(loop):
	for i in range(SIMULTANEOUS_SCAN):
		loop.create_task(scanner(loop))
	while True:
		await asyncio.sleep(1)

loop = asyncio.get_event_loop()
loop.run_until_complete(main(loop))
loop.close()