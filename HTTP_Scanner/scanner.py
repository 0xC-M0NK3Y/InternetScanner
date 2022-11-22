import asyncio
from config import PORT_SCAN_ADDR, SCAN_AMOUNT, SCAN_PORTS, IP_RANGES, PASSWORD
from asyncio import Queue
from resource import RLIMIT_NOFILE, getrlimit
import aiohttp

async def scan(queue):
	while True:
		target = await queue.get()
		async with aiohttp.ClientSession() as session:
			try:
				async with session.get("http://"+target.split(':')[0]) as response:
					html = await response.text()
							# déjà au lieu de marquer tout ce code, tu veux pas faire
							# une fonction
			except:
				pass
		queue.task_done()

async def fetcher(queue):
	while True:
		reader, writer = await asyncio.open_connection(*PORT_SCAN_ADDR)
		print("Connected")
		writer.write(f"{PASSWORD} {IP_RANGES} {SCAN_PORTS} {SCAN_AMOUNT}\n".encode())
		await writer.drain()
		while True:
			data = await reader.read(500)
			await queue.put(data.decode().strip())
			if b"end" in data or len(data) == 0:
				break
		print('Close the connection')
		writer.close()
		await writer.wait_closed()
		while not queue.empty():
			await asyncio.sleep(1)

async def main():
	queue = Queue()
	for i in range(0, int(getrlimit(RLIMIT_NOFILE)[1] / 1.5)):
		asyncio.create_task(scan(queue))
	await fetcher(queue)


asyncio.run(main())
