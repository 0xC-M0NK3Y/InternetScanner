import asyncio
from config import PORT_SCAN_ADDR, SCAN_AMOUNT, SCAN_PORTS, IP_RANGES, PASSWORD
from asyncio import Queue
from resource import RLIMIT_NOFILE, getrlimit
import ftplib
import sys

async def scanner(queue):
	while True:
		target = await queue.get()
		try:
			with ftplib.FTP(target.split(':')[0], timeout=1) as ftp:
				try:
						ftp.login("admin", "admin")
						ftp.dir()
						print(f"FOUND ADMIN {target}")
				except:
					pass
				try:
						ftp.login()
						ftp.dir()
						print(f"FOUND {target}")
				except:
					pass
				ftp.quit()
		except:
			pass
		sys.stdout.flush()
		queue.task_done()

async def fetcher(queue):
	while True:
		reader, writer = await asyncio.open_connection(*PORT_SCAN_ADDR)
		print("Connected")
		writer.write(f"{PASSWORD} {IP_RANGES} {SCAN_PORTS} {SCAN_AMOUNT}\n".encode())
		await writer.drain()
		while True:
			data = await reader.read(500)
			liste = data.decode().split('\n')
			for i in liste:
				if len(i) > 8:
					await queue.put(i.strip())
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
		asyncio.create_task(scanner(queue))
	await fetcher(queue)


asyncio.run(main())
