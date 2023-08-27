import asyncio
from config import PORT_SCAN_ADDR, SCAN_AMOUNT, SCAN_PORTS, IP_RANGES, PASSWORD
from asyncio import Queue
from resource import RLIMIT_NOFILE, getrlimit
import aiohttp
from scanners import scanners
import time
import sys
import uuid
import os

def write_in_file(dirn, text):
	file = dirn+str(uuid.uuid4())
	out = open(file, 'w')
	print(text, file=out)
	out.close()
	return file

async def scan(queue, fp, dirn):
	while True:
		ret = []
		target = await queue.get()
		for k, v in scanners.lst.items():
			tmp, t = await v(target)
			if t == True:
				if k in scanners.file_output:
					ret.append((k, write_in_file(dirn, tmp)))
				else:
					ret.append((k, tmp))
		if len(ret) > 0:
			print(f'{target}:{ret}', file=fp)
		queue.task_done()

async def fetcher(queue, fp):
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
		if int(time.time()) % 15*60 == 0:
			fp.flush()
		await writer.wait_closed()
		while not queue.empty():
			await asyncio.sleep(1)

async def main():
	if len(sys.argv) != 3:
		print(f"Usage {sys.argv[0]} <outfile> <outdir>")
		exit()

	dirn = sys.argv[2]
	if not os.path.isdir(dirn):
		print(f"Error: {dirn} does not exist")
		exit()
	if not os.access(dirn, os.W_OK):
		print(f"Error: user does not have write permission to {dirn}")
		exit()
	if not os.access(sys.argv[1], os.W_OK):
		print(f"Error: user does not have write permission to {sys.argv[1]}")
		exit()
	if dirn[len(dirn)-1] != '/':
		dirn += '/'
	fp = open(sys.argv[1], 'w')
	queue = Queue()
	for i in range(0, int(getrlimit(RLIMIT_NOFILE)[1] / 1.5)):
		asyncio.create_task(scan(queue, fp, dirn))
	await fetcher(queue, fp)

asyncio.run(main())
