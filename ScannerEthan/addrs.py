from random import randint
from config import ORDERED_SCAN

global tmp, file_w
tmp=0

if ORDERED_SCAN:
    try:
        tmp=int(open("NUM","r").read())
    except:
        pass
    file_w=open("NUM","w")

def get_random_address():
    global tmp, file_w
    while True:
        if not ORDERED_SCAN:
            tmp = randint(0, 4294967296)
        else:
            tmp+=1
            if tmp%10000 == 0:
                file_w.write(str(tmp))
                file_w.seek(0)
            elif tmp%4294967296==0:
                tmp=0

        o1 = tmp & 0xff
        o2 = (tmp >> 8) & 0xff
        o3 = (tmp >> 16) & 0xff
        o4 = (tmp >> 24) & 0xff

        if (o1 == 127 or                             # 127.0.0.0/8      - Loopback
          (o1 == 0) or                              # 0.0.0.0/8        - Invalid address space
          (o1 == 3) or                              # 3.0.0.0/8        - General Electric Company
          (o1 == 15 or o1 == 16) or                 # 15.0.0.0/7       - Hewlett-Packard Company
          (o1 == 56) or                             # 56.0.0.0/8       - US Postal Service
          (o1 == 10) or                             # 10.0.0.0/8       - Internal network
          (o1 == 192 and o2 == 168) or               # 192.168.0.0/16   - Internal network
          (o1 == 172 and o2 >= 16 and o2 < 32) or     # 172.16.0.0/14    - Internal network
          (o1 == 100 and o2 >= 64 and o2 < 127) or    # 100.64.0.0/10    - IANA NAT reserved
          (o1 == 169 and o2 > 254) or                # 169.254.0.0/16   - IANA NAT reserved
          (o1 == 198 and o2 >= 18 and o2 < 20) or     # 198.18.0.0/15    - IANA Special use
          (o1 >= 224) or                            # 224.*.*.*+       - Multicast
          (o1 == 6 or o1 == 7 or o1 == 11 or o1 == 21 or o1 == 22 or o1 == 26 or o1 == 28 or o1 == 29 or o1 == 30 or o1 == 33 or o1 == 55 or o1 == 214 or o1 == 215) # Department of Defense
        ):
            pass
        else:
            return f"{o1}.{o2}.{o3}.{o4}"
