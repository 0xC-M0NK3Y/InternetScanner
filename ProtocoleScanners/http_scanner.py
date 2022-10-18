import socket
import requests
import threading

def connect_to_scanner(addr, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((addr, port))
    print("Connected to "+addr+":"+str(port))
    return sock

def send_request(sock, port, number):
    req = "groume 0.0.0.0/0 " + str(port) + " " + str(number) + "\n"
    sock.send(req.encode())
    final = str()
    while 1:
        ips = sock.recv(10000)
        tmp = ips.decode()
        final = final + tmp
        if "end".encode() in ips:
            break    
    ip_list = final.split(":80\n")
    ip_list.pop()
    return ip_list
    
def make_get_req(ip, serv, index):
    try:
        r = requests.get("http://"+ip)
        serv[index] = r.headers.get('Server')
    except:
        serv[index] = "fail"

serveurs = {"nginx", "Apache", "cloudflare", "Webs", "None", "AkamaiGHost", "CloudFront", "Microsoft-IIS", "httpd", "SonicWALL",
            "awselb", "gvs", "Microsoft-HTTPAPI", "openresty", "IdeaWebServer", "APISIX", "gunicorn", "squid", "Kestrel", "Radioshop Stream Server",
            "DNVRS-Webs", "IPC@CHIP", "LiteSpeed", "Swift"}



addr = "127.0.0.1"
port = 9955
encoding = 'utf-8'
sock = connect_to_scanner(addr, port)

ip_list = send_request(sock, 80, 10)
serv_list = []

while True:
    for i in range(0, len(ip_list)):
        serv_list.append("")
        thrds = threading.Thread(target=(make_get_req(ip_list[i], serv_list, i)))
        thrds.start()
    thrds.join()
    for i in range(0, len(serv_list)):
        print("server = "+ str(serv_list[i])+ " ip : "+ip_list[i])
    serv_list.clear()
    ip_list = send_request(sock, 80, 10)
    
