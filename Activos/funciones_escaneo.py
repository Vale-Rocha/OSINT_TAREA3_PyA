import socket
import json
import time
import platform
import subprocess
import csv
from datetime import datetime
Authorized = 1

PUERTOS_COMUNES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    161: "snmp",
    443: "https",
    445: "microsoft-ds",
    3306: "mysql",
    3389: "rdp",
    5900: "vnc",
    8080: "http-proxy",
}

# Scapy opcional (requiere permisos de administrador)
try:
    from scapy.all import sr1, IP, ICMP, TCP, conf
    _SCAPY_DIS = False
except Exception:
    _SCAPY_DIS = True

socket_timeout = 2.0

def scapy_pingICMP(ip: str, intentos: int = 3, timeout: float = 1.0) -> bool:
    if _SCAPY_DIS:
        raise RuntimeError("scapy no disponible o permisos insuficientes")
    conf.verb = 0
    for _ in range(intentos):
        try:
            pkt = IP(dst=ip)/ICMP()
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp is not None:
                return True
        except PermissionError:
            raise
        except Exception:
            pass
        time.sleep(0.2)
    return False
def scapy_tcp_scan(ip: str, ports: list, intentos: int = 1, timeout: float = 1.0) -> dict:
   
    if _SCAPY_DIS:
        return {port: "scapy no disponible" for port in ports}
    conf.verb = 0  # Desactivar salida de Scapy
    resultados = {}

    for port in ports:
        abierto = False
        for _ in range(intentos):
            pkt = IP(dst=ip)/TCP(dport=port, flags="S") 
            resp = sr1(pkt, timeout=timeout, verbose=0)
            
            if resp is None:
                resultados[port] = "filtered/no response"
            elif resp.haslayer(TCP):
                if resp[TCP].flags == 0x12: 
                    resultados[port] = "open"
                    sr1(IP(dst=ip)/TCP(dport=port, flags="R"), timeout=timeout, verbose=0)
                elif resp[TCP].flags == 0x14: 
                    resultados[port] = "closed"
            else:
                resultados[port] = "unknown"
            time.sleep(0.1)
    return resultados

def ping_sinroot(ip: str, intentos: int = 3) -> bool:
    sist = platform.system().lower()
    if sist == "windows":
        cmd = ["ping", "-n", str(intentos), "-w", "1000", ip]
    else:
        cmd = ["ping", "-c", str(intentos), "-W", "1", ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False
    

def leer_conSocket(ip: str, ports: list, timeout: float = socket_timeout) -> dict:
    res = {}
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((ip, p))
            banner = b""
            try:
                s.settimeout(1.0)
                banner = s.recv(1024)
            except Exception:
                banner = b""
            finally:
                s.close()
            res[p] = {
                "open": True,
                "banner": banner.decode(errors="replace") if banner else ""
            }
        except socket.timeout:
            res[p] = {"open": False, "banner": ""}
        except ConnectionRefusedError:
            res[p] = {"open": False, "banner": ""}
        except Exception as e:
            res[p] = {"open": False, "error": str(e)}
        finally:
            try:
                s.close()
            except Exception:
                pass
    return res

def guardar_result(resultados):
    with open("resultados.json", "w", encoding="utf-8") as f:
        json.dump(resultados, f, indent=2, ensure_ascii=False)
    
    with open("resultados.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Prueba", "IP", "inicio", "fin",  "Puerto","Estado","banner"])
        for prueba, data in resultados.items():
            ip = data.get("ip", "")
            inicio = data.get("inicio", "")
            fin = data.get("fin", "")
            res = data.get("resultado", "")
            if isinstance(res, dict):
                for port, info in res.items():
                    if isinstance(info, dict):
                        if "state" in info:
                            estado = info["state"]
                        elif "open" in info:
                            estado = "open" if info["open"] else "closed"
                        else:
                            estado = ""
                        banner = info.get("banner", "")
                    elif isinstance(info, str):
                        estado = info
                        banner = ""
                    else:
                        estado = str(info)
                        banner = ""
                    
                    writer.writerow([prueba, ip, inicio, fin, port,estado, banner])
            elif isinstance(res, list):
                for host in res:
                    h_ip = host.get("ip", "")
                    tcp = host.get("tcp", {})
                    for port, estado in tcp.items():
                        writer.writerow([prueba, h_ip, inicio, fin, port, estado, ""])
            else:
                writer.writerow([prueba, ip, inicio, fin, "N/A", res, ""])
    print("Resultados guardados en 'resultados.json' y 'resultados.csv'")

def nmap(target: str,ports: str) -> dict :
    import nmap
    nm = nmap.PortScanner()
    nm.scan(hosts=target, ports=ports, timeout=5)

    results_json = []
    for host in nm.all_hosts(): 
        info = { 
            'ip': host, 
            'hostname': nm[host].hostname(), 
            'state': nm[host].state(), 
            'tcp': {} 
        } 
        for puerto, datos in nm[host]['tcp'].items(): 
            info['tcp'][str(puerto)] = datos['state'] 
        results_json.append(info)
        
    return results_json 
