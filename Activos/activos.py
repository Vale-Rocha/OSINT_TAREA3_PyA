from datetime import datetime
import principal as lib
resultados = {}
AUTHORIZED = 0
who = '1.1.1.1'

def menu_activos():
    while True:
        print("\n---MENU ACTIVO---\n---OPCIONES---\n0.Salir\n1.Nmap\n2.ScapyPing\n3.PingsinRoot\n4.Socket\n5.ScapyTcpScan\n6.Exportar")
        opcion = input("Ingrese una opcion: ").strip().upper()
        match opcion:
            case "0" | "SALIR":
                return 0
            
            case "1" | "NMAP":
                inicio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                res_nmap = lib.nmap(who, "22,23,80,443,8080")
                fin = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"nmap -> {who}:", res_nmap)
                resultados["nmap"] =  {'ip' : who, 'inicio': inicio, 'fin': fin, "resultado" : res_nmap}
                
            case "2" | "SCAPYPING" | "PING":
                inicio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    res_scapy = lib.scapy_pingICMP(who, intentos=2)
                except Exception as e:
                    res_scapy = f"error: {e}"
                fin = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"scapy_pingICMP -> {who}:", res_scapy)
                resultados["scapy_pingICMP"] = {"ip": who, "inicio": inicio, "fin": fin, "resultado": res_scapy}
                
            case "3" | "PINGSINROOT" | "NO ROOT":
                inicio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    resP = lib.ping_sinroot(who, intentos=2)
                except Exception as e:
                    resP = f"error: {e}"
                fin = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"ping_sinroot -> {who}:", resP)
                resultados["ping_sinroot"] = {"ip": who,"inicio":inicio, "fin": fin, "resultado": resP}
                
            case "4" | "SOCKET":
                inicio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                res_socket = lib.leer_conSocket(who, [22, 80, 8080, 9999], timeout=1.0)
                fin = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"leer_conSocket -> {who} [22,80,9999]:", res_socket)
                resultados["leer_conSocket"] = {"ip": who, "inicio": inicio, "fin": fin, "resultado": res_socket}
            case "5" | "SCAPYTCP":
                inicio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    res_tcp = lib.scapy_tcp_scan(who, [22, 80, 8080, 9999]) 
                except Exception as e:
                    res_tcp = f"error: {e}"
                fin = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"scapy_tcp_scan -> {who}:", res_tcp)
                resultados["scapy_tcp_scan"] = {"ip": who, "inicio": inicio, "fin": fin, "resultado": res_tcp}
            
            case "6" | "EXPORTAR":
                lib.guardar_result(resultados)
                
            case _:
                print("ERROR: Ingrese una opcion valida")

def Auth():
    if AUTHORIZED == 0:
        print("\nACCESO DENEGADO\n")
    elif AUTHORIZED == 1:
        print("\nBIENVENIDO")
        menu_activos()
    else:
        print("\nERROR DE AUTENTICACION\n") 
        
if __name__ == "__main__":
    Auth()
    
