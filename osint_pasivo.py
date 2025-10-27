#Actividades pasivas con Python

import os
import builtwith 
import dns.resolver 
import whois11 
import requests
import re
import whoisit 
import time
import pyhunter 
import socket
import shodan as shodan
import json
import csv

from datetime import datetime

# Función para generar nombres de archivos CSV con timestamp

def generar_nombre_csv(base, dominio):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    carpeta_dominio = os.path.join("resultados_csv", dominio)
    os.makedirs(carpeta_dominio, exist_ok=True)
    nombre = f"{base}_{timestamp}.csv"
    return os.path.join(carpeta_dominio, nombre)

#1. Función para BuiltWith

def builtwith_info(dominio, timeout=10):

    old_to = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        
        info = builtwith.parse(f"http://{dominio}")

        if not info:

            info = builtwith.parse(f"https://www.{dominio}")

    except Exception as e:
        print(f"Error o timeout en BuiltWith: {e}")
        return None

    finally:
        resultados_builtwith = []

        for key, value in info.items():
            resultados_builtwith.append((key, "->", value))

        # Serializar a CSV
        nombre_archivo = generar_nombre_csv("builtwith", dominio)
        with open(nombre_archivo, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Tecnología', '->', 'Detalles'])
            for row in resultados_builtwith:
                writer.writerow(row)

        if not resultados_builtwith:
            print("No se encontraron tecnologías asociadas.")
        else:
            print(f"Resultados de BuiltWith en CSV guardados en '{nombre_archivo}'")
        
        # Restaurar el timeout global previo
        socket.setdefaulttimeout(old_to)

        return resultados_builtwith

#2. Función para obtener registros DNS

def registros_dns(dominio):
    tipos  = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    resultados_dns = {}

    for rtype in tipos:
        try:
            respuestas = dns.resolver.resolve(dominio, rtype, lifetime = 3)
            resultados_dns[rtype] = [str(rdata) for rdata in respuestas]
            time.sleep(0.3)
        except Exception as e:
            resultados_dns[rtype] = []
            print(f"{rtype}: no disponible o error - {e}")

    #Serializar a CSV

    nombre_archivo = generar_nombre_csv("dns_registros", dominio)
    with open(nombre_archivo, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Tipo de Registro', 'Valores'])
        for rtype, values in resultados_dns.items():
            writer.writerow([rtype, ', '.join(values) if values else 'No disponible'])
    
    if resultados_dns == []:
            print("No se encontraron registros DNS asociados.")
    
    else:
            print(f"Resultados de DNS en CSV guardados en '{nombre_archivo}'")
    
    return resultados_dns

#3. Función para subdominios con DNS

def subdominios_dns(dominio):

    tipos  = ['A', 'AAAA', 'MX', 'NS', 'TXT']

    wordlist = ['www', 'mail', 'ftp', 
                'test', 'dev', 'api', 
                'blog', 'vpn', 'ns1', 
                'mx', 'correo']
    
    subdominios_encontrados = []

    for sub in wordlist:

        nombre = f"{sub}.{dominio}"
        ips = []

        for rtype in tipos:

            try:
                respuestas = dns.resolver.resolve(nombre, rtype, lifetime = 2)
                ips.extend([r.to_text() for r in respuestas])
                
                time.sleep(0.3)
            
            except Exception:
                pass

            if ips:
                subdominios_encontrados.append({'subdominio': nombre,'ips': ips})
            
    #Serializar a CSV
    nombre_archivo = generar_nombre_csv("subdominios_encontrados", dominio)
    with open(nombre_archivo, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Subdominio', 'IPs'])
        for entry in subdominios_encontrados:
            writer.writerow([entry['subdominio'], ', '.join(entry['ips'])])

            if subdominios_encontrados == []:
                print("No se encontraron subdominios asociados.")
            
            else:
                print(f"Resultados de subdominios en CSV guardados en '{nombre_archivo}'")
    
    return subdominios_encontrados

#4. Función para búsqueda WHOIS (RDAP opcional)

def whois_busqueda(dominio, timeout=10):

    old_to = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        info_whois = whois11.whois(dominio)
    except Exception as e:
        info_whois = f"Error en consulta WHOIS: {e}"

    try:
        whoisit.bootstrap()
        resultado_rdap = whoisit.domain(dominio)
    except Exception as e:
        resultado_rdap = f"Error en consulta RDAP: {e}"
        
    finally:
        # Restaurar el timeout global previo
        socket.setdefaulttimeout(old_to)

        # Serializar a CSV
        nombre_archivo = generar_nombre_csv("whois_rdap", dominio)
        with open(nombre_archivo, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Tipo', 'Información'])
            writer.writerow(['WHOIS', str(info_whois)])
            if resultado_rdap:
                writer.writerow(['RDAP', str(resultado_rdap)])

    print(f"Resultados de WHOIS y RDAP en CSV guardados en '{nombre_archivo}'")

    return info_whois, resultado_rdap

#5. Función para búsqueda en Shodan

def shodan_busqueda(dominio):
    api_key = input("Introduce tu API Key de Shodan: ").strip()

    sh = shodan.Shodan(api_key)

    dominio_host = f"hostname:{dominio}"
    
    try:
        resultados_shodan = sh.search(dominio_host)
    
    except shodan.APIError as e:
        print(f"Error en la búsqueda de Shodan: {e}")
        return None
    
    
    finally:

    # Serializar a CSV sólo si hay resultados
        if resultados_shodan:
            nombre_archivo = generar_nombre_csv("shodan", dominio)
            with open(nombre_archivo, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(['IP', 'Puerto', 'Organización', 'Sistema Operativo'])
                for resultado in resultados_shodan.get('matches', []):
                    writer.writerow([
                        resultado.get('ip_str', 'N/A'),
                        resultado.get('port', 'N/A'),
                        resultado.get('org', 'N/A'),
                        resultado.get('os', 'N/A')
                    ])

            print(f"Resultados de Shodan en CSV guardados en '{nombre_archivo}'")

        else:
            None
    
    return resultados_shodan

#6. Función para búsqueda en Hunter.io

def hunter_busqueda(dominio):
    api_key = input("Introduce tu API Key de Hunter.io: ").strip()

    if not api_key:
        print("API Key no proporcionada. No se realizará la búsqueda en Hunter.io.")
        return None
    
    hunter = pyhunter.PyHunter(api_key)

    resultados_hunter = hunter.domain_search(dominio)

    # Serializar a CSV si hay resultados
    if resultados_hunter:
        nombre_archivo = generar_nombre_csv("hunter", dominio)
        with open(nombre_archivo, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Correo Electrónico', 'Tipo', 'Fuente'])
            for email in resultados_hunter.get('emails', []):
                writer.writerow([
                    email.get('value', 'N/A'),
                    email.get('type', 'N/A'),
                    email.get('sources', 'N/A')
                ])

        print(f"Resultados de Hunter.io en CSV guardados en '{nombre_archivo}'")
    else:
        print("No hay resultados de Hunter.io para serializar.")

    return resultados_hunter

#7. Función para recopilar correos

def crawl_correos(dominio):

    url = f"http://www.{dominio}"

    lista_correos = []
    
    try:
        respuesta = requests.get(url, timeout=5)

        if respuesta.status_code != 200:
            print("No se pudo acceder al sitio web.")
            print("Intentando con https...")

            respuesta = requests.get(url.replace("http://", "https://"), timeout=3)

            if respuesta.status_code != 200:
                print("No se pudo acceder al sitio web con https tampoco.")
                return lista_correos
        
        #Set de correos encontrados

        regExmail = r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+"
        correos_encontrados = set(re.findall(regExmail, respuesta.text, re.I))

        for correo in correos_encontrados:
            lista_correos.append(correo)
    
    except Exception as e:
        print(f"Error al rastrear correos: {e}")
    
    finally:

        #Serializar a CSV
        nombre_archivo = generar_nombre_csv("correos_encontrados", dominio)
        with open(nombre_archivo, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Correo Electrónico'])
            for correo in lista_correos:
                writer.writerow([correo])
        
        if lista_correos == []:
            print("No se encontraron correos electrónicos asociados.")
        
        else:
            print(f"Resultados de correos electrónicos en CSV guardados en '{nombre_archivo}'")

    return lista_correos


# Función para generar reporte JSON consolidado

def generar_reporte_json(dominio, **kwargs):
    """Genera un reporte JSON con todos los resultados, usando kwargs para flexibilidad."""
    
    # Asegurar que el reporte tenga todos los campos esperados, incluso si son None
    reporte = {
        "dominio_analizado": dominio,
        "fecha_analisis": datetime.now().isoformat(),
        # Los resultados de whois_busqueda son una tupla de (whois, rdap)
        "whois_rdap": {
            "whois": kwargs.get('info_whois'),
            "rdap": kwargs.get('resultado_rdap')
        },
        "builtwith": kwargs.get('resultados_builtwith'),
        "dns": kwargs.get('resultados_dns'),
        "subdominios": kwargs.get('subdominios_encontrados'),
        "shodan": kwargs.get('resultados_shodan'),
        "hunter.io": kwargs.get('resultados_hunter'),
        "correos_encontrados": kwargs.get('lista_correos')
    }

    carpeta = os.path.join("resultados_csv", dominio)
    os.makedirs(carpeta, exist_ok=True)
    nombre_archivo = os.path.join(carpeta, f"reporte_pasivo_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")

    with open(nombre_archivo, "w", encoding="utf-8") as f:
        # Usar un manejador de objetos por defecto para asegurar que objetos complejos como
        # el objeto WHOIS (si no es un string) se conviertan a string antes de la serialización
        def default_serializer(obj):
            if isinstance(obj, str) and (obj.startswith("Error") or obj.startswith("WhoisQuery")):
                 return obj # Si es un error o string, déjalo
            return str(obj) # Convierte cualquier objeto no serializable a su representación string

        json.dump(reporte, f, indent=4, ensure_ascii=False, default=default_serializer)
    print(f"Reporte JSON generado en '{nombre_archivo}'")
#Función principal

def main():

    dominio = "example.com"

    resultados_dict = {}

    resultados_dict['resultados_builtwith'] = builtwith_info(dominio)
    resultados_dict['resultados_dns'] = registros_dns(dominio)
    resultados_dict['subdominios_encontrados'] = subdominios_dns(dominio)
    resultados_dict['resultados_shodan'] = shodan_busqueda(dominio)
    resultados_dict['resultados_hunter'] = hunter_busqueda(dominio)
    resultados_dict['lista_correos'] = crawl_correos(dominio)

    whois_res, rdap_res = whois_busqueda(dominio)
    resultados_dict['info_whois'] = whois_res
    resultados_dict['resultado_rdap'] = rdap_res
    
    print("\nTodas las búsquedas completadas.")

    generar_reporte_json(dominio, **resultados_dict)

if __name__ == "__main__":
    main()
