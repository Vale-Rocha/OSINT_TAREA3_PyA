Actividades activas con Python

Script que verifica el estado de conexion, puertos abiertos y posibles vulnerabilidades. Utiliza python y las librerias de nmap, socket y scapy
Contenido

    funciones_escaneo.py — Código del manejo y estructura de funciones
    activos.py - Código principal del proyecto.
    resultados.csv y resultados.json - Resultados del script

Requisitos

    Python 3.8+ (probado en 3.13 en este equipo):
        Las siguientes librerías deben de estar disponibles: socket, json, time, platform, subprocess, csv, python-nmap
    Tener instalado npcap y nmap (Estos se encuentran en https://nmap.org/)

Uso

    Abrir funciones_escaneo.py y asignar los puertos a escanear en las funciones
    Abrir activos.py y en la variable "who" la ip a probar
    Ejecutar el script:

py activos.py

Salida

Los CSV se generan en resultados_csv/<dominio>/ con nombres con timestamp, por ejemplo:

    builtwith_YYYYMMDD_HHMMSS.csv
    dns_registros_YYYYMMDD_HHMMSS.csv
    subdominios_encontrados_YYYYMMDD_HHMMSS.csv
    whois_rdap_YYYYMMDD_HHMMSS.csv
    shodan_YYYYMMDD_HHMMSS.csv
    hunter_YYYYMMDD_HHMMSS.csv
    correos_encontrados_YYYYMMDD_HHMMSS.csv

Cada CSV contiene filas legibles con los campos principales extraídos por cada función.

Se genera un recopilado en formato JSON en resultados_csv/<dominio>/reporte_pasivo_YYYYMMDD_HHMMSS.json con todos los returns de las funciones y timestamps.
Buenas prácticas y seguridad

    No compartas tus API keys en repositorios públicos. Guárdalas en variables de entorno o en un archivo local ignorado por git (ej. .env) y adapta el script para leerlas.
    Asegúrate de tener autorización para realizar reconocimiento contra el dominio objetivo. Este script puede generar consultas que, sin permiso, podrían ser inapropiadas o ilegales.
    Respeta las políticas de uso de servicios como Shodan o Hunter.io.

Timeouts y tiempos de vida

    Se implementaron timeouts de 5 segundos (se puede modificar).
    Se implementaron lifetimes de 2-3 segundos.

Licencia

Proyecto bajo licencia MIT. Puedes adaptar y distribuir el código respetando la licencia.

Notas

    Algunas integraciones requieren claves/API.
    El script requiere el dominio normalizado (sin http(s):// ni / final)
 
