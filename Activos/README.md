Actividades activas con Python

Script que verifica el estado de conexion, puertos abiertos y posibles vulnerabilidades.

Contenido

    funciones_escaneo.py — Código del manejo y estructura de funciones
    activos.py - Código principal del proyecto.
    resultados.csv, resultados.json - Resultados generales del script
    <funcion>_<fecha>.csv - resultado de una acccion en especifico en csv
Requisitos

    Python 3.8+ (probado en 3.13 en este equipo):
    Las siguientes librerías deben de estar disponibles: 
        socket 
        json
        time
        platform
        subprocess
        csv
        python-nmap
    Tener instalado npcap y nmap (Estos se encuentran en https://nmap.org/)

Uso

    Abrir funciones_escaneo.py y asignar los puertos a escanear en las funciones
    Abrir activos.py y en la variable "who" la ip a probar
    Ejecutar el script:
    py activos.py

Salida

Los CSV se generan en el mismo directorio que el script. Cada funcion genera un csv con su respectivo nombre con timestamp, por ejemplo:

    resultados.csv
    nmap_2025-10-29_15-47-54.csv
    scapy_pingICMP_2025-10-29_15-47-54.csv
    ping_sinroot_2025-10-29_15-47-54.csv
    leer_conSocket_2025-10-29_15-47-54.csv
    scapy_tcp_scan_2025-10-29_15-47-54.csv
    
Cada CSV contiene filas legibles con los campos principales extraídos por cada función.

Se genera un recopilado en formato JSON en en el mismo directorio que el script con todos los returns de las funciones y timestamps.
    ```
    resultados.json
    ```
    
Buenas prácticas y seguridad

    No compartas tus API keys en repositorios públicos. Guárdalas en variables de entorno o en un archivo local ignorado por git (ej. .env) y adapta el script para leerlas.
    Asegúrate de tener autorización para realizar reconocimiento contra el dominio objetivo. Este script puede generar consultas que, sin permiso, podrían ser inapropiadas o ilegales.
    Respeta las políticas de uso de servicios como nmap.

Timeouts y tiempos de vida

    Se implementaron timeouts de 5 segundos (se puede modificar).

Licencia

Proyecto bajo licencia MIT. Puedes adaptar y distribuir el código respetando la licencia.

Notas

 

 
