README ACTIVO

REQUERIMIENTOS

--El script funciona en modulos; se tiene que descargar funciones_escaneo.py (script que tiene las funciones) y activos.py (script que llama las funciones).
--Las siguientes librerías deben de estar disponibles: socket, json, time, platform, subprocess, csv, python-nmap. Asi como tener instalado npcap y nmap (Estos se encuentran en https://nmap.org/).

FUNCIONAMIENTO
--Para el utilizar el script se necesita saber la dirección IPv4 de quien queremos probar. Esta se modifica en la **variable who en Activos.py**.
--Correr en la consola (e.g. py activos.py)
--Los resultados del script se exportan a .csv y .json.


PERMISOS
--Varios actividades no se realizan si no hay permisos de superusuario (Scapy).
--La variable ENTERA AUTHORIZED en activos.py se usa para que este script no se realize de manera accidental: **si AUTHORIZED = 1 SE EJECUTA EL CODIGO**, si AUTHORIZED = 0 no, de igual manera para cualquier otro valor. 
