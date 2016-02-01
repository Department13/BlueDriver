# BlueDriver
Bluetooth Low-Energy Wardriving

usage: scan.py [-h] [-o OUIFILE] -l LOGFILE [-i LISTEN_INTERFACE]

Listen interface is an HCI Bluetooth 4.0 or greater Bluetooth interface

# Requirements
- PyBluez (https://github.com/karulis/pybluez)
- pyGattlib (https://bitbucket.org/OscarAcena/pygattlib)

# Suggestions
- For best results, disable bluetooth and bluetooth-applet services (service bluetooth stop)
- Have an OUI file available so devices can be listed alongside their chip manufacturer (one is included)
