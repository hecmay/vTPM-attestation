fs0:
echo -off
echo This is the startup.nsh
"Hello.efi"

load "CryptRuntimeDxe.efi"
ifconfig -s eth0 dhcp

stall 8000000
ifconfig -l eth0
"TestSocket.efi"
