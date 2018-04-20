#!/bin/sh
BIOS=edk2/Build/OvmfX64/DEBUG_GCC5/FV
case $1 in
"boot-img")
    vtpm-support/qemu-tpm/x86_64-softmmu/qemu-system-x86_64 -display sdl \
    -m 1024 -boot d -bios $BIOS/OVMF.fd -boot menu=on \
    -net nic,vlan=0 -net tap,vlan=0,ifname=tap0,script=no,downscript=no \
    -tpmdev cuse-tpm,id=tpm0,path=/dev/vtpm0 \
    -device tpm-tis,tpmdev=tpm0 edk2/Build/server.img
    ;;
"start")
    brctl show
    qemu-system-x86_64 -display sdl -m 2048\
    -net nic,model=pcnet,vlan=0 -net tap,vlan=0,ifname=tap0,script=/etc/qemu-ifup,downscript=no \
    -boot c -bios $BIOS/OVMF.fd -boot menu=on -tpmdev \
    cuse-tpm,id=tpm0,path=/dev/vtpm0 \
    -serial file:/home/hecmay/debug.log -global isa-debugcon.iobase=0x402 \
    -device tpm-tis,tpmdev=tpm0 edk2/Build/test.img
    ;;
"create-vtpm0")
    rm /tmp/myvtpm0
    sudo mkdir /tmp/myvtpm0
    sudo chown -R tss:root  /tmp/myvtpm0
    sudo swtpm_setup --tpm-state /tmp/myvtpm0  --createek
    sudo env TPM_PATH=/tmp/myvtpm0/ swtpm_cuse -n vtpm0
    ;;
"create-vtpm1")
    mkdir /tmp/myvtpm1
    chown -R tss:root  /tmp/myvtpm1
    swtpm_setup --tpm-state /tmp/myvtpm1  --createek
    export TPM_PATH=/tmp/myvtpm1
    swtpm_cuse -n vtpm1 --log file=/tmp/myvtpm1/out.log
    ;;
"re-tpm")
    sudo env TPM_PATH=/tmp/myvtpm0/ swtpm_cuse -n vtpm0
    ;;
"mount")
    sudo mount -o loop edk2/Build/test.img /home/hecmay/test/
    ;;
"create-fs")
    sudo umount /home/hecmay/test
    rm edk2/Build/test.img
    dd if=/dev/zero of=edk2/Build/test.img bs=1M count=256
    mkfs -V -t vfat edk2/Build/test.img
    sudo mount -o loop edk2/Build/test.img /home/hecmay/test/
    sudo cp edk2/Build/MyApps/DEBUG_GCC5/X64/*.efi /home/hecmay/test/
    sudo cp edk2/Build/MdeModule/DEBUG_GCC5/X64/*.efi /home/hecmay/test/
    sudo cp edk2/Build/CryptoPkg/DEBUG_GCC5/X64/CryptRuntimeDxe.efi /home/hecmay/test/
    sudo mkdir /home/hecmay/test/Efi
    sudo touch /home/hecmay/test/Efi/data.log
    sudo touch /home/hecmay/test/data.log
    sudo cp cert.pem /home/hecmay/test/Event.log
    ;;
"test-socket")
    cd edk2
    build -p MdeModulePkg/MdeModulePkg.dsc -t GCC5 -b DEBUG -a X64 -m RmtPkg/TcpSocket.inf
    ll Build/MdeModule/DEBUG_GCC5/X64/TestSocket.efi
    md5sum Build/MdeModule/DEBUG_GCC5/X64/TestSocket.efi
    cd ..
    sudo ./boot.sh create-fs 
    md5sum /home/hecmay/test/TestSocket.efi
    sleep 50
    sudo ./boot.sh re-tpm && sudo ./boot.sh start
    ;;
"stdsocket")
    cd edk2
    build -p MdeModulePkg/MdeModulePkg.dsc -t GCC5 -b DEBUG -a X64 -m RmtPkg/StdSocket/StdSocket.inf
    ll Build/MdeModule/DEBUG_GCC5/X64/StdSocket.efi
    md5sum Build/MdeModule/DEBUG_GCC5/X64/StdSocket.efi
    sudo rm /home/hecmay/test/StdSocket.efi 
    sudo cp -f Build/MdeModule/DEBUG_GCC5/X64/StdSocket.efi /home/hecmay/test/
    md5sum /home/hecmay/test/StdSocket.efi
    cd ..
    sudo ./boot.sh re-tpm && sudo ./boot.sh start
    ;;
"prepare")
    sudo ./xup.sh tap0
    sudo ./boot.sh create-vtpm0
    sudo ./boot.sh mount
    ;;
"open")
    sudo ./boot.sh re-tpm && sudo ./boot.sh start
    ;;
esac
