Resources:

[Guide](https://www.raspberrypi.com/documentation/computers/linux_kernel.html)

---

#Install Dependencies
```
$ sudo apt install clang llvm build-essential pkg-config libpcap-dev libelf-dev zlib1g-dev
```

#Install Tool: https://github.com/domcyrus/rustnet/blob/main/INSTALL.md#linux-package-installation
```
$ cargo install rustnet-monitor
```

#We need to compile kernel with bpf.. 
#Info for kernel
```
$ tr -d '\0' </proc/device-tree/model; echo
Raspberry Pi 4 Model B Rev 1.4

$ uname -r
6.18.50+rpt-rpi-v8
```

#git kernel: https://github.com/raspberrypi/linux
```
sudo git clone --depth=1 --branch rpi-6.18.y https://github.com/raspberrypi/linux.git
cd ~/linux
```

#Kernel Compiling dependencies
```
sudo apt install bc bison flex libssl-dev make gcc git libncurses-dev dwarves
```

#MakesureBPF filtering is enabled
```
#Make image
sudo make bcm2711_defconfig

#Enable bpf debugs
scripts/config --enable DEBUG_INFO_DWARF5 
scripts/config --enable DEBUG_INFO_BTF
scripts/config --enable DEBUG_INFO

#make olddefconfig
```

#Verify debug is enabled
```
grep -E 'CONFIG_DEBUG_INFO(_DWARF5|_BTF)?=' .config
```

#Make Kernel Image (-j2 is cores used. speed it up a lil)
```
sudo make -j2 Image.gz modules dtbs
```

#Kernel Compiled
```
ls -al ~/linux/arch/arm64/boot
Image.gz
Image.gz: gzip compressed data, max compression, from Unix, original size modulo 2^32 30882304
```

#Make Install
```
sudo make -j6 modules_install
```

#Run the following commands to create a backup image of the current kernel, install the fresh kernel image, overlays, README, and unmount the partitions:
```
    sudo cp /boot/firmware/$KERNEL.img /boot/firmware/$KERNEL-backup.img
    sudo cp arch/arm64/boot/Image.gz /boot/firmware/$KERNEL.img
    sudo cp arch/arm64/boot/dts/broadcom/*.dtb /boot/firmware/
    sudo cp arch/arm64/boot/dts/overlays/*.dtb* /boot/firmware/overlays/
    sudo cp arch/arm64/boot/dts/overlays/README /boot/firmware/overlays/
```

#Depending on your kernel version, run the following command:
For kernels up to version 6.4:
```
sudo cp arch/arm/boot/dts/*.dtb /boot/firmware/
```
#For kernels version 6.5 and above:
```
sudo cp arch/arm/boot/dts/broadcom/*.dtb /boot/firmware/
```
#Copy over the overlays and README:
```
sudo cp arch/arm/boot/dts/overlays/*.dtb* /boot/firmware/overlays/
sudo cp arch/arm/boot/dts/overlays/README /boot/firmware/overlays/
```

Finally, reboot to freshly compiled kernel:
```
sudo reboot
```
