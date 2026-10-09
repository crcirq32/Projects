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

