#fdisk
```
sudo fdisk /dev/<partition_to_adjust>
#e - resize
#p - print partitions
#F - free space
```

#dd
```
if=/dev/<partition_to_copy> of=/dev/<partition_coping_to> status=progress bs=4M
```

#make sure to run this when resizing partition
```
sudo resize2fs /dev/<partition#>
```
