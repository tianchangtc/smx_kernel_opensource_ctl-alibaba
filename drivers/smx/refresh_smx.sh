sudo rmmod smx

sudo dmesg -C

sudo insmod smx.ko

echo "module smx +p" | sudo tee /sys/kernel/debug/dynamic_debug/control
echo 8G | sudo tee /sys/class/smx/smx0/smx_control/create_block
echo "12:23:34:45:56:67 0x222200000000 8G" | sudo tee /sys/class/smx/smx0b0/control/remote_config
