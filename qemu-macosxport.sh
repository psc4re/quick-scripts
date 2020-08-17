# Install QEMU OSX port with ARM support
sudo port install qemu +target_arm
export QEMU=$(which qemu-system-arm)

# Dowload kernel and export location
sudo port install wget
wget https://github.com/dhruvvyas90/qemu-rpi-kernel/raw/master/kernel-qemu-4.4.34-jessie
export RPI_KERNEL=./kernel-qemu-4.4.34-jessie

# Download filesystem and export location
wget http://downloads.raspberrypi.org/raspbian/images/raspbian-2016-11-29/2016-11-25-raspbian-jessie.zip
unzip 2016-11-25-raspbian-jessie.zip
export RPI_FS=./2016-11-25-raspbian-jessie.img

# Tweak filesystem: start qemu with init flag, switch to guest window to execute tweak and close window afterwards
$QEMU -kernel $RPI_KERNEL \
-cpu arm1176 -m 256 \
-M versatilepb -no-reboot -serial stdio \
-append "root=/dev/sda2 panic=1 rootfstype=ext4 rw init=/bin/bash" \
-drive "file=$RPI_FS,index=0,media=disk,format=raw"

sed -i -e 's/^/#/' /etc/ld.so.preload
sed -i -e 's/^/#/' /etc/fstab

# Emulate Raspberry Pi
$QEMU -kernel $RPI_KERNEL \
-cpu arm1176 -m 256 \
-M versatilepb -no-reboot -serial stdio \
-append "root=/dev/sda2 panic=1 rootfstype=ext4 rw" \
-drive "file=$RPI_FS,index=0,media=disk,format=raw" \
-net user,hostfwd=tcp::5022-:22

# Login to Raspberry Pi
ssh -p 5022 pi@localhost

# Referenced from OSX raspberry pi emulation via QEMU - https://gist.github.com/JasonGhent/e7deab904b30cbc08a7d
# Referenced from Emulating Jessie image with 4.x.xx kernel - https://github.com/dhruvvyas90/qemu-rpi-kernel/wiki/Emulating-Jessie-image-with-4.x.xx-kernel
