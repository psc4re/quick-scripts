sudo apt-get install qemu-system
DIR="armexploitation/"
if [ ! -d $DIR ]; then
	mkdir $DIR
fi
cd $DIR
# Download files
if [ ! -f "raspbian-jessie-lite.qcow" ]; then 
	wget http://downloads.raspberrypi.org/raspbian_lite/images/raspbian_lite-2017-07-05/2017-07-05-raspbian-jessie-lite.zip
	wget https://github.com/dhruvvyas90/qemu-rpi-kernel/raw/master/kernel-qemu-4.4.34-jessie
	unzip 2017-07-05-raspbian-jessie-lite.zip
	qemu-img convert -f raw -O qcow2  2017-07-05-raspbian-jessie-lite.img raspbian-jessie-lite.qcow
	qemu-img resize raspbian-jessie-lite.qcow +6G
fi

sudo qemu-system-arm -kernel ./kernel-qemu-4.4.34-jessie -append "root=/dev/sda2 panic=1 rootfstype=ext4 rw" -hda raspbian-jessie-lite.qcow -cpu arm1176 -m 256 -M versatilepb -no-reboot -serial stdio -net nic -net user -net tap,ifname=tap0,script=no,downscript=no
