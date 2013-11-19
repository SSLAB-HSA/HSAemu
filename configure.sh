#!/bin/sh
if [ -z $1 ]; then
	echo "use stage: ./configure.sh <llvm-2.9 dirtectly location>"
	exit
fi

##########################################################
#	setting env
##########################################################
hsa_dir=$PWD
env=HSA_ENV_SETTING
echo "#!/bin/sh" > $env
echo "root_dir=$PWD" >> $env
echo "qemu_dir=$PWD/qemu/arm-softmmu" >> $env
echo "llvm_dir=$1" >> $env
echo "vm_dir='vm location'" >> $env
echo "kernel='kernel file name'" >> $env
echo "file_system='file system file name'" >> $env
echo "image='os image'" >> $env
echo "vm_mem='vm memory size'" >> $env
echo "vm_port='vm tcp port'" >> $env
echo "vm_cpu='virtual CPU'" >> $env
echo "vm_board='vm mother board'" >> $env
echo "vm_hsa_CU='number of GPU compute unit'" >> $env
echo "qemu_cmd='qemu boot command'" >> $env
echo "debug_tool='debug tool for HSAemu'" >> $env
echo "debug_cmd='debug command file'" >> $env
echo "" >> $env
echo '
#example: 
#vm_dir=$root_dir/../Linaro_new
#kernel=$vm_dir/vmlinuz-3.5.0-1-linaro-vexpress
#file_system=$vm_dir/initrd.img-3.5.0-1-linaro-vexpress
#image=$vm_dir/vexpress.img
#vm_mem=1024
#vm_port=1234
#vm_cpu=cortex-a9
#vm_board=vexpress-a9
#vm_hsa_CU=8
#qemu_cmd='-nographic'
#debug_tool=cgdb
#debug_cmd="--command $root_dir/script/gdbcmmd.txt --args"
' >> $env

cd $hsa_dir/qemu
./configure --target-list=arm-softmmu

