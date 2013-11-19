#!/bin/sh
old=$1
new=$2
if [ -z $old ] || [ -z $new ]; then
	echo "use stage: $ chgcc <old version number> <new version numner>"
else
sudo update-alternatives --install /usr/bin/cpp cpp /usr/bin/cpp-$old 30
sudo update-alternatives --install /usr/bin/cpp cpp /usr/bin/cpp-$new 40

sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-$old 30
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-$new 40

sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-$old 30
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-$new 40

sudo update-alternatives --config gcc
sudo update-alternatives --config g++
sudo update-alternatives --config cpp
fi
