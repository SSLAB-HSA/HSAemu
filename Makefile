build += script
build += qemu
build += runtime

all:
	@for i in $(build); 	\
	do 			\
		$(MAKE) -C $$i;	\
	done
clean:
	@for i in $(build); 		\
	do				\
		$(MAKE) -C $$i clean; 	\
	done
