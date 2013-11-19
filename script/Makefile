include ../HSA_ENV_SETTING
script += loginVM
script += runVM
script += upload2VM
script += debug

all:
	@for i in $(script); 				\
	do						\
		echo "#!/bin/bash" > $$i.hsa; 		\
		echo source $(root_dir)/HSA_ENV_SETTING >> $$i.hsa;	\
		cat src/$$i.cmad >> $$i.hsa; 		\
		chmod +x $$i.hsa;			\
	done
clean:
	@for i in $(script);	\
	do			\
		rm $$i.hsa;	\
	done
