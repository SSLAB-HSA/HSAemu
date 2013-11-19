#include "hsa_mntor.h"
#include "hsa_component.h"

void hsa_parse(const char *optarg)
{
	int cus, threads = 0, maxcus = 0;
	char *endptr;
	char option[128];

	cus = strtoul(optarg, &endptr, 10);
	if (endptr != optarg) {
		if (*endptr == ',') {
			endptr++;
		}
	}
	if (get_param_value(option, 128, "maxcpus", endptr) != 0)
		maxcus = strtoull(option, NULL, 10);
	if (get_param_value(option, 128, "threads", endptr) != 0)
		threads = strtoull(option, NULL, 10);

	/* compute missing values, prefer sockets over cores over threads */
	cus = cus > 0 ? cus : 1;
	threads = threads > 0 ? threads : 1;

	hsa_cus = cus;
	/* zdguo: not used currently */
	(void)threads;
	(void)maxcus;
}

int hsa_remote_m2s(void *_env, int addr, int len)
{
	if (len != sizeof(hsa_m2s_cmd)) {
		HSA_DEBUG_LOG("error len, remote API call\n");
	}
	hsa_m2s_cmd cmd_buff;
	hsa_copy_from_guest((CPUArchState *)_env, &cmd_buff, (target_ulong)addr, len);

	target_ulong data_src = (target_ulong)cmd_buff.agent_addr;
	size_t data_size = (size_t)cmd_buff.mem_size;
	void *data_ptr = NULL;

	if (data_src && data_size && cmd_buff.op != hsa_m2s_op_arg_ptr) {
		data_ptr = calloc(1, data_size);
		hsa_copy_from_guest((CPUArchState *)_env, 
				data_ptr, 
				data_src, 
				data_size);
	}

	if (cmd_buff.op == hsa_m2s_op_ndrange) {
		memcpy(agent_env, _env, sizeof(CPUArchState));
	}
	int m2s_ret = hsa_m2s_call( ((int*)&cmd_buff), data_ptr);
	
	if(data_ptr) free(data_ptr);
	return m2s_ret;
}
int hsa_do_vgpu(void *_env, uint64_t _para_addr)
{
	int ret;
	ret = hsa_set_agent_addr((CPUArchState *)_env, (target_ulong)_para_addr);

	zdguo_debug_print(ZDGUO_LEVEL_DEBUG,
			ZDGUO_DEBUG_THREAD_CPU,
			"<hsa_do_vgpu> agent.addr=0x%lx\n",
			(unsigned long)_env);

	return ret;
}

int hsa_set_debug(uint32_t debug_level)
{
	if (RESET_PROFILE_INFO >= debug_level) {
		hsa_set_debug_level(debug_level);
		return 0;
	}
	return -1;
}


void hsa_vgpu_init(const char *cpu_model)
{
	/* init CPUs */
	if (cpu_model == NULL) {
		cpu_model = "qemu64";
	}
	hsa_global_init(); 

	zdguo_debug_print(ZDGUO_LEVEL_DEBUG,
			ZDGUO_DEBUG_THREAD_MAIN,
			"<hsa_vgpu_init> after init, begin to init cus\n");

	hsa_init_mntor(hsa_cus, cpu_model);

	int hsa_argc = 3;
	char para0[] = "/tmp";
	char para1[] = "--si-sim";
	char para2[] = "detailed";
	char *hsa_argv[3];
	hsa_argv[0] = para0;
	hsa_argv[1] = para1;
	hsa_argv[2] = para2;
	hsa_m2s_init(hsa_argc, hsa_argv);
}
void hsa_reset_profile(Monitor *mon, const QDict *qdict)
{
	hsa_m2s_cmd cmd_buff;
	memset(&cmd_buff, 0, sizeof(cmd_buff));
	cmd_buff.op = hsa_m2s_op_reset;
	hsa_m2s_call( ((int*)&cmd_buff), NULL);

	hsa_set_debug_level(RESET_PROFILE_INFO);
}
void hsa_setup_profile(Monitor *mon, const QDict *qdict)
{
	fprintf(stderr, "%4d -- level all\n", ZDGUO_LEVEL_ALL);
	fprintf(stderr, "%4d -- level debug\n", ZDGUO_LEVEL_DEBUG);
	fprintf(stderr, "%4d -- level info\n", ZDGUO_LEVEL_INFO);
	fprintf(stderr, "%4d -- level profile low\n", ZDGUO_LEVEL_PRO_L);
	fprintf(stderr, "%4d -- level profile high\n", ZDGUO_LEVEL_PRO_H);
	fprintf(stderr, "%4d -- level bug\n", ZDGUO_LEVEL_BUG);
	fprintf(stderr, "%4d -- level error\n", ZDGUO_LEVEL_ERROR);
	fprintf(stderr, "%4d -- level none\n", ZDGUO_LEVEL_NONE);
	fprintf(stderr, "%4d -- reset TLB counter\n", RESET_PROFILE_INFO);

	int64_t level = qdict_get_int(qdict, "val");
	if (level <= RESET_PROFILE_INFO && level >= ZDGUO_LEVEL_ALL) {
		hsa_set_debug_level(level);
	}

}

