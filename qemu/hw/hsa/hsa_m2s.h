#ifndef HSA_M2S_H
#define HSA_M2S_H

enum hsa_m2s_op {
	hsa_m2s_op_init = 0,
	hsa_m2s_op_release,
	hsa_m2s_op_reset,
	hsa_m2s_op_program_bin,
	hsa_m2s_op_kernel,
	hsa_m2s_op_arg_value,
	hsa_m2s_op_arg_ptr,
	hsa_m2s_op_ndrange
};

typedef union{
	struct {int op, agent_addr, mem_size;};
	struct {int op2, agent_addr2, mem_size2, program_id;};
	struct {int op3, agent_addr3, mem_size3, kernel_id3, index;};
	struct {int op4, agent_addr4, mem_size4, kernel_id4, dim;};
}hsa_m2s_cmd;

extern struct mem_t *hsa_si_mem;

int hsa_m2s_init(int argc, char **argv);
int hsa_m2s_call(int *cmd_buf, void *data);
int hsa_m2s_release(void);

#endif
