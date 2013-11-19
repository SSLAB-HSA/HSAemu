#ifndef HSA_CU_I386_H
#define HSA_CU_I386_H
#include "qemu-thread.h"
#define WORKITEM_MAX_DIM 3

typedef struct CU_PROF_T{
    int64_t cu_begin,
     cu_end, 
     cu_kernel, 
     cu_loop_st, 
     cu_loop_ed, 
     per_kernel,
     tlb_miss,
     tlb_hit,
     slow_access;
     QemuMutex tlb_hit_mutex;
     QemuMutex tlb_miss_mutex;
     QemuMutex slow_access_mutex;
}CU_PROF;

typedef struct dim3_t {
    uint32_t dim[WORKITEM_MAX_DIM];
}dim3;

typedef struct wavefrnt_t {
    dim3 begin, end;
}wavefrnt;

typedef struct HSACUState {
	int nr_cores;
	QemuCond *halt_cond;
	QemuMutex *hsa_mutex;
	QemuThread *thread;
	int thread_id;
	int created;
	int stopped;
	CU_PROF cu_prof;
	//barrier
	//QemuMutex hsa_barrier_mutex;
	QemuThread *lw_thread;
	int barrier_count;
	pthread_barrier_t hsa_barrier;
	int lw_thread_created;
	int lw_has_work;
	int reset_lw_flag;

	struct HSACUState *next_cpu;
} HSACUState;

typedef struct lw_arg_t {
    dim3 itemId;
    dim3 groupId;
    int vaild;
    uint8_t *group_mem_base;
    HSACUState *cu_env;
    CPUArchState *cpu_env;
}lw_arg;

enum {
	MNTOR = 0,
	CU_TH,
	LW_TH
};

#endif
