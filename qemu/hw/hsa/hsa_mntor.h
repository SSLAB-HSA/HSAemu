#ifndef HSA_I386_H
#define HSA_I386_H
#include <stdlib.h>
#include <stdio.h>
#include "qemu-thread.h"
#include "qemu-common.h"
#include "qemu-timer.h"
#include "hsa_cu.h"
#include "hsa_linkloader.h"
#include "HConvert.h"

/* thread identifier */
#define ZDGUO_DEBUG_THREAD_CU       0
#define ZDGUO_DEBUG_THREAD_MAIN     1
#define ZDGUO_DEBUG_THREAD_MNTOR    2
#define ZDGUO_DEBUG_THREAD_CPU      3

/* light weight thread state */
enum {
    LW_THREAD_NOT_CREATED = 0,
    LW_THREAD_CREATED = 1,
};

/* debug info level */
enum {
    ZDGUO_LEVEL_ALL = 0,
    ZDGUO_LEVEL_DEBUG,
    ZDGUO_LEVEL_INFO,
    ZDGUO_LEVEL_PRO_L,
    ZDGUO_LEVEL_PRO_H,
    ZDGUO_LEVEL_BUG,
    ZDGUO_LEVEL_ERROR,
    ZDGUO_LEVEL_NONE,
    RESET_PROFILE_INFO
};

/* zdguo: hsa aql define */
typedef struct _hsa_aql{
    uint32_t flag;
    uint32_t reserved;
    uint64_t kernelObjectAddress;
    uint64_t completionObjectAddress;
    uint64_t kernargAddress;
    uint64_t dispatchId;
    uint32_t gridSize_x;
    uint32_t gridSize_y;
    uint32_t gridSize_z;
    uint32_t workgroupSize_x;
    uint32_t workgroupSize_y;
    uint32_t workgroupSize_z;
    uint32_t workgroupGroupSegmentSizeBytes;
    uint32_t workitemPrivateSegmentSizeBytes;
    uint32_t workitemSpillSegmentSizeBytes;
    uint32_t workitemArgSegmentSizeBytes;
    uint32_t syncDW0;
    uint32_t syncDW1;
    uint32_t syncDW2;
    uint32_t syncDW3;
    uint32_t syncDW4;
    uint32_t syncDW5;
    uint32_t syncDW6;
    uint32_t syncDW7;
    uint32_t syncDW8;
    uint32_t syncDW9;
    uint64_t reserved_return;
}hsa_aql;

typedef struct _completionobject{
	int32_t  status;
	uint32_t reserved;
	uint32_t completionSignalAddress;
	uint64_t parseTimeStamp;
	uint64_t dispatchTimeStamp;
	uint64_t completionTimeStamp;
}completionobject;

typedef struct _user_queue{
    uint64_t basePointer;
    uint64_t doorbellPointer;
    uint64_t dispatchID;
    uint32_t writeOffset;
    uint32_t readOffset;
    uint32_t size;
    uint32_t PASID;
    uint32_t queueID;
    uint32_t priority;
}user_queue;

#define SET_WORK_ID(dst, src)   \
    memcpy((dst), (src), sizeof(dim3))

#if defined(__i386__)
static inline int testandset (spinlock_t *p)
{
    long int readval = 0;

    __asm__ __volatile__ ("lock; cmpxchgl %2, %0"
                          : "+m" (*p), "+a" (readval)
                          : "r" (1)
                          : "cc");
    return readval;
}
#elif defined(__x86_64__)
static inline int testandset (spinlock_t *p)
{
    long int readval = 0;

    __asm__ __volatile__ ("lock; cmpxchgl %2, %0"
                          : "+m" (*p), "+a" (readval)
                          : "r" (1)
                          : "cc");
    return readval;
}
#elif defined(__arm__)
static inline int testandset (spinlock_t *spinlock)
{
    register unsigned int ret;
    __asm__ __volatile__("swp %0, %1, [%2]"
                         : "=r"(ret)
                         : "0"(1), "r"(spinlock));

    return ret;
}
#endif

#if !defined(__hppa__)
static inline void resetlock (spinlock_t *p)
{
    *p = SPIN_LOCK_UNLOCKED;
}
#endif

static inline void hsa_spin_lock(spinlock_t *lock)
{
    while (testandset(lock));
}

static inline void hsa_spin_unlock(spinlock_t *lock)
{
    resetlock(lock);
}

// debug 
extern volatile int page_fault_accrued;
extern __thread int lw_thread_id; // may for debug

// normal
extern volatile int hsa_cus;
extern CPUArchState *agent_env;
extern uint64_t crnt_dispatchid;
extern __thread HSACUState *per_cu_env;
extern __thread int thread_type;
extern __thread CPUArchState *per_agent_env;

// barrier
extern QemuMutex hsa_barrier_mutex;
extern pthread_barrier_t hsa_barrier;

// group memory
extern volatile size_t group_mem_len;
extern __thread uint8_t *per_group_mem_base;
extern __thread uint8_t *per_group_mem_end;

// work index
extern volatile dim3 itemPerGroup;
extern volatile dim3 groupPerGrid;
extern volatile size_t group_szie;
extern volatile size_t grid_size;
extern __thread dim3 per_itemId;
extern __thread dim3 per_groupId;

#define MEM_ALLOC_CHECK(ptr, msg) \
	if (ptr == NULL) {          \
		fprintf(stderr, "in %s, line %u, can't allocate: %s\n", \
		__FILE__, __LINE__, msg); \
		exit(-1);             \
	}

#define HSA_DEBUG_LOG(msg) \
	fprintf(stderr, "in %s, line %u, %s\n", __FILE__, __LINE__, msg);
void hsa_mntor_resume_cus(void);
void hsa_init_cu_thread(void *_env);
void hsa_global_init(void);
int hsa_set_agent_addr(CPUArchState *_env, target_ulong _para_addr);
void hsa_init_mntor(int hsa_cus, const char *cpu_model);
int hsa_create_lw_thread(HSACUState *env);
void hsa_prepare_lw_thread(HSACUState *env);
void zdguo_debug_print(int levle, int thread_nb, const char *fmt, ...);
void hsa_set_debug_level(target_ulong level);
size_t hsa_copy_to_guest(CPUArchState *env,
							 target_ulong dst,
							 void *src,
							 const size_t size);

size_t hsa_copy_from_guest(CPUArchState *env, void *dest, target_ulong src, const size_t size);
#endif
