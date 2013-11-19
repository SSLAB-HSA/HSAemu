#ifndef HSA_H
#define HSA_H
// *******************************************************
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>
#define USER_Q_SIZE 8
#define MAX_MEMOBJ_SIZE 32
  
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

typedef struct value_and_len{
	void *val;
	size_t len;
}hsaVL;

#define KBYTE 1024
#define MBYTE 1024*1024
#define GBYTE 1024*1024*1024
#define LITTLE_MEM_SIZE 0xFFFFFFFF

#define SET_VL_BITMAP(dst, arg, src_ptr, src_len, buf) \
	memcpy(buf, src_ptr, src_len); \
	(dst)->arg.val = (void*)buf; \
	(dst)->arg.len = (size_t)src_len; \
	buf += src_len;

#define GET_VL_INFO(ret_len, dst, src, arg) \
	ret_len = (src)->arg.len; \
	if ((dst) && param_value_size >= ret_len) { \
		memcpy((dst), (src)->arg.val, ret_len); \
	}

#define GET_ELEMENT_INFO(ret_len, dst, src, arg) \
	(ret_len) = sizeof((src)->arg);  \
	if ((dst) && param_value_size >= ret_len) { \
		memcpy((dst), &(src)->arg, ret_len); \
	}

#define MEM_ALLOC_CHECK(ptr, msg) \
	if (ptr == NULL) { \
		fprintf(stderr, "in %s, line %u, can't allocate: %s\n", \
				__FILE__, __LINE__, msg); \
		exit(-1); \
	}

#define HSA_DEBUG_LOG(msg) \
	fprintf(stderr, "in %s, line %u, %s\n", __FILE__, __LINE__, msg);

#define NOT_IMPLEMENTED() \
	fprintf(stderr, "not implemented: %s\n", __func__); \
	exit(-1);

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

#define INIT_M2S_CMD(src, len) \
	(len) = sizeof(src); \
	memset((&(src)), 0, len);

// arm cross compiler bug: R1 have to mov %3

#define HSAEMU_REMOTE_M2S(ret, ptr, size) \
	__asm__ __volatile__("push {R0,R1,R2}\n\t" \
			"mov R1, %1\n\t" \
			"mov R2, %2\n\t" \
			"swi 0x38\n\t" \
			"mov %0, R0\n\t" \
			"pop {R0,R1,R2}\n\t" \
			: "=r" (ret) \
			: "r" (ptr), "r" (size) \
			: "memory");

// *******************************************************

struct _cl_platform_id{
	hsaVL profile;
	hsaVL version;
	hsaVL name;
	hsaVL vendor;
	hsaVL exten;
};

struct _cl_device_id{
	cl_uint addr;
	cl_bool available;
	cl_bool cmpile_available;
	cl_device_fp_config doub_fp;
	cl_bool end_little;
	cl_bool ecc;
	cl_device_exec_capabilities exe_ability;
	hsaVL exten;
	cl_ulong global_cache_size;
	cl_device_mem_cache_type global_cache_type;
	cl_uint global_cache_line;
	cl_ulong global_mem_size;
	cl_bool img_support;
	size_t img2D_height;
	size_t img2D_width;
	size_t img3D_height;
	size_t img3D_width;
	size_t img3D_depth;
	cl_ulong local_mem_size;
	cl_device_local_mem_type local_mem_type;
	cl_uint freq;
	cl_uint num_CU;
	cl_uint const_arg;
	cl_ulong const_buf_size;
	cl_ulong alloc_mem_size;
	size_t param_size;
	cl_uint img_read_arg;
	cl_uint sampler;
	size_t group_size;
	cl_uint work_dim;
	hsaVL work_item;
	cl_uint img_write_arg;
	cl_uint addr_align;
	cl_uint data_align;
	hsaVL name;
	cl_platform_id plat;
	cl_uint vect_char;
	cl_uint vect_short;
	cl_uint vect_int;
	cl_uint vect_long;
	cl_uint vect_fp;
	cl_uint vect_doub_fp;
	cl_uint vect_half;
	hsaVL profile;
	size_t time_resolution;
	cl_command_queue_properties queue_prop;
	cl_device_fp_config fp;
	cl_device_type dev_type;
	hsaVL vendor;
	cl_uint vendor_id;
	hsaVL dev_version;
	hsaVL drive_version;
	cl_uint refcont;
	// workgroupInfo
	// size_t group_dim[3]; // work_item??
};

struct _cl_context{
	cl_uint refcont;
	hsaVL prop;
	hsaVL dev;
	cl_uint num_memobj;
	cl_uint max_memobj;
	cl_mem *memlist;
};

struct _cl_command_queue{
	cl_context cntxt;
	cl_device_id dev;
	cl_uint refcont;
	cl_command_queue_properties prop;
	user_queue *user_queue;
};

struct _cl_mem{
	cl_mem_object_type type;
	cl_mem_flags flags;
	size_t size;
	void *host_ptr;
	cl_uint count;
	cl_uint refcont;
	cl_context cntxt;
	void *buf;
#ifdef USE_M2S	
	int m2s_dev_addr;
#endif	
};

struct _cl_program{
	cl_uint refcont;
	cl_context cntxt;
	cl_uint num_dev;
	hsaVL dev;
	hsaVL src_code;
	hsaVL bin_size;
	hsaVL bin;
#ifdef USE_M2S	
	int m2s_program_id;
#endif
};

struct _cl_kernel{ 
	hsaVL name;
	cl_uint num_arg;
	cl_uint refcont;
	cl_context cntxt;
	cl_program progm;
	hsaVL arg_list;
	hsaVL bin;
	cl_uint max_arg;
	cl_ulong used_local_mem;
#ifdef USE_M2S	
	int m2s_kernel_id;
#endif	
};

struct _cl_event{
	cl_command_queue cmdQ;
	cl_command_type type;
	cl_int status;
	cl_uint refcont;
};

struct _cl_sampler{
	int tmp;
};

#endif
