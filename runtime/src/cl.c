#include <CL/cl.h>
#include <hsa.h>

// Platform API
extern CL_API_ENTRY cl_int CL_API_CALL
clGetPlatformIDs(cl_uint          num_entries,
                 cl_platform_id * platforms,
                 cl_uint *        num_platforms) CL_API_SUFFIX__VERSION_1_0
{
	if ((!num_entries && platforms)||
			(!num_entries && !num_platforms)) return CL_INVALID_VALUE;

	if (num_platforms) *num_platforms = 1;

	if (platforms) {
		size_t plat_len = sizeof(struct _cl_platform_id);
		uint8_t *buf = (uint8_t*)calloc(1, plat_len + KBYTE);
		cl_platform_id plat = (cl_platform_id)buf;
		buf += plat_len;

		char profile[] = "FULL_PROFILE";
		SET_VL_BITMAP(plat, profile, profile, sizeof(profile), buf);
		char version[] = "OpenCL 1.0 NTHU SSLab 1.0";
		SET_VL_BITMAP(plat, version, version, sizeof(version), buf);
		char name[] = "HSAemu";
		SET_VL_BITMAP(plat, name, name, sizeof(name), buf);
		char vendor[] = "NTHU System Software Laboratory";
		SET_VL_BITMAP(plat, vendor, vendor, sizeof(vendor), buf);
		char exten[] = "NULL";
		SET_VL_BITMAP(plat, exten, exten, sizeof(exten), buf);
		*platforms = plat;
	}
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL 
clGetPlatformInfo(cl_platform_id   platform, 
                  cl_platform_info param_name,
                  size_t           param_value_size, 
                  void *           param_value,
                  size_t *         param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	if (!platform) return CL_INVALID_PLATFORM;

	size_t len = 0;

	switch(param_name) {
		case CL_PLATFORM_PROFILE:
			GET_VL_INFO(len, param_value, platform, profile);
			break;
		case CL_PLATFORM_VERSION:
			GET_VL_INFO(len, param_value, platform, version);
			break;
		case CL_PLATFORM_NAME:
			GET_VL_INFO(len, param_value, platform, name);
			break;
		case CL_PLATFORM_VENDOR:
			GET_VL_INFO(len, param_value, platform, vendor);
			break;
		case CL_PLATFORM_EXTENSIONS:
			GET_VL_INFO(len, param_value, platform, exten);
			break;
		default:
			return CL_INVALID_VALUE;
	}

	if (param_value_size_ret) *param_value_size_ret = len;
	return CL_SUCCESS;
}

// Device APIs
extern CL_API_ENTRY cl_int CL_API_CALL
clGetDeviceIDs(cl_platform_id   platform,
               cl_device_type   device_type, 
               cl_uint          num_entries, 
               cl_device_id *   devices, 
               cl_uint *        num_devices) CL_API_SUFFIX__VERSION_1_0
{
	if (num_devices) *num_devices = 1;
	if (devices) {
		size_t dev_len = sizeof(struct _cl_device_id);
		uint8_t *buf = (uint8_t*)calloc(1, dev_len + KBYTE);
		cl_device_id dev = (cl_device_id)buf;
		buf += dev_len;
		
		dev->addr = 32;
		dev->available = CL_TRUE;
		dev->cmpile_available = CL_FALSE;
		dev->doub_fp = (CL_FP_FMA |
				CL_FP_ROUND_TO_NEAREST |
				CL_FP_ROUND_TO_ZERO |
				CL_FP_ROUND_TO_INF |
				CL_FP_INF_NAN |
				CL_FP_DENORM);
		dev->end_little = CL_TRUE;
		dev->ecc = CL_FALSE;
		dev->exe_ability = CL_EXEC_KERNEL;
		
		void *ptr = platform->exten.val;
		size_t size_tmp = platform->exten.len;
		SET_VL_BITMAP(dev, exten, ptr, size_tmp, buf);

		dev->global_cache_size = 0;
		dev->global_cache_type = CL_NONE;
		dev->global_cache_line = 0;
		dev->global_mem_size = (cl_ulong)LITTLE_MEM_SIZE;
		dev->img_support = CL_FALSE;
		dev->img2D_height = 0;
		dev->img2D_width = 0;
		dev->img3D_height = 0;
		dev->img3D_width = 0;
		dev->img3D_depth = 0;
		dev->local_mem_size = 64 * KBYTE;
		dev->local_mem_type = CL_LOCAL;
		dev->freq = 1000;
		dev->num_CU = 8;
		dev->const_arg = 8;
		dev->const_buf_size = 64 * KBYTE;
		dev->alloc_mem_size = (cl_ulong)LITTLE_MEM_SIZE;
		dev->param_size = 256;
		dev->img_read_arg = 0;
		dev->sampler = 0;
		dev->group_size = 512;
		dev->work_dim = 3;

		size_t size_tmp_array[] = {512, 512, 512};
		SET_VL_BITMAP(dev, work_item, size_tmp_array, 
				sizeof(size_tmp_array), buf);

		dev->img_write_arg = 0;
		dev->addr_align = 32;
		dev->data_align = 4;

		ptr = platform->name.val;
		size_tmp = platform->name.len;
		SET_VL_BITMAP(dev, name, ptr, size_tmp, buf);

		dev->plat = platform;
		dev->vect_char = 0;
		dev->vect_short = 0;
		dev->vect_int = 0;
		dev->vect_long = 0;
		dev->vect_fp = 0;
		dev->vect_doub_fp = 0;
		dev->vect_half = 0;

		ptr = platform->profile.val;
		size_tmp = platform->profile.len;
		SET_VL_BITMAP(dev, profile, ptr, size_tmp, buf);

		dev->time_resolution = GBYTE;
		dev->queue_prop = CL_QUEUE_PROFILING_ENABLE;
		dev->fp = (CL_FP_ROUND_TO_NEAREST | CL_FP_INF_NAN);
		dev->dev_type = CL_DEVICE_TYPE_GPU;
		
		ptr = platform->vendor.val;
		size_tmp = platform->vendor.len;
		SET_VL_BITMAP(dev, vendor, ptr, size_tmp, buf);

		dev->vendor_id = 0;
		
		ptr = platform->version.val;
		size_tmp = platform->version.len;
		SET_VL_BITMAP(dev, dev_version, ptr, size_tmp, buf);
		SET_VL_BITMAP(dev, drive_version, ptr, size_tmp, buf);

		dev->refcont = 1;
		*devices = dev;
	}
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clGetDeviceInfo(cl_device_id    device,
                cl_device_info  param_name, 
                size_t          param_value_size, 
                void *          param_value,
                size_t *        param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	if (!device) return CL_INVALID_DEVICE;

	size_t len = 0;

	switch(param_name) {
		case CL_DEVICE_ADDRESS_BITS:
			GET_ELEMENT_INFO(len, param_value, device, addr);
			break;
		case CL_DEVICE_AVAILABLE:
			GET_ELEMENT_INFO(len, param_value, device, available);
			break;
		case CL_DEVICE_COMPILER_AVAILABLE:
			GET_ELEMENT_INFO(len, param_value, device, cmpile_available);
			break;
		case CL_DEVICE_DOUBLE_FP_CONFIG:
			GET_ELEMENT_INFO(len, param_value, device, doub_fp);
			break;
		case CL_DEVICE_ENDIAN_LITTLE:
			GET_ELEMENT_INFO(len, param_value, device, end_little);
			break;
		case CL_DEVICE_ERROR_CORRECTION_SUPPORT:
			GET_ELEMENT_INFO(len, param_value, device, ecc);
			break;
		case CL_DEVICE_EXECUTION_CAPABILITIES:
			GET_ELEMENT_INFO(len, param_value, device, exe_ability);
			break;
		case CL_DEVICE_EXTENSIONS:
			GET_VL_INFO(len, param_value, device, exten);
			break;
		case CL_DEVICE_GLOBAL_MEM_CACHE_SIZE:
			GET_ELEMENT_INFO(len, param_value, device, global_cache_size);
			break;
		case CL_DEVICE_GLOBAL_MEM_CACHE_TYPE:
			GET_ELEMENT_INFO(len, param_value, device, global_cache_type);
			break;
		case CL_DEVICE_GLOBAL_MEM_CACHELINE_SIZE:
			GET_ELEMENT_INFO(len, param_value, device, global_cache_line);
			break;
		case CL_DEVICE_GLOBAL_MEM_SIZE:
			GET_ELEMENT_INFO(len, param_value, device, global_mem_size);
			break;
		case CL_DEVICE_IMAGE_SUPPORT:
			GET_ELEMENT_INFO(len, param_value, device, img_support);
			break;
		case CL_DEVICE_IMAGE2D_MAX_HEIGHT:
			GET_ELEMENT_INFO(len, param_value, device, img2D_height);
			break;
		case CL_DEVICE_IMAGE2D_MAX_WIDTH:
			GET_ELEMENT_INFO(len, param_value, device, img2D_width);
			break;
		case CL_DEVICE_IMAGE3D_MAX_HEIGHT:
			GET_ELEMENT_INFO(len, param_value, device, img3D_height);
			break;
		case CL_DEVICE_IMAGE3D_MAX_WIDTH:
			GET_ELEMENT_INFO(len, param_value, device, img3D_width);
			break;
		case CL_DEVICE_IMAGE3D_MAX_DEPTH:
			GET_ELEMENT_INFO(len, param_value, device, img3D_depth);
			break;
		case CL_DEVICE_LOCAL_MEM_SIZE:
			GET_ELEMENT_INFO(len, param_value, device, local_mem_size);
			break;
		case CL_DEVICE_LOCAL_MEM_TYPE:
			GET_ELEMENT_INFO(len, param_value, device, local_mem_type);
			break;
		case CL_DEVICE_MAX_CLOCK_FREQUENCY:
			GET_ELEMENT_INFO(len, param_value, device, freq);
			break;
		case CL_DEVICE_MAX_COMPUTE_UNITS:
			GET_ELEMENT_INFO(len, param_value, device, num_CU);
			break;
		case CL_DEVICE_MAX_CONSTANT_ARGS:
			GET_ELEMENT_INFO(len, param_value, device, const_arg);
			break;
		case CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE:
			GET_ELEMENT_INFO(len, param_value, device, const_buf_size);
			break;
		case CL_DEVICE_MAX_MEM_ALLOC_SIZE:
			GET_ELEMENT_INFO(len, param_value, device, alloc_mem_size);
			break;
		case CL_DEVICE_MAX_PARAMETER_SIZE:
			GET_ELEMENT_INFO(len, param_value, device, param_size);
			break;
		case CL_DEVICE_MAX_READ_IMAGE_ARGS:
			GET_ELEMENT_INFO(len, param_value, device, img_read_arg);
			break;
		case CL_DEVICE_MAX_SAMPLERS:
			GET_ELEMENT_INFO(len, param_value, device, sampler);
			break;
		case CL_DEVICE_MAX_WORK_GROUP_SIZE:
			GET_ELEMENT_INFO(len, param_value, device, group_size);
			break;
		case CL_DEVICE_MAX_WORK_ITEM_DIMENSIONS:
			GET_ELEMENT_INFO(len, param_value, device, work_dim);
			break;
		case CL_DEVICE_MAX_WORK_ITEM_SIZES:
			GET_VL_INFO(len, param_value, device, work_item);
			break;
		case CL_DEVICE_MAX_WRITE_IMAGE_ARGS:
			GET_ELEMENT_INFO(len, param_value, device, img_write_arg);
			break;
		case CL_DEVICE_MEM_BASE_ADDR_ALIGN:
			GET_ELEMENT_INFO(len, param_value, device, addr_align);
			break;
		case CL_DEVICE_MIN_DATA_TYPE_ALIGN_SIZE:
			GET_ELEMENT_INFO(len, param_value, device, data_align);
			break;
		case CL_DEVICE_NAME:
			GET_VL_INFO(len, param_value, device, name);
			break;
		case CL_DEVICE_PLATFORM:
			GET_ELEMENT_INFO(len, param_value, device, plat);
			break;
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_CHAR:
			GET_ELEMENT_INFO(len, param_value, device, vect_char);
			break;
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_SHORT:
			GET_ELEMENT_INFO(len, param_value, device, vect_short);
			break;
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_INT:
			GET_ELEMENT_INFO(len, param_value, device, vect_int);
			break;
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_LONG:
			GET_ELEMENT_INFO(len, param_value, device, vect_long);
			break;
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_FLOAT:
			GET_ELEMENT_INFO(len, param_value, device, vect_fp);
			break;
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_DOUBLE:
			GET_ELEMENT_INFO(len, param_value, device, vect_doub_fp);
			break;
		case CL_DEVICE_PREFERRED_VECTOR_WIDTH_HALF:
			GET_ELEMENT_INFO(len, param_value, device, vect_half);
		case CL_DEVICE_PROFILE:
			GET_VL_INFO(len, param_value, device, profile);
			break;
		case CL_DEVICE_PROFILING_TIMER_RESOLUTION:
			GET_ELEMENT_INFO(len, param_value, device, time_resolution);
			break;
		case CL_DEVICE_QUEUE_PROPERTIES:
			GET_ELEMENT_INFO(len, param_value, device, queue_prop);
			break;
		case CL_DEVICE_SINGLE_FP_CONFIG:
			GET_ELEMENT_INFO(len, param_value, device, fp);
			break;
		case CL_DEVICE_TYPE:
			GET_ELEMENT_INFO(len, param_value, device, dev_type);
			break;
		case CL_DEVICE_VENDOR:
			GET_VL_INFO(len, param_value, device, vendor);
			break;
		case CL_DEVICE_VENDOR_ID:
			GET_ELEMENT_INFO(len, param_value, device, vendor_id);
			break;
		case CL_DEVICE_VERSION:
			GET_VL_INFO(len, param_value, device, dev_version);
			break;
		case CL_DRIVER_VERSION:
			GET_VL_INFO(len, param_value, device, drive_version);
			break;
		default:
			return CL_INVALID_VALUE;
	}

	if (param_value_size_ret) *param_value_size_ret = len;
	return CL_SUCCESS;
}
    
extern CL_API_ENTRY cl_int CL_API_CALL
clCreateSubDevices(cl_device_id                         in_device,
                   const cl_device_partition_property * properties,
                   cl_uint                              num_devices,
                   cl_device_id *                       out_devices,
                   cl_uint *                            num_devices_ret) CL_API_SUFFIX__VERSION_1_2
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clRetainDevice(cl_device_id device) CL_API_SUFFIX__VERSION_1_2
{
	if (!device) return CL_INVALID_DEVICE;

	device->refcont++;
	return CL_SUCCESS;
}
    
extern CL_API_ENTRY cl_int CL_API_CALL
clReleaseDevice(cl_device_id device) CL_API_SUFFIX__VERSION_1_2
{
	if (!device) return CL_INVALID_DEVICE;

	device->refcont--;
	if (device->refcont == 0) {
		free(device);
	}

	return CL_SUCCESS;
}
    
// Context APIs 
extern CL_API_ENTRY cl_context CL_API_CALL
clCreateContext(const cl_context_properties * properties,
                cl_uint                 num_devices,
                const cl_device_id *    devices,
                void (CL_CALLBACK * pfn_notify)(const char *, const void *, size_t, void *),
                void *                  user_data,
                cl_int *                errcode_ret) CL_API_SUFFIX__VERSION_1_0
{
	cl_int err = CL_SUCCESS;
	cl_context cntxt = NULL;
	if (!num_devices || !devices) err = CL_INVALID_VALUE;
	if (err != CL_SUCCESS) goto CONTXT_FAULT;
	
	size_t cntxt_len = sizeof(struct _cl_context);
	size_t prop_len = 3 * sizeof(cl_context_properties);
	size_t dev_len = num_devices * sizeof(cl_device_id);
	size_t memlist_len = MAX_MEMOBJ_SIZE * sizeof(cl_mem);
	size_t total_len = cntxt_len + prop_len + 
		dev_len + memlist_len;
	uint8_t *buf = (uint8_t*)calloc(1, total_len);

	cntxt = (cl_context)buf;
	cntxt->refcont = 1;
	cntxt->num_memobj = 0;
	cntxt->max_memobj = MAX_MEMOBJ_SIZE;
	buf += cntxt_len;

	cntxt->memlist = (cl_mem*)buf;
	buf += memlist_len;

	cntxt->prop.val = (void*)buf;
	cntxt->prop.len = prop_len;
	if (properties) {
		memcpy(cntxt->prop.val, properties, prop_len);
	}else{
		cl_context_properties *ptr = NULL;
		ptr = (cl_context_properties*)cntxt->prop.val;
		ptr[0] = CL_CONTEXT_PLATFORM;
		err = clGetPlatformIDs(1, (cl_platform_id*)(ptr+1), NULL);
		ptr[2] = 0;
	}
	buf += prop_len;

	cntxt->dev.val = (void*)buf;
	cntxt->dev.len = dev_len;
	memcpy(cntxt->dev.val, devices, dev_len);

CONTXT_FAULT:
	if (errcode_ret) *errcode_ret = err;
	return cntxt;
}

extern CL_API_ENTRY cl_context CL_API_CALL
clCreateContextFromType(const cl_context_properties * properties,
                        cl_device_type          device_type,
                        void (CL_CALLBACK *     pfn_notify)(const char *, const void *, size_t, void *),
                        void *                  user_data,
                        cl_int *                errcode_ret) CL_API_SUFFIX__VERSION_1_0
{
	cl_int err = CL_SUCCESS;
	size_t cntxt_len = sizeof(struct _cl_context);
	size_t prop_len = 3 * sizeof(cl_context_properties);
	size_t dev_len = sizeof(cl_device_id);
	size_t memlist_len = MAX_MEMOBJ_SIZE * sizeof(cl_mem);
	size_t total_len = cntxt_len + prop_len + 
		dev_len + memlist_len;
	uint8_t *buf = (uint8_t*)calloc(1, total_len);

	cl_context cntxt = (cl_context)buf;
	cntxt->refcont = 1;
	cntxt->max_memobj = MAX_MEMOBJ_SIZE;
	buf += cntxt_len;

	cntxt->memlist = (cl_mem*)buf;
	buf += memlist_len;

	cntxt->prop.val = (void*)buf;
	cntxt->prop.len = prop_len;
	if (properties) {
		memcpy(cntxt->prop.val, properties, prop_len);
	}else{
		cl_context_properties *ptr = NULL;
		ptr = (cl_context_properties*)cntxt->prop.val;
		ptr[0] = CL_CONTEXT_PLATFORM;
		err = clGetPlatformIDs(1, (cl_platform_id*)(ptr+1), NULL);
		ptr[2] = 0;
	}
	buf += prop_len;

	cntxt->dev.val = (void*)buf;
	cntxt->dev.len = dev_len;
	cl_platform_id *plat_ptr = (cl_platform_id*)cntxt->prop.val;
	cl_device_id *dev_ptr = (cl_device_id*)cntxt->dev.val;
	err = clGetDeviceIDs(plat_ptr[1], device_type, 1, dev_ptr, NULL);

	if (errcode_ret) *errcode_ret = err;
	return cntxt;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clRetainContext(cl_context context) CL_API_SUFFIX__VERSION_1_0
{
	if (!context) return CL_INVALID_CONTEXT;

	context->refcont++;
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clReleaseContext(cl_context context) CL_API_SUFFIX__VERSION_1_0
{
	if (!context) return CL_INVALID_CONTEXT;

	context->refcont--;
	if (context->refcont == 0) {
		free(context);	
	}

	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clGetContextInfo(cl_context         context, 
                 cl_context_info    param_name, 
                 size_t             param_value_size, 
                 void *             param_value, 
                 size_t *           param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	if (!context) return CL_INVALID_CONTEXT;
	
	size_t len = 0;

	switch(param_name) {
		case CL_CONTEXT_REFERENCE_COUNT:
			GET_ELEMENT_INFO(len, param_value, context, refcont);
			break;
		case CL_CONTEXT_DEVICES:
			GET_VL_INFO(len, param_value, context, dev);
			break;
		case CL_CONTEXT_PROPERTIES:
			GET_VL_INFO(len, param_value, context, prop);
			break;
		default:
			return CL_INVALID_VALUE;
	}

	if (param_value_size_ret) *param_value_size_ret = len;
	return CL_SUCCESS;
}

// Command Queue APIs
extern CL_API_ENTRY cl_command_queue CL_API_CALL
clCreateCommandQueue(cl_context                     context, 
                     cl_device_id                   device, 
                     cl_command_queue_properties    properties,
                     cl_int *                       errcode_ret) CL_API_SUFFIX__VERSION_1_0
{
	cl_int err = CL_SUCCESS;
	if (device < 0) err = CL_INVALID_DEVICE;
	if (err != CL_SUCCESS) goto CREATE_CMD_Q_FAULT;

	size_t cmdQ_len = sizeof(struct _cl_command_queue);
	size_t userQ_len = sizeof(user_queue);
	size_t aqlQ_len = USER_Q_SIZE * sizeof(hsa_aql);
	size_t completion_len = USER_Q_SIZE * sizeof(completionobject);
	size_t total_len = cmdQ_len + userQ_len + aqlQ_len + completion_len;
	volatile uint8_t* buf = (uint8_t*)calloc(1, total_len);

	cl_command_queue cmdQ = (cl_command_queue)buf;
	buf += cmdQ_len;
	user_queue *userQ = (user_queue*)buf;
	buf += userQ_len;
	hsa_aql *aqlQ = (hsa_aql*)buf;
	buf += aqlQ_len;
	completionobject *cmplQ = (completionobject*)buf;
	
	userQ->basePointer = (uint64_t)(uintptr_t)aqlQ;
	userQ->doorbellPointer = 0;
	userQ->size = (uint32_t)aqlQ_len;
	userQ->queueID = (uint32_t)getpid();

	cmdQ->cntxt = context;
	cmdQ->dev = device;
	cmdQ->refcont = 1;
	cmdQ->prop = properties;
	cmdQ->user_queue = userQ;

	int i = 0;
	for (i=0; i<USER_Q_SIZE; i++) {
		aqlQ->completionObjectAddress = (uint64_t)(uintptr_t)cmplQ;
		cmplQ->status = 2;
		aqlQ++;
		cmplQ++;
	}

	if (errcode_ret) *errcode_ret = err;
	return cmdQ;

CREATE_CMD_Q_FAULT:
	if (errcode_ret) *errcode_ret = err;
	return NULL;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clRetainCommandQueue(cl_command_queue command_queue) CL_API_SUFFIX__VERSION_1_0
{
	if (!command_queue) return CL_INVALID_COMMAND_QUEUE;

	command_queue->refcont++;
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clReleaseCommandQueue(cl_command_queue command_queue) CL_API_SUFFIX__VERSION_1_0
{
	if (!command_queue) return CL_INVALID_COMMAND_QUEUE;

	command_queue->refcont--;
	if (command_queue->refcont == 0) {
		free(command_queue);
	}
	return CL_SUCCESS;  
}

extern CL_API_ENTRY cl_int CL_API_CALL
clGetCommandQueueInfo(cl_command_queue      command_queue,
                      cl_command_queue_info param_name,
                      size_t                param_value_size,
                      void *                param_value,
                      size_t *              param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	if (!command_queue) return CL_INVALID_COMMAND_QUEUE;

	size_t len = 0;

	switch(param_name) {
		case CL_QUEUE_CONTEXT:
			GET_ELEMENT_INFO(len, param_value, command_queue, cntxt);
			break;
		case CL_QUEUE_DEVICE:
			GET_ELEMENT_INFO(len, param_value, command_queue, dev);
			break;
		case CL_QUEUE_REFERENCE_COUNT:
			GET_ELEMENT_INFO(len, param_value, command_queue, refcont);
			break;
		case CL_QUEUE_PROPERTIES:
			GET_ELEMENT_INFO(len, param_value, command_queue, prop);
			break;
		default:
			return CL_INVALID_VALUE;
	}

	if (param_value_size_ret)
		*param_value_size_ret = len;
	return CL_SUCCESS;
}

// Memory Object APIs
extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateBuffer(cl_context   context,
               cl_mem_flags flags,
               size_t       size,
               void *       host_ptr,
               cl_int *     errcode_ret) CL_API_SUFFIX__VERSION_1_0
{
	cl_int err = CL_SUCCESS;
	if (!context) err = CL_INVALID_CONTEXT;
	if (err != CL_SUCCESS) goto CREATE_BUF_FAULT;

	size_t mem_len = sizeof(struct _cl_mem);
	size_t total_len = mem_len;
	if(!host_ptr) total_len += size;
	uint8_t *buf = (uint8_t*)calloc(1, total_len);
	cl_mem memobj = (cl_mem)buf;

	memobj->type = CL_MEM_OBJECT_BUFFER;
	memobj->flags = flags;
	memobj->size = size;
	memobj->host_ptr = host_ptr;
	memobj->count = 0;
	memobj->refcont = 1;
	memobj->cntxt = context;
	buf += mem_len;

	if (host_ptr) {
		memobj->buf = host_ptr;
	} else {
		memobj->buf = (void*)buf;
	}

	// register to context
	cl_bool reg = CL_FALSE;
	cl_mem *memlist = context->memlist;
	context->num_memobj++;
	cl_uint i = 0;

	for (i = 0; i < MAX_MEMOBJ_SIZE; i++) {
		if (!memlist[i]) {
			memlist[i] = memobj;
			reg = CL_TRUE;
			break;
		}
	}
	
	if (reg != CL_TRUE) {
		err = CL_MEM_OBJECT_ALLOCATION_FAILURE;
		goto CREATE_BUF_FAULT;
	}

	clRetainContext(context);
	if (errcode_ret) *errcode_ret = err;
	return memobj;

CREATE_BUF_FAULT:
	if (memobj) free(memobj);
	if (errcode_ret) *errcode_ret = err;
	return NULL;
}

extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateSubBuffer(cl_mem                   buffer,
                  cl_mem_flags             flags,
                  cl_buffer_create_type    buffer_create_type,
                  const void *             buffer_create_info,
                  cl_int *                 errcode_ret) CL_API_SUFFIX__VERSION_1_1{return NULL;}

extern CL_API_ENTRY cl_mem CL_API_CALL
clCreateImage(cl_context              context,
              cl_mem_flags            flags,
              const cl_image_format * image_format,
              const cl_image_desc *   image_desc, 
              void *                  host_ptr,
              cl_int *                errcode_ret) CL_API_SUFFIX__VERSION_1_2{return NULL;}
                        
extern CL_API_ENTRY cl_int CL_API_CALL
clRetainMemObject(cl_mem memobj) CL_API_SUFFIX__VERSION_1_0
{
	if (!memobj) return CL_INVALID_MEM_OBJECT;

	memobj->refcont++;
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clReleaseMemObject(cl_mem memobj) CL_API_SUFFIX__VERSION_1_0
{
	if (!memobj) return CL_INVALID_MEM_OBJECT;

	memobj->refcont--;
	if (memobj->refcont == 0) {
		// unregister
		cl_bool reg = CL_FALSE;
		cl_mem *memlist = ((memobj->cntxt)->memlist);
		cl_uint i = 0;
		
		for (i = 0; i < MAX_MEMOBJ_SIZE; i++) {
			if (memlist[i] == memobj) {
				memlist[i] = NULL;
				reg = CL_TRUE;
				break;
			}
		}

		if (reg != CL_TRUE) {
			return CL_INVALID_MEM_OBJECT;
		}

		(memobj->cntxt)->num_memobj--;
		clReleaseContext(memobj->cntxt);
		free(memobj);
	}
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clGetSupportedImageFormats(cl_context           context,
                           cl_mem_flags         flags,
                           cl_mem_object_type   image_type,
                           cl_uint              num_entries,
                           cl_image_format *    image_formats,
                           cl_uint *            num_image_formats) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}
                                    
extern CL_API_ENTRY cl_int CL_API_CALL
clGetMemObjectInfo(cl_mem           memobj,
                   cl_mem_info      param_name, 
                   size_t           param_value_size,
                   void *           param_value,
                   size_t *         param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	if (!memobj) return CL_INVALID_MEM_OBJECT;

	size_t len = 0;

	switch(param_name) {
		case CL_MEM_TYPE:
			GET_ELEMENT_INFO(len, param_value, memobj, type);
			break;
		case CL_MEM_FLAGS:
			GET_ELEMENT_INFO(len, param_value, memobj, flags);
			break;
		case CL_MEM_SIZE:
			GET_ELEMENT_INFO(len, param_value, memobj, size);
			break;
		case CL_MEM_HOST_PTR:
			GET_ELEMENT_INFO(len, param_value, memobj, host_ptr);
			break;
		case CL_MEM_MAP_COUNT:
			GET_ELEMENT_INFO(len, param_value, memobj, count);
			break;
		case CL_MEM_REFERENCE_COUNT:
			GET_ELEMENT_INFO(len, param_value, memobj, refcont);
			break;
		case CL_MEM_CONTEXT:
			GET_ELEMENT_INFO(len, param_value, memobj, cntxt);
			break;									
		default:
			return CL_INVALID_VALUE;
	}

	if (param_value_size_ret)
		*param_value_size_ret = len;
	return CL_SUCCESS;	
}

extern CL_API_ENTRY cl_int CL_API_CALL
clGetImageInfo(cl_mem           image,
               cl_image_info    param_name, 
               size_t           param_value_size,
               void *           param_value,
               size_t *         param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clSetMemObjectDestructorCallback(cl_mem memobj, 
                                 void (CL_CALLBACK * pfn_notify)( cl_mem memobj, void* user_data), 
                                 void * user_data ) CL_API_SUFFIX__VERSION_1_1
{
	NOT_IMPLEMENTED();
	return 0;
}  

// Sampler APIs
extern CL_API_ENTRY cl_sampler CL_API_CALL
clCreateSampler(cl_context          context,
                cl_bool             normalized_coords, 
                cl_addressing_mode  addressing_mode, 
                cl_filter_mode      filter_mode,
                cl_int *            errcode_ret) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return NULL;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clRetainSampler(cl_sampler sampler) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clReleaseSampler(cl_sampler sampler) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clGetSamplerInfo(cl_sampler         sampler,
                 cl_sampler_info    param_name,
                 size_t             param_value_size,
                 void *             param_value,
                 size_t *           param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}
                            
// Program Object APIs 
extern CL_API_ENTRY cl_program CL_API_CALL
clCreateProgramWithSource(cl_context        context,
                          cl_uint           count,
                          const char **     strings,
                          const size_t *    lengths,
                          cl_int *          errcode_ret) CL_API_SUFFIX__VERSION_1_0
{
	fprintf(stderr, "please use clCreateProgramWithBinary !\n");
	NOT_IMPLEMENTED();
	return NULL;
}

extern CL_API_ENTRY cl_program CL_API_CALL
clCreateProgramWithBinary(cl_context                     context,
                          cl_uint                        num_devices,
                          const cl_device_id *           device_list,
                          const size_t *                 lengths,
                          const unsigned char **         binaries,
                          cl_int *                       binary_status,
                          cl_int *                       errcode_ret) CL_API_SUFFIX__VERSION_1_0
{
	cl_int err = CL_SUCCESS;
	if (!context) err = CL_INVALID_CONTEXT;
	if (!device_list || !lengths || !binaries) err = CL_INVALID_VALUE;
	if (err != CL_SUCCESS) goto CREATE_PROGM_BIN_FAULT;

	// FIX ME
	if(num_devices != 1) printf("num_device != 1\n");

	size_t progm_len = sizeof(struct _cl_program);
	size_t total_len = progm_len;
	
	int i = 0;
	for (i = 0; i < num_devices; ++i) {
		total_len += lengths[i];
	}
	
	size_t bin_size_tb_len = num_devices * sizeof(size_t);
	total_len += bin_size_tb_len;

	size_t bin_indx_tb_len = num_devices * 
		sizeof(unsigned char*);
	total_len += bin_indx_tb_len;

	uint8_t *buf = (uint8_t*)calloc(1, total_len);
	cl_program progm = (cl_program)buf;
	progm->refcont = 1;
	progm->cntxt = context;
	progm->num_dev = num_devices;
	progm->dev.val = context->dev.val;
	progm->dev.len = context->dev.len;
	progm->src_code.val = NULL;
	progm->src_code.len = 0;
	buf += progm_len;

	progm->bin_size.val = (void*)buf;
	progm->bin_size.len = bin_size_tb_len;
	buf += bin_size_tb_len;

	progm->bin.val = (void*)buf;
	progm->bin.len = bin_indx_tb_len;
	buf += bin_indx_tb_len;

	size_t *bin_size = (size_t*)progm->bin_size.val;
	unsigned char **bin = (unsigned char**)progm->bin.val;
	for (i = 0; i < num_devices; ++i) {
		bin_size[i] = lengths[i];
		bin[i] = (unsigned char*)buf;
		memcpy(buf, binaries[i], lengths[i]);
		buf += lengths[i];

		if(binary_status)
			binary_status[i] = CL_SUCCESS;
	}

	if (errcode_ret) *errcode_ret = err;

#if defined(USE_M2S) && defined(ARM)
	hsa_m2s_cmd m2s_tmp;
	int m2s_size = 0;
	int m2s_ret = 0;
	INIT_M2S_CMD(m2s_tmp, m2s_size);
	m2s_tmp.op = hsa_m2s_op_program_bin;
	m2s_tmp.agent_addr = (int)bin[0];
	m2s_tmp.mem_size = (int)bin_size[0];//FIXME
	HSAEMU_REMOTE_M2S(m2s_ret, &m2s_tmp, m2s_size);
	progm->m2s_program_id = m2s_ret;
#endif

	return progm;

CREATE_PROGM_BIN_FAULT:
	if (errcode_ret) *errcode_ret = err;
	return NULL;
}

extern CL_API_ENTRY cl_program CL_API_CALL
clCreateProgramWithBuiltInKernels(cl_context            context,
                                  cl_uint               num_devices,
                                  const cl_device_id *  device_list,
                                  const char *          kernel_names,
                                  cl_int *              errcode_ret) CL_API_SUFFIX__VERSION_1_2
{
	NOT_IMPLEMENTED();
	return NULL;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clRetainProgram(cl_program program) CL_API_SUFFIX__VERSION_1_0
{
	if (!program) return CL_INVALID_PROGRAM;

	program->refcont++;
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clReleaseProgram(cl_program program) CL_API_SUFFIX__VERSION_1_0
{
	if (!program) return CL_INVALID_PROGRAM;
	program->refcont--;
	if (program->refcont == 0) {
		free(program);
	}
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clBuildProgram(cl_program           program,
               cl_uint              num_devices,
               const cl_device_id * device_list,
               const char *         options, 
               void (CL_CALLBACK *  pfn_notify)(cl_program program, void * user_data),
               void *               user_data) CL_API_SUFFIX__VERSION_1_0
{
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clCompileProgram(cl_program           program,
                 cl_uint              num_devices,
                 const cl_device_id * device_list,
                 const char *         options, 
                 cl_uint              num_input_headers,
                 const cl_program *   input_headers,
                 const char **        header_include_names,
                 void (CL_CALLBACK *  pfn_notify)(cl_program program, void * user_data),
                 void *               user_data) CL_API_SUFFIX__VERSION_1_2
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_program CL_API_CALL
clLinkProgram(cl_context           context,
              cl_uint              num_devices,
              const cl_device_id * device_list,
              const char *         options, 
              cl_uint              num_input_programs,
              const cl_program *   input_programs,
              void (CL_CALLBACK *  pfn_notify)(cl_program program, void * user_data),
              void *               user_data,
              cl_int *             errcode_ret ) CL_API_SUFFIX__VERSION_1_2
{
	NOT_IMPLEMENTED();
	return NULL;
}


extern CL_API_ENTRY cl_int CL_API_CALL
clUnloadPlatformCompiler(cl_platform_id platform) CL_API_SUFFIX__VERSION_1_2
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clGetProgramInfo(cl_program         program,
                 cl_program_info    param_name,
                 size_t             param_value_size,
                 void *             param_value,
                 size_t *           param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	if (!program) return CL_INVALID_PROGRAM;

	size_t len = 0;

	switch(param_name) {
		case CL_PROGRAM_REFERENCE_COUNT:
			GET_ELEMENT_INFO(len, param_value, program, refcont);
			break;
		case CL_PROGRAM_CONTEXT:
			GET_ELEMENT_INFO(len, param_value, program, cntxt);
			break;
		case CL_PROGRAM_NUM_DEVICES:
			GET_ELEMENT_INFO(len, param_value, program, num_dev);
			break;
		case CL_PROGRAM_DEVICES:
			GET_VL_INFO(len, param_value, program, dev);
			break;
		case CL_PROGRAM_SOURCE:
			GET_VL_INFO(len, param_value, program, src_code);
			break;
		case CL_PROGRAM_BINARY_SIZES:
			GET_VL_INFO(len, param_value, program, bin_size);
			break;
		case CL_PROGRAM_BINARIES:
			GET_VL_INFO(len, param_value, program, bin);
			break;									
		default:
			return CL_INVALID_VALUE;
	}

	if (param_value_size_ret)
		*param_value_size_ret = len;
	return CL_SUCCESS;	
}

extern CL_API_ENTRY cl_int CL_API_CALL
clGetProgramBuildInfo(cl_program            program,
                      cl_device_id          device,
                      cl_program_build_info param_name,
                      size_t                param_value_size,
                      void *                param_value,
                      size_t *              param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}
                            
// Kernel Object APIs
extern CL_API_ENTRY cl_kernel CL_API_CALL
clCreateKernel(cl_program      program,
               const char *    kernel_name,
               cl_int *        errcode_ret) CL_API_SUFFIX__VERSION_1_0
{
	cl_int err = CL_SUCCESS;
	if (!program) err = CL_INVALID_PROGRAM;
	if (!kernel_name) err = CL_INVALID_VALUE;
	if (err != CL_SUCCESS) goto CREATE_KERNEL_FAULT;

	size_t kernobj_len = sizeof(struct _cl_kernel);
	size_t name_len = strlen(kernel_name);
	size_t max_arglist_len = (KBYTE) >> 2;
	size_t total_len = kernobj_len + name_len + max_arglist_len;
	uint8_t *buf = (uint8_t*)calloc(1, total_len);

	cl_kernel kernel = (cl_kernel)buf;
	kernel->num_arg = 0;
	kernel->refcont = 1;
	kernel->cntxt = program->cntxt;
	kernel->progm = program;
	kernel->max_arg = max_arglist_len / sizeof(hsaVL);
	kernel->used_local_mem = 0;
	buf += kernobj_len;

	kernel->name.val = (void*)buf;
	kernel->name.len = name_len;
	memcpy(buf, kernel_name, name_len);
	buf += name_len;

	kernel->arg_list.val = (void*)buf;
	kernel->arg_list.len = max_arglist_len;

	//FIX ME:
	//kernel->bin.val = program->src_code.val;
	//kernel->bin.len = program->src_code.len;
	unsigned char **bin_ptr = (unsigned char**)program->bin.val;
	size_t *bin_size = (size_t*)program->bin_size.val;
	kernel->bin.val = (void*)(bin_ptr[0]);
	kernel->bin.len = bin_size[0];

	if (errcode_ret) *errcode_ret = err;

#if defined(USE_M2S) && defined(ARM)
	hsa_m2s_cmd m2s_tmp;
	int m2s_size = 0;
	int m2s_ret = 0;
	INIT_M2S_CMD(m2s_tmp, m2s_size);
	m2s_tmp.op2 = hsa_m2s_op_kernel;
	m2s_tmp.agent_addr2 = (int)kernel->name.val;
	m2s_tmp.mem_size2 = (int)kernel->name.len;
	m2s_tmp.program_id = (int)program->m2s_program_id;
	HSAEMU_REMOTE_M2S(m2s_ret, &m2s_tmp, m2s_size);
	kernel->m2s_kernel_id = m2s_ret;
#endif

	return kernel;

CREATE_KERNEL_FAULT:
	if (errcode_ret) *errcode_ret = err;
	return NULL; 
}

extern CL_API_ENTRY cl_int CL_API_CALL
clCreateKernelsInProgram(cl_program     program,
                         cl_uint        num_kernels,
                         cl_kernel *    kernels,
                         cl_uint *      num_kernels_ret) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clRetainKernel(cl_kernel    kernel) CL_API_SUFFIX__VERSION_1_0
{
	if (!kernel) return CL_INVALID_KERNEL;

	kernel->refcont++;
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clReleaseKernel(cl_kernel   kernel) CL_API_SUFFIX__VERSION_1_0
{
	if (!kernel) return CL_INVALID_KERNEL;

	kernel->refcont--;

	if (kernel->refcont == 0) {
		free(kernel);
	}

	return CL_SUCCESS; 
}

extern CL_API_ENTRY cl_int CL_API_CALL
clSetKernelArg(cl_kernel    kernel,
               cl_uint      arg_index,
               size_t       arg_size,
               const void * arg_value) CL_API_SUFFIX__VERSION_1_0
{
	if (!kernel) return CL_INVALID_KERNEL;

	cl_uint max_arg = kernel->max_arg;
	if (arg_index >= max_arg) return CL_INVALID_ARG_INDEX;

	// check registed table
	cl_mem *memlist = NULL;
	void *arg_ptr = (void*)arg_value;
	cl_bool value_is_dev_mem = CL_FALSE;
	if (arg_ptr && arg_size == sizeof(cl_mem*)) {
		cl_mem tmp = NULL;
		memcpy(&tmp, arg_ptr, arg_size);
		memlist = ((kernel->cntxt)->memlist);
		cl_uint i = 0;
		cl_uint count = (kernel->cntxt)->num_memobj;
		
		for (i = 0; i < count; i++) {
			if (memlist[i] == tmp) {
				value_is_dev_mem = CL_TRUE;
				memlist += i;
				break;
			}
		}		
	}
	// reset arguments
	if (value_is_dev_mem) {
		arg_ptr = &((*memlist)->buf);
		arg_size = sizeof((*memlist)->buf);
	}
#if defined(USE_M2S)
	int m2s_dev_addr = 0;
	if (value_is_dev_mem) {
		m2s_dev_addr = (int)((*memlist)->buf);
	}
#endif
	
	// is local memory
	if (!arg_ptr) {
		value_is_dev_mem = CL_TRUE;
		kernel->used_local_mem += arg_size;
	}

	hsaVL *arg_list = (hsaVL*)kernel->arg_list.val;
	arg_list[arg_index].val = arg_ptr;
	arg_list[arg_index].len = arg_size;

	if ((arg_index + 1) > kernel->num_arg) {
		kernel->num_arg = arg_index + 1;
	}

#if defined(USE_M2S) && defined (ARM)
	hsa_m2s_cmd m2s_tmp;
	int m2s_size = 0;
	int m2s_ret = 0;
	INIT_M2S_CMD(m2s_tmp, m2s_size);
	m2s_tmp.op3 = hsa_m2s_op_arg_value;
	m2s_tmp.agent_addr3 = (int)arg_ptr;
	m2s_tmp.mem_size3 = (int)arg_size;
	m2s_tmp.index = (int)arg_index;
	m2s_tmp.kernel_id3 = (int)kernel->m2s_kernel_id;
	if (value_is_dev_mem) {
		m2s_tmp.op3 = hsa_m2s_op_arg_ptr;
		m2s_tmp.agent_addr3 = m2s_dev_addr;
	}
	HSAEMU_REMOTE_M2S(m2s_ret, &m2s_tmp, m2s_size);
	if (m2s_ret < 0) HSA_DEBUG_LOG("remote kernarg fail\n");
#endif

	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clGetKernelInfo(cl_kernel       kernel,
                cl_kernel_info  param_name,
                size_t          param_value_size,
                void *          param_value,
                size_t *        param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	if (!kernel) return CL_INVALID_KERNEL;

	size_t len = 0;

	switch(param_name) {
		case CL_KERNEL_FUNCTION_NAME:
			GET_VL_INFO(len, param_value, kernel, name);
			break;
		case CL_KERNEL_NUM_ARGS:
			GET_ELEMENT_INFO(len, param_value, kernel, num_arg);
			break;
		case CL_KERNEL_REFERENCE_COUNT:
			GET_ELEMENT_INFO(len, param_value, kernel, refcont);
			break;
		case CL_KERNEL_CONTEXT:
			GET_ELEMENT_INFO(len, param_value, kernel, cntxt);
			break;
		case CL_KERNEL_PROGRAM:
			GET_ELEMENT_INFO(len, param_value, kernel, progm);
			break;						
		default:
			return CL_INVALID_VALUE;
	}

	if (param_value_size_ret)
		*param_value_size_ret = len;
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clGetKernelArgInfo(cl_kernel       kernel,
                   cl_uint         arg_indx,
                   cl_kernel_arg_info  param_name,
                   size_t          param_value_size,
                   void *          param_value,
                   size_t *        param_value_size_ret) CL_API_SUFFIX__VERSION_1_2
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clGetKernelWorkGroupInfo(cl_kernel                  kernel,
                         cl_device_id               device,
                         cl_kernel_work_group_info  param_name,
                         size_t                     param_value_size,
                         void *                     param_value,
                         size_t *                   param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	if (!kernel) return CL_INVALID_KERNEL;
	if (!device) return CL_INVALID_DEVICE;

	size_t len = 0;

	switch(param_name) {
		case CL_KERNEL_WORK_GROUP_SIZE:
			GET_ELEMENT_INFO(len, param_value, device, group_size);
			break;
		case CL_KERNEL_COMPILE_WORK_GROUP_SIZE:
			GET_VL_INFO(len, param_value, device, work_item);
			break;
		case CL_KERNEL_LOCAL_MEM_SIZE:
			GET_ELEMENT_INFO(len, param_value, kernel, used_local_mem);
			break;					
		default:
			return CL_INVALID_VALUE;
	}

	if (param_value_size_ret)
		*param_value_size_ret = len;
	return CL_SUCCESS;	
}

// Event Object APIs
extern CL_API_ENTRY cl_int CL_API_CALL
clWaitForEvents(cl_uint             num_events,
                const cl_event *    event_list) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clGetEventInfo(cl_event         event,
               cl_event_info    param_name,
               size_t           param_value_size,
               void *           param_value,
               size_t *         param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	if (!event) return CL_INVALID_EVENT;

	size_t len = 0;

	switch(param_name) {
		case CL_EVENT_COMMAND_QUEUE:
			GET_ELEMENT_INFO(len, param_value, event, cmdQ);
			break;
		case CL_EVENT_COMMAND_TYPE:
			GET_ELEMENT_INFO(len, param_value, event, type);
			break;
		case CL_EVENT_COMMAND_EXECUTION_STATUS:
			GET_ELEMENT_INFO(len, param_value, event, status);
			break;
		case CL_EVENT_REFERENCE_COUNT:
			GET_ELEMENT_INFO(len, param_value, event, refcont);
			break;				
		default:
			return CL_INVALID_VALUE;
	}

	if (param_value_size_ret)
		*param_value_size_ret = len;
	return CL_SUCCESS;	
}
                            
extern CL_API_ENTRY cl_event CL_API_CALL
clCreateUserEvent(cl_context    context,
                  cl_int *      errcode_ret) CL_API_SUFFIX__VERSION_1_1
{
	NOT_IMPLEMENTED();
	return NULL;
}
                            
extern CL_API_ENTRY cl_int CL_API_CALL
clRetainEvent(cl_event event) CL_API_SUFFIX__VERSION_1_0
{
	if(!event) return CL_INVALID_EVENT;
	event->refcont++;
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clReleaseEvent(cl_event event) CL_API_SUFFIX__VERSION_1_0
{
	if(!event) return CL_INVALID_EVENT;

	event->refcont--;
	if(event->refcont == 0){
		free(event);
	}
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clSetUserEventStatus(cl_event   event,
                     cl_int     execution_status) CL_API_SUFFIX__VERSION_1_1
{
	NOT_IMPLEMENTED();
	return 0;
}
                     
extern CL_API_ENTRY cl_int CL_API_CALL
clSetEventCallback( cl_event    event,
                    cl_int      command_exec_callback_type,
                    void (CL_CALLBACK * pfn_notify)(cl_event, cl_int, void *),
                    void *      user_data) CL_API_SUFFIX__VERSION_1_1
{
	NOT_IMPLEMENTED();
	return 0;
}

// Profiling APIs
extern CL_API_ENTRY cl_int CL_API_CALL
clGetEventProfilingInfo(cl_event            event,
                        cl_profiling_info   param_name,
                        size_t              param_value_size,
                        void *              param_value,
                        size_t *            param_value_size_ret) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}
                                
// Flush and Finish APIs
extern CL_API_ENTRY cl_int CL_API_CALL
clFlush(cl_command_queue command_queue) CL_API_SUFFIX__VERSION_1_0
{
	if (!command_queue || !command_queue->user_queue)
		return CL_INVALID_COMMAND_QUEUE;

	user_queue *userQ = command_queue->user_queue;
	hsa_aql *aql = (hsa_aql*)(uintptr_t)(userQ->basePointer + userQ->readOffset);
	volatile completionobject *comple = (completionobject*)(uintptr_t)aql->completionObjectAddress;
	
	if (userQ->readOffset == userQ->writeOffset) {
		// no task have to flush
		return CL_SUCCESS;
	}


	while (!comple->status);

	if (comple->status > 0) {
		userQ->readOffset += sizeof(hsa_aql);
		if (userQ->readOffset == userQ->size) userQ->readOffset = 0;
	} else {
		HSA_DEBUG_LOG("kernel function fault\n");
		while(1);
	}

	return CL_SUCCESS;	
}

extern CL_API_ENTRY cl_int CL_API_CALL
clFinish(cl_command_queue command_queue) CL_API_SUFFIX__VERSION_1_0
{
	return clFlush(command_queue);
}

// Enqueued Commands APIs
static void hsaCreateEvent(cl_command_queue    command_queue,
                           cl_event *    event)
{
	// FIX ME !!
	if (!event) return;

	cl_event tmp = (cl_event)calloc(1, sizeof(struct _cl_event));
	tmp->cmdQ = command_queue;
	tmp->type = CL_COMMAND_TASK;
	tmp->status = CL_COMPLETE;
	tmp->refcont = 1;

	*event = tmp;
}
extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueReadBuffer(cl_command_queue    command_queue,
                    cl_mem              buffer,
                    cl_bool             blocking_read,
                    size_t              offset,
                    size_t              size, 
                    void *              ptr,
                    cl_uint             num_events_in_wait_list,
                    const cl_event *    event_wait_list,
                    cl_event *          event) CL_API_SUFFIX__VERSION_1_0
{
	if (!buffer) return CL_INVALID_MEM_OBJECT;
	clFinish(command_queue);

	if (size > buffer->size) size = buffer->size;
	if (offset > size) offset = size - 1;
	
	uint8_t *buf = (uint8_t*)buffer->buf;
	buf += offset;

	memcpy(ptr, buf, size);

	hsaCreateEvent(command_queue, event);

	return CL_SUCCESS;
}
                            
extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueReadBufferRect(cl_command_queue    command_queue,
                        cl_mem              buffer,
                        cl_bool             blocking_read,
                        const size_t *      buffer_offset,
                        const size_t *      host_offset, 
                        const size_t *      region,
                        size_t              buffer_row_pitch,
                        size_t              buffer_slice_pitch,
                        size_t              host_row_pitch,
                        size_t              host_slice_pitch,                        
                        void *              ptr,
                        cl_uint             num_events_in_wait_list,
                        const cl_event *    event_wait_list,
                        cl_event *          event) CL_API_SUFFIX__VERSION_1_1
{
	NOT_IMPLEMENTED();
	return 0;
}
                            
extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueWriteBuffer(cl_command_queue   command_queue, 
                     cl_mem             buffer, 
                     cl_bool            blocking_write, 
                     size_t             offset, 
                     size_t             size, 
                     const void *       ptr, 
                     cl_uint            num_events_in_wait_list, 
                     const cl_event *   event_wait_list, 
                     cl_event *         event) CL_API_SUFFIX__VERSION_1_0
{	
	if (!buffer) return CL_INVALID_MEM_OBJECT;
	clFinish(command_queue);

	if (size > buffer->size) size = buffer->size;
	if (offset > size) offset = size - 1;
	
	uint8_t *buf = (uint8_t*)buffer->buf;
	buf += offset; //FIXME

	memcpy(buf, ptr, size);

	hsaCreateEvent(command_queue, event);

	return CL_SUCCESS;	
}
                            
extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueWriteBufferRect(cl_command_queue    command_queue,
                         cl_mem              buffer,
                         cl_bool             blocking_write,
                         const size_t *      buffer_offset,
                         const size_t *      host_offset, 
                         const size_t *      region,
                         size_t              buffer_row_pitch,
                         size_t              buffer_slice_pitch,
                         size_t              host_row_pitch,
                         size_t              host_slice_pitch,                        
                         const void *        ptr,
                         cl_uint             num_events_in_wait_list,
                         const cl_event *    event_wait_list,
                         cl_event *          event) CL_API_SUFFIX__VERSION_1_1
{
	NOT_IMPLEMENTED();
	return 0;
}
                            
extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueFillBuffer(cl_command_queue   command_queue,
                    cl_mem             buffer, 
                    const void *       pattern, 
                    size_t             pattern_size, 
                    size_t             offset, 
                    size_t             size, 
                    cl_uint            num_events_in_wait_list, 
                    const cl_event *   event_wait_list, 
                    cl_event *         event) CL_API_SUFFIX__VERSION_1_2
{
	NOT_IMPLEMENTED();
	return 0;
}
                            
extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueCopyBuffer(cl_command_queue    command_queue, 
                    cl_mem              src_buffer,
                    cl_mem              dst_buffer, 
                    size_t              src_offset,
                    size_t              dst_offset,
                    size_t              size, 
                    cl_uint             num_events_in_wait_list,
                    const cl_event *    event_wait_list,
                    cl_event *          event) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}
                            
extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueCopyBufferRect(cl_command_queue    command_queue, 
                        cl_mem              src_buffer,
                        cl_mem              dst_buffer, 
                        const size_t *      src_origin,
                        const size_t *      dst_origin,
                        const size_t *      region, 
                        size_t              src_row_pitch,
                        size_t              src_slice_pitch,
                        size_t              dst_row_pitch,
                        size_t              dst_slice_pitch,
                        cl_uint             num_events_in_wait_list,
                        const cl_event *    event_wait_list,
                        cl_event *          event) CL_API_SUFFIX__VERSION_1_1
{
	NOT_IMPLEMENTED();
	return 0;
}
                            
extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueReadImage(cl_command_queue     command_queue,
                   cl_mem               image,
                   cl_bool              blocking_read, 
                   const size_t *       origin,
                   const size_t *       region,
                   size_t               row_pitch,
                   size_t               slice_pitch, 
                   void *               ptr,
                   cl_uint              num_events_in_wait_list,
                   const cl_event *     event_wait_list,
                   cl_event *           event) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueWriteImage(cl_command_queue    command_queue,
                    cl_mem              image,
                    cl_bool             blocking_write, 
                    const size_t *      origin,
                    const size_t *      region,
                    size_t              input_row_pitch,
                    size_t              input_slice_pitch, 
                    const void *        ptr,
                    cl_uint             num_events_in_wait_list,
                    const cl_event *    event_wait_list,
                    cl_event *          event) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueFillImage(cl_command_queue   command_queue,
                   cl_mem             image, 
                   const void *       fill_color, 
                   const size_t *     origin, 
                   const size_t *     region, 
                   cl_uint            num_events_in_wait_list, 
                   const cl_event *   event_wait_list, 
                   cl_event *         event) CL_API_SUFFIX__VERSION_1_2
{
	NOT_IMPLEMENTED();
	return 0;
}
                            
extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueCopyImage(cl_command_queue     command_queue,
                   cl_mem               src_image,
                   cl_mem               dst_image, 
                   const size_t *       src_origin,
                   const size_t *       dst_origin,
                   const size_t *       region, 
                   cl_uint              num_events_in_wait_list,
                   const cl_event *     event_wait_list,
                   cl_event *           event) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueCopyImageToBuffer(cl_command_queue command_queue,
                           cl_mem           src_image,
                           cl_mem           dst_buffer, 
                           const size_t *   src_origin,
                           const size_t *   region, 
                           size_t           dst_offset,
                           cl_uint          num_events_in_wait_list,
                           const cl_event * event_wait_list,
                           cl_event *       event) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueCopyBufferToImage(cl_command_queue command_queue,
                           cl_mem           src_buffer,
                           cl_mem           dst_image, 
                           size_t           src_offset,
                           const size_t *   dst_origin,
                           const size_t *   region, 
                           cl_uint          num_events_in_wait_list,
                           const cl_event * event_wait_list,
                           cl_event *       event) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY void * CL_API_CALL
clEnqueueMapBuffer(cl_command_queue command_queue,
                   cl_mem           buffer,
                   cl_bool          blocking_map, 
                   cl_map_flags     map_flags,
                   size_t           offset,
                   size_t           size,
                   cl_uint          num_events_in_wait_list,
                   const cl_event * event_wait_list,
                   cl_event *       event,
                   cl_int *         errcode_ret) CL_API_SUFFIX__VERSION_1_0
{
	cl_int err = CL_SUCCESS;
	if (!command_queue) err = CL_INVALID_COMMAND_QUEUE;
	if (!buffer) err = CL_INVALID_MEM_OBJECT;
	if (err != CL_SUCCESS) goto MAP_FAULT;
	clFinish(command_queue);

	cl_mem *list = (command_queue->cntxt)->memlist;
	cl_bool reg = CL_FALSE;

	int i = 0;
	for (i = 0; i < MAX_MEMOBJ_SIZE; i++) {
		if (list[i] == buffer) {
			reg = CL_TRUE;
			break;
		}
	}

	void *ret_value = NULL;

	if (reg == CL_TRUE) {
		ret_value = buffer->buf;
	} else {
		err = CL_INVALID_MEM_OBJECT;
		goto MAP_FAULT;
	}

	if (errcode_ret) *errcode_ret = err;
	hsaCreateEvent(command_queue, event);
	return ret_value;

MAP_FAULT:
	if (errcode_ret) *errcode_ret = err;
	return NULL;
}

extern CL_API_ENTRY void * CL_API_CALL
clEnqueueMapImage(cl_command_queue  command_queue,
                  cl_mem            image, 
                  cl_bool           blocking_map, 
                  cl_map_flags      map_flags, 
                  const size_t *    origin,
                  const size_t *    region,
                  size_t *          image_row_pitch,
                  size_t *          image_slice_pitch,
                  cl_uint           num_events_in_wait_list,
                  const cl_event *  event_wait_list,
                  cl_event *        event,
                  cl_int *          errcode_ret) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return NULL;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueUnmapMemObject(cl_command_queue command_queue,
                        cl_mem           memobj,
                        void *           mapped_ptr,
                        cl_uint          num_events_in_wait_list,
                        const cl_event *  event_wait_list,
                        cl_event *        event) CL_API_SUFFIX__VERSION_1_0
{
	if (!command_queue) return CL_INVALID_COMMAND_QUEUE;
	if (!memobj) return CL_INVALID_MEM_OBJECT;
	if (!mapped_ptr) return CL_INVALID_VALUE;
	clFinish(command_queue);

	hsaCreateEvent(command_queue, event);
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueMigrateMemObjects(cl_command_queue       command_queue,
                           cl_uint                num_mem_objects,
                           const cl_mem *         mem_objects,
                           cl_mem_migration_flags flags,
                           cl_uint                num_events_in_wait_list,
                           const cl_event *       event_wait_list,
                           cl_event *             event) CL_API_SUFFIX__VERSION_1_2
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueNDRangeKernel(cl_command_queue command_queue,
                       cl_kernel        kernel,
                       cl_uint          work_dim,
                       const size_t *   global_work_offset,
                       const size_t *   global_work_size,
                       const size_t *   local_work_size,
                       cl_uint          num_events_in_wait_list,
                       const cl_event * event_wait_list,
                       cl_event *       event) CL_API_SUFFIX__VERSION_1_0
{
	// check arguments
	if (!command_queue) return CL_INVALID_COMMAND_QUEUE;
	if (!kernel) return CL_INVALID_KERNEL;
	if (work_dim < 1 || work_dim > 3)
		return CL_INVALID_WORK_DIMENSION;
	if (!global_work_size) return CL_INVALID_GLOBAL_WORK_SIZE;
	if (!local_work_size) return CL_INVALID_WORK_GROUP_SIZE;
	clFinish(command_queue);
	
	size_t grid_size[3] = {1, 1, 1};
	size_t group_size[3] = {1, 1, 1};
	size_t total_group_size = 1;
	int i;
	for (i=0; i<work_dim; i++) {
		if ((global_work_size[i] % local_work_size[i]) != 0)
			return CL_INVALID_WORK_GROUP_SIZE;

		grid_size[i] = global_work_size[i];
		group_size[i] = local_work_size[i];
		total_group_size *= local_work_size[i];
	}

	if (total_group_size > CL_DEVICE_MAX_WORK_GROUP_SIZE)
		return CL_INVALID_WORK_GROUP_SIZE;

	if ((num_events_in_wait_list > 0 && event_wait_list == NULL) ||
			(num_events_in_wait_list == 0 && event_wait_list != NULL))
		return CL_INVALID_EVENT_WAIT_LIST;

	// check whether queue is full before memory allocate
	user_queue *userQ = command_queue->user_queue;
	if ((userQ->writeOffset + sizeof(hsa_aql) == userQ->readOffset) ||
			(userQ->writeOffset + sizeof(hsa_aql) == userQ->size && userQ->readOffset == 0))
		return CL_OUT_OF_RESOURCES;

	// perpare kernarg
	size_t kernarg_len = 0;
	size_t group_mem_len = 0;
	size_t group_mem_addr_len = sizeof(void*);
	hsaVL *arg_list = kernel->arg_list.val;
	cl_uint currt_num_arg = kernel->num_arg;

	for (i = 0; i < currt_num_arg; i++) {
		if (arg_list[i].val) {
			kernarg_len += arg_list[i].len;
		}else{
			kernarg_len += group_mem_addr_len;
			group_mem_len += arg_list[i].len;
		}
	}

	void *kernarg_buf = calloc(1, kernarg_len);
	void *ptr = kernarg_buf;
	
	for (i = 0; i < currt_num_arg; i++) {
		if (arg_list[i].val) {
			size_t tmp_len = arg_list[i].len;
			memcpy(ptr, arg_list[i].val, tmp_len);
			ptr += tmp_len;
		}else{
			ptr += group_mem_addr_len;
		}		
	}

	// setup the AQL packet
	hsa_aql *aql = (hsa_aql*)(uintptr_t)(userQ->basePointer + userQ->writeOffset);
	aql->flag |= (work_dim & 3) << 20;
	aql->kernelObjectAddress = (uint32_t)(uintptr_t)kernel->bin.val;
	aql->kernargAddress = (uint32_t)(uintptr_t)kernarg_buf;
	aql->workgroupGroupSegmentSizeBytes = (uint32_t)group_mem_len;
	aql->workitemArgSegmentSizeBytes = (uint32_t)kernarg_len;
	aql->reserved = (uint32_t)kernel->bin.len; // is that right ?
	aql->dispatchId = userQ->dispatchID++;
	aql->gridSize_x = grid_size[0];
	aql->gridSize_y = grid_size[1];
	aql->gridSize_z = grid_size[2];
	aql->workgroupSize_x = group_size[0];
	aql->workgroupSize_y = group_size[1];
	aql->workgroupSize_z = group_size[2];
	// setup compleobj
	completionobject *cmpleobj = (completionobject*)(uintptr_t)aql->completionObjectAddress;
	memset(cmpleobj, 0, sizeof(completionobject));

	// modify the writeoffset after the aql has been setted
	userQ->writeOffset += sizeof(hsa_aql);
	if (userQ->writeOffset == userQ->size)
		userQ->writeOffset = 0;

#if !defined(USE_M2S) && defined(ARM)
	int ret = 0;
	__asm__("push {R1,R2}\n\t"
			"mov R1, %1\n\t"
			"swi 0x37\n\t"
			"mov %0, R2\n\t"
			"pop {R1,R2}\n\t"
			: "=r" (ret)
			: "r" ((uintptr_t)userQ)
			: "memory");

	if (ret < 0) {
		return CL_OUT_OF_RESOURCES;
	}
#else
	userQ->readOffset += sizeof(hsa_aql);
	if (userQ->readOffset == userQ->size) {
		userQ->readOffset = 0;
	}
#endif


#if defined(USE_M2S) && defined(ARM)
	int ndrange_args[] = {
		0, 0, 0, // global_work_offset
		grid_size[0], grid_size[1], grid_size[2], // global_work_size
		group_size[0], group_size[1], group_size[2], // local_work_size
		0, 0, 0, // start group
		grid_size[0] / group_size[0], // group count
		grid_size[1] / group_size[1],
		grid_size[2] / group_size[2],
	};

	hsa_m2s_cmd m2s_tmp;
	int m2s_size = 0;
	int m2s_ret = 0;
	INIT_M2S_CMD(m2s_tmp, m2s_size);
	m2s_tmp.op4 = hsa_m2s_op_ndrange;
	m2s_tmp.agent_addr4 = (int)ndrange_args;
	m2s_tmp.mem_size4 = sizeof(ndrange_args);
	m2s_tmp.kernel_id4 = (int)kernel->m2s_kernel_id;
	m2s_tmp.dim = work_dim;
	HSAEMU_REMOTE_M2S(m2s_ret, &m2s_tmp, m2s_size);
	if (m2s_ret < 0) HSA_DEBUG_LOG("remote ndrange fail\n");
#endif

	// should free kernarg_buf
	// but clEnqueueNDRangeKernel is non-blocking function
	// kernarg_buf can be freed only if kernel already be executed
	hsaCreateEvent(command_queue, event);
	return CL_SUCCESS;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueTask(cl_command_queue  command_queue,
              cl_kernel         kernel,
              cl_uint           num_events_in_wait_list,
              const cl_event *  event_wait_list,
              cl_event *        event) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueNativeKernel(cl_command_queue  command_queue,
					            void (CL_CALLBACK * user_func)(void *), 
                      void *            args,
                      size_t            cb_args, 
                      cl_uint           num_mem_objects,
                      const cl_mem *    mem_list,
                      const void **     args_mem_loc,
                      cl_uint           num_events_in_wait_list,
                      const cl_event *  event_wait_list,
                      cl_event *        event) CL_API_SUFFIX__VERSION_1_0
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueMarkerWithWaitList(cl_command_queue command_queue,
                            cl_uint           num_events_in_wait_list,
                            const cl_event *  event_wait_list,
                            cl_event *        event) CL_API_SUFFIX__VERSION_1_2
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clEnqueueBarrierWithWaitList(cl_command_queue command_queue,
                             cl_uint           num_events_in_wait_list,
                             const cl_event *  event_wait_list,
                             cl_event *        event) CL_API_SUFFIX__VERSION_1_2
{
	NOT_IMPLEMENTED();
	return 0;
}

extern CL_API_ENTRY cl_int CL_API_CALL
clSetPrintfCallback(cl_context          context,
                    void (CL_CALLBACK * pfn_notify)(cl_context program, 
                                                    cl_uint printf_data_len, 
                                                    char * printf_data_ptr, 
                                                    void * user_data),
                    void * user_data) CL_API_SUFFIX__VERSION_1_2
{
	NOT_IMPLEMENTED();
	return 0;
}



// Extension function access
// *
// * Returns the extension function address for the given function name,
// * or NULL if a valid function can not be found.  The client must
// * check to make sure the address is not NULL, before using or 
// * calling the returned function address.
/*
extern CL_API_ENTRY void * CL_API_CALL 
clGetExtensionFunctionAddressForPlatform(cl_platform_id platform,
                                         const char *   func_name) CL_API_SUFFIX__VERSION_1_2{return NULL;}
    

// Deprecated OpenCL 1.1 APIs
extern CL_API_ENTRY CL_EXT_PREFIX__VERSION_1_1_DEPRECATED cl_mem CL_API_CALL
clCreateImage2D(cl_context              context,
                cl_mem_flags            flags,
                const cl_image_format * image_format,
                size_t                  image_width,
                size_t                  image_height,
                size_t                  image_row_pitch, 
                void *                  host_ptr,
                cl_int *                errcode_ret) CL_EXT_SUFFIX__VERSION_1_1_DEPRECATED{return NULL;}
    
extern CL_API_ENTRY CL_EXT_PREFIX__VERSION_1_1_DEPRECATED cl_mem CL_API_CALL
clCreateImage3D(cl_context              context,
                cl_mem_flags            flags,
                const cl_image_format * image_format,
                size_t                  image_width, 
                size_t                  image_height,
                size_t                  image_depth, 
                size_t                  image_row_pitch, 
                size_t                  image_slice_pitch, 
                void *                  host_ptr,
                cl_int *                errcode_ret) CL_EXT_SUFFIX__VERSION_1_1_DEPRECATED{return NULL;}
    
extern CL_API_ENTRY CL_EXT_PREFIX__VERSION_1_1_DEPRECATED cl_int CL_API_CALL
clEnqueueMarker(cl_command_queue    command_queue,
                cl_event *          event) CL_EXT_SUFFIX__VERSION_1_1_DEPRECATED{return NULL;}
    
extern CL_API_ENTRY CL_EXT_PREFIX__VERSION_1_1_DEPRECATED cl_int CL_API_CALL
clEnqueueWaitForEvents(cl_command_queue command_queue,
                        cl_uint          num_events,
                        const cl_event * event_list) CL_EXT_SUFFIX__VERSION_1_1_DEPRECATED{return NULL;}
    
extern CL_API_ENTRY CL_EXT_PREFIX__VERSION_1_1_DEPRECATED cl_int CL_API_CALL
clEnqueueBarrier(cl_command_queue command_queue) CL_EXT_SUFFIX__VERSION_1_1_DEPRECATED{return NULL;}

extern CL_API_ENTRY CL_EXT_PREFIX__VERSION_1_1_DEPRECATED cl_int CL_API_CALL
clUnloadCompiler(void) CL_EXT_SUFFIX__VERSION_1_1_DEPRECATED{return NULL;}
    
extern CL_API_ENTRY CL_EXT_PREFIX__VERSION_1_1_DEPRECATED void * CL_API_CALL
clGetExtensionFunctionAddress(const char * func_name) CL_EXT_SUFFIX__VERSION_1_1_DEPRECATED{return NULL;}
*/
