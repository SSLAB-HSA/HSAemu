#include "hsa_mntor.h"
#include "hsa_helper.h"

// debug
int zdguo_debug_level = 7;
volatile int page_fault_accrued = 0;
__thread int lw_thread_id = 0; // only for debug

// normal
static QemuCond hsa_cu_cond;
static QemuCond hsa_mainthread_cond;
static QemuCond hsa_cu_mntor_cond;
static QemuMutex hsa_cu_mutex;
static QemuMutex hsa_mntor_mutex;
static QemuThread hsa_cu_mntor_thread;
static spinlock_t mnt_ready_read = SPIN_LOCK_UNLOCKED;
static spinlock_t userQ_readoffset = SPIN_LOCK_UNLOCKED;
CPUArchState *agent_env;
volatile int hsa_cus = 1;
target_ulong commdQ_addr = 0;
user_queue userQ;
volatile unsigned int cu_busy_cnt;
volatile unsigned int cu_monitor_ready;
void *kernel_entry = NULL;
void *kernel_para = NULL;
uint64_t crnt_dispatchid;
static HSACUState *all_cu_state = NULL;
__thread HSACUState *per_cu_env = NULL;
__thread int thread_type;
__thread CPUArchState *per_agent_env = NULL;

// work index
QemuMutex group_lock;
volatile dim3 itemPerGroup;
volatile dim3 groupPerGrid;
dim3 finished_groupId;
volatile size_t group_szie = 0;
volatile size_t grid_size = 0;
volatile size_t nb_group = 0;
volatile int no_group_remain = 0;
__thread dim3 per_itemId;
__thread dim3 per_groupId;

// group memory
volatile size_t group_mem_len = 0;
__thread uint8_t *per_group_mem_base = NULL;
__thread uint8_t *per_group_mem_end = NULL;

// barrier
volatile size_t currt_nb_threads = 0;
QemuMutex barr_create_mutex;
__thread lw_arg *per_lw_thread_arg = NULL;

// profile
int64_t global_tlb_miss = 0;
int64_t global_tlb_hit = 0;
int64_t global_slow_access = 0;

void hsa_set_debug_level(target_ulong level)
{
	if ((int)level == RESET_PROFILE_INFO) {
		global_tlb_hit = 0;
		global_tlb_miss = 0;
		global_slow_access = 0;
		return;
	}
	zdguo_debug_level = (int)level;
}

void zdguo_debug_print(int level, int thread_nb, const char *fmt, ...)
{
	va_list ap;
	char tmp_buf[256];

	if (level < zdguo_debug_level)
		return;
	switch (thread_nb) {
		case ZDGUO_DEBUG_THREAD_MAIN:
			fprintf(stderr, "zdguo: [main thread]");
			break;
		case ZDGUO_DEBUG_THREAD_MNTOR:
			fprintf(stderr, "zdguo: [monitor thread]");
			break;
		case ZDGUO_DEBUG_THREAD_CPU:
			fprintf(stderr, "zdguo: [CPU thread]");
			break;
		case ZDGUO_DEBUG_THREAD_CU:
		default:
			if (per_cu_env)
				fprintf(stderr, "zdguo: [cu thread %d]", per_cu_env->thread_id);
			else
				fprintf(stderr, "zdguo: [unknown thread]");
			break;
	}

	va_start(ap, fmt);
	vsprintf(tmp_buf, fmt, ap);
	fprintf(stderr, "%s", tmp_buf);
	va_end(ap);
}
static void zdguo_profile_print(uint64_t exe, uint64_t total)
{
	double rtime, exet;
	
	if (ZDGUO_LEVEL_PRO_H < zdguo_debug_level)
		return;

	exet = (double)exe / 1000000000L;
	rtime = (double)total / 1000000000L;

	fprintf(stderr, "zdguo: kernel execution profiling info: ========\n");
	if (ZDGUO_LEVEL_PRO_L >= zdguo_debug_level) {
		fprintf(stderr, "          cu     total(s)    loop(s)   kernel(s) per_kernel(ns)\n");
		int i;
		for(i=0; i<hsa_cus; i++) {
			HSACUState *env = &all_cu_state[i];
			fprintf(stderr, "     %4d %10.5lf %10.5lf %10.5lf     %ld\n",
					env->thread_id,
					(double)(env->cu_prof.cu_end - env->cu_prof.cu_begin) / 1000000000L,
					(double)(env->cu_prof.cu_loop_ed - env->cu_prof.cu_loop_st) / 1000000000L,
					(double)(env->cu_prof.cu_kernel) / 1000000000L,
					env->cu_prof.per_kernel);
		}

		fprintf(stderr, "    tlb miss    tlb hit    slow access\n");
		int64_t total_miss = 0, total_hit = 0, total_slow = 0;

		for(i=0; i<hsa_cus; i++) {
			HSACUState *env = &all_cu_state[i];
			fprintf(stderr, "    %4ld        %4ld       %4ld\n",
					env->cu_prof.tlb_miss,
					env->cu_prof.tlb_hit,
					env->cu_prof.slow_access);
			total_miss += env->cu_prof.tlb_miss;
			total_hit  += env->cu_prof.tlb_hit;
			total_slow += env->cu_prof.slow_access;
		}
		fprintf(stderr, "total: tlb miss: %4ld, tlb hit: %4ld, slow access: %4ld\n", 
			total_miss, total_hit, total_slow);

		global_tlb_miss += total_miss;
		global_tlb_hit  += total_hit;
		global_slow_access += total_slow;

		fprintf(stderr, "accumulation: tlb miss: %4ld, tlb hit: %4ld, slow access: %4ld\n", 
			global_tlb_miss, global_tlb_hit, global_slow_access);
	}
	fprintf(stderr, "zdguo: kernel execution total time: %lf, with %d CUs\n", rtime, hsa_cus);
}

static int hsa_get_work(void)
{
	qemu_mutex_lock(&group_lock);
	if (no_group_remain) {
		qemu_mutex_unlock(&group_lock);
		return 0;
	}
	
	SET_WORK_ID(&per_groupId, &finished_groupId);
	// update ID
	if ((finished_groupId.dim[0]+1) < groupPerGrid.dim[0]) {
		finished_groupId.dim[0]++;
	} else if ((finished_groupId.dim[1]+1) < groupPerGrid.dim[1]) {
		finished_groupId.dim[0] = 0;
		finished_groupId.dim[1]++;
	} else if ((finished_groupId.dim[2]+1) < groupPerGrid.dim[2]) {
		finished_groupId.dim[0] = 0;
		finished_groupId.dim[1] = 0;
		finished_groupId.dim[2]++;
	} else {
		// the last workgroup
		no_group_remain = 1;
	}

	// debug
	//fprintf(stderr, "CU %d, get group:(%u, %u, %u)\n",
	//	per_cu_env->thread_id,
	//	per_groupId.dim[0], per_groupId.dim[1], per_groupId.dim[2]);
	qemu_mutex_unlock(&group_lock);
	return 1;
}

static void hsa_block_signal(void)
{
	sigset_t set;

	sigemptyset(&set);
	sigaddset(&set, SIG_IPI);
	sigaddset(&set, SIGIO);
	sigaddset(&set, SIGALRM);
	sigaddset(&set, SIGBUS);
	pthread_sigmask(SIG_BLOCK, &set, NULL);
}
static void hsa_cu_resume_mntor(HSACUState *env){
	
	qemu_mutex_lock(env->hsa_mutex);

	cu_busy_cnt--;
	if (cu_busy_cnt == 0) {
		// last one CU wakeup mnotr
		qemu_cond_signal(&hsa_cu_mntor_cond);
	}

	env->stopped = 1;
	while (env->stopped) {
		qemu_cond_wait(env->halt_cond, env->hsa_mutex);
	}
	// every CU use "hsa_mutex" by turns
	qemu_mutex_unlock(env->hsa_mutex);	
}

#define FOR_EACH_DIM(idx, dim_t, size) \
	for((idx).dim[(dim_t)]=0; \
		(idx).dim[(dim_t)]<itemPerGroup.dim[(dim_t)]; \
		(idx).dim[(dim_t)]++)

#define FOR_EACH_DIM3(idx, size) \
	FOR_EACH_DIM((idx), 2, (size)) \
		FOR_EACH_DIM((idx), 1, (size)) \
			FOR_EACH_DIM((idx), 0, (size))

static void *hsa_cu_thread_fn(void *arg)
{
	thread_type = CU_TH;
	HSACUState *env = (HSACUState*)arg;
	int ret;
	uint64_t tmp_begin, tmp_end, cnt;

	hsa_block_signal();
	qemu_thread_get_self(env->thread);
	env->thread_id = qemu_get_thread_id();
	env->created = 1;
	per_cu_env = env;
	per_agent_env = (CPUArchState*)malloc(sizeof(CPUArchState));
	MEM_ALLOC_CHECK(per_agent_env, "per_agent_env\n");
	hsa_cu_resume_mntor(env);

	while (1) {
		memset(&(env->cu_prof), 0, sizeof(env->cu_prof));
		env->cu_prof.cu_begin = get_clock();
		per_group_mem_base = (uint8_t*)calloc(1, group_mem_len);
		// "per_group_mem_end" no used currently
		per_group_mem_end = per_group_mem_base + group_mem_len;
		memcpy(per_agent_env, agent_env, sizeof(CPUArchState));

		ret = hsa_get_work();
		env->reset_lw_flag = 1;
		env->cu_prof.cu_loop_st = get_clock();
		cnt = 0;
		while (kernel_entry && ret > 0 && !page_fault_accrued) {
			
			FOR_EACH_DIM3(per_itemId, itemPerGroup) {
				tmp_begin = get_clock();
				// debug
				//fprintf(stderr, "CU %d, item id:(%u, %u, %u)\n",
				//	env->thread_id,
				//	per_itemId.dim[0], per_itemId.dim[1], per_itemId.dim[2]);
				((void (*)(void *))kernel_entry)(kernel_para);

				tmp_end = get_clock();
				env->cu_prof.cu_kernel += (tmp_end - tmp_begin);
				cnt++;
				if (env->lw_thread_created == LW_THREAD_CREATED) {
					goto ONE_GROUP_DONE;
				}
			}
ONE_GROUP_DONE:			
			ret = hsa_get_work(); //scheduler 1
			env->reset_lw_flag = 1;
		}
		env->cu_prof.cu_loop_ed = get_clock();
		if (cnt)
			env->cu_prof.per_kernel = env->cu_prof.cu_kernel / cnt;
		
		// clean up lw thread
		if (env->lw_thread_created == LW_THREAD_CREATED) {
			// setting lw var
			env->lw_has_work = 0;
			int barr_cnt = env->barrier_count;
			pthread_barrier_wait(&(env->hsa_barrier));
	
			int i;
			for (i=0; i<(barr_cnt-1); i++)
				qemu_thread_join(&(env->lw_thread[i]));
			
			pthread_barrier_destroy(&(env->hsa_barrier));
			env->lw_thread_created = LW_THREAD_NOT_CREATED;
			env->barrier_count = 0;
			if (env->lw_thread) {
				free(env->lw_thread);
				env->lw_thread = NULL;
			}
			if (per_lw_thread_arg) {
				free(per_lw_thread_arg);
				per_lw_thread_arg = NULL;
			}

			qemu_mutex_lock(&barr_create_mutex);
			currt_nb_threads -= group_szie;
			qemu_mutex_unlock(&barr_create_mutex);
		}

		// clean up group memory
		if (per_group_mem_base) {
			free(per_group_mem_base);
			per_group_mem_base = NULL;
		}
		env->cu_prof.cu_end = get_clock();
		hsa_cu_resume_mntor(env);
	}

	return NULL;
}

void hsa_global_init(void)
{
	qemu_cond_init(&hsa_mainthread_cond);
	qemu_cond_init(&hsa_cu_mntor_cond);
	qemu_cond_init(&hsa_cu_cond);
	qemu_mutex_init(&hsa_cu_mutex);
	qemu_mutex_init(&hsa_mntor_mutex);
	qemu_mutex_init(&barr_create_mutex);
	qemu_mutex_init(&group_lock);

	agent_env = (CPUArchState*)malloc(sizeof(CPUArchState));
	MEM_ALLOC_CHECK(agent_env, "agent_env");
}

static void hsa_main_resume_mntor(void)
{
	while(qemu_mutex_trylock(&hsa_mntor_mutex) == 0) {
		cu_monitor_ready = 0;
		qemu_cond_signal(&hsa_mainthread_cond);
		qemu_mutex_unlock(&hsa_mntor_mutex);
	}

	return;
}
size_t hsa_copy_to_guest(CPUArchState *env,
							 target_ulong dst,
							 void *src,
							 const size_t size)
{
	uintptr_t phy_addr;
	size_t valid_length, left_size = size;
	target_ulong current_dst = dst;
	void *current_src = src;

	while ((left_size > 0) && !page_fault_accrued) {
		phy_addr = get_phyaddr(env, current_dst, MMU_USER_IDX);

		if (phy_addr) {
			valid_length = TARGET_PAGE_SIZE - (phy_addr & ~TARGET_PAGE_MASK);
			if (valid_length > left_size) valid_length = left_size;
			memcpy((void *)phy_addr, current_src, valid_length);
			current_dst += valid_length;
			current_src += valid_length;
			left_size -= valid_length;
		}
	}
	
	if(left_size){
		HSA_DEBUG_LOG("copy from guest fault\n");
		exit(-1);
	}
	
	return (size - left_size);
}

size_t hsa_copy_from_guest(CPUArchState *env,
							 void *dest,
							 target_ulong src,
							 const size_t size)
{
	uintptr_t phy_addr;
	size_t valid_length, left_size = size;
	target_ulong src_current = src;
	void *dest_current = dest;

	while ((left_size > 0) && !page_fault_accrued) {
		phy_addr = get_phyaddr(env, src_current, MMU_USER_IDX);

		if (phy_addr) {
			valid_length = TARGET_PAGE_SIZE - (phy_addr & ~TARGET_PAGE_MASK);
			if (valid_length > left_size) valid_length = left_size;
			memcpy(dest_current, (void *)phy_addr, valid_length);
			dest_current += valid_length;
			left_size -= valid_length;
			src_current += valid_length;
		}
	}
	
	if(left_size){
		HSA_DEBUG_LOG("copy from guest fault\n");
		exit(-1);
	}
	
	return (size - left_size);
}

int hsa_set_agent_addr(CPUArchState *_env, target_ulong _para_addr)
{
	int ret = -1;
	
	// check
	if (!_env || !_para_addr) {
		HSA_DEBUG_LOG("useQ is NULL");
		return ret;
	}

	hsa_spin_lock(&mnt_ready_read);
	if (cu_monitor_ready) {
		// take the snapshot of current env */
		memcpy(agent_env, _env, sizeof(CPUArchState));
		commdQ_addr = _para_addr;
		hsa_spin_lock(&userQ_readoffset);
		hsa_copy_from_guest(agent_env, &userQ, commdQ_addr, sizeof(user_queue));
		hsa_spin_unlock(&userQ_readoffset);
		hsa_main_resume_mntor();
		ret = 0;
	}
	else {
		/* zdguo: monitor thread not ready yet, 
		   means that there is still check point for the unfinished job,
		   so the new dispatched job is wared by the monitor */
		/* zdguo: sinec the GPU still has work to do, the new coming job should
		   in the same command queue. */
		if (commdQ_addr == _para_addr) {
			hsa_spin_lock(&userQ_readoffset);
			hsa_copy_from_guest(agent_env, &userQ, commdQ_addr, sizeof(user_queue));
			hsa_spin_unlock(&userQ_readoffset);
			ret = 0;
		}

	}
	hsa_spin_unlock(&mnt_ready_read);

	return ret;
}

void hsa_init_cu_thread(void *_env)
{
	HSACUState *env = _env;

	zdguo_debug_print(ZDGUO_LEVEL_DEBUG,
			ZDGUO_DEBUG_THREAD_MNTOR, 
			"<hsa_init_cu_thread> before thread create\n");

	env->nr_cores = hsa_cus;
	env->halt_cond = &hsa_cu_cond;
	env->hsa_mutex = &hsa_cu_mutex;
	env->thread = g_malloc0(sizeof(QemuThread));
	env->lw_thread_created = LW_THREAD_NOT_CREATED;
	qemu_thread_create(env->thread, hsa_cu_thread_fn, env,
			QEMU_THREAD_JOINABLE);

	qemu_mutex_init(&(env->cu_prof.tlb_hit_mutex));
	qemu_mutex_init(&(env->cu_prof.tlb_miss_mutex));
	qemu_mutex_init(&(env->cu_prof.slow_access_mutex));
}

static void hsa_mntor_init_all_cu(const char *cu_model)
{
	size_t all_cu_state_len = hsa_cus * sizeof(HSACUState);
	all_cu_state = malloc(all_cu_state_len);
	MEM_ALLOC_CHECK(all_cu_state, "all_cu_state\n");
	memset(all_cu_state, 0, all_cu_state_len);

	cu_busy_cnt = hsa_cus;
	int i;
	for (i=0; i<hsa_cus; i++) {
		if( (i+1) != hsa_cus ) {
			all_cu_state[i].next_cpu = &all_cu_state[i+1];
		}
		hsa_init_cu_thread(&all_cu_state[i]);
	}
	
	hsa_mntor_resume_cus();

	zdguo_debug_print(ZDGUO_LEVEL_DEBUG, 
			ZDGUO_DEBUG_THREAD_MNTOR,
			"<hsa_vgpu_init> waken up by cu thread.\n");
}

void hsa_mntor_resume_cus(void)
{
	// reset CUs state
	int i = 0;
	for(i=0; i<hsa_cus; i++){
		all_cu_state[i].stopped = 0;
	}

	// wait all CUs 
	cu_busy_cnt = hsa_cus;	
	qemu_cond_broadcast(&hsa_cu_cond);
	while (cu_busy_cnt > 0) {
		qemu_cond_wait(&hsa_cu_mntor_cond, &hsa_cu_mutex);
	}	
}

static void hsa_setgvals(hsa_aql *aqlp)
{
	itemPerGroup.dim[0] = aqlp->workgroupSize_x;
	itemPerGroup.dim[1] = aqlp->workgroupSize_y;
	itemPerGroup.dim[2] = aqlp->workgroupSize_z;

	group_szie = itemPerGroup.dim[0] *
		itemPerGroup.dim[1] * itemPerGroup.dim[2];

	groupPerGrid.dim[0] = aqlp->gridSize_x / itemPerGroup.dim[0];
	groupPerGrid.dim[1] = aqlp->gridSize_y / itemPerGroup.dim[1];
	groupPerGrid.dim[2] = aqlp->gridSize_z / itemPerGroup.dim[2];

	grid_size = aqlp->gridSize_x * 
		aqlp->gridSize_y * aqlp->gridSize_z;

	nb_group = groupPerGrid.dim[0] *
		groupPerGrid.dim[1] * groupPerGrid.dim[2];

	// debug
	//fprintf(stderr, "groupPerGrid:(%u, %u, %u) itemPerGroup:(%u, %u, %u)\n",
	//	groupPerGrid.dim[0], groupPerGrid.dim[1], groupPerGrid.dim[2],
	//	itemPerGroup.dim[0], itemPerGroup.dim[1], itemPerGroup.dim[2]);

	finished_groupId.dim[0] = 0;
	finished_groupId.dim[1] = 0;
	finished_groupId.dim[2] = 0;
	no_group_remain = 0;

	currt_nb_threads = 0;
	
	crnt_dispatchid = aqlp->dispatchId;
	page_fault_accrued = 0;
	kernel_entry = NULL;
	if (kernel_para) {
		free(kernel_para);
		kernel_para = NULL;
	}	
}
static size_t hsa_get_kernobj_size(target_ulong knlobj_addr)
{
	size_t last_sec_offset = (target_ulong)load_32(knlobj_addr + 20);
	//size_t last_sec_size = (size_t)load_16(knlobj_addr + last_sec_offset);

	return last_sec_offset;
}

static void *hsa_prepare_code_cache(hsa_aql *aqlp)
{
	target_ulong kernobj_addr = (target_ulong)aqlp->kernelObjectAddress;
	target_ulong kernarg_addr = (target_ulong)aqlp->kernargAddress;
	size_t kernarg_len = aqlp->workitemArgSegmentSizeBytes;
	group_mem_len = aqlp->workgroupGroupSegmentSizeBytes;
	void *brig_buf = NULL;
	void *kernarg_buf = NULL;
	void *currt_kernentry = NULL;

	// check
	if (!aqlp->gridSize_x || !aqlp->workgroupSize_x ||
		!aqlp->gridSize_y || !aqlp->workgroupSize_y ||
		!aqlp->gridSize_z || !aqlp->workgroupSize_z ) {
		HSA_DEBUG_LOG("invaild work-dim\n");
		return NULL;
	}
	// setting global variables
	hsa_setgvals(aqlp);

	// object cache
	static target_ulong prev_kernobj_addr = 0;
	static void *prev_kernentry = NULL;
	if (prev_kernobj_addr != kernobj_addr)	{
		prev_kernobj_addr = kernobj_addr;
	}else{
		currt_kernentry = prev_kernentry;
		goto LOAD_KERARG;
	}

	// load brig 
	size_t kernobj_len = hsa_get_kernobj_size(kernobj_addr);

	if (!kernobj_len) {
		HSA_DEBUG_LOG("invaild kernel object file\n");
		return NULL;
	}

	brig_buf = malloc(kernobj_len);
	MEM_ALLOC_CHECK(brig_buf, "brig_buf\n");

	hsa_copy_from_guest(agent_env, brig_buf, kernobj_addr, kernobj_len);
	char *file_name;	
	file_name = (char *)malloc(sizeof(char)*20);

	// convert birg to object file
	HConvert((unsigned char *)brig_buf, kernobj_len, file_name);
	// link-loader
	currt_kernentry = cc_producer(file_name);
	// update kernel entry
	prev_kernentry = currt_kernentry;

LOAD_KERARG:
	// load kernel arg 
	kernarg_buf = malloc(kernarg_len);
	MEM_ALLOC_CHECK(kernarg_buf, "kernarg_buf\n");
	hsa_copy_from_guest(agent_env, kernarg_buf, kernarg_addr, kernarg_len);
	kernel_para = kernarg_buf;

	// clean up
	if(brig_buf) free(brig_buf);
	remove(file_name); // does it have to do ?
	return currt_kernentry;
}
static void *hsa_mntor_thread_fn(void *cu_model)
{
	hsa_aql aql;
	completionobject compleobj;
	target_ulong aql_ptr;
	thread_type = MNTOR;

	memset(&compleobj, 0, sizeof(compleobj));
	hsa_block_signal();
	// create and init all cu threads	
	qemu_mutex_lock(&hsa_cu_mutex);
	hsa_mntor_init_all_cu((const char *)cu_model);
	// wake up QEMU
	qemu_mutex_lock(&hsa_mntor_mutex);
	cu_monitor_ready = 1;
	qemu_cond_signal(&hsa_mainthread_cond);

	while (1) {
		/* zdguo: cu monitor thread main loop */
		while (cu_monitor_ready) {
			/* zdguo: waiting for new job */
			qemu_cond_wait(&hsa_mainthread_cond, &hsa_mntor_mutex);
		}

		if (userQ.readOffset != userQ.writeOffset) {
			compleobj.parseTimeStamp = get_clock();
			aql_ptr = (target_ulong)(userQ.basePointer + userQ.readOffset);
			hsa_copy_from_guest(agent_env, &aql, aql_ptr, sizeof(hsa_aql));
			hsa_copy_from_guest(agent_env, &compleobj, 
				(target_ulong)aql.completionObjectAddress, sizeof(compleobj));
			
			if (compleobj.status != 0) {
				HSA_DEBUG_LOG("invalid AQL\n");
				break;
			}
			
			kernel_entry = hsa_prepare_code_cache(&aql);
			if(kernel_entry){
				compleobj.dispatchTimeStamp = get_clock();
				hsa_mntor_resume_cus();
				compleobj.completionTimeStamp = get_clock();
				compleobj.status = 1;
				zdguo_profile_print(compleobj.completionTimeStamp - compleobj.parseTimeStamp, 
					compleobj.completionTimeStamp - compleobj.dispatchTimeStamp);
			}else{
				HSA_DEBUG_LOG("kernel entry is NULL\n");
			}

			/* zdguo: write back to the user mode queue */
			hsa_copy_to_guest(agent_env, (target_ulong)aql.completionObjectAddress,
				&compleobj, sizeof(compleobj));
		}

		// job finished, ready again
		hsa_spin_lock(&mnt_ready_read);
		cu_monitor_ready = 1;
		commdQ_addr = 0;
		hsa_spin_unlock(&mnt_ready_read);
	}

	return NULL;
}

void hsa_init_mntor(int hsa_cus, const char *cpu_model)
{
	qemu_mutex_lock(&hsa_mntor_mutex);
	cu_monitor_ready = 0;

	qemu_thread_create(&hsa_cu_mntor_thread, hsa_mntor_thread_fn, (void *)cpu_model,
			QEMU_THREAD_JOINABLE);

	while (!cu_monitor_ready) {
		/* zdguo: wait for all cu threads to be created */
		qemu_cond_wait(&hsa_mainthread_cond, &hsa_mntor_mutex);
	}

	qemu_mutex_unlock(&hsa_mntor_mutex);
}
static void *hsa_lw_thread_fn(void *arg)
{
	thread_type = LW_TH;
	lw_thread_id = qemu_get_thread_id();// debug
	lw_arg *thread_arg = (lw_arg *)arg;
	per_cu_env = thread_arg->cu_env;	
	// debug
	//printf("lw thread %d barr(lw_thread_fn)\n", lw_thread_id);

	// wait "hsa_prepare_lw_thread" init thread_arg
	pthread_barrier_wait(&(per_cu_env->hsa_barrier));
	per_agent_env = thread_arg->cpu_env;
	per_group_mem_base = thread_arg->group_mem_base;
		
	while (per_cu_env->lw_has_work) {
		//SET_WORK_ID(&(per_currt_global_id), &(thread_arg->gid));
		SET_WORK_ID(&per_groupId, &(thread_arg->groupId));
		SET_WORK_ID(&per_itemId, &(thread_arg->itemId));
		per_cu_env = thread_arg->cu_env;

		((void (*)(void *))kernel_entry)(kernel_para);

		//fprintf(stderr, "lw thread %d barr(finish kernel)\n", lw_thread_id);
		pthread_barrier_wait(&(per_cu_env->hsa_barrier));
	}

	return NULL;
}
#define BARRIER_LIMIT 800
int hsa_create_lw_thread(HSACUState *env)
{
	// check
	int barr_cnt = group_szie;
	if (barr_cnt <= 1) {
		fprintf(stderr, "barrier_cnt less than 2\n");
		return -1;
	}

REDO_BARR_CHECK:
	qemu_mutex_lock(&barr_create_mutex);
	if ((currt_nb_threads + group_szie) <= BARRIER_LIMIT) {
		currt_nb_threads += group_szie;
		qemu_mutex_unlock(&barr_create_mutex);
	} else {
		qemu_mutex_unlock(&barr_create_mutex);
		while((currt_nb_threads + group_szie) > BARRIER_LIMIT);
		goto REDO_BARR_CHECK;
	}
	
	// init
	int ret = pthread_barrier_init(&(env->hsa_barrier), NULL, barr_cnt);
	if (ret) {
		fprintf(stderr, "can't init barrier\n");
		return -1;
	}

	QemuThread *lw_thread = (QemuThread*)malloc(sizeof(QemuThread) * (barr_cnt - 1));
	MEM_ALLOC_CHECK(lw_thread, "lw_thread\n");

	lw_arg *lw_thread_arg = (lw_arg*)malloc(sizeof(lw_arg) * (barr_cnt - 1));
	MEM_ALLOC_CHECK(lw_thread_arg, "lw_arg\n");

	//setting env
	env->barrier_count = barr_cnt;
	env->lw_thread = lw_thread;
	per_lw_thread_arg = lw_thread_arg;
	env->lw_has_work = 1;

	int i = 0;
	for (i=0; i<(barr_cnt-1); i++) {
		// lw get barrier first
		lw_thread_arg[i].cu_env = env;
		qemu_thread_create(&lw_thread[i], hsa_lw_thread_fn,
			&lw_thread_arg[i], QEMU_THREAD_JOINABLE);
	}

	return 0;
}

void hsa_prepare_lw_thread(HSACUState *env)
{
	int cnt = 0;
	int begin = 0;
	dim3 tmpitemId;
	FOR_EACH_DIM3(tmpitemId, itemPerGroup){
		if (unlikely(!begin)) {
			if (tmpitemId.dim[2] == per_itemId.dim[2] && 
				tmpitemId.dim[1] == per_itemId.dim[1] &&
				tmpitemId.dim[0] == per_itemId.dim[0])
				begin = 1;
			continue;
		}
		SET_WORK_ID(&(per_lw_thread_arg[cnt].groupId), &per_groupId);
		SET_WORK_ID(&(per_lw_thread_arg[cnt].itemId), &tmpitemId);
		per_lw_thread_arg[cnt].cpu_env = per_agent_env;
		per_lw_thread_arg[cnt].group_mem_base = per_group_mem_base;
		per_lw_thread_arg[cnt].cu_env = env;
		cnt++;
	}

	//fprintf(stderr, "CU thread %d barr(prepare_lw)\n",
	//	per_cu_env->thread_id);
	// lw thread can begin to execute
	pthread_barrier_wait(&(env->hsa_barrier));
}
