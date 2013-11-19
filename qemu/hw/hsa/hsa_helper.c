#include "hsa_helper.h"

static int hsa_tlb_fill(CPUARMState *env, 
		target_ulong addr, 
		int is_write, 
		int mmu_idx)
{
	int ret;

	ret = cpu_arm_handle_mmu_fault(env, addr, is_write, mmu_idx);

	if (unlikely(ret)) {
		HSA_DEBUG_LOG("page fault\n");
		while(1);
	}
	return ret;
}

#define GROUP_MEM_CHECK_LD(addr, len) \
	if((addr) > (len)){ \
		HSA_DEBUG_LOG("invaild group memory load\n"); \
		return 0; \
	}

#define GROUP_MEM_CHECK_ST(addr, len) \
	if((addr) > (len)){ \
		HSA_DEBUG_LOG("invaild group memory store\n"); \
		return; \
	}
uint8_t group_load_8(target_ulong addr)
{
	GROUP_MEM_CHECK_LD(addr, group_mem_len);
	uint8_t *ptr = (uint8_t*)(per_group_mem_base + addr);
	return (*ptr);
}
void group_store_8(target_ulong addr, uint8_t val)
{
	GROUP_MEM_CHECK_ST(addr, group_mem_len);
	uint8_t *ptr = (uint8_t*)(per_group_mem_base + addr);
	*ptr = val;
}
uint16_t group_load_16(target_ulong addr){
	GROUP_MEM_CHECK_LD(addr, group_mem_len);
	uint16_t *ptr = (uint16_t*)(per_group_mem_base + addr);
	return (*ptr);	
}
void group_store_16(target_ulong addr, uint16_t val)
{
	GROUP_MEM_CHECK_ST(addr, group_mem_len);
	uint16_t *ptr = (uint16_t*)(per_group_mem_base + addr);
	*ptr = val;
}
uint32_t group_load_32(target_ulong addr)
{
	GROUP_MEM_CHECK_LD(addr, group_mem_len);
	uint32_t *ptr = (uint32_t*)(per_group_mem_base + addr);
	return (*ptr);
}
void group_store_32(target_ulong addr, uint32_t val)
{
	GROUP_MEM_CHECK_ST(addr, group_mem_len);
	uint32_t *ptr = (uint32_t*)(per_group_mem_base + addr);
	*ptr = val;

}
uint64_t group_load_64(target_ulong addr)
{
	GROUP_MEM_CHECK_LD(addr, group_mem_len);
	uint64_t *ptr = (uint64_t*)(per_group_mem_base + addr);
	return (*ptr);
}
void group_store_64(target_ulong addr, uint64_t val)
{
	GROUP_MEM_CHECK_ST(addr, group_mem_len);
	uint64_t *ptr = (uint64_t*)(per_group_mem_base + addr);
	*ptr = val;
}
#define GLOBAL_MEM_CHECK_LD(addr) \
	if((addr) == 0) { \
		page_fault_accrued = 1; \
		HSA_DEBUG_LOG("invalid global memory load\n"); \
		return 0; \
	}

#define GLOBAL_MEM_CHECK_ST(addr) \
	if((addr) == 0) { \
		page_fault_accrued = 1; \
		HSA_DEBUG_LOG("invalid global memory store\n"); \
		return; \
	}

#define PROFILE_MMU(env, flag, flag_mutex) \
	if (env) { \
		qemu_mutex_lock(&(env->cu_prof.flag_mutex)); \
		env->cu_prof.flag++; \
		qemu_mutex_unlock(&(env->cu_prof.flag_mutex)); \
	}

uint8_t load_8(target_ulong addr)
{
	uint8_t res = 0;
	int index, mmu_idx = MMU_USER_IDX;
	target_ulong tlb_addr;
	CPUArchState *env = ((per_agent_env != NULL) ? per_agent_env:agent_env);

	GLOBAL_MEM_CHECK_LD(addr);

	/* test if there is match for unaligned or IO access */
	/* XXX: could done more in memory macro in a non portable way */
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<test_helper_ld> raice a IO access\n");
			return -1;
		} else {
			/* unaligned/aligned access in the same page */
			uintptr_t addend;
			addend = env->tlb_table[mmu_idx][index].addend;
			res = ldub_raw((uint8_t *)(intptr_t)(addr + addend));
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 0/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
	return res;
}

void store_8(target_ulong addr, uint8_t val)
{
	int index, mmu_idx = MMU_USER_IDX;
	target_ulong tlb_addr;
	CPUArchState *env = ((per_agent_env != NULL) ? per_agent_env:agent_env);

	GLOBAL_MEM_CHECK_ST(addr);

	/* test if there is match for unaligned or IO access */
	/* XXX: could done more in memory macro in a non portable way */
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<store_32> raice a IO access\n");
			return;
		} else {
			/* unaligned/aligned access in the same page */
			uintptr_t addend;
			addend = env->tlb_table[mmu_idx][index].addend;
			stb_raw((uint8_t *)(intptr_t)(addr + addend), val);
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 1/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
	return;
}

static uint16_t load_16_slow(CPUArchState *env, target_ulong addr, int mmu_idx)
{
	uint16_t res = 0, res1, res2;
	int index, shift;
	target_ulong tlb_addr, addr1, addr2;

	if (per_cu_env && page_fault_accrued)
		return 0;

	zdguo_debug_print(ZDGUO_LEVEL_DEBUG,
			ZDGUO_DEBUG_THREAD_CU,
			"<test_helper_slow_ld> beginning\n");
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<test_helper_slow_ld> raice a IO access\n");
		} else if (((addr & ~TARGET_PAGE_MASK) + sizeof(uint16_t) - 1) >= TARGET_PAGE_SIZE) {
			addr1 = addr & ~(sizeof(uint16_t) - 1);
			addr2 = addr1 + sizeof(uint16_t);
			res1 = load_16_slow(env, addr1, mmu_idx);
			res2 = load_16_slow(env, addr2, mmu_idx);
			shift = (addr & (sizeof(uint16_t) - 1)) * 8;
#ifdef TARGET_WORDS_BIGENDIAN
			res = (res1 << shift) | (res2 >> ((sizeof(uint16_t) * 8) - shift));
#else
			res = (res1 >> shift) | (res2 << ((sizeof(uint16_t) * 8) - shift));
#endif
			res = (uint16_t)res;
		} else {
			/* unaligned/aligned access in the same page */
			uintptr_t addend = env->tlb_table[mmu_idx][index].addend;
			res = lduw_raw((uint8_t *)(intptr_t)(addr + addend));
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 0/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
	return res;
}

uint16_t load_16(target_ulong addr)
{
	uint16_t res = 0;
	int index, mmu_idx = MMU_USER_IDX;
	target_ulong tlb_addr;
	CPUArchState *env = ((per_agent_env != NULL) ? per_agent_env:agent_env);

	GLOBAL_MEM_CHECK_LD(addr);

	/* test if there is match for unaligned or IO access */
	/* XXX: could done more in memory macro in a non portable way */
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<test_helper_ld> raice a IO access\n");
			return -1;
		} else if (((addr & ~TARGET_PAGE_MASK) + sizeof(uint16_t) - 1) >= TARGET_PAGE_SIZE) {
			/* slow unaligned access (it spans two pages or IO) */
			res = load_16_slow(env, addr, mmu_idx);
		} else {
			/* unaligned/aligned access in the same page */
			uintptr_t addend;
			addend = env->tlb_table[mmu_idx][index].addend;
			res = lduw_raw((uint8_t *)(intptr_t)(addr + addend));
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 0/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
	return res;
}

static void store_16_slow(CPUArchState *env, target_ulong addr, uint16_t val, int mmu_idx)
{
	target_ulong tlb_addr;
	int index, i;

	if (per_cu_env && page_fault_accrued)
		return;

	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			/* IO access */
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<store_32_slow> raice a IO access\n");
			return;
		} else if (((addr & ~TARGET_PAGE_MASK) + sizeof(uint16_t) - 1) >= TARGET_PAGE_SIZE) {
			/* XXX: not efficient, but simple */
			/* Note: relies on the fact that tlb_fill() does not remove the
			 * previous page from the TLB cache.  */
			for(i = sizeof(uint16_t) - 1; i >= 0; i--) {
#ifdef TARGET_WORDS_BIGENDIAN
				store_8(addr + i, val >> (((sizeof(uint16_t) - 1) * 8) - (i * 8)));
#else
				store_8(addr + i, val >> (i * 8));
#endif
			}
			zdguo_debug_print(ZDGUO_LEVEL_INFO,
					ZDGUO_DEBUG_THREAD_CU,
					"<store_32_slow> unaligned access\n");
			return;
		} else {
			/* aligned/unaligned access in the same page */
			uintptr_t addend = env->tlb_table[mmu_idx][index].addend;
			stw_raw((uint8_t *)(intptr_t)(addr + addend), val);
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 1/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
}


void store_16(target_ulong addr, uint16_t val)
{
	int index, mmu_idx = MMU_USER_IDX;
	target_ulong tlb_addr;
	CPUArchState *env = ((per_agent_env != NULL) ? per_agent_env:agent_env);

	GLOBAL_MEM_CHECK_ST(addr);

	/* test if there is match for unaligned or IO access */
	/* XXX: could done more in memory macro in a non portable way */
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<store_32> raice a IO access\n");
			return;
		} else if (((addr & ~TARGET_PAGE_MASK) + sizeof(uint16_t) - 1) >= TARGET_PAGE_SIZE) {
			/* slow unaligned access (it spans two pages or IO) */
			store_16_slow(env, addr, val, mmu_idx);
		} else {
			/* unaligned/aligned access in the same page */
			uintptr_t addend;
			addend = env->tlb_table[mmu_idx][index].addend;
			stw_raw((uint8_t *)(intptr_t)(addr + addend), val);
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 1/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
	return;
}

static uint32_t load_32_slow(CPUArchState *env, target_ulong addr, int mmu_idx)
{
	uint32_t res = 0, res1, res2;
	int index, shift;
	target_ulong tlb_addr, addr1, addr2;

	if (per_cu_env && page_fault_accrued)
		return 0;

	zdguo_debug_print(ZDGUO_LEVEL_DEBUG,
			ZDGUO_DEBUG_THREAD_CU,
			"<test_helper_slow_ld> beginning\n");
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<test_helper_slow_ld> raice a IO access\n");
		} else if (((addr & ~TARGET_PAGE_MASK) + sizeof(uint32_t) - 1) >= TARGET_PAGE_SIZE) {
			addr1 = addr & ~(sizeof(uint32_t) - 1);
			addr2 = addr1 + sizeof(uint32_t);
			res1 = load_32_slow(env, addr1, mmu_idx);
			res2 = load_32_slow(env, addr2, mmu_idx);
			shift = (addr & (sizeof(uint32_t) - 1)) * 8;
#ifdef TARGET_WORDS_BIGENDIAN
			res = (res1 << shift) | (res2 >> ((sizeof(uint32_t) * 8) - shift));
#else
			res = (res1 >> shift) | (res2 << ((sizeof(uint32_t) * 8) - shift));
#endif
			res = (uint32_t)res;
		} else {
			/* unaligned/aligned access in the same page */
			uintptr_t addend = env->tlb_table[mmu_idx][index].addend;
			res = ldl_raw((uint8_t *)(intptr_t)(addr + addend));
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 0/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
	return res;
}

uint32_t load_32(target_ulong addr)
{
	uint32_t res = 0;
	int index, mmu_idx = MMU_USER_IDX;
	target_ulong tlb_addr;
	CPUArchState *env = ((per_agent_env != NULL) ? per_agent_env:agent_env);

	GLOBAL_MEM_CHECK_LD(addr);
	
	/* test if there is match for unaligned or IO access */
	/* XXX: could done more in memory macro in a non portable way */
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		PROFILE_MMU(per_cu_env, tlb_hit, tlb_hit_mutex);
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<test_helper_ld> raice a IO access\n");
			return -1;
		} else if (((addr & ~TARGET_PAGE_MASK) + sizeof(uint32_t) - 1) >= TARGET_PAGE_SIZE) {
			/* slow unaligned access (it spans two pages or IO) */
			PROFILE_MMU(per_cu_env, slow_access, slow_access_mutex);
			res = load_32_slow(env, addr, mmu_idx);
		} else {
			/* unaligned/aligned access in the same page */
			uintptr_t addend;
			addend = env->tlb_table[mmu_idx][index].addend;
			res = ldl_raw((uint8_t *)(intptr_t)(addr + addend));
		}
	} else {
		/* the page is not in the TLB : fill it */
		// profile
		PROFILE_MMU(per_cu_env, tlb_miss, tlb_miss_mutex);
		if (0 == hsa_tlb_fill(env, addr, 0/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
	return res;
}

static void store_32_slow(CPUArchState *env, target_ulong addr, uint32_t val, int mmu_idx)
{
	target_ulong tlb_addr;
	int index, i;

	if (per_cu_env && page_fault_accrued)
		return;

	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			/* IO access */
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<store_32_slow> raice a IO access\n");
			return;
		} else if (((addr & ~TARGET_PAGE_MASK) + sizeof(uint32_t) - 1) >= TARGET_PAGE_SIZE) {
			/* XXX: not efficient, but simple */
			/* Note: relies on the fact that tlb_fill() does not remove the
			 * previous page from the TLB cache.  */
			for(i = sizeof(uint32_t) - 1; i >= 0; i--) {
#ifdef TARGET_WORDS_BIGENDIAN
				store_8(addr + i, val >> (((sizeof(uint32_t) - 1) * 8) - (i * 8)));
#else
				store_8(addr + i, val >> (i * 8));
#endif
			}
			zdguo_debug_print(ZDGUO_LEVEL_INFO,
					ZDGUO_DEBUG_THREAD_CU,
					"<store_32_slow> unaligned access\n");
			return;
		} else {
			/* aligned/unaligned access in the same page */
			uintptr_t addend = env->tlb_table[mmu_idx][index].addend;
			stl_raw((uint8_t *)(intptr_t)(addr + addend), val);
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 1/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
}

void store_32(target_ulong addr, uint32_t val)
{
	int index, mmu_idx = MMU_USER_IDX;
	target_ulong tlb_addr;
	CPUArchState *env = ((per_agent_env != NULL) ? per_agent_env:agent_env);

	GLOBAL_MEM_CHECK_ST(addr);

	/* test if there is match for unaligned or IO access */
	/* XXX: could done more in memory macro in a non portable way */
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		PROFILE_MMU(per_cu_env, tlb_hit, tlb_hit_mutex);
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<store_32> raice a IO access\n");
			return;
		} else if (((addr & ~TARGET_PAGE_MASK) + sizeof(uint32_t) - 1) >= TARGET_PAGE_SIZE) {
			/* slow unaligned access (it spans two pages or IO) */
			PROFILE_MMU(per_cu_env, slow_access, slow_access_mutex);
			store_32_slow(env, addr, val, mmu_idx);
		} else {
			/* unaligned/aligned access in the same page */
			uintptr_t addend;
			addend = env->tlb_table[mmu_idx][index].addend;
			stl_raw((uint8_t *)(intptr_t)(addr + addend), val);
		}
	} else {
		/* the page is not in the TLB : fill it */
		PROFILE_MMU(per_cu_env, tlb_miss, tlb_miss_mutex);
		if (0 == hsa_tlb_fill(env, addr, 1/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
	return;
}

static uint64_t load_64_slow(CPUArchState *env, target_ulong addr, int mmu_idx)
{
	uint64_t res = 0, res1, res2;
	int index, shift;
	target_ulong tlb_addr, addr1, addr2;

	if (per_cu_env && page_fault_accrued)
		return 0;

	zdguo_debug_print(ZDGUO_LEVEL_DEBUG,
			ZDGUO_DEBUG_THREAD_CU,
			"<test_helper_slow_ld> beginning\n");
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<test_helper_slow_ld> raice a IO access\n");
		} else if (((addr & ~TARGET_PAGE_MASK) + sizeof(uint64_t) - 1) >= TARGET_PAGE_SIZE) {
			addr1 = addr & ~(sizeof(uint64_t) - 1);
			addr2 = addr1 + sizeof(uint64_t);
			res1 = load_64_slow(env, addr1, mmu_idx);
			res2 = load_64_slow(env, addr2, mmu_idx);
			shift = (addr & (sizeof(uint64_t) - 1)) * 8;
#ifdef TARGET_WORDS_BIGENDIAN
			res = (res1 << shift) | (res2 >> ((sizeof(uint64_t) * 8) - shift));
#else
			res = (res1 >> shift) | (res2 << ((sizeof(uint64_t) * 8) - shift));
#endif
			res = (uint64_t)res;
		} else {
			/* unaligned/aligned access in the same page */
			uintptr_t addend = env->tlb_table[mmu_idx][index].addend;
			res = ldq_raw((uint8_t *)(intptr_t)(addr + addend));
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 0/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
	return res;
}

uint64_t load_64(target_ulong addr)
{
	uint64_t res = 0;
	int index, mmu_idx = MMU_USER_IDX;
	target_ulong tlb_addr;
	CPUArchState *env = ((per_agent_env != NULL) ? per_agent_env:agent_env);

	GLOBAL_MEM_CHECK_LD(addr);

	/* test if there is match for unaligned or IO access */
	/* XXX: could done more in memory macro in a non portable way */
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<test_helper_ld> raice a IO access\n");
			return -1;
		} else if (((addr & ~TARGET_PAGE_MASK) + sizeof(uint64_t) - 1) >= TARGET_PAGE_SIZE) {
			/* slow unaligned access (it spans two pages or IO) */
			res = load_64_slow(env, addr, mmu_idx);
		} else {
			/* unaligned/aligned access in the same page */
			uintptr_t addend;
			addend = env->tlb_table[mmu_idx][index].addend;
			res = ldq_raw((uint8_t *)(intptr_t)(addr + addend));
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 0/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
	return res;
}

static void store_64_slow(CPUArchState *env, target_ulong addr, uint64_t val, int mmu_idx)
{
	target_ulong tlb_addr;
	int index, i;

	if (per_cu_env && page_fault_accrued)
		return;

	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_write;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			/* IO access */
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<store_32_slow> raice a IO access\n");
			return;
		} else if (((addr & ~TARGET_PAGE_MASK) + sizeof(uint64_t) - 1) >= TARGET_PAGE_SIZE) {
			/* XXX: not efficient, but simple */
			/* Note: relies on the fact that tlb_fill() does not remove the
			 * previous page from the TLB cache.  */
			for(i = sizeof(uint64_t) - 1; i >= 0; i--) {
#ifdef TARGET_WORDS_BIGENDIAN
				store_8(addr + i, val >> (((sizeof(uint64_t) - 1) * 8) - (i * 8)));
#else
				store_8(addr + i, val >> (i * 8));
#endif
			}
			zdguo_debug_print(ZDGUO_LEVEL_INFO,
					ZDGUO_DEBUG_THREAD_CU,
					"<store_32_slow> unaligned access\n");
			return;
		} else {
			/* aligned/unaligned access in the same page */
			uintptr_t addend = env->tlb_table[mmu_idx][index].addend;
			stq_raw((uint8_t *)(intptr_t)(addr + addend), val);
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 1/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
}


void store_64(target_ulong addr, uint64_t val)
{
	int index, mmu_idx = MMU_USER_IDX;
	target_ulong tlb_addr;
	CPUArchState *env = ((per_agent_env != NULL) ? per_agent_env:agent_env);

	GLOBAL_MEM_CHECK_ST(addr);

	/* test if there is match for unaligned or IO access */
	/* XXX: could done more in memory macro in a non portable way */
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_CU,
					"<store_32> raice a IO access\n");
			return;
		} else if (((addr & ~TARGET_PAGE_MASK) + sizeof(uint64_t) - 1) >= TARGET_PAGE_SIZE) {
			/* slow unaligned access (it spans two pages or IO) */
			store_64_slow(env, addr, val, mmu_idx);
		} else {
			/* unaligned/aligned access in the same page */
			uintptr_t addend;
			addend = env->tlb_table[mmu_idx][index].addend;
			stq_raw((uint8_t *)(intptr_t)(addr + addend), val);
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 1/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
	return;
}

uintptr_t get_phyaddr(CPUArchState *env, target_ulong addr, int mmu_idx)
{
	uintptr_t res = 0;
	int index;
	target_ulong tlb_addr;

	GLOBAL_MEM_CHECK_LD(addr);

	/* test if there is match for unaligned or IO access */
	/* XXX: could done more in memory macro in a non portable way */
	index = (addr >> TARGET_PAGE_BITS) & (CPU_TLB_SIZE - 1);
redo:
	tlb_addr = env->tlb_table[mmu_idx][index].addr_read;
	if ((addr & TARGET_PAGE_MASK) == (tlb_addr & (TARGET_PAGE_MASK | TLB_INVALID_MASK))) {
		if (tlb_addr & ~TARGET_PAGE_MASK) {
			zdguo_debug_print(ZDGUO_LEVEL_DEBUG,
					ZDGUO_DEBUG_THREAD_MNTOR,
					"<test_helper_ld> raice a IO access\n");
		} else {
			/* unaligned/aligned access in the same page */
			uintptr_t addend;
			addend = env->tlb_table[mmu_idx][index].addend;
			res = (uintptr_t)(intptr_t)(addr + addend);
		}
	} else {
		/* the page is not in the TLB : fill it */
		if (0 == hsa_tlb_fill(env, addr, 0/*READ_ACCESS_TYPE*/, mmu_idx))
			goto redo;
	}
	return res;
}

/* Item ID related helper functions */
#define WORK_ID_CHECK(idx) \
	if((idx) > WORKITEM_MAX_DIM){ \
		HSA_DEBUG_LOG("invalid dim index, have to abort job\n"); \
		return 0; \
	}
uint32_t helper_WorkItemId(uint32_t idx)
{
	WORK_ID_CHECK(idx);
	return per_itemId.dim[idx];
}

uint32_t helper_WorkItemAId(uint32_t idx)
{
	WORK_ID_CHECK(idx);
	return (per_groupId.dim[idx] * itemPerGroup.dim[idx] + per_itemId.dim[idx]);
}

uint32_t helper_WorkGroupId(uint32_t idx)
{
	WORK_ID_CHECK(idx);
	return per_groupId.dim[idx];
}

uint32_t helper_WorkGroupSize(uint32_t idx)
{
	WORK_ID_CHECK(idx);
	return itemPerGroup.dim[idx];
}

uint32_t helper_WorkGridSize(uint32_t idx)
{
	WORK_ID_CHECK(idx);
	return (groupPerGrid.dim[idx] * itemPerGroup.dim[idx]);
}

uint32_t helper_WorkGridGroups(uint32_t idx)
{
	WORK_ID_CHECK(idx);
	return groupPerGrid.dim[idx];
}

uint32_t helper_LaneId(void)
{
	// not yet implement
	return 0;
}

uint32_t helper_MaxDynWaveId(void)
{
	// not yet implement
	return 0;
}

uint32_t helper_MaxCuId(void)
{
	return (hsa_cus - 1);
}

uint64_t helpder_DispatchId(void)
{
	return crnt_dispatchid;
}

uint32_t helper_WorkDim(void)
{
	// not yet implement
	return 0;
}

uint32_t helper_WorkitemaidFlat(void)
{
	// not yet implement
	return 0;
}

uint32_t helper_WorkitemidFlat(void)
{
	// not yet implement
	return 0;
}

//Helper Function, math
float helper_FSqrt(float arg)
{
	return sqrt(arg);
}

float helper_Fract_f32(float arg)
{
	return MIN(arg - floorf(arg), 0x1.fffffep-1f);
}

double helpee_Fract_f64(double arg)
{
	return MIN(arg - floor(arg), 0x1.fffffffffffffp-1);
}

float helper_Fcos(float arg)
{
	return cosf(arg);
}

float helper_Fsin(float arg)
{
	return sinf(arg);
}

double helper_Flog2(double arg)
{
	return log(arg)/log(2);
}

double helper_Fexp2(double arg)
{
	return exp(arg * log(2));
}

double helper_Frsqrt(double arg)
{
	return 1 / sqrt(arg);
}

double helper_Frcp(double arg)
{
	return 1 / arg;
}

void hsa_helper_barrier(void)
{
	if (page_fault_accrued)
		return;

	if (per_cu_env->lw_thread_created == LW_THREAD_NOT_CREATED &&
		thread_type == CU_TH) {
		
		int ret = hsa_create_lw_thread(per_cu_env);
		if (ret < 0) {
			fprintf(stderr, "can't create lw threads\n");
			exit(-1);
		}
		per_cu_env->lw_thread_created = LW_THREAD_CREATED;
	}

	if(per_cu_env->reset_lw_flag && thread_type == CU_TH){
		per_cu_env->reset_lw_flag = 0;
		hsa_prepare_lw_thread(per_cu_env);
	}

	// debug
	//if(thread_type == CU_TH){
	//	fprintf(stderr, "CU thread %d barr\n", per_cu_env->thread_id);
	//}else{
	//	fprintf(stderr, "lw thread %d barr\n", lw_thread_id);
	//}
	pthread_barrier_wait(&(per_cu_env->hsa_barrier));
}

int helper_WorkItemInc(void)
{
	// not yet implement
	return 0;
}


int helper_WorkItemIncbyN(uint32_t n)
{
	// not yet implement
	return 0;
}
/*
static int WorkItemInc(dim3 *wid)
{
	// not yet implement
	return 0;
}
*/
uint32_t helper_WorkItemNthAId(uint32_t dimension, uint32_t Nth)
{
	// not yet implement
	return 0;
}

