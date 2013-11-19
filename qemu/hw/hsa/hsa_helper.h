#ifndef HSA_HELPER_H
#define HSA_HELPER_H
#include <math.h>
#include "hsa_mntor.h"

typedef struct func_entry_t {
  char const *name;
  size_t name_len;
  void *addr;
}func_entry_t;

// group memory helper
uint8_t group_load_8(target_ulong addr);
void group_store_8(target_ulong addr, uint8_t val);
uint16_t group_load_16(target_ulong addr);
void group_store_16(target_ulong addr, uint16_t val);
uint32_t group_load_32(target_ulong addr);
void group_store_32(target_ulong addr, uint32_t val);
uint64_t group_load_64(target_ulong addr);
void group_store_64(target_ulong addr, uint64_t val);
// global memory helper
uint8_t load_8(target_ulong addr);
void store_8(target_ulong addr, uint8_t val);
uint16_t load_16(target_ulong addr);
void store_16(target_ulong addr, uint16_t val);
uint32_t load_32(target_ulong addr);
void store_32(target_ulong addr, uint32_t val);
uint64_t load_64(target_ulong addr);
void store_64(target_ulong addr, uint64_t val);
void store_32_flag(target_ulong addr, uint32_t val, uint32_t flag);
uintptr_t get_phyaddr(CPUArchState *env, target_ulong addr, int mmu_idx);

/* zdguo: for item IDs */
uint32_t helper_WorkItemId(uint32_t dimension);
uint32_t helper_WorkItemAId(uint32_t dimension);
uint32_t helper_WorkGroupId(uint32_t dimension);
uint32_t helper_WorkGroupSize(uint32_t dimension);
uint32_t helper_WorkGridSize(uint32_t dimension);
uint32_t helper_WorkGridGroups(uint32_t dimension);
uint32_t helper_LaneId(void);
uint32_t helper_MaxDynWaveId(void);
uint32_t helper_MaxCuId(void);
uint64_t helpder_DispatchId(void);
uint32_t helper_WorkDim(void);
uint32_t helper_WorkitemaidFlat(void);
uint32_t helper_WorkitemidFlat(void);

/* zdguo: Helper Function, math*/
float helper_FSqrt(float arg);
float helper_Fract_f32(float arg);
double helpee_Fract_f64(double arg);
float helper_Fcos(float arg);
float helper_Fsin(float arg);
double helper_Flog2(double arg);
double helper_Fexp2(double arg);
double helper_Frsqrt(double arg);
double helper_Frcp(double arg);
void hsa_helper_barrier(void);
int helper_WorkItemInc(void);
int helper_WorkItemIncbyN(uint32_t n);
uint32_t helper_WorkItemNthAId(uint32_t dimension, uint32_t Nth);

#endif
