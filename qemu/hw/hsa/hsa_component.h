#ifndef HSA_H
#define HSA_H
#include "qemu-option.h"
#include "qdict.h"
#include "hsa_m2s.h"

void hsa_parse(const char *optarg);
int hsa_do_vgpu(void *_env, uint64_t _para_addr);
int hsa_set_debug(uint32_t debug_level);
void hsa_vgpu_init(const char *cpu_model);
int hsa_remote_m2s(void *_env, int addr, int len);
void hsa_reset_profile(Monitor *mon, const QDict *qdict);
void hsa_setup_profile(Monitor *mon, const QDict *qdict);

#endif
