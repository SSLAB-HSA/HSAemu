#include <assert.h>
#include "cpu.h"
#include "helper.h"
#include "host-utils.h"

#include "hw/lm32_pic.h"
#include "hw/lm32_juart.h"

#if !defined(CONFIG_USER_ONLY)
#define MMUSUFFIX _mmu
#define SHIFT 0
#include "softmmu_template.h"
#define SHIFT 1
#include "softmmu_template.h"
#define SHIFT 2
#include "softmmu_template.h"
#define SHIFT 3
#include "softmmu_template.h"

void helper_raise_exception(CPULM32State *env, uint32_t index)
{
    env->exception_index = index;
    cpu_loop_exit(env);
}

void helper_hlt(CPULM32State *env)
{
    env->halted = 1;
    env->exception_index = EXCP_HLT;
    cpu_loop_exit(env);
}

void helper_wcsr_im(CPULM32State *env, uint32_t im)
{
    lm32_pic_set_im(env->pic_state, im);
}

void helper_wcsr_ip(CPULM32State *env, uint32_t im)
{
    lm32_pic_set_ip(env->pic_state, im);
}

void helper_wcsr_jtx(CPULM32State *env, uint32_t jtx)
{
    lm32_juart_set_jtx(env->juart_state, jtx);
}

void helper_wcsr_jrx(CPULM32State *env, uint32_t jrx)
{
    lm32_juart_set_jrx(env->juart_state, jrx);
}

uint32_t helper_rcsr_im(CPULM32State *env)
{
    return lm32_pic_get_im(env->pic_state);
}

uint32_t helper_rcsr_ip(CPULM32State *env)
{
    return lm32_pic_get_ip(env->pic_state);
}

uint32_t helper_rcsr_jtx(CPULM32State *env)
{
    return lm32_juart_get_jtx(env->juart_state);
}

uint32_t helper_rcsr_jrx(CPULM32State *env)
{
    return lm32_juart_get_jrx(env->juart_state);
}

/* Try to fill the TLB and return an exception if error. If retaddr is
   NULL, it means that the function was called in C code (i.e. not
   from generated code or from helper.c) */
void tlb_fill(CPULM32State *env, target_ulong addr, int is_write, int mmu_idx,
              uintptr_t retaddr)
{
    TranslationBlock *tb;
    int ret;

    ret = cpu_lm32_handle_mmu_fault(env, addr, is_write, mmu_idx);
    if (unlikely(ret)) {
        if (retaddr) {
            /* now we have a real cpu fault */
            tb = tb_find_pc(retaddr);
            if (tb) {
                /* the PC is inside the translated code. It means that we have
                   a virtual CPU fault */
                cpu_restore_state(tb, env, retaddr);
            }
        }
        cpu_loop_exit(env);
    }
}
#endif

