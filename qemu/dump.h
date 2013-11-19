/*
 * QEMU dump
 *
 * Copyright Fujitsu, Corp. 2011, 2012
 *
 * Authors:
 *     Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#ifndef DUMP_H
#define DUMP_H

typedef struct ArchDumpInfo {
    int d_machine;  /* Architecture */
    int d_endian;   /* ELFDATA2LSB or ELFDATA2MSB */
    int d_class;    /* ELFCLASS32 or ELFCLASS64 */
} ArchDumpInfo;

typedef int (*write_core_dump_function)(void *buf, size_t size, void *opaque);
int cpu_write_elf64_note(write_core_dump_function f, CPUArchState *env,
                                                  int cpuid, void *opaque);
int cpu_write_elf32_note(write_core_dump_function f, CPUArchState *env,
                                                  int cpuid, void *opaque);
int cpu_write_elf64_qemunote(write_core_dump_function f, CPUArchState *env,
                                                          void *opaque);
int cpu_write_elf32_qemunote(write_core_dump_function f, CPUArchState *env,
                                                          void *opaque);
int cpu_get_dump_info(ArchDumpInfo *info);
ssize_t cpu_get_note_size(int class, int machine, int nr_cpus);

#endif
