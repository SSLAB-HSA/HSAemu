#ifndef HSA_LINKLOADER_H
#define HSA_LINKLOADER_H
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <stdint.h>

/* zdguo: need modify, not portable */
#define ELF_USES_RELOCA 1

#define	EI_MAG0		0		/* e_ident[] indexes */
#define	EI_MAG1		1
#define	EI_MAG2		2
#define	EI_MAG3		3
#define	EI_CLASS	4
#define	EI_DATA		5
#define	EI_VERSION	6
#define	EI_OSABI	7
#define	EI_PAD		8

#define EV_NONE		0		/* e_version, EI_VERSION */
#define EV_CURRENT	1
#define EV_NUM		2

#define	ELFMAG0		0x7f		/* EI_MAG */
#define	ELFMAG1		'E'
#define	ELFMAG2		'L'
#define	ELFMAG3		'F'
#define	ELFMAG		"\177ELF"
#define	SELFMAG		4

#define	ELFCLASSNONE	0		/* EI_CLASS */
#define	ELFCLASS32	1
#define	ELFCLASS64	2
#define	ELFCLASSNUM	3

#define ELFDATANONE	0		/* e_ident[EI_DATA] */
#define ELFDATA2LSB	1
#define ELFDATA2MSB	2

/* These constants define the various ELF target machines */
#define EM_NONE  0
#define EM_M32   1
#define EM_SPARC 2
#define EM_386   3
#define EM_68K   4
#define EM_88K   5
#define EM_486   6   /* Perhaps disused */
#define EM_860   7
#define EM_MIPS		8	/* MIPS R3000 (officially, big-endian only) */
#define EM_MIPS_RS4_BE 10	/* MIPS R4000 big-endian */
#define EM_PARISC      15	/* HPPA */
#define EM_SPARC32PLUS 18	/* Sun's "v8plus" */
#define EM_PPC	       20	/* PowerPC */
#define EM_PPC64       21       /* PowerPC64 */
#define EM_ARM		40		/* ARM */
#define EM_SH	       42	/* SuperH */
#define EM_SPARCV9     43	/* SPARC v9 64-bit */
#define EM_IA_64	50	/* HP/Intel IA-64 */
#define EM_X86_64	62	/* AMD x86-64 */
#define EM_S390		22	/* IBM S/390 */
#define EM_CRIS         76      /* Axis Communications 32-bit embedded processor */
#define EM_V850		87	/* NEC v850 */
#define EM_H8_300H      47      /* Hitachi H8/300H */
#define EM_H8S          48      /* Hitachi H8S     */
#define EM_LATTICEMICO32 138    /* LatticeMico32 */
#define EM_OPENRISC     92        /* OpenCores OpenRISC */
#define EM_UNICORE32    110     /* UniCore32 */

/* These constants define the different elf file types */
#define ET_NONE   0
#define ET_REL    1
#define ET_EXEC   2
#define ET_DYN    3
#define ET_CORE   4
#define ET_LOPROC 0xff00
#define ET_HIPROC 0xffff

/* These constants are for the segment types stored in the image headers */
#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4
#define PT_SHLIB   5
#define PT_PHDR    6
#define PT_LOPROC  0x70000000
#define PT_HIPROC  0x7fffffff
#define PT_MIPS_REGINFO		0x70000000
#define PT_MIPS_OPTIONS		0x70000001

#if UINTPTR_MAX == UINT64_MAX   /* host is 64 bits */
#define ELF_CLASS      ELFCLASS64
#define ELF_ARCH       EM_X86_64
#define elf_check_arch(x) ( ((x) == ELF_ARCH) )
#else
#define ELF_CLASS       ELFCLASS32
#define ELF_ARCH        EM_386
#define elf_check_arch(x) ( ((x) == EM_386) || ((x) == EM_486) )
#endif

#define ELF_DATA       ELFDATA2LSB
#define EI_NIDENT	16

/* sh_type */
#define SHT_NULL        0
#define SHT_PROGBITS    1
#define SHT_SYMTAB      2
#define SHT_STRTAB      3
#define SHT_RELA        4
#define SHT_HASH        5
#define SHT_DYNAMIC     6
#define SHT_NOTE        7
#define SHT_NOBITS      8
#define SHT_REL         9
#define SHT_SHLIB       10
#define SHT_DYNSYM      11
#define SHT_LOPROC      0x70000000
#define SHT_HIPROC      0x7FFFFFFF
#define SHT_LOUSER      0x80000000
#define SHT_HIUSER      0x8FFFFFFF

/* symbol bind type */
#define STB_LOCAL   0
#define STB_GLOBAL  1
#define STB_WEAK    2
#define STB_LOPROC  13
#define STB_HIPROC  15

/* symbol type */
#define STT_NOTYPE  0
#define STT_OBJECT  1
#define STT_FUNC    2
#define STT_SECTION 3
#define STT_FILE    4
#define STT_COMMON  5
#define STT_TLS     6
#define STT_LOOS    7
#define STT_HIOS    8
#define STT_LOPROC  13
#define STT_HIPROC  15

#define SHN_UNDEF       0
#define SHN_LORESERVE   0xff00
#define SHN_LOPROC      0xff00
#define SHN_HIPROC      0xff1f
#define SHN_ABS         0xfff1
#define SHN_COMMON      0xfff2
#define SHN_XINDEX      0xffff
#define SHN_HIRESERVE   0xffff

/* x86 relocate type */
#define R_X86_64_NONE           0       /* No reloc */
#define R_X86_64_64             1       /* Direct 64 bit  */
#define R_X86_64_PC32           2       /* PC relative 32 bit signed */
#define R_X86_64_GOT32          3       /* 32 bit GOT entry */
#define R_X86_64_PLT32          4       /* 32 bit PLT address */
#define R_X86_64_COPY           5       /* Copy symbol at runtime */
#define R_X86_64_GLOB_DAT       6       /* Create GOT entry */
#define R_X86_64_JUMP_SLOT      7       /* Create PLT entry */
#define R_X86_64_RELATIVE       8       /* Adjust by program base */
#define R_X86_64_GOTPCREL       9       /* 32 bit signed pc relative
					   offset to GOT */
#define R_X86_64_32             10      /* Direct 32 bit zero extended */
#define R_X86_64_32S            11      /* Direct 32 bit sign extended */
#define R_X86_64_16             12      /* Direct 16 bit zero extended */
#define R_X86_64_PC16           13      /* 16 bit sign extended pc relative */
#define R_X86_64_8              14      /* Direct 8 bit sign extended  */
#define R_X86_64_PC8            15      /* 8 bit sign extended pc relative */

#define R_X86_64_NUM            16

#define ELF_ST_BIND(i) ((i)>>4)
#define ELF_ST_TYPE(i) ((i)&0xf)
#define ELF_ST_INFO(b, t) (((b)<<4) + ((t)&0xf))

/* 32-bit ELF base types. */
typedef unsigned int Elf32_Addr;
typedef unsigned short Elf32_Half;
typedef unsigned int Elf32_Off;
typedef signed int  Elf32_Sword;
typedef unsigned int Elf32_Word;

/* 64-bit ELF base types. */
typedef unsigned long long Elf64_Addr;
typedef unsigned short Elf64_Half;
typedef signed short	 Elf64_SHalf;
typedef unsigned long long Elf64_Off;
typedef signed int	 Elf64_Sword;
typedef unsigned int Elf64_Word;
typedef unsigned long long Elf64_Xword;
typedef signed long long  Elf64_Sxword;

typedef struct elf32_hdr{
	unsigned char	e_ident[EI_NIDENT];
	Elf32_Half	e_type;
	Elf32_Half	e_machine;
	Elf32_Word	e_version;
	Elf32_Addr	e_entry;  /* Entry point */
	Elf32_Off	e_phoff;
	Elf32_Off	e_shoff;
	Elf32_Word	e_flags;
	Elf32_Half	e_ehsize;
	Elf32_Half	e_phentsize;
	Elf32_Half	e_phnum;
	Elf32_Half	e_shentsize;
	Elf32_Half	e_shnum;
	Elf32_Half	e_shstrndx;
} Elf32_Ehdr;

typedef struct elf64_hdr {
	unsigned char	e_ident[16];		/* ELF "magic number" */
	Elf64_Half e_type;
	Elf64_Half e_machine;
	Elf64_Word e_version;
	Elf64_Addr e_entry;		/* Entry point virtual address */
	Elf64_Off e_phoff;		/* Program header table file offset */
	Elf64_Off e_shoff;		/* Section header table file offset */
	Elf64_Word e_flags;
	Elf64_Half e_ehsize;
	Elf64_Half e_phentsize;
	Elf64_Half e_phnum;
	Elf64_Half e_shentsize;
	Elf64_Half e_shnum;
	Elf64_Half e_shstrndx;
} Elf64_Ehdr;

/* These constants define the permissions on sections in the program
   header, p_flags. */
#define PF_R		0x4
#define PF_W		0x2
#define PF_X		0x1

typedef struct elf32_phdr{
	Elf32_Word	p_type;
	Elf32_Off	p_offset;
	Elf32_Addr	p_vaddr;
	Elf32_Addr	p_paddr;
	Elf32_Word	p_filesz;
	Elf32_Word	p_memsz;
	Elf32_Word	p_flags;
	Elf32_Word	p_align;
} Elf32_Phdr;

typedef struct elf64_phdr {
	Elf64_Word p_type;
	Elf64_Word p_flags;
	Elf64_Off p_offset;		/* Segment file offset */
	Elf64_Addr p_vaddr;		/* Segment virtual address */
	Elf64_Addr p_paddr;		/* Segment physical address */
	Elf64_Xword p_filesz;		/* Segment size in file */
	Elf64_Xword p_memsz;		/* Segment size in memory */
	Elf64_Xword p_align;		/* Segment alignment, file & memory */
} Elf64_Phdr;

typedef struct elf32_shdr {
	Elf32_Word	sh_name;
	Elf32_Word	sh_type;
	Elf32_Word	sh_flags;
	Elf32_Addr	sh_addr;
	Elf32_Off	    sh_offset;
	Elf32_Word	sh_size;
	Elf32_Word	sh_link;
	Elf32_Word	sh_info;
	Elf32_Word	sh_addralign;
	Elf32_Word	sh_entsize;
} Elf32_Shdr;

typedef struct elf64_shdr {
	Elf64_Word sh_name;		/* Section name, index in string tbl */
	Elf64_Word sh_type;		/* Type of section */
	Elf64_Xword sh_flags;		/* Miscellaneous section attributes */
	Elf64_Addr sh_addr;		/* Section virtual addr at execution */
	Elf64_Off sh_offset;		/* Section file offset */
	Elf64_Xword sh_size;		/* Size of section in bytes */
	Elf64_Word sh_link;		/* Index of another section */
	Elf64_Word sh_info;		/* Additional section information */
	Elf64_Xword sh_addralign;	/* Section alignment */
	Elf64_Xword sh_entsize;	/* Entry size if section holds table */
} Elf64_Shdr;

/* Note header in a PT_NOTE section */
typedef struct elf32_note {
	Elf32_Word	n_namesz;	/* Name size */
	Elf32_Word	n_descsz;	/* Content size */
	Elf32_Word	n_type;		/* Content type */
} Elf32_Nhdr;

/* Note header in a PT_NOTE section */
typedef struct elf64_note {
	Elf64_Word n_namesz;	/* Name size */
	Elf64_Word n_descsz;	/* Content size */
	Elf64_Word n_type;	/* Content type */
} Elf64_Nhdr;

typedef struct elf32_rel {
	Elf32_Addr	r_offset;
	Elf32_Word	r_info;
} Elf32_Rel;

typedef struct elf64_rel {
	Elf64_Addr r_offset;	/* Location at which to apply the action */
	Elf64_Xword r_info;	/* index and type of relocation */
} Elf64_Rel;

typedef struct elf32_rela{
	Elf32_Addr	r_offset;
	Elf32_Word	r_info;
	Elf32_Sword	r_addend;
} Elf32_Rela;

typedef struct elf64_rela {
	Elf64_Addr r_offset;	/* Location at which to apply the action */
	Elf64_Xword r_info;	/* index and type of relocation */
	Elf64_Sxword r_addend;	/* Constant addend used to compute value */
} Elf64_Rela;

typedef struct elf32_sym{
	Elf32_Word	st_name;
	Elf32_Addr	st_value;
	Elf32_Word	st_size;
	unsigned char	st_info;
	unsigned char	st_other;
	Elf32_Half	st_shndx;
} Elf32_Sym;

typedef struct elf64_sym {
	Elf64_Word st_name;		/* Symbol name, index in string tbl */
	unsigned char	st_info;	/* Type and binding attributes */
	unsigned char	st_other;	/* No defined meaning, 0 */
	Elf64_Half st_shndx;		/* Associated section index */
	Elf64_Addr st_value;		/* Value of the symbol */
	Elf64_Xword st_size;		/* Associated symbol size */
} Elf64_Sym;

#define ELF32_R_SYM(i) ((i)>>8)
#define ELF32_R_TYPE(i)   ((unsigned char)(i))
#define ELF64_R_SYM(i) ((i)>>32)
#define ELF64_R_TYPE(i)   ((i)&0xffffffffL)

#ifdef ELF_CLASS
#if ELF_CLASS == ELFCLASS32

#define elf_hdr		elf32_hdr
#define elf_phdr	elf32_phdr
#define elf_note	elf32_note
#define elf_shdr	elf32_shdr
#define elf_sym		elf32_sym
#define elf_addr_t	Elf32_Off

#ifdef ELF_USES_RELOCA
# define ELF_RELOC      Elf32_Rela
#else
# define ELF_RELOC      Elf32_Rel
#endif

#define ELF_R_SYM ELF32_R_SYM;
#define ELF_R_TYPE ELF32_R_TYPE

#else

#define elf_hdr		elf64_hdr
#define elf_phdr	elf64_phdr
#define elf_note	elf64_note
#define elf_shdr	elf64_shdr
#define elf_sym		elf64_sym
#define elf_addr_t	Elf64_Off

#ifdef ELF_USES_RELOCA
# define ELF_RELOC      Elf64_Rela
#else
# define ELF_RELOC      Elf64_Rel
#endif

#define ELF_R_SYM ELF64_R_SYM
#define ELF_R_TYPE ELF64_R_TYPE

#endif /* if ELF_CLASS */
#endif /* ifdef ELF_CLASS */

struct strtab {
	char **strtabidxp;
	int strtabnb;
	int shstrtab;
};

typedef struct elf_sec {
	struct elf_shdr *shdr;
	unsigned char *buf;
	int buf_size;
	Elf64_Word sh_type;
	void *extra;
} Elf_Sec;

struct elf_obj {
	struct elf_hdr *ehdrp;
	struct elf_shdr *shdr_tablep;
	struct elf_sec *sec_tablep;
	unsigned char *SHNCommonData;
	unsigned char *SHNCommonDataPtr;
	unsigned long SHNCommonDataFreeSize;
};

void *cc_producer(const char *filename);

#endif
