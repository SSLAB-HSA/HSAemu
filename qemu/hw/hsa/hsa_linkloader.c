#include "hsa_linkloader.h"
#include "hsa_helper.h"

#define CODE_CACHE_SIZE 1024 * 1024
// alligned to sysconf(_SC_PAGE_SIZE)
unsigned char cc[CODE_CACHE_SIZE] __attribute__((aligned(4096)));
static int isfailed;

static int stub_printf(target_ulong vaddr) {
	/*
	   va_list ap;
	   va_start(ap, fmt);
	   int result = vprintf(fmt, ap);
	   va_end(ap);
	   return result;
	 */
	zdguo_debug_print(ZDGUO_LEVEL_DEBUG, 0, "addr=0x%x\n", vaddr);
	return vaddr;
}

#define DEF(NAME, ADDR) \
{NAME, sizeof(NAME) - 1, (void *)(&(ADDR))},

func_entry_t const helper_tab[] = {
	DEF("my_printf", stub_printf)
/*
	DEF("", group_load_8)
	DEF("", group_store_8)
	DEF("", group_load_16)
	DEF("", group_store_16)
*/	
	DEF("_load_group_32", group_load_32)	
	DEF("_store_group_32", group_store_32)
/*	
	DEF("", group_load_64)
	DEF("", group_store_64)	
*/
	DEF("_load_8", load_8)
	DEF("_store_8", store_8)
	DEF("_load_16", load_16)
	DEF("_store_16", store_16)
	DEF("_load_32", load_32)
	DEF("_store_32", store_32)
	DEF("_load_64", load_64)
	DEF("_store_64", store_64)
	DEF("Barrier", hsa_helper_barrier)
	DEF("helper_Fsin", helper_Fsin)
	DEF("helper_Fcos", helper_Fcos)
	DEF("helper_Sqrt", helper_FSqrt)
	DEF("helper_WorkItemIncbyN", helper_WorkItemIncbyN)
	DEF("helper_WorkItemNthAId", helper_WorkItemNthAId)
	DEF("helper_hsa_get_global_id", helper_WorkitemaidFlat)
	DEF("helper_WorkItemAId", helper_WorkItemAId)	
	DEF("helper_WorkItemId", helper_WorkItemId)
	DEF("helper_WorkGroupId", helper_WorkGroupId)
	DEF("helper_WorkGroupSize", helper_WorkGroupSize)
};

#undef DEF

static void set_sec_entry(struct elf_sec *sec_entry,
		struct elf_shdr *shdr,
		unsigned char *image_buf,
		int index)
{
	unsigned char *buf;

	sec_entry->shdr = shdr;
	sec_entry->sh_type = shdr->sh_type;
	sec_entry->buf_size = shdr->sh_size;


	switch (sec_entry->sh_type) {
		case SHT_STRTAB:
		case SHT_PROGBITS:
		case SHT_NOBITS:
			buf = image_buf + shdr->sh_offset;
			break;
		case SHT_REL:
		case SHT_RELA:
		case SHT_SYMTAB: 
			buf = image_buf + shdr->sh_offset;
			sec_entry->extra = (void *)(unsigned long)(shdr->sh_size / shdr->sh_entsize);
			break;
		default:
			buf = NULL;
	}
	sec_entry->buf = buf;
}

static struct elf_sec *load_sectiontable(unsigned char *image_buf, struct elf_shdr *shdr_table)
{
	struct elf_hdr *ehdr = (struct elf_hdr *)image_buf;
	struct elf_sec *sec_table;
	int i;

	sec_table = (struct elf_sec *)malloc(sizeof(struct elf_sec) * ehdr->e_shnum);
	if (!sec_table) {
		zdguo_debug_print(ZDGUO_LEVEL_ERROR,
				ZDGUO_DEBUG_THREAD_MNTOR,
				"elf_sec space malloc failed.\n");
		return NULL;
	}

	for (i = 0; i < ehdr->e_shnum; i++) {
		set_sec_entry(sec_table + i, shdr_table + i, image_buf, i);
	}

	return sec_table;
}

/* zdguo: when get index from name, please init idx=-1 before calling this function */
static char *get_idxorname(struct elf_obj *elfobj, const char *name, int *idx)
{
	struct elf_hdr *ehdrp = elfobj->ehdrp;
	struct elf_shdr *shdr_tablep = elfobj->shdr_tablep;
	struct elf_sec *sec_tablep = elfobj->sec_tablep;
	struct elf_sec *sec_shstrtab = &((sec_tablep)[ehdrp->e_shstrndx]);
	unsigned long stroff;
	int i;

	if (*idx < 0 && name != NULL) {
		/* find idx by name */
		for (i = 0; i < ehdrp->e_shnum; i++) {
			stroff = shdr_tablep[i].sh_name;
			if (strcmp((char *)(sec_shstrtab->buf + stroff), name) == 0) {
				*idx = i;
				return NULL;
			}
		}
	}
	else if (*idx > 0 && name == NULL) {
		/* find name by index */
		stroff = shdr_tablep[*idx].sh_name;
		return (char *)(sec_shstrtab->buf + stroff);
	}

	return NULL;
}

static char *get_symname(struct elf_obj *elfobj, struct elf_sym *sym_entry)
{
	int idx;
	unsigned char *strtab;

	idx = -1;
	get_idxorname(elfobj, ".strtab", &idx);
	strtab = elfobj->sec_tablep[idx].buf;

	return (char *)(strtab + sym_entry->st_name);
}

static void *allocateSHNCommonData(struct elf_obj *elfobj, size_t size, size_t align)
{
	void *ret_addr;
	size_t rem;

	if (size <= 0 || align == 0)
		return NULL;

	rem = (unsigned long)(elfobj->SHNCommonDataPtr) % align;
	if (rem != 0) {
		elfobj->SHNCommonDataPtr += align - rem;
		elfobj->SHNCommonDataFreeSize -= align - rem;
	}

	if (elfobj->SHNCommonDataFreeSize < size)
		return NULL;

	ret_addr = elfobj->SHNCommonDataPtr;
	elfobj->SHNCommonDataPtr += size;
	elfobj->SHNCommonDataFreeSize -= size;

	return ret_addr;
}

static void *get_symety_addr(struct elf_obj *elfobj, struct elf_sym *sym_entry, int autoAlloc)
{
	struct elf_shdr *shdr_tablep;
	struct elf_sec *sec;
	size_t idx = (size_t)sym_entry->st_shndx, align;
	unsigned int section_type;
	void *ret_addr = NULL;

	switch (ELF_ST_TYPE(sym_entry->st_info)) {
		case STT_OBJECT:
			switch (idx)
		case SHN_COMMON: {
					 if (!autoAlloc) {
						 return NULL;
					 }
					 align = sym_entry->st_value;
					 ret_addr = allocateSHNCommonData(elfobj, sym_entry->st_size, align);
					 if (!ret_addr) {
						 zdguo_debug_print(ZDGUO_LEVEL_ERROR,
								 ZDGUO_DEBUG_THREAD_MNTOR,
								 "Unable to allocate memory for SHN_COMMON.\n");
						 isfailed = 1;
					 }
					 break;
					 case SHN_ABS:
					 case SHN_UNDEF:
					 case SHN_XINDEX:
					 zdguo_debug_print(ZDGUO_LEVEL_ERROR,
							 ZDGUO_DEBUG_THREAD_MNTOR,
							 "STT_OBJECT with special st_shndx.\n");
					 isfailed = 1;
					 break;
					 default:
					 shdr_tablep = elfobj->shdr_tablep;
					 section_type = shdr_tablep[idx].sh_type;

					 if (section_type == SHT_PROGBITS) {
						 sec = &elfobj->sec_tablep[idx];
						 ret_addr = (void *)(sec->buf + sym_entry->st_value);
					 }
					 else if (section_type == SHT_NOBITS) {
						 align = 16;
						 ret_addr = allocateSHNCommonData(elfobj, sym_entry->st_size, align);
						 if (!ret_addr) {
							 zdguo_debug_print(ZDGUO_LEVEL_ERROR,
									 ZDGUO_DEBUG_THREAD_MNTOR,
									 "Unable to allocate memory for SHN_COMMON.\n");
							 isfailed = 1;
						 }
					 }
					 else {
						 zdguo_debug_print(ZDGUO_LEVEL_ERROR,
								 ZDGUO_DEBUG_THREAD_MNTOR,
								 "STT_OBJECT with not BITS setion.\n");
						 isfailed = 1;
					 }
					 break;
				 }
			break;
		case STT_FUNC:
			switch (idx) {
				case SHN_ABS:
				case SHN_COMMON:
				case SHN_UNDEF:
				case SHN_XINDEX:
					zdguo_debug_print(ZDGUO_LEVEL_ERROR,
							ZDGUO_DEBUG_THREAD_MNTOR,
							"STT_FUNC with special st_shndx.\n");
					isfailed = 1;
					break;
				default: {
						 shdr_tablep = elfobj->shdr_tablep;
						 if (shdr_tablep[idx].sh_type != SHT_PROGBITS) {
							 zdguo_debug_print(ZDGUO_LEVEL_ERROR,
									 ZDGUO_DEBUG_THREAD_MNTOR,
									 "STT_FUNC with not BITS section.\n");
							 isfailed = 1;
						 }

						 sec = &elfobj->sec_tablep[idx];
						 ret_addr = (void *)(sec->buf + sym_entry->st_value);
						 break;
					 }
			}
			break;
		case STT_SECTION:
			switch (idx) {
				case SHN_ABS:
				case SHN_COMMON:
				case SHN_UNDEF:
				case SHN_XINDEX:
					zdguo_debug_print(ZDGUO_LEVEL_ERROR,
							ZDGUO_DEBUG_THREAD_MNTOR,
							"STT_SECTION with special st_shndx.\n");
					isfailed = 1;
					break;
				default: {
						 shdr_tablep = elfobj->shdr_tablep;
						 if (shdr_tablep[idx].sh_type != SHT_PROGBITS && 
								 shdr_tablep[idx].sh_type != SHT_NOBITS) {
							 zdguo_debug_print(ZDGUO_LEVEL_ERROR,
									 ZDGUO_DEBUG_THREAD_MNTOR,
									 "STT_SECTION with not BITS section.\n");
							 isfailed = 1;
						 }

						 sec = &elfobj->sec_tablep[idx];
						 ret_addr = (void *)(sec->buf + sym_entry->st_value);
						 break;
					 }
			}
			break;
		case STT_NOTYPE:
			switch (idx) {
				case SHN_ABS:
				case SHN_COMMON:
				case SHN_XINDEX:
					zdguo_debug_print(ZDGUO_LEVEL_ERROR,
							ZDGUO_DEBUG_THREAD_MNTOR,
							"STT_NOTYPE with special st_shndx.\n");
					isfailed = 1;
					break;
				case SHN_UNDEF:
					return 0;
				default: {
						 shdr_tablep = elfobj->shdr_tablep;
						 if (shdr_tablep[idx].sh_type != SHT_PROGBITS && 
								 shdr_tablep[idx].sh_type != SHT_NOBITS) {
							 zdguo_debug_print(ZDGUO_LEVEL_ERROR,
									 ZDGUO_DEBUG_THREAD_MNTOR,
									 "STT_NOTYPE with not BITS section.\n");
							 isfailed = 1;
						 }

						 sec = &elfobj->sec_tablep[idx];
						 ret_addr = (void *)(sec->buf + sym_entry->st_value);
						 break;
					 }
			}
			break;
		case STT_COMMON:
		case STT_FILE:
		case STT_TLS:
		case STT_LOOS:
		case STT_HIOS:
		case STT_LOPROC:
		case STT_HIPROC:
		default:
			zdguo_debug_print(ZDGUO_LEVEL_BUG,
					ZDGUO_DEBUG_THREAD_MNTOR,
					"Not implement.\n");
			isfailed = 1;
			break;
	}

	return ret_addr;
}

static void relocateX86_64(struct elf_obj *elfobj,
		void *(*find_sym)(void *context, char const *name),
		void *context,
		struct elf_sec *reltab,
		unsigned char *text)
{
	int idx, i, reltab_size;
	struct elf_sym *symtab, *sym_entry;
	ELF_RELOC *rel_tablep, *rel_entry;
	int32_t *inst, P, A, S;

	idx = -1;
	get_idxorname(elfobj, ".symtab", &idx);
	if (idx < 0) {
		zdguo_debug_print(ZDGUO_LEVEL_ERROR,
				ZDGUO_DEBUG_THREAD_MNTOR,
				".symtab can't find.\n");
		isfailed = 1;
		return;
	}
	symtab = (struct elf_sym *)(elfobj->sec_tablep[idx].buf);

	reltab_size = (int)(unsigned long)reltab->extra;
	rel_tablep = (ELF_RELOC *)reltab->buf;
	for (i = 0; i < reltab_size; i++) {
		rel_entry = &rel_tablep[i];
		sym_entry = &symtab[ELF_R_SYM(rel_entry->r_info)];

		inst = (int32_t *)&(text[rel_entry->r_offset]);
		P = (int32_t)(int64_t)inst;
		A = (int32_t)(int64_t)rel_entry->r_addend;
		S = (int32_t)(int64_t)get_symety_addr(elfobj, sym_entry, 1);

		if (0 == S) {
			S = (int64_t)find_sym(context, get_symname(elfobj, sym_entry));
			/* zdguo: set the S to the symbol entry struct for optimization */
		}

		switch (ELF_R_TYPE(rel_entry->r_info)) {            
			case R_X86_64_64:
				*inst = (S+A);
				break;
			case R_X86_64_PC32:
				*inst = (S+A-P);
				break;
			case R_X86_64_32:
			case R_X86_64_32S:
				*inst = (S+A);
				break;
			default:
				zdguo_debug_print(ZDGUO_LEVEL_ERROR,
						ZDGUO_DEBUG_THREAD_MNTOR,
						"Not implemented relocation type.\n");
				isfailed = 1;
				break;
		}
	}

	return;
}

static void relocate(struct elf_obj *elfobj,
		void *(*find_sym)(void *context, char const *name),
		void *context)
{
	struct elf_hdr *ehdrp = elfobj->ehdrp;
	struct elf_shdr *shdr_tablep = elfobj->shdr_tablep;
	struct elf_sec *sec_tablep = elfobj->sec_tablep;
	struct elf_sym *symtab, *symety;
	ELF_RELOC *reltab;
	int i, idx, symtab_size;
	unsigned long SHNCommonDataSize = 0, align;
	char *reltab_name, *need_rel_name;

	idx = -1;
	get_idxorname(elfobj, ".symtab", &idx);
	if (idx < 0) {
		zdguo_debug_print(ZDGUO_LEVEL_ERROR,
				ZDGUO_DEBUG_THREAD_MNTOR, 
				"Can't find .symtab section");
		isfailed = 1;
		return;
	}

	symtab = (struct elf_sym *)(sec_tablep[idx].buf);
	symtab_size = (int)(unsigned long)sec_tablep[idx].extra;
	for (i = 0; i < symtab_size; i++) {
		symety = &symtab[i];

		if (ELF_ST_TYPE(symety->st_info) != STT_OBJECT) {
			continue;
		}

		idx = (int)symety->st_shndx;
		switch (idx) {
			case SHN_COMMON:
				{
					align = (unsigned long)symety->st_value;
					SHNCommonDataSize += (unsigned long)symety->st_size + align;
				}
				break;
			case SHN_ABS:
			case SHN_UNDEF:
			case SHN_XINDEX:
				break;
			default:
				if (shdr_tablep[idx].sh_type == SHT_NOBITS) {
					// FIXME(logan): This is a workaround for .lcomm directives
					// bug of LLVM ARM MC code generator.  Remove this when the
					// LLVM bug is fixed.

					align = 16;
					SHNCommonDataSize += (unsigned long)symety->st_size + align;
				}
				break;
		}
	}

	if (SHNCommonDataSize > 0) {
		elfobj->SHNCommonData = (unsigned char *)valloc(SHNCommonDataSize);
		elfobj->SHNCommonDataFreeSize = SHNCommonDataSize;
		elfobj->SHNCommonDataPtr = elfobj->SHNCommonData;
	}
	else {
		elfobj->SHNCommonData = NULL;
		elfobj->SHNCommonDataFreeSize = SHNCommonDataSize;
		elfobj->SHNCommonDataPtr = NULL;
	}

	for (i = 0; i < ehdrp->e_shnum; i++) {
		if (shdr_tablep[i].sh_type != SHT_REL &&
				shdr_tablep[i].sh_type != SHT_RELA) {
			continue;
		}
		reltab = (ELF_RELOC *)sec_tablep[i].buf;
		if (!reltab) {
			zdguo_debug_print(ZDGUO_LEVEL_ERROR,
					ZDGUO_DEBUG_THREAD_MNTOR,
					"Relocation section can't be NULL.\n");
			isfailed = 1;
			return;
		}

		reltab_name = get_idxorname(elfobj, NULL, &i);
		if (shdr_tablep[i].sh_type == SHT_REL) {
			need_rel_name = reltab_name + 4;
		}
		else {
			need_rel_name = reltab_name + 5;
		}

		idx = -1;
		get_idxorname(elfobj, need_rel_name, &idx);
		if (idx < 0) {
			zdguo_debug_print(ZDGUO_LEVEL_ERROR,
					ZDGUO_DEBUG_THREAD_MNTOR,
					"Can't find need rel section");
			isfailed = 1;
			return;
		}

		switch (ehdrp->e_machine){
			case EM_X86_64:
				relocateX86_64(elfobj, find_sym, context, &sec_tablep[i], sec_tablep[idx].buf);
				break;
			default:
				zdguo_debug_print(ZDGUO_LEVEL_BUG,
						ZDGUO_DEBUG_THREAD_MNTOR,
						"Only support X86_64 relocation\n");
				isfailed = 1;
				return;
				break;
		}
	}
	/* protect code cache */

	return;
}

static void *loaderGetSymAddr(struct elf_obj *elfobj, const char *name)
{
	int idx, i, sym_size;
	struct elf_sym *symtab, *symety;
	unsigned char *strtable;

	idx = -1;
	get_idxorname(elfobj, ".symtab", &idx);
	symtab = (struct elf_sym *)elfobj->sec_tablep[idx].buf;
	sym_size = (int)(unsigned long)elfobj->sec_tablep[idx].extra;

	idx = -1;
	get_idxorname(elfobj, ".strtab", &idx);
	strtable = elfobj->sec_tablep[idx].buf;

	for (i = 0; i < sym_size; i++) {
		if (strcmp(name, (char *)(strtable + symtab[i].st_name)) == 0) {
			break;
		}
	}

	if (i >= sym_size) {
		zdguo_debug_print(ZDGUO_LEVEL_ERROR,
				ZDGUO_DEBUG_THREAD_MNTOR,
				"LoaderGetSymAddr can't find symbol: %s\n", name);
		return NULL;
	}
	symety = &symtab[i];

	return get_symety_addr(elfobj, symety, 0);
}

/* Verify the portions of EHDR within E_IDENT for the target.
   This can be performed before bswapping the entire header.  */
static int elf_check_ident(struct elf_hdr *ehdr)
{
	return (ehdr->e_ident[EI_MAG0] == ELFMAG0
			&& ehdr->e_ident[EI_MAG1] == ELFMAG1
			&& ehdr->e_ident[EI_MAG2] == ELFMAG2
			&& ehdr->e_ident[EI_MAG3] == ELFMAG3
			&& ehdr->e_ident[EI_CLASS] == ELF_CLASS
			&& ehdr->e_ident[EI_DATA] == ELF_DATA
			&& ehdr->e_ident[EI_VERSION] == EV_CURRENT);
}

static int elf_check_ehdr(struct elf_hdr *ehdr)
{
	return (elf_check_arch(ehdr->e_machine)
			&& (ehdr->e_phnum == 0 || ehdr->e_ehsize == sizeof(struct elf_hdr))
			&& (ehdr->e_shnum == 0 || ehdr->e_shentsize == sizeof(struct elf_shdr))
			&& ehdr->e_shentsize == sizeof(struct elf_shdr));
}

static void *find_sym(void *context, char const *name) {

	static size_t const tab_size = sizeof(helper_tab) / sizeof(struct func_entry_t);

	// Note: Since our table is small, we are using trivial O(n) searching
	// function.  For bigger table, it will be better to use binary
	// search or hash function.
	size_t i;
	size_t name_len = strlen(name);
	for (i = 0; i < tab_size; ++i) {
		if (name_len == helper_tab[i].name_len && strcmp(name, helper_tab[i].name) == 0) {
			return helper_tab[i].addr;
		}
	}

	zdguo_debug_print(ZDGUO_LEVEL_ERROR, ZDGUO_DEBUG_THREAD_MNTOR, "Can't find symbol: %s\n", name);
	isfailed = 1;

	return NULL;
}

void *cc_producer(const char *filename)
{
	struct elf_hdr *ehdr;
	struct elf_shdr *shdr_table;
	struct elf_sec *sec_table = NULL;
	struct elf_obj elfobj;
	struct stat sb;
	unsigned char *image = NULL;
	int fd, ret;
	void *kernel_entry;

	isfailed = 0;
	fd = open(filename, O_RDONLY);
	if (0 > fd) {
		zdguo_debug_print(ZDGUO_LEVEL_ERROR,
				ZDGUO_DEBUG_THREAD_MNTOR, 
				"Open file: %s error.\n", filename);
		return NULL;
	}

	if (fstat(fd, &sb) != 0) {
		zdguo_debug_print(ZDGUO_LEVEL_ERROR, 
				ZDGUO_DEBUG_THREAD_MNTOR,
				"Unable to stat the file.\n");
		goto failed;
	}

	image = cc;
	ret = mprotect(image, sb.st_size, PROT_READ | PROT_WRITE | PROT_EXEC);
	if (ret < 0) {
		zdguo_debug_print(ZDGUO_LEVEL_ERROR,
				ZDGUO_DEBUG_THREAD_MNTOR,
				"ERROR: Unable to change the protect the code cache, error num: %d\n",
				errno);
		goto failed;
	}
	ret = read(fd, image, sb.st_size);
	if (sb.st_size != ret) {
		zdguo_debug_print(ZDGUO_LEVEL_ERROR,
				ZDGUO_DEBUG_THREAD_MNTOR, 
				"ERROR: Unable to read the file: %s\n", filename);
		goto failed;
	}

	ehdr = (struct elf_hdr *)image;

	/* First of all, some simple consistency checks */
	if (!elf_check_ident(ehdr)) {
		zdguo_debug_print(ZDGUO_LEVEL_ERROR,
				ZDGUO_DEBUG_THREAD_MNTOR, 
				"Check ident failed.\n");
		goto failed;
	}

	if (!elf_check_ehdr(ehdr)) {
		zdguo_debug_print(ZDGUO_LEVEL_ERROR,
				ZDGUO_DEBUG_THREAD_MNTOR,
				"Check ehdr failed.\n");
		goto failed;
	}
	memset(&elfobj, 0, sizeof(struct elf_obj));

	shdr_table = (struct elf_shdr *)(image + ehdr->e_shoff);

	sec_table = load_sectiontable(image, shdr_table);

	if (!sec_table) {
		zdguo_debug_print(ZDGUO_LEVEL_ERROR,
				ZDGUO_DEBUG_THREAD_MNTOR,
				"fetch sec_table failed.\n");
		goto failed;
	}
	elfobj.ehdrp = ehdr;
	elfobj.shdr_tablep = shdr_table;
	elfobj.sec_tablep = sec_table;

	relocate(&elfobj, find_sym, NULL);

	if (isfailed)
		goto failed;

	kernel_entry = loaderGetSymAddr(&elfobj, "Kernel_Entry");

	if (0) {
		ret = ((int (*)(int))kernel_entry)(100);
		printf("==================================\n");
		printf("ELF object finished with code: %d\n", ret);
	}

	close(fd);
	if (sec_table)
		free(sec_table);
	if (elfobj.SHNCommonData)
		free(elfobj.SHNCommonData);

	return kernel_entry;

failed:
	if (sec_table)
		free(sec_table);
	if (elfobj.SHNCommonData)
		free(elfobj.SHNCommonData);
	close(fd);
	return NULL;
}
