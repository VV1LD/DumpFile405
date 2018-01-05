/*****************************************************************
*
* ============== Dump File for 4.05 - WildCard ===============
*
*	Thanks to:
*	-Specter for his kernel exploit / Code Execution method
*	-IDC for his patches
*	-Grass Skeu for his original Dump File on 1.76 that most
*	of this code came from, thanks Skeu!
*
******************************************************************/

#include "ps4.h"
#include "elf64.h"
#include "elf_common.h"

// Defines

#define IP(a, b, c, d) (((a) << 0) + ((b) << 8) + ((c) << 16) + ((d) << 24))

#define	CTL_KERN	1	/* "high kernel": proc, limits */
#define	KERN_PROC	14	/* struct: process entries */
#define	KERN_PROC_VMMAP	32	/* VM map entries for process */
#define	KERN_PROC_PID	1	/* by process id */

#define TRUE 1
#define FALSE 0

#define X86_CR0_WP (1 << 16)

#define printfsocket(format, ...)\
	do {\
		char buffer[512];\
		int size = sprintf(buffer, format, ##__VA_ARGS__);\
		sceNetSend(sock, buffer, size, 0);\
	} while(0)

int sock;

struct auditinfo_addr {
    /*
    4    ai_auid;
    8    ai_mask;
    24    ai_termid;
    4    ai_asid;
    8    ai_flags;r
    */
    char useless[184];
};

unsigned int long long __readmsr(unsigned long __register) {
	// Loads the contents of a 64-bit model specific register (MSR) specified in
	// the ECX register into registers EDX:EAX. The EDX register is loaded with
	// the high-order 32 bits of the MSR and the EAX register is loaded with the
	// low-order 32 bits. If less than 64 bits are implemented in the MSR being
	// read, the values returned to EDX:EAX in unimplemented bit locations are
	// undefined.
	unsigned long __edx;
	unsigned long __eax;
	__asm__ ("rdmsr" : "=d"(__edx), "=a"(__eax) : "c"(__register));
	return (((unsigned int long long)__edx) << 32) | (unsigned int long long)__eax;
}


static inline __attribute__((always_inline)) uint64_t readCr0(void) {
	uint64_t cr0;
	
	asm volatile (
		"movq %0, %%cr0"
		: "=r" (cr0)
		: : "memory"
 	);
	
	return cr0;
}

static inline __attribute__((always_inline)) void writeCr0(uint64_t cr0) {
	asm volatile (
		"movq %%cr0, %0"
		: : "r" (cr0)
		: "memory"
	);
}


struct ucred {
	uint32_t useless1;
	uint32_t cr_uid;     // effective user id
	uint32_t cr_ruid;    // real user id
 	uint32_t useless2;
    	uint32_t useless3;
    	uint32_t cr_rgid;    // real group id
    	uint32_t useless4;
    	void *useless5;
    	void *useless6;
    	void *cr_prison;     // jail(2)
    	void *useless7;
    	uint32_t useless8;
    	void *useless9[2];
    	void *useless10;
    	struct auditinfo_addr useless11;
    	uint32_t *cr_groups; // groups
    	uint32_t useless12;
};

struct filedesc {
	void *useless1[3];
    	void *fd_rdir;
    	void *fd_jdir;
};

struct proc {
    	char useless[64];
    	struct ucred *p_ucred;
    	struct filedesc *p_fd;
};



struct thread {
    	void *useless;
    	struct proc *td_proc;
};

struct kpayload_args{
	uint64_t user_arg;
};

struct kdump_args{
    	uint64_t argArrayPtr;
};


// dump file functions

typedef struct {
    int index;
    uint64_t fileoff;
    size_t bufsz;
    size_t filesz;
} SegmentBufInfo;


void hexdump(uint8_t *raw, size_t size) {
    for (int i = 1; i <= size; i += 1) {
        printfsocket("%02X ", raw[i - 1]);
        if (i % 16 == 0) {
            printfsocket("\n");
        }
    }
}


void print_phdr(Elf64_Phdr *phdr) {
    printfsocket("=================================\n");
    printfsocket("     p_type %08x\n", phdr->p_type);
    printfsocket("     p_flags %08x\n", phdr->p_flags);
    printfsocket("     p_offset %016llx\n", phdr->p_offset);
    printfsocket("     p_vaddr %016llx\n", phdr->p_vaddr);
    printfsocket("     p_paddr %016llx\n", phdr->p_paddr);
    printfsocket("     p_filesz %016llx\n", phdr->p_filesz);
    printfsocket("     p_memsz %016llx\n", phdr->p_memsz);
    printfsocket("     p_align %016llx\n", phdr->p_align);
}


void dumpfile(char *name, uint8_t *raw, size_t size) {
    FILE *fd = fopen(name, "wb");
    if (fd != NULL) {
        fwrite(raw, 1, size, fd);
        fclose(fd);
    }
    else {
        printfsocket("dump err.\n");
    }
}


int read_decrypt_segment(int fd, uint64_t index, uint64_t offset, size_t size, uint8_t *out) {
    uint64_t realOffset = (index << 32) | offset;
    uint8_t *addr = (uint8_t*)mmap(0, size, PROT_READ, MAP_PRIVATE | 0x80000, fd, realOffset);
    if (addr != MAP_FAILED) {
        memcpy(out, addr, size);
        munmap(addr, size);
        return TRUE;
    }
    else {
        printfsocket("mmap segment [%d] err(%d) : %s\n", index, errno, strerror(errno));
        return FALSE;
    }
}



int is_segment_in_other_segment(Elf64_Phdr *phdr, int index, Elf64_Phdr *phdrs, int num) {
    for (int i = 0; i < num; i += 1) {
        Elf64_Phdr *p = &phdrs[i];
        if (i != index) {
            if (p->p_filesz > 0) {
                // printfsocket("offset : %016x,  toffset : %016x\n", phdr->p_offset, p->p_offset);
                // printfsocket("offset : %016x,  toffset + size : %016x\n", phdr->p_offset, p->p_offset + p->p_filesz);
                if ((phdr->p_offset >= p->p_offset) && ((phdr->p_offset + phdr->p_filesz) <= (p->p_offset + p->p_filesz))) {
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}


SegmentBufInfo *parse_phdr(Elf64_Phdr *phdrs, int num, int *segBufNum) {
    printfsocket("segment num : %d\n", num);
    SegmentBufInfo *infos = (SegmentBufInfo *)malloc(sizeof(SegmentBufInfo) * num);
    int segindex = 0;
    for (int i = 0; i < num; i += 1) {
        Elf64_Phdr *phdr = &phdrs[i];
        // print_phdr(phdr);

        if (phdr->p_filesz > 0 && phdr->p_type != 0x6fffff01) {
            if (!is_segment_in_other_segment(phdr, i, phdrs, num)) {
                SegmentBufInfo *info = &infos[segindex];
                segindex += 1;
                info->index = i;
                info->bufsz = (phdr->p_filesz + (phdr->p_align - 1)) & (~(phdr->p_align - 1));
                info->filesz = phdr->p_filesz;
                info->fileoff = phdr->p_offset;

                // printfsocket("seg buf info %d -->\n", segindex);
                // printfsocket("    index : %d\n    bufsz : 0x%016llX\n", info->index, info->bufsz);
                // printfsocket("    filesz : 0x%016llX\n    fileoff : 0x%016llX\n", info->filesz, info->fileoff);
            }
        }
    }
    *segBufNum = segindex;
    return infos;
}


void do_dump(char *saveFile, int fd, SegmentBufInfo *segBufs, int segBufNum, Elf64_Ehdr *ehdr) {
    FILE *sf = fopen(saveFile, "wb");
    if (sf != NULL) {
        size_t elfsz = 0x40 + ehdr->e_phnum * sizeof(Elf64_Phdr);
        printfsocket("elf header + phdr size : 0x%08X\n", elfsz);
        fwrite(ehdr, elfsz, 1, sf);

        for (int i = 0; i < segBufNum; i += 1) {
            printfsocket("sbuf index : %d, offset : 0x%016x, bufsz : 0x%016x, filesz : 0x%016x\n", segBufs[i].index, segBufs[i].fileoff, segBufs[i].bufsz, segBufs[i].filesz);
            uint8_t *buf = (uint8_t*)malloc(segBufs[i].bufsz);
            memset(buf, 0, segBufs[i].bufsz);
            if (read_decrypt_segment(fd, segBufs[i].index, 0, segBufs[i].filesz, buf)) {
                fseek(sf, segBufs[i].fileoff, SEEK_SET);
                fwrite(buf, segBufs[i].bufsz, 1, sf);
            }
            free(buf);
        }
        fclose(sf);
    }
    else {
        printfsocket("fopen %s err : %s\n", saveFile, strerror(errno));
    }
}


void dumpSelfPatch(void){

	// hook our kernel functions
	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x30EB30];
	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x347580);

	printfkernel("applying patches\n");

	// Disable write protection

	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// patch allowed to mmap self *thanks to IDC
	*(uint8_t*)(kernel_base + 0x31EE40) = 0x90; //0x0F
	*(uint8_t*)(kernel_base + 0x31EE41) = 0xE9; //0x84
	*(uint8_t*)(kernel_base + 0x31EF98) = 0x90; //0x74
	*(uint8_t*)(kernel_base + 0x31EF99) = 0x90; //0x0F

	// restore write protection

	writeCr0(cr0);

	printfkernel("kernel patched\n");

}

void dumpSelfPatchOrig(void){

	// hook our kernel functions
	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x30EB30];
		int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x347580);
	printfkernel("restoring kernel\n");

	// Disable write protection

	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// restore kernel 
	*(uint8_t*)(kernel_base + 0x31EE40) = 0x0F; //0x0F
	*(uint8_t*)(kernel_base + 0x31EE41) = 0x84; //0x84
	*(uint8_t*)(kernel_base + 0x31EF98) = 0x74; //0x74
	*(uint8_t*)(kernel_base + 0x31EF99) = 0x0F; //0x0F

	// restore write protection

	writeCr0(cr0);

	printfkernel("kernel restored\n");

}


void decrypt_and_dump_self(char *selfFile, char *saveFile) {
	
	// patch for decrypting

	printfsocket("applying patches\n");
	syscall(11,dumpSelfPatch);

    int fd = open(selfFile, O_RDONLY,0);
    if (fd != -1) {
        void *addr = mmap(0, 0x4000, PROT_READ, MAP_PRIVATE, fd, 0);
        if (addr != MAP_FAILED) {
            printfsocket("mmap %s : %p\n", selfFile, addr);

            uint16_t snum = *(uint16_t*)((uint8_t*)addr + 0x18);
            Elf64_Ehdr *ehdr = (Elf64_Ehdr *)((uint8_t*)addr + 0x20 + snum * 0x20);
            printfsocket("ehdr : %p\n", ehdr);

            Elf64_Phdr *phdrs = (Elf64_Phdr *)((uint8_t *)ehdr + 0x40);
            printfsocket("phdrs : %p\n", phdrs);

            int segBufNum = 0;
            SegmentBufInfo *segBufs = parse_phdr(phdrs, ehdr->e_phnum, &segBufNum);
            do_dump(saveFile, fd, segBufs, segBufNum, ehdr);
            printfsocket("dump completed\n");

            free(segBufs);
            munmap(addr, 0x4000);
        }
        else {
            printfsocket("mmap file %s err : %s\n", selfFile, strerror(errno));
        }
    }
    else {
        printfsocket("open %s err : %s\n", selfFile, strerror(errno));
    }
	// set it back to normal

	printfsocket("restoring kernel\n");
	syscall(11,dumpSelfPatchOrig);
}



int kpayload(struct thread *td){

	struct ucred* cred;
	struct filedesc* fd;

	fd = td->td_proc->p_fd;
	cred = td->td_proc->p_ucred;

	void* kernel_base = &((uint8_t*)__readmsr(0xC0000082))[-0x30EB30];
	uint8_t* kernel_ptr = (uint8_t*)kernel_base;
	void** got_prison0 =   (void**)&kernel_ptr[0xF26010];
	void** got_rootvnode = (void**)&kernel_ptr[0x206D250];

	// resolve kernel functions

	int (*copyout)(const void *kaddr, void *uaddr, size_t len) = (void *)(kernel_base + 0x286d70);
	int (*printfkernel)(const char *fmt, ...) = (void *)(kernel_base + 0x347580);

	cred->cr_uid = 0;
	cred->cr_ruid = 0;
	cred->cr_rgid = 0;
	cred->cr_groups[0] = 0;

	cred->cr_prison = *got_prison0;
	fd->fd_rdir = fd->fd_jdir = *got_rootvnode;

	// escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
	void *td_ucred = *(void **)(((char *)td) + 304); // p_ucred == td_ucred
	
	// sceSblACMgrIsSystemUcred
	uint64_t *sonyCred = (uint64_t *)(((char *)td_ucred) + 96);
	*sonyCred = 0xffffffffffffffff;
	
	// sceSblACMgrGetDeviceAccessType
	uint64_t *sceProcType = (uint64_t *)(((char *)td_ucred) + 88);
	*sceProcType = 0x3801000000000013; // Max access
	
	// sceSblACMgrHasSceProcessCapability
	uint64_t *sceProcCap = (uint64_t *)(((char *)td_ucred) + 104);
	*sceProcCap = 0xffffffffffffffff; // Sce Process

	uint16_t *securityFlags = (uint64_t *)(kernel_base+0x2001516);
	*securityFlags = *securityFlags & ~(1 << 15);

	// specters debug settings patchs

	*(char *)(kernel_base + 0x186b0a0) = 0; 
	*(char *)(kernel_base + 0x2001516) |= 0x14;
	*(char *)(kernel_base + 0x2001539) |= 1;
	*(char *)(kernel_base + 0x2001539) |= 2;
	*(char *)(kernel_base + 0x200153A) |= 1;
	*(char *)(kernel_base + 0x2001558) |= 1;	

	// Disable write protection

	uint64_t cr0 = readCr0();
	writeCr0(cr0 & ~X86_CR0_WP);

	// debug menu full patches thanks to sealab

	*(uint32_t *)(kernel_base + 0x4CECB7) = 0;
	*(uint32_t *)(kernel_base + 0x4CFB9B) = 0;

	// Target ID Patches :)

	*(uint16_t *)(kernel_base + 0x1FE59E4) = 0x8101;
	*(uint16_t *)(kernel_base + 0X1FE5A2C) = 0x8101;
	*(uint16_t *)(kernel_base + 0x200151C) = 0x8101;

	// restore write protection

	writeCr0(cr0);

	// Say hello and put the kernel base just for reference

	printfkernel("\n\n\nHELLO FROM YOUR KERN DUDE =)\n\n\n");
	printfkernel("kernel base is:0x%016llx\n", kernel_base);


	return 0;
}


int _main(struct thread *td){

	// Init and resolve libraries
	initKernel();
	initLibc();
	initNetwork();
	initPthread();

	// create our server
	struct sockaddr_in server;

	server.sin_len = sizeof(server);
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = IP(192, 168, 1, 64);
	server.sin_port = sceNetHtons(9023);
	memset(server.sin_zero, 0, sizeof(server.sin_zero));
	sock = sceNetSocket("debug", AF_INET, SOCK_STREAM, 0);
	sceNetConnect(sock, (struct sockaddr *)&server, sizeof(server));
	
	int flag = 1;
	sceNetSetsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));


	printfsocket("connected\n");

	// jailbreak / debug settings etc
	syscall(11,kpayload,td);

	// decrypt some files ;)
	printfsocket("decrypting files now ;)\n");

	decrypt_and_dump_self("/system_ex/app/NPXS20001/eboot.bin","/mnt/usb0/405/NPXS20001-eboot.bin");
	decrypt_and_dump_self("/system_ex/app/NPXS20103/eboot.bin","/mnt/usb0/405/NPXS20103-eboot.bin");
	decrypt_and_dump_self("/system_ex/app/NPXS20113/eboot.bin","/mnt/usb0/405/NPXS20113-eboot.bin");
	decrypt_and_dump_self("/system_ex/app/NPXS20114/eboot.bin","/mnt/usb0/405/NPXS20114-eboot.bin");
	decrypt_and_dump_self("/system_ex/app/NPXS20118/eboot.bin","/mnt/usb0/405/NPXS20118-eboot.bin");
	decrypt_and_dump_self("/system_ex/app/NPXS20120/eboot.bin","/mnt/usb0/405/NPXS20120-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS20119/eboot.bin","/mnt/usb0/405/NPXS20119-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS21000/eboot.bin","/mnt/usb0/405/NPXS21000-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS21001/eboot.bin","/mnt/usb0/405/NPXS21001-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS21002/eboot.bin","/mnt/usb0/405/NPXS21002-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS21003/eboot.bin","/mnt/usb0/405/NPXS21003-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS21004/eboot.bin","/mnt/usb0/405/NPXS21004-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS21005/eboot.bin","/mnt/usb0/405/NPXS21005-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS21006/eboot.bin","/mnt/usb0/405/NPXS21006-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS21007/eboot.bin","/mnt/usb0/405/NPXS21007-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS21010/eboot.bin","/mnt/usb0/405/NPXS21010-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS21012/eboot.bin","/mnt/usb0/405/NPXS21012-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS21016/eboot.bin","/mnt/usb0/405/NPXS21016-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS21019/eboot.bin","/mnt/usb0/405/NPXS21019-eboot.bin");
	decrypt_and_dump_self("/system/vsh/app/NPXS22010/eboot.bin","/mnt/usb0/405/NPXS22010-eboot.bin");
	decrypt_and_dump_self("/system/vsh/sce_video_service/eboot.bin","/mnt/usb0/vsh/sce_video_service.bin");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/platform.sdll","/mnt/usb0/405/platform.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.AppContentUtilWrapper.sdll","/mnt/usb0/405/Sce.Vsh.AppContentUtilWrapper.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.EventApp.sdll","/mnt/usb0/405/Sce.Vsh.EventApp.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.GameCustomData.sdll","/mnt/usb0/405/Sce.Vsh.GameCustomData.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.GriefReport.sdll","/mnt/usb0/405/Sce.Vsh.GriefReport.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.Messages.sdll","/mnt/usb0/405/Sce.Vsh.Messages.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.Np.AppLaunchLink.sdll","/mnt/usb0/405/Sce.Vsh.Np.AppLaunchLink.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.Orbis.BgftAccessor.sdll","/mnt/usb0/405/Sce.Vsh.Orbis.BgftAccessor.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.Orbis.CdlgServerNpCommerce.sdll","/mnt/usb0/405/Sce.Vsh.Orbis.CdlgServerNpCommerce.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.SessionInvitation.sdll","/mnt/usb0/405/Sce.Vsh.SessionInvitation.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.Sticker.sdll","/mnt/usb0/405/Sce.Vsh.Sticker.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/Sce.Vsh.VideoRecordingWrapper.sdll","/mnt/usb0/405/Sce.Vsh.VideoRecordingWrapper.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20103/psm/Application/Sce.Vsh.VideoEdit.Wrapper.sdll","/mnt/usb0/405/Sce.Vsh.VideoEdit.Wrapper.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20113/psm/Application/Sce.Vsh.DiscPlayer.sdll","/mnt/usb0/405/Sce.Vsh.DiscPlayer.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20114/psm/Application/Sce.CloudClient.App.Platform.sdll","/mnt/usb0/405/Sce.CloudClient.App.Platform.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20118/psm/Application/Sce.Vsh.RemotePlay.sdll","/mnt/usb0/405/Sce.Vsh.RemotePlay.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20120/psm/Application/ClassLibrary1.sdll","/mnt/usb0/405/ClassLibrary1.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20120/psm/Application/Sce.Vsh.MarlinDownloaderWrapper.sdll","/mnt/usb0/405/Sce.Vsh.MarlinDownloaderWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/I18N.CJK.sdll","/mnt/usb0/405/I18N.CJK.sdll");
	decrypt_and_dump_self("/system/common/lib/I18N.sdll","/mnt/usb0/405/I18N.sdll");
	decrypt_and_dump_self("/system/common/lib/mscorlib.sdll","/mnt/usb0/405/mscorlib.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.PlayStation.Core.sdll","/mnt/usb0/405/Sce.PlayStation.Core.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.PlayStation.HighLevel.UI2.sdll","/mnt/usb0/405/Sce.PlayStation.HighLevel.UI2.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.PlayStation.HighLevel.UI2Platform.sdll","/mnt/usb0/405/Sce.PlayStation.HighLevel.UI2Platform.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.PlayStation.Ime.sdll","/mnt/usb0/405/Sce.PlayStation.Ime.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.PlayStation.Orbis.sdll","/mnt/usb0/405/Sce.PlayStation.Orbis.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.PlayStation.Orbis.Speech.sdll","/mnt/usb0/405/Sce.PlayStation.Orbis.Speech.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Accessor.Db.Notify.sdll","/mnt/usb0/405/Sce.Vsh.Accessor.Db.Notify.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Accessor.Db.sdll","/mnt/usb0/405/Sce.Vsh.Accessor.Db.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Accessor.sdll","/mnt/usb0/405/Sce.Vsh.Accessor.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.AppDbWrapper.sdll","/mnt/usb0/405/Sce.Vsh.AppDbWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.AppInstUtilWrapper.sdll","/mnt/usb0/405/Sce.Vsh.AppInstUtilWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.AutoMounterWrapper.sdll","/mnt/usb0/405/Sce.Vsh.AutoMounterWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.BackupRestoreUtil.sdll","/mnt/usb0/405/Sce.Vsh.BackupRestoreUtil.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.DataTransfer.sdll","/mnt/usb0/405/Sce.Vsh.DataTransfer.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Db.Shared.sdll","/mnt/usb0/405/Sce.Vsh.Db.Shared.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.DbPreparationWrapper.sdll","/mnt/usb0/405/Sce.Vsh.DbPreparationWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.DbRecoveryUtilityWrapper.sdll","/mnt/usb0/405/Sce.Vsh.DbRecoveryUtilityWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.ErrorDialogUtilWrapper.sdll","/mnt/usb0/405/Sce.Vsh.ErrorDialogUtilWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.EventServiceWrapper.sdll","/mnt/usb0/405/Sce.Vsh.EventServiceWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.FileSelector.sdll","/mnt/usb0/405/Sce.Vsh.FileSelector.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Friend.sdll","/mnt/usb0/405/Sce.Vsh.Friend.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.GameListRetrieverWrapper.sdll","/mnt/usb0/405/Sce.Vsh.GameListRetrieverWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Gls.GlsSharedMediaView.sdll","/mnt/usb0/405/Sce.Vsh.Gls.GlsSharedMediaView.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Gls.NativeCall.sdll","/mnt/usb0/405/Sce.Vsh.Gls.NativeCall.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.GriefReportStorage.sdll","/mnt/usb0/405/Sce.Vsh.GriefReportStorage.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.JsExtension.sdll","/mnt/usb0/405/Sce.Vsh.JsExtension.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.KernelSysWrapper.sdll","/mnt/usb0/405/Sce.Vsh.KernelSysWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Lx.sdll","/mnt/usb0/405/Sce.Vsh.Lx.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.MarlinDownloaderWrapper.sdll","/mnt/usb0/405/Sce.Vsh.MarlinDownloaderWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Messages.BgAccessLib.sdll","/mnt/usb0/405/Sce.Vsh.Messages.BgAccessLib.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Messages.DbAccessLib.sdll","/mnt/usb0/405/Sce.Vsh.Messages.DbAccessLib.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Messages.StorageAccessLib.sdll","/mnt/usb0/405/Sce.Vsh.Messages.StorageAccessLib.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.MimeType.sdll","/mnt/usb0/405/Sce.Vsh.MimeType.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.MorpheusUpdWrapper.sdll","/mnt/usb0/405/Sce.Vsh.MorpheusUpdWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.MyGameList.sdll","/mnt/usb0/405/Sce.Vsh.MyGameList.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.AppInfo.sdll","/mnt/usb0/405/Sce.Vsh.Np.AppInfo.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Asm.sdll","/mnt/usb0/405/Sce.Vsh.Np.Asm.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Common.sdll","/mnt/usb0/405/Sce.Vsh.Np.Common.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.IdMapper.sdll","/mnt/usb0/405/Sce.Vsh.Np.IdMapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Manager.sdll","/mnt/usb0/405/Sce.Vsh.Np.Manager.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.RifManager.sdll","/mnt/usb0/405/Sce.Vsh.Np.RifManager.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.ServiceChecker.sdll","/mnt/usb0/405/Sce.Vsh.Np.ServiceChecker.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.ServiceChecker2.sdll","/mnt/usb0/405/Sce.Vsh.Np.ServiceChecker2.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Sns.sdll","/mnt/usb0/405/Sce.Vsh.Np.Sns.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Tmdb.sdll","/mnt/usb0/405/Sce.Vsh.Np.Tmdb.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Trophy.sdll","/mnt/usb0/405/Sce.Vsh.Np.Trophy.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Np.Webapi.sdll","/mnt/usb0/405/Sce.Vsh.Np.Webapi.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Orbis.AbstractStorage.sdll","/mnt/usb0/405/Sce.Vsh.Orbis.AbstractStorage.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Orbis.Bgft.sdll","/mnt/usb0/405/Sce.Vsh.Orbis.Bgft.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Orbis.ContentManager.sdll","/mnt/usb0/405/Sce.Vsh.Orbis.ContentManager.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.PartyCommon.sdll","/mnt/usb0/405/Sce.Vsh.PartyCommon.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Passcode.sdll","/mnt/usb0/405/Sce.Vsh.Passcode.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.PatchCheckerClientWrapper.sdll","/mnt/usb0/405/Sce.Vsh.PatchCheckerClientWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.ProfileCache.sdll","/mnt/usb0/405/Sce.Vsh.ProfileCache.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.PsnMessageUtil.sdll","/mnt/usb0/405/Sce.Vsh.PsnMessageUtil.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.PsnUtil.sdll","/mnt/usb0/405/Sce.Vsh.PsnUtil.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Registry.sdll","/mnt/usb0/405/Sce.Vsh.Registry.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.RequestShareScreen.sdll","/mnt/usb0/405/Sce.Vsh.RequestShareScreen.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.RequestShareStorageWrapper.sdll","/mnt/usb0/405/Sce.Vsh.RequestShareStorageWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.sdll","/mnt/usb0/405/Sce.Vsh.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.SessionInvitation.sdll","/mnt/usb0/405/Sce.Vsh.SessionInvitation.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.ShareServerPostWrapper.sdll","/mnt/usb0/405/Sce.Vsh.ShareServerPostWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.ShellCoreUtilWrapper.sdll","/mnt/usb0/405/Sce.Vsh.ShellCoreUtilWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.SQLite.sdll","/mnt/usb0/405/Sce.Vsh.SQLite.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Sticker.StickerLibAccessor.sdll","/mnt/usb0/405/Sce.Vsh.Sticker.StickerLibAccessor.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.SyscallWrapper.sdll","/mnt/usb0/405/Sce.Vsh.SyscallWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.SysfileUtilWrapper.sdll","/mnt/usb0/405/Sce.Vsh.SysfileUtilWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.SystemLoggerWrapper.sdll","/mnt/usb0/405/Sce.Vsh.SystemLoggerWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.SysUtilWrapper.sdll","/mnt/usb0/405/Sce.Vsh.SysUtilWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Theme.sdll","/mnt/usb0/405/Sce.Vsh.Theme.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.UpdateServiceWrapper.sdll","/mnt/usb0/405/Sce.Vsh.UpdateServiceWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.UsbStorageScene.sdll","/mnt/usb0/405/Sce.Vsh.UsbStorageScene.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.UserServiceWrapper.sdll","/mnt/usb0/405/Sce.Vsh.UserServiceWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.VideoServiceWrapper.sdll","/mnt/usb0/405/Sce.Vsh.VideoServiceWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.VoiceMsg.VoiceMsgWrapper.sdll","/mnt/usb0/405/Sce.Vsh.VoiceMsg.VoiceMsgWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.VrEnvironment.sdll","/mnt/usb0/405/Sce.Vsh.VrEnvironment.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.WebBrowser.sdll","/mnt/usb0/405/Sce.Vsh.WebBrowser.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Webbrowser.XdbWrapper.sdll","/mnt/usb0/405/Sce.Vsh.Webbrowser.XdbWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.Webbrowser.XutilWrapper.sdll","/mnt/usb0/405/Sce.Vsh.Webbrowser.XutilWrapper.sdll");
	decrypt_and_dump_self("/system/common/lib/Sce.Vsh.WebViewDialog.sdll","/mnt/usb0/405/Sce.Vsh.WebViewDialog.sdll");
	decrypt_and_dump_self("/system/common/lib/System.Core.sdll","/mnt/usb0/405/System.Core.sdll");
	decrypt_and_dump_self("/system/common/lib/System.Json.sdll","/mnt/usb0/405/System.Json.sdll");
	decrypt_and_dump_self("/system/common/lib/System.Runtime.Serialization.sdll","/mnt/usb0/405/System.Runtime.Serialization.sdll");
	decrypt_and_dump_self("/system/common/lib/System.sdll","/mnt/usb0/405/System.sdll");
	decrypt_and_dump_self("/system/common/lib/System.ServiceModel.sdll","/mnt/usb0/405/System.ServiceModel.sdll");
	decrypt_and_dump_self("/system/common/lib/System.ServiceModel.Web.sdll","/mnt/usb0/405/System.ServiceModel.Web.sdll");
	decrypt_and_dump_self("/system/common/lib/System.Web.Services.sdll","/mnt/usb0/405/System.Web.Services.sdll");
	decrypt_and_dump_self("/system/common/lib/System.Xml.Linq.sdll","/mnt/usb0/405/System.Xml.Linq.sdll");
	decrypt_and_dump_self("/system/common/lib/System.Xml.sdll","/mnt/usb0/405/System.Xml.sdll");
	decrypt_and_dump_self("/system/vsh/app/NPXS22010/psm/Application/Sce.Cdlg.Platform.sdll","/mnt/usb0/405/Sce.Cdlg.Platform.sdll");
	decrypt_and_dump_self("/system/vsh/app/NPXS22010/psm/Application/Sce.Vsh.ShellUIUtilWrapper.sdll","/mnt/usb0/Sce.Vsh.ShellUIUtilWrapper.sdll");
	decrypt_and_dump_self("/system/vsh/sce_video_service/psm/Application/Sce.Vsh.VideoFramework.Platform.sdll","/mnt/usb0/405/Sce.Vsh.VideoFramework.Platform.sdll");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/psm/Application/app.sexe","/mnt/usb0/405/NPXS20001-app.sexe");
	decrypt_and_dump_self("/system_ex/app/NPXS20103/psm/Application/app.sexe","/mnt/usb0/405/NPXS20103-app.sexe");
	decrypt_and_dump_self("/system_ex/app/NPXS20113/psm/Application/app.sexe","/mnt/usb0/405/NPXS20113-app.sexe");
	decrypt_and_dump_self("/system_ex/app/NPXS20114/psm/Application/app.sexe","/mnt/usb0/405/NPXS20114-app.sexe");
	decrypt_and_dump_self("/system_ex/app/NPXS20118/psm/Application/app.sexe","/mnt/usb0/405/NPXS20118-app.sexe");
	decrypt_and_dump_self("/system_ex/app/NPXS20120/psm/Application/app.sexe","/mnt/usb0/405/NPXS20120-app.sexe");
	decrypt_and_dump_self("/system/vsh/app/NPXS22010/psm/Application/app.sexe","/mnt/usb0/405/NPXS22010-app.sexe");
	decrypt_and_dump_self("/system/vsh/sce_video_service/psm/Application/app.sexe","/mnt/usb0/405/sce_video_service-app.sexe");
	decrypt_and_dump_self("/system_ex/app/NPXS20120/avbaseMiniApp.self","/mnt/usb0/405/NPXS20120-avbaseMiniApp.self");
	decrypt_and_dump_self("/system/common/lib/orbis-jsc-compiler.self","/mnt/usb0/405/orbis-jsc-compiler.self");
	decrypt_and_dump_self("/system/common/lib/ScePlayReady.self","/mnt/usb0/405/ScePlayReady.self");
	decrypt_and_dump_self("/system/common/lib/SecureUIProcess.self","/mnt/usb0/405/SecureUIProcess.self");
	decrypt_and_dump_self("/system/common/lib/SecureWebProcess.self","/mnt/usb0/405/SecureWebProcess.self");
	decrypt_and_dump_self("/system/common/lib/swagner.self","/mnt/usb0/405/swagner.self");
	decrypt_and_dump_self("/system/common/lib/swreset.self","/mnt/usb0/405/swreset.self");
	decrypt_and_dump_self("/system/common/lib/UIProcess.self","/mnt/usb0/405/UIProcess.self");
	decrypt_and_dump_self("/system/common/lib/webapp.self","/mnt/usb0/405/webapp.self");
	decrypt_and_dump_self("/system/common/lib/WebBrowserUIProcess.self","/mnt/usb0/405/WebBrowserUIProcess.self");
	decrypt_and_dump_self("/system/common/lib/WebProcess.self","/mnt/usb0/405/WebProcess.self");
	decrypt_and_dump_self("/system/common/lib/WebProcessHeapLimited.self","/mnt/usb0/405/WebProcessHeapLimited.self");
	decrypt_and_dump_self("/system/common/lib/WebProcessHTMLTile.self","/mnt/usb0/405/WebProcessHTMLTile.self");
	decrypt_and_dump_self("/system/common/lib/WebProcessWebApp.self","/mnt/usb0/405/WebProcessWebApp.self");
	decrypt_and_dump_self("/system/vsh/app/NPXS21007/BgmPlayerCore.self","/mnt/usb0/405/NPXS21007-BgmPlayerCore.self");
	decrypt_and_dump_self("/system/vsh/app/NPXS21007/BgmPlayerCore2.self","/mnt/usb0/405/NPXS21007-BgmPlayerCore2.self");
	decrypt_and_dump_self("/system_ex/app/NPXS20113/bdj.elf","/mnt/usb0/405/NPXS20113-bdj.elf");
	decrypt_and_dump_self("/system_ex/app/NPXS20113/BdmvPlayerCore.elf","/mnt/usb0/405/NPXS20113-BdmvPlayerCore.elf");
	decrypt_and_dump_self("/system_ex/app/NPXS20113/BdvdPlayerCore.elf","/mnt/usb0/405/NPXS20113-BdvdPlayerCore.elf");
	decrypt_and_dump_self("/system_ex/app/NPXS20113/bdjstack/bin/JavaJitCompiler.elf","/mnt/usb0/405/NPXS20113-bdjstack-JavaJitCompiler.elf");
	decrypt_and_dump_self("/system/common/lib/custom_video_core.elf","/mnt/usb0/405/custom_video_core.elf");
	decrypt_and_dump_self("/system/common/lib/MonoCompiler.elf","/mnt/usb0/405/MonoCompiler.elf");
	decrypt_and_dump_self("/system/sys/coredump.elf","/mnt/usb0/405/coredump.elf");
	decrypt_and_dump_self("/system/sys/fs_cleaner.elf","/mnt/usb0/405/fs_cleaner.elf");
	decrypt_and_dump_self("/system/sys/GnmCompositor.elf","/mnt/usb0/405/GnmCompositor.elf");
	decrypt_and_dump_self("/system/sys/gpudump.elf","/mnt/usb0/405/gpudump.elf");
	decrypt_and_dump_self("/system/sys/orbis_audiod.elf","/mnt/usb0/405/orbis_audiod.elf");
	decrypt_and_dump_self("/system/sys/orbis_setip.elf","/mnt/usb0/405/orbis_setip.elf");
	decrypt_and_dump_self("/system/sys/SceSysCore.elf","/mnt/usb0/405/SceSysCore.elf");
	decrypt_and_dump_self("/system/sys/SceVdecProxy.elf","/mnt/usb0/405/SceVdecProxy.elf");
	decrypt_and_dump_self("/system/sys/SceVencProxy.elf","/mnt/usb0/405/SceVencProxy.elf");
	decrypt_and_dump_self("/system/vsh/SceShellCore.elf","/mnt/usb0/vsh/SceShellCore.elf");
	decrypt_and_dump_self("/system/vsh/app/NPXS21004/avbase.elf","/mnt/usb0/405/NPXS21004-avbase.elf");
	decrypt_and_dump_self("/system/vsh/app/NPXS21004/becore.elf","/mnt/usb0/405/NPXS21004-becore.elf");
	decrypt_and_dump_self("/system_ex/app/NPXS20001/libSceVsh_aot.sprx","/mnt/usb0/405/NPXS20001-libSceVsh_aot.sprx");
	decrypt_and_dump_self("/system_ex/app/NPXS20113/libAacs.sprx","/mnt/usb0/405/NPXS20113-libAacs.sprx");
	decrypt_and_dump_self("/system_ex/app/NPXS20113/libBdplus.sprx","/mnt/usb0/405/NPXS20113-libBdplus.sprx");
	decrypt_and_dump_self("/system_ex/app/NPXS20113/libCprm.sprx","/mnt/usb0/405/NPXS20113-libCprm.sprx");
	decrypt_and_dump_self("/system_ex/app/NPXS20113/libCss.sprx","/mnt/usb0/405/NPXS20113-libCss.sprx");
	decrypt_and_dump_self("/system_ex/app/NPXS20118/gaikai-player.sprx","/mnt/usb0/405/NPXS20118-gaikai-player.sprx");
	decrypt_and_dump_self("/system_ex/app/NPXS20120/libSceWebApp_aot.sprx","/mnt/usb0/405/NPXS20120-libSceWebApp_aot.sprx");
	decrypt_and_dump_self("/system/common/lib/libc.sprx","/mnt/usb0/405/libc.sprx");
	decrypt_and_dump_self("/system/common/lib/libkernel.sprx","/mnt/usb0/405/libkernel.sprx");
	decrypt_and_dump_self("/system/common/lib/libkernel_sys.sprx","/mnt/usb0/405/libkernel_sys.sprx");
	decrypt_and_dump_self("/system/common/lib/libkernel_web.sprx","/mnt/usb0/405/libkernel_web.sprx");
	decrypt_and_dump_self("/system/common/lib/libMonoCompiler.sprx","/mnt/usb0/405/libMonoCompiler.sprx");
	decrypt_and_dump_self("/system/common/lib/libMonoCompilerBridge.sprx","/mnt/usb0/405/libMonoCompilerBridge.sprx");
	decrypt_and_dump_self("/system/common/lib/libMonoLogProfiler.sprx","/mnt/usb0/405/libMonoLogProfiler.sprx");
	decrypt_and_dump_self("/system/common/lib/libMonoVirtualMachine.sprx","/mnt/usb0/405/libMonoVirtualMachine.sprx");
	decrypt_and_dump_self("/system/common/lib/libMonoVirtualMachineBridge.sprx","/mnt/usb0/405/libMonoVirtualMachineBridge.sprx");
	decrypt_and_dump_self("/system/common/lib/libMonoWrapperProfiler.sprx","/mnt/usb0/405/libMonoWrapperProfiler.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAbstractDailymotion.sprx","/mnt/usb0/405/libSceAbstractDailymotion.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAbstractFacebook.sprx","/mnt/usb0/405/libSceAbstractFacebook.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAbstractLocal.sprx","/mnt/usb0/405/libSceAbstractLocal.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAbstractStorage.sprx","/mnt/usb0/405/libSceAbstractStorage.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAbstractTwitter.sprx","/mnt/usb0/405/libSceAbstractTwitter.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAbstractYoutube.sprx","/mnt/usb0/405/libSceAbstractYoutube.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAjm.sprx","/mnt/usb0/405/libSceAjm.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAppContent.sprx","/mnt/usb0/405/libSceAppContent.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAppInstUtil.sprx","/mnt/usb0/405/libSceAppInstUtil.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAt9Enc.sprx","/mnt/usb0/405/libSceAt9Enc.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAudio3d.sprx","/mnt/usb0/405/libSceAudio3d.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAudiodec.sprx","/mnt/usb0/405/libSceAudiodec.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAudiodecCpu.sprx","/mnt/usb0/405/libSceAudiodecCpu.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAudiodecCpuDdp.sprx","/mnt/usb0/405/libSceAudiodecCpuDdp.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAudiodecCpuDtsHdLbr.sprx","/mnt/usb0/405/libSceAudiodecCpuDtsHdLbr.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAudiodecCpuHevag.sprx","/mnt/usb0/405/libSceAudiodecCpuHevag.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAudiodecCpuM4aac.sprx","/mnt/usb0/405/libSceAudiodecCpuM4aac.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAudioIn.sprx","/mnt/usb0/405/libSceAudioIn.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAudioOut.sprx","/mnt/usb0/405/libSceAudioOut.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAutoMounterClient.sprx","/mnt/usb0/405/libSceAutoMounterClient.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAvcap.sprx","/mnt/usb0/405/libSceAvcap.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAvPlayer.sprx","/mnt/usb0/405/libSceAvPlayer.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAvPlayerStreaming.sprx","/mnt/usb0/405/libSceAvPlayerStreaming.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceAvSetting.sprx","/mnt/usb0/405/libSceAvSetting.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceBackupRestoreUtil.sprx","/mnt/usb0/405/libSceBackupRestoreUtil.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceBeisobmf.sprx","/mnt/usb0/405/libSceBeisobmf.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceBemp2sys.sprx","/mnt/usb0/405/libSceBemp2sys.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceBgft.sprx","/mnt/usb0/405/libSceBgft.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceBluetoothHid.sprx","/mnt/usb0/405/libSceBluetoothHid.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceCamera.sprx","/mnt/usb0/405/libSceCamera.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceCdlgUtilServer.sprx","/mnt/usb0/405/libSceCdlgUtilServer.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceClSysCallWrapper.sprx","/mnt/usb0/405/libSceClSysCallWrapper.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceCommonDialog.sprx","/mnt/usb0/405/libSceCommonDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceCompanionHttpd.sprx","/mnt/usb0/405/libSceCompanionHttpd.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceCompanionUtil.sprx","/mnt/usb0/405/libSceCompanionUtil.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceCompositeExt.sprx","/mnt/usb0/405/libSceCompositeExt.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceContentDelete.sprx","/mnt/usb0/405/libSceContentDelete.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceContentExport.sprx","/mnt/usb0/405/libSceContentExport.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceContentSearch.sprx","/mnt/usb0/405/libSceContentSearch.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceConvertKeycode.sprx","/mnt/usb0/405/libSceConvertKeycode.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceCoreIPC.sprx","/mnt/usb0/405/libSceCoreIPC.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceCustomMusicCore.sprx","/mnt/usb0/405/libSceCustomMusicCore.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceCustomMusicService.sprx","/mnt/usb0/405/libSceCustomMusicService.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceDataTransfer.sprx","/mnt/usb0/405/libSceDataTransfer.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceDepth.sprx","/mnt/usb0/405/libSceDepth.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceDiscMap.sprx","/mnt/usb0/405/libSceDiscMap.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceDtcpIp.sprx","/mnt/usb0/405/libSceDtcpIp.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceEditMp4.sprx","/mnt/usb0/405/libSceEditMp4.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceErrorDialog.sprx","/mnt/usb0/405/libSceErrorDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceFiber.sprx","/mnt/usb0/405/libSceFiber.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceFios2.sprx","/mnt/usb0/405/libSceFios2.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceFont.sprx","/mnt/usb0/405/libSceFont.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceFontFt.sprx","/mnt/usb0/405/libSceFontFt.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceFreeTypeHinter.sprx","/mnt/usb0/405/libSceFreeTypeHinter.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceFreeTypeOl.sprx","/mnt/usb0/405/libSceFreeTypeOl.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceFreeTypeOptOl.sprx","/mnt/usb0/405/libSceFreeTypeOptOl.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceFreeTypeOt.sprx","/mnt/usb0/405/libSceFreeTypeOt.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceFreeTypeSubFunc.sprx","/mnt/usb0/405/libSceFreeTypeSubFunc.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceGameCustomDataDialog.sprx","/mnt/usb0/405/libSceGameCustomDataDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceGameLiveStreaming.sprx","/mnt/usb0/405/libSceGameLiveStreaming.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceGameUpdate.sprx","/mnt/usb0/405/libSceGameUpdate.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceGifParser.sprx","/mnt/usb0/405/libSceGifParser.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceGnmDriver.sprx","/mnt/usb0/405/libSceGnmDriver.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceGnmDriverForNeoMode.sprx","/mnt/usb0/405/libSceGnmDriverForNeoMode.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceGvMp4Parser.sprx","/mnt/usb0/405/libSceGvMp4Parser.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceHidControl.sprx","/mnt/usb0/405/libSceHidControl.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceHmd.sprx","/mnt/usb0/405/libSceHmd.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceHmdSetupDialog.sprx","/mnt/usb0/405/libSceHmdSetupDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceHttp.sprx","/mnt/usb0/405/libSceHttp.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceIduUtil.sprx","/mnt/usb0/405/libSceIduUtil.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceImageUtil.sprx","/mnt/usb0/405/libSceImageUtil.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceIme.sprx","/mnt/usb0/405/libSceIme.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceImeBackend.sprx","/mnt/usb0/405/libSceImeBackend.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceImeDialog.sprx","/mnt/usb0/405/libSceImeDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceInjectedBundle.sprx","/mnt/usb0/405/libSceInjectedBundle.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceInvitationDialog.sprx","/mnt/usb0/405/libSceInvitationDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceIpmi.sprx","/mnt/usb0/405/libSceIpmi.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceJitBridge.sprx","/mnt/usb0/405/libSceJitBridge.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceJpegDec.sprx","/mnt/usb0/405/libSceJpegDec.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceJpegEnc.sprx","/mnt/usb0/405/libSceJpegEnc.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceJpegParser.sprx","/mnt/usb0/405/libSceJpegParser.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceJscCompiler.sprx","/mnt/usb0/405/libSceJscCompiler.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceJson.sprx","/mnt/usb0/405/libSceJson.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceJson2.sprx","/mnt/usb0/405/libSceJson2.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceKbEmulate.sprx","/mnt/usb0/405/libSceKbEmulate.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceKeyboard.sprx","/mnt/usb0/405/libSceKeyboard.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceLibcInternal.sprx","/mnt/usb0/405/libSceLibcInternal.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceLoginDialog.sprx","/mnt/usb0/405/libSceLoginDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceLoginService.sprx","/mnt/usb0/405/libSceLoginService.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceM4aacEnc.sprx","/mnt/usb0/405/libSceM4aacEnc.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceManxWtf.sprx","/mnt/usb0/405/libSceManxWtf.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceMbus.sprx","/mnt/usb0/405/libSceMbus.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceMetadataReaderWriter.sprx","/mnt/usb0/405/libSceMetadataReaderWriter.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceMouse.sprx","/mnt/usb0/405/libSceMouse.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceMove.sprx","/mnt/usb0/405/libSceMove.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceMoveTracker.sprx","/mnt/usb0/405/libSceMoveTracker.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceMsgDialog.sprx","/mnt/usb0/405/libSceMsgDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceMusicCoreServerClient.sprx","/mnt/usb0/405/libSceMusicCoreServerClient.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceMusicCoreServerClientJsEx.sprx","/mnt/usb0/405/libSceMusicCoreServerClientJsEx.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceMusicPlayerService.sprx","/mnt/usb0/405/libSceMusicPlayerService.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNet.sprx","/mnt/usb0/405/libSceNet.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNetCtl.sprx","/mnt/usb0/405/libSceNetCtl.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNetCtlApDialog.sprx","/mnt/usb0/405/libSceNetCtlApDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNgs2.sprx","/mnt/usb0/405/libSceNgs2.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpAuth.sprx","/mnt/usb0/405/libSceNpAuth.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpCommerce.sprx","/mnt/usb0/405/libSceNpCommerce.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpCommon.sprx","/mnt/usb0/405/libSceNpCommon.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpEulaDialog.sprx","/mnt/usb0/405/libSceNpEulaDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpFriendListDialog.sprx","/mnt/usb0/405/libSceNpFriendListDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpGriefReport.sprx","/mnt/usb0/405/libSceNpGriefReport.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpManager.sprx","/mnt/usb0/405/libSceNpManager.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpMatching2.sprx","/mnt/usb0/405/libSceNpMatching2.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpParty.sprx","/mnt/usb0/405/libSceNpParty.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpProfileDialog.sprx","/mnt/usb0/405/libSceNpProfileDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpScoreRanking.sprx","/mnt/usb0/405/libSceNpScoreRanking.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpSignaling.sprx","/mnt/usb0/405/libSceNpSignaling.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpSns.sprx","/mnt/usb0/405/libSceNpSns.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpSnsDailymotionDialog.sprx","/mnt/usb0/405/libSceNpSnsDailymotionDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpSnsDialog.sprx","/mnt/usb0/405/libSceNpSnsDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpSnsFacebookDialog.sprx","/mnt/usb0/405/libSceNpSnsFacebookDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpSnsYouTubeDialog.sprx","/mnt/usb0/405/libSceNpSnsYouTubeDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpTrophy.sprx","/mnt/usb0/405/libSceNpTrophy.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpTus.sprx","/mnt/usb0/405/libSceNpTus.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpUtility.sprx","/mnt/usb0/405/libSceNpUtility.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceNpWebApi.sprx","/mnt/usb0/405/libSceNpWebApi.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceOpusCeltDec.sprx","/mnt/usb0/405/libSceOpusCeltDec.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceOrbisCompat.sprx","/mnt/usb0/405/libSceOrbisCompat.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceOrbisCompatForVideoService.sprx","/mnt/usb0/405/libSceOrbisCompatForVideoService.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePad.sprx","/mnt/usb0/405/libScePad.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePadTracker.sprx","/mnt/usb0/405/libScePadTracker.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePatchCheckerClient.sprx","/mnt/usb0/405/libScePatchCheckerClient.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePigletv2VSH.sprx","/mnt/usb0/405/libScePigletv2VSH.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePlayGo.sprx","/mnt/usb0/405/libScePlayGo.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePlayGoDialog.sprx","/mnt/usb0/405/libScePlayGoDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePlayReady.sprx","/mnt/usb0/405/libScePlayReady.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePngDec.sprx","/mnt/usb0/405/libScePngDec.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePngEnc.sprx","/mnt/usb0/405/libScePngEnc.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePngParser.sprx","/mnt/usb0/405/libScePngParser.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceProfileCacheExternal.sprx","/mnt/usb0/405/libSceProfileCacheExternal.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePs2EmuMenuDialog.sprx","/mnt/usb0/405/libScePs2EmuMenuDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePsm.sprx","/mnt/usb0/405/libScePsm.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePsmKitSystem.sprx","/mnt/usb0/405/libScePsmKitSystem.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePsmUtil.sprx","/mnt/usb0/405/libScePsmUtil.sprx");
	decrypt_and_dump_self("/system/common/lib/libScePsm_aot.sprx","/mnt/usb0/405/libScePsm_aot.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceRandom.sprx","/mnt/usb0/405/libSceRandom.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceRegMgr.sprx","/mnt/usb0/405/libSceRegMgr.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceRemoteplay.sprx","/mnt/usb0/405/libSceRemoteplay.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceRtc.sprx","/mnt/usb0/405/libSceRtc.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceRudp.sprx","/mnt/usb0/405/libSceRudp.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSaveData.sprx","/mnt/usb0/405/libSceSaveData.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSaveDataDialog.sprx","/mnt/usb0/405/libSceSaveDataDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceScm.sprx","/mnt/usb0/405/libSceScm.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceScreenShot.sprx","/mnt/usb0/405/libSceScreenShot.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceShareFactoryUtil.sprx","/mnt/usb0/405/libSceShareFactoryUtil.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSharePlay.sprx","/mnt/usb0/405/libSceSharePlay.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceShareUtility.sprx","/mnt/usb0/405/libSceShareUtility.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceShellUIUtil.sprx","/mnt/usb0/405/libSceShellUIUtil.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSigninDialog.sprx","/mnt/usb0/405/libSceSigninDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSocialScreen.sprx","/mnt/usb0/405/libSceSocialScreen.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSocialScreenDialog.sprx","/mnt/usb0/405/libSceSocialScreenDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSpSysCallWrapper.sprx","/mnt/usb0/405/libSceSpSysCallWrapper.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSsl.sprx","/mnt/usb0/405/libSceSsl.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSysCore.sprx","/mnt/usb0/405/libSceSysCore.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSysmodule.sprx","/mnt/usb0/405/libSceSysmodule.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSystemGesture.sprx","/mnt/usb0/405/libSceSystemGesture.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSystemLogger.sprx","/mnt/usb0/405/libSceSystemLogger.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSystemService.sprx","/mnt/usb0/405/libSceSystemService.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceSysUtil.sprx","/mnt/usb0/405/libSceSysUtil.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceTextToSpeech.sprx","/mnt/usb0/405/libSceTextToSpeech.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceTtsCoreEnUs.sprx","/mnt/usb0/405/libSceTtsCoreEnUs.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceTtsCoreJp.sprx","/mnt/usb0/405/libSceTtsCoreJp.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceUlt.sprx","/mnt/usb0/405/libSceUlt.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceUpdateService.sprx","/mnt/usb0/405/libSceUpdateService.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceUsbd.sprx","/mnt/usb0/405/libSceUsbd.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceUsbStorage.sprx","/mnt/usb0/405/libSceUsbStorage.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceUsbStorageDialog.sprx","/mnt/usb0/405/libSceUsbStorageDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceUserService.sprx","/mnt/usb0/405/libSceUserService.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVdecCore.sprx","/mnt/usb0/405/libSceVdecCore.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVdecSavc.sprx","/mnt/usb0/405/libSceVdecSavc.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVdecSavc2.sprx","/mnt/usb0/405/libSceVdecSavc2.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVdecShevc.sprx","/mnt/usb0/405/libSceVdecShevc.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVdecsw.sprx","/mnt/usb0/405/libSceVdecsw.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVdecwrap.sprx","/mnt/usb0/405/libSceVdecwrap.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVideoCoreInterface.sprx","/mnt/usb0/405/libSceVideoCoreInterface.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVideoCoreServerInterface.sprx","/mnt/usb0/405/libSceVideoCoreServerInterface.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVideodec.sprx","/mnt/usb0/405/libSceVideodec.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVideodec2.sprx","/mnt/usb0/405/libSceVideodec2.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVideoDecoderArbitration.sprx","/mnt/usb0/405/libSceVideoDecoderArbitration.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVideoNativeExtEssential.sprx","/mnt/usb0/405/libSceVideoNativeExtEssential.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVideoOut.sprx","/mnt/usb0/405/libSceVideoOut.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVideoOutSecondary.sprx","/mnt/usb0/405/libSceVideoOutSecondary.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVideoRecording.sprx","/mnt/usb0/405/libSceVideoRecording.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVoice.sprx","/mnt/usb0/405/libSceVoice.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVoiceQoS.sprx","/mnt/usb0/405/libSceVoiceQoS.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVrServiceDialog.sprx","/mnt/usb0/405/libSceVrServiceDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVrTracker.sprx","/mnt/usb0/405/libSceVrTracker.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceVshCommon_aot.sprx","/mnt/usb0/405/libSceVshCommon_aot.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceWeb.sprx","/mnt/usb0/405/libSceWeb.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceWebBrowserDialog.sprx","/mnt/usb0/405/libSceWebBrowserDialog.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceWebBrowserInjectedBundle.sprx","/mnt/usb0/405/libSceWebBrowserInjectedBundle.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceWebCdlgInjectedBundle.sprx","/mnt/usb0/405/libSceWebCdlgInjectedBundle.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceWebForVideoService.sprx","/mnt/usb0/405/libSceWebForVideoService.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceWebKit2.sprx","/mnt/usb0/405/libSceWebKit2.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceWebKit2ForVideoService.sprx","/mnt/usb0/405/libSceWebKit2ForVideoService.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceWebKit2Secure.sprx","/mnt/usb0/405/libSceWebKit2Secure.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceWkFontConfig.sprx","/mnt/usb0/405/libSceWkFontConfig.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceXml.sprx","/mnt/usb0/405/libSceXml.sprx");
	decrypt_and_dump_self("/system/common/lib/libSceZlib.sprx","/mnt/usb0/405/libSceZlib.sprx");
	decrypt_and_dump_self("/system/common/lib/libswctrl.sprx","/mnt/usb0/405/libswctrl.sprx");
	decrypt_and_dump_self("/system/common/lib/libswreset.sprx","/mnt/usb0/405/libswreset.sprx");
	decrypt_and_dump_self("/system/common/lib/ulobjmgr.sprx","/mnt/usb0/405/ulobjmgr.sprx");
	decrypt_and_dump_self("/system/common/lib/WebAppBundle.sprx","/mnt/usb0/405/WebAppBundle.sprx");
	decrypt_and_dump_self("/system/priv/lib/libmdbg_syscore.sprx","/mnt/usb0/405/libmdbg_syscore.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceAc3Enc.sprx","/mnt/usb0/405/libSceAc3Enc.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceAudiodecCpuDts.sprx","/mnt/usb0/405/libSceAudiodecCpuDts.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceAudiodecCpuDtsHdMa.sprx","/mnt/usb0/405/libSceAudiodecCpuDtsHdMa.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceAudiodecCpuLpcm.sprx","/mnt/usb0/405/libSceAudiodecCpuLpcm.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceAudiodReport.sprx","/mnt/usb0/405/libSceAudiodReport.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceComposite.sprx","/mnt/usb0/405/libSceComposite.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceDipsw.sprx","/mnt/usb0/405/libSceDipsw.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceDiscMapForVsh.sprx","/mnt/usb0/405/libSceDiscMapForVsh.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceDseehx.sprx","/mnt/usb0/405/libSceDseehx.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceDtsEnc.sprx","/mnt/usb0/405/libSceDtsEnc.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceGnmDriver_sys.sprx","/mnt/usb0/405/libSceGnmDriver_sys.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceLoginMgrServer.sprx","/mnt/usb0/405/libSceLoginMgrServer.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceMarlin.sprx","/mnt/usb0/405/libSceMarlin.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceOpusCeltEnc.sprx","/mnt/usb0/405/libSceOpusCeltEnc.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceS3da.sprx","/mnt/usb0/405/libSceS3da.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceSdma.sprx","/mnt/usb0/405/libSceSdma.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceSrcUtl.sprx","/mnt/usb0/405/libSceSrcUtl.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceSulphaDrv.sprx","/mnt/usb0/405/libSceSulphaDrv.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceVencCore.sprx","/mnt/usb0/405/libSceVencCore.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceVencCoreForNeo.sprx","/mnt/usb0/405/libSceVencCoreForNeo.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceVisionManager.sprx","/mnt/usb0/405/libSceVisionManager.sprx");
	decrypt_and_dump_self("/system/priv/lib/libSceVorbisDec.sprx","/mnt/usb0/405/libSceVorbisDec.sprx");
	decrypt_and_dump_self("/system/vsh/app/NPXS22010/libSceCdlg_aot.sprx","/mnt/usb0/405/NPXS22010-libSceCdlg_aot.sprx");

	// dont forget to close the socket
	sceNetSocketClose(sock);

    return 0;
}


