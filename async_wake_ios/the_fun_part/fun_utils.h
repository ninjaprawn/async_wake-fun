//
//  fun_utils.h
//  async_wake_ios
//
//  Created by George on 18/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#ifndef fun_utils_h
#define fun_utils_h

#include <stdio.h>
#include <mach-o/loader.h>
#include <CommonCrypto/CommonDigest.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <mach/mach.h>
#include <sys/stat.h>


#include "find_port.h"

// Needed definitions
kern_return_t mach_vm_allocate(vm_map_t target, mach_vm_address_t *address, mach_vm_size_t size, int flags);
kern_return_t mach_vm_read_overwrite(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, mach_vm_address_t data, mach_vm_size_t *outsize);
kern_return_t mach_vm_write(vm_map_t target_task, mach_vm_address_t address, vm_offset_t data, mach_msg_type_number_t dataCnt);

// "General" purpose
uint8_t *get_sha256(uint8_t* code_dir);
uint8_t *get_code_directory(const char* name);
int cp(const char *from, const char *to);
int file_exist(char *filename);

// Kernel utility stuff
void init_kernel_utils(mach_port_t tfp0, mach_port_t user_client);
uint64_t kalloc(vm_size_t size);
size_t kread(uint64_t where, void *p, size_t size);
uint32_t kread32(uint64_t where);
uint64_t kread64(uint64_t where);
size_t kwrite(uint64_t where, const void *p, size_t size);
void kwrite32(uint64_t where, uint32_t what);
void kwrite64(uint64_t where, uint64_t what);

#endif /* fun_utils_h */
