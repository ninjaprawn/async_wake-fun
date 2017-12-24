//
//  fun.h
//  async_wake_ios
//
//  Created by George on 14/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#ifndef fun_h
#define fun_h

#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#import <sys/mount.h>
#import <spawn.h>
#import <copyfile.h>
#import <mach-o/dyld.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <sys/utsname.h>

#include <mach/mach.h>

#include <pthread.h>

#include <Foundation/Foundation.h>

#include "kmem.h"
#include "find_port.h"
#include "kutils.h"
#include "symbols.h"
#include "early_kalloc.h"
#include "kdbg.h"
#include "patchfinder64.h"

#include "fun_objc.h"
#include "fun_utils.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

extern uint64_t iokit_user_client_trap(
									   mach_port_t connect,
									   unsigned int index,
									   uintptr_t p1,
									   uintptr_t p2,
									   uintptr_t p3,
									   uintptr_t p4,
									   uintptr_t p5,
									   uintptr_t p6 );


void let_the_fun_begin(mach_port_t tfp0, mach_port_t user_client);

#endif /* fun_h */
