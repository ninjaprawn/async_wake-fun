//
//  fun_utils.c
//  async_wake_ios
//
//  Created by George on 18/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include "fun_utils.h"

uint32_t swap_uint32(uint32_t val) {
	val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
	return (val << 16) | (val >> 16);
}

uint8_t *get_sha256(uint8_t* code_dir) {
	uint8_t *out = malloc(CC_SHA256_DIGEST_LENGTH);
	
	uint32_t* code_dir_int = (uint32_t*)code_dir;
	
	uint32_t realsize = 0;
	for (int j = 0; j < 10; j++) {
		if (swap_uint32(code_dir_int[j]) == 0xfade0c02) {
			realsize = swap_uint32(code_dir_int[j+1]);
			code_dir += 4*j;
		}
	}
	
	CC_SHA256(code_dir, realsize, out);
	
	return out;
}

uint8_t *get_code_directory(const char* name) {
	// Assuming it is a macho
	
	FILE* fd = fopen(name, "r");
	
	printf("%s\n", name);
	
	struct mach_header_64 mh;
	fread(&mh, sizeof(struct mach_header_64), 1, fd);
	
	long off = sizeof(struct mach_header_64);
	for (int i = 0; i < mh.ncmds; i++) {
		const struct load_command cmd;
		fseek(fd, off, SEEK_SET);
		fread(&cmd, sizeof(struct load_command), 1, fd);
		if (cmd.cmd == 0x1d) {
			uint32_t off_cs;
			fread(&off_cs, sizeof(uint32_t), 1, fd);
			uint32_t size_cs;
			fread(&size_cs, sizeof(uint32_t), 1, fd);
			
			uint8_t *cd = malloc(size_cs);
			fseek(fd, off_cs, SEEK_SET);
			fread(cd, size_cs, 1, fd);
			return cd;
		} else {
			off += cmd.cmdsize;
		}
	}
	return NULL;
}


int cp(const char *from, const char *to) {
	int fd_to, fd_from;
	char buf[4096];
	ssize_t nread;
	int saved_errno;
	
	fd_from = open(from, O_RDONLY);
	if (fd_from < 0)
		return -1;
	
	fd_to = open(to, O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (fd_to < 0)
		goto out_error;
	
	while (nread = read(fd_from, buf, sizeof buf), nread > 0)
	{
		char *out_ptr = buf;
		ssize_t nwritten;
		
		do {
			nwritten = write(fd_to, out_ptr, nread);
			
			if (nwritten >= 0)
			{
				nread -= nwritten;
				out_ptr += nwritten;
			}
			else if (errno != EINTR)
			{
				goto out_error;
			}
		} while (nread > 0);
	}
	
	if (nread == 0)
	{
		if (close(fd_to) < 0)
		{
			fd_to = -1;
			goto out_error;
		}
		close(fd_from);
		
		/* Success! */
		return 0;
	}
	
out_error:
	saved_errno = errno;
	
	close(fd_from);
	if (fd_to >= 0)
		close(fd_to);
	
	errno = saved_errno;
	return -1;
}

int file_exist (char *filename) {
	struct stat   buffer;
	return (stat (filename, &buffer) == 0);
}


/****** Kernel utility stuff ******/

mach_port_t tfpzero;
mach_port_t uc;
void init_kernel_utils(mach_port_t tfp0, mach_port_t user_client) {
	tfpzero = tfp0;
}

uint64_t kalloc(vm_size_t size) {
	mach_vm_address_t address = 0;
	mach_vm_allocate(tfpzero, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
	return address;
}


size_t kread(uint64_t where, void *p, size_t size) {
	int rv;
	size_t offset = 0;
	while (offset < size) {
		mach_vm_size_t sz, chunk = 2048;
		if (chunk > size - offset) {
			chunk = size - offset;
		}
		rv = mach_vm_read_overwrite(tfpzero, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
		if (rv || sz == 0) {
			printf("[fun_utils] error on kread(0x%016llx)\n", (offset + where));
			break;
		}
		offset += sz;
	}
	return offset;
}

uint32_t kread32(uint64_t where) {
	uint32_t out;
	kread(where, &out, sizeof(uint32_t));
	return out;
}

uint64_t kread64(uint64_t where) {
	uint64_t out;
	kread(where, &out, sizeof(uint64_t));
	return out;
}

size_t kwrite(uint64_t where, const void *p, size_t size) {
	int rv;
	size_t offset = 0;
	while (offset < size) {
		size_t chunk = 2048;
		if (chunk > size - offset) {
			chunk = size - offset;
		}
		rv = mach_vm_write(tfpzero, where + offset, (mach_vm_offset_t)p + offset, chunk);
		if (rv) {
			printf("[fun_utils] error on kwrite(0x%016llx)\n", (offset + where));
			break;
		}
		offset += chunk;
	}
	return offset;
}

void kwrite32(uint64_t where, uint32_t what) {
	uint32_t _what = what;
	kwrite(where, &_what, sizeof(uint32_t));
}


void kwrite64(uint64_t where, uint64_t what) {
	uint64_t _what = what;
	kwrite(where, &_what, sizeof(uint64_t));
}
