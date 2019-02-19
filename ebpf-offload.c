#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include "ebpf-offload.h"

#define EBPF_START                0x1
#define EBPF_NOT_READY            0x0
#define EBPF_READY                0x1

#define set_filename(name) do { \
        int len = strlen(fname) + 1; \
        eo->name ## _filename = malloc(len); \
        strncpy(eo->name ## _filename, fname, len) ; \
    } while(0);

#define open_file(name, flags) do { \
        eo->name ## _fd = open(eo->name ## _filename, flags); \
        if (eo->name ## _fd < 0) { \
            perror("open"); \
            return 1; \
        } \
    } while(0);

static void ebpf_load_program(struct ebpf_offload *eo);
static void ebpf_load_data(struct ebpf_offload *eo, int offset);
static void ebpf_write_data(struct ebpf_offload *eo);
static int ebpf_execute(struct ebpf_offload *eo);

struct ebpf_offload *ebpf_create()
{
    struct ebpf_offload *eo = calloc(1, sizeof(*eo));
    eo->prog_len_offset     = 0x0;
    eo->mem_len_offset      = 0x4;
    eo->prog_offset         = 0x1000;
    eo->control_prog_offset = 0x100000;
    eo->ret_offset          = 0x200000;
    eo->ready_offset        = 0x200004;
    eo->regs_offset         = 0x200008;
    eo->mem_offset          = 0x800000;
    return eo;
}

int ebpf_set_nvme(struct ebpf_offload *eo, const char *fname)
{
    set_filename(nvme);
    open_file(nvme, O_TRUNC | O_RDWR | O_DIRECT);
    return 0;
}

int ebpf_set_p2pmem(struct ebpf_offload *eo, const char *fname)
{
    set_filename(p2pmem);
    open_file(p2pmem, O_TRUNC | O_RDWR);
    return 0;
}

int ebpf_set_ebpf(struct ebpf_offload *eo, const char *fname, size_t size)
{
    set_filename(ebpf);
    open_file(ebpf, O_TRUNC | O_RDWR);
    eo->ebpf_size = size;
    return 0;
}

int ebpf_set_prog(struct ebpf_offload *eo, const char *fname)
{
    set_filename(prog);
    open_file(prog, O_RDONLY);
    return 0;
}

int ebpf_set_data(struct ebpf_offload *eo, const char *fname)
{
    set_filename(data);
    open_file(data, O_RDONLY);
    return 0;
}

void ebpf_set_chunks(struct ebpf_offload *eo, size_t chunks)
{
    eo->chunks = chunks;
}

void ebpf_set_chunk_size(struct ebpf_offload *eo, size_t chunk_size)
{
    eo->chunk_size = chunk_size;
}

int ebpf_init(struct ebpf_offload *eo)
{
    if (eo->nvme_fd == 0) {
        fprintf(stderr, "NVMe device not initialized.");
        return 1;
    }
    if (eo->p2pmem_fd == 0) {
        fprintf(stderr, "p2pmem device not initialized.");
        return 1;
    }
    if (eo->ebpf_fd == 0) {
        fprintf(stderr, "eBPF device not initialized.");
        return 1;
    }
    if (eo->prog_fd == 0) {
        fprintf(stderr, "eBPF program not initialized.");
        return 1;
    }
    if (eo->chunks == 0) {
        fprintf(stderr, "Number of chunks not initialized.");
        return 1;
    }
    if (eo->chunk_size == 0) {
        fprintf(stderr, "Chunk size not initialized.");
        return 1;
    }
    eo->p2pmem_size = eo->chunk_size * eo->chunks;
    eo->p2pmem_buffer = mmap(NULL, eo->p2pmem_size, PROT_READ | PROT_WRITE,
            MAP_SHARED, eo->p2pmem_fd, 0);
    if (eo->p2pmem_buffer == MAP_FAILED) {
        perror("mmap (p2pmem_buffer)");
        return 1;
    }
    eo->ebpf_buffer = mmap(NULL, eo->ebpf_size, PROT_READ | PROT_WRITE, MAP_SHARED, eo->ebpf_fd, 0);
    if (eo->ebpf_buffer == MAP_FAILED) {
        perror("mmap (ebpf_buffer)");
        munmap(eo->p2pmem_buffer, eo->p2pmem_size);
        return 1;
    }
    return 0;
}

static void ebpf_write_data(struct ebpf_offload *eo)
{
    void *buf = mmap(NULL, eo->p2pmem_size, PROT_READ, MAP_SHARED, eo->data_fd, 0);
    if (buf == MAP_FAILED) {
        perror("mmap");
        exit(EXIT_FAILURE);
    }

    ssize_t count = write(eo->nvme_fd, buf, eo->p2pmem_size);
    if (count != eo->p2pmem_size) {
        if (count == -1) {
            perror("write");
        }
        fprintf(stderr, "Copying %s to %s failed. Wanted: %lu bytes. Transferred: %lu\n",
                eo->data_filename, eo->nvme_filename, eo->p2pmem_size, count);
        exit(EXIT_FAILURE);
    }
    munmap(buf, eo->p2pmem_size);
}

static void ebpf_load_program(struct ebpf_offload *eo)
{
    /* Get program size */
    int size = lseek(eo->prog_fd, 0, SEEK_END);
    lseek(eo->prog_fd, 0, SEEK_SET);

    int* prog_len_ptr = (int32_t*) (eo->ebpf_buffer + eo->prog_len_offset);
    void *prog_ptr = eo->ebpf_buffer + eo->prog_offset;

    /* Write to device */
    *prog_len_ptr = size;
    size_t bytes = read(eo->prog_fd, prog_ptr, size);
    if (bytes != size) {
        fprintf(stderr, "Copying %s to %s failed. Program length: %d. Bytes transferred: %lu.\n",
                eo->prog_filename, eo->ebpf_filename, size, bytes);
        exit(EXIT_FAILURE);
    }
}

static void ebpf_load_data(struct ebpf_offload *eo, int offset)
{
    ssize_t count = pread(eo->nvme_fd, eo->p2pmem_buffer, eo->chunk_size, offset);
    if (count != eo->chunk_size) {
        if (count == -1) {
            perror("pread");
        }
        fprintf(stderr, "DMAing to %s failed. Chunk size: %lu. Bytes transferred: %lu",
                eo->nvme_filename, eo->chunk_size, count);
        exit(EXIT_FAILURE);
    }

    ssize_t* mem_len_ptr = (ssize_t*) (eo->ebpf_buffer + eo->mem_len_offset);
    *mem_len_ptr = count;
}

static int ebpf_execute(struct ebpf_offload *eo)
{
    int *control_prog_ptr = (int32_t*) (eo->ebpf_buffer + eo->control_prog_offset);
    volatile int *ready_ptr = (int32_t*) (eo->ebpf_buffer + eo->ready_offset);
    volatile int *ret_ptr = (int32_t*) (eo->ebpf_buffer + eo->ret_offset);

    *ready_ptr = EBPF_NOT_READY;
    *control_prog_ptr = EBPF_START;

    /* Wait until eBPF program finishes */
    while (!*ready_ptr);

    return *ret_ptr;
}


void ebpf_run(struct ebpf_offload *eo, int *result)
{
    if (eo->data_fd) {
        ebpf_write_data(eo);
    }
    ebpf_load_program(eo);
    for (int i = 0; i < eo->chunks; i++) {
        if (eo->data_fd) {
            ebpf_load_data(eo, i * eo->chunk_size);
        }
        int res = ebpf_execute(eo);
        if (result)
            result[i] = res;
    }
}

void ebpf_destroy(struct ebpf_offload *eo)
{
    if (eo->nvme_filename) {
        free(eo->nvme_filename);
        close(eo->nvme_fd);
    }
    if (eo->p2pmem_filename) {
        free(eo->p2pmem_filename);
        close(eo->p2pmem_fd);
    }
    if (eo->ebpf_filename) {
        free(eo->ebpf_filename);
        close(eo->ebpf_fd);
    }
    if (eo->prog_filename) {
        free(eo->prog_filename);
        close(eo->prog_fd);
    }
    if (eo->data_filename) {
        free(eo->data_filename);
        close(eo->data_fd);
    }
    munmap(eo->p2pmem_buffer, eo->p2pmem_size);
    munmap(eo->ebpf_buffer, eo->ebpf_size);
    free(eo);
}
