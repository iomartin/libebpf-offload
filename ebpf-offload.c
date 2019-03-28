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
#include <sys/ioctl.h>
#include <stdbool.h>

#include "ebpf-offload.h"

#define EBPF_START                0x1
#define EBPF_NOT_READY            0x0
#define EBPF_READY                0x1

static void set_filename(const char *fname, char **ptr)
{
    int len = strlen(fname) + 1;
    *ptr = malloc(len);
    strcpy(*ptr, fname);
}

static void open_file(int *fildes, char *name, int flags)
{
    *fildes = open(name, flags);
    if (*fildes < 0) {
        perror("open");
        exit(1);
    }
}

struct ebpf_offload *ebpf_create()
{
    struct ebpf_offload *eo = calloc(1, sizeof(*eo));

    eo->use_raw_io = false;

    eo->prog_len_offset     = EBPF_TEXT_LEN_OFFSET;
    eo->mem_len_offset      = EBPF_MEM_LEN_OFFSET;
    eo->prog_offset         = EBPF_TEXT_OFFSET;
    eo->ret_offset          = EBPF_RET_OFFSET;
    eo->ready_offset        = EBPF_READY_OFFSET;
    eo->regs_offset         = EBPF_REGS_OFFSET;
    eo->mem_offset          = EBPF_MEM_OFFSET;
    return eo;
}

void ebpf_use_raw_io(struct ebpf_offload *eo, bool use_raw_io)
{
    eo->use_raw_io = use_raw_io;
}

int ebpf_set_nvme(struct ebpf_offload *eo, const char *fname)
{
    set_filename(fname, &eo->nvme_filename);
    return 0;
}

int ebpf_set_p2pmem(struct ebpf_offload *eo, const char *fname)
{
    set_filename(fname, &eo->p2pmem_filename);
    return 0;
}

int ebpf_set_ebpf(struct ebpf_offload *eo, const char *fname, size_t size)
{
    set_filename(fname, &eo->ebpf_filename);
    eo->ebpf_size = size;
    return 0;
}

int ebpf_set_prog(struct ebpf_offload *eo, const char *fname)
{
    set_filename(fname, &eo->prog_filename);
    return 0;
}

int ebpf_set_data(struct ebpf_offload *eo, const char *fname)
{
    set_filename(fname, &eo->data_filename);
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
    if (eo->nvme_filename && eo->use_raw_io) {
        open_file(&eo->nvme_fd, eo->nvme_filename, O_TRUNC | O_RDWR | O_DIRECT);
    }
    if (eo->p2pmem_filename) {
        open_file(&eo->p2pmem_fd, eo->p2pmem_filename, O_TRUNC | O_RDWR);
    }
    if (eo->ebpf_filename) {
        open_file(&eo->ebpf_fd, eo->ebpf_filename, O_TRUNC | O_RDWR);
    }
    if (eo->prog_filename) {
        open_file(&eo->prog_fd, eo->prog_filename, O_RDONLY);
    }
    if (eo->data_filename) {
        open_file(&eo->data_fd, eo->data_filename, O_RDONLY | O_DIRECT);
    }

    if (eo->nvme_fd == 0 && eo->use_raw_io) {
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

int ebpf_send_command(struct ebpf_offload *eo, char opcode, uint32_t length, uint64_t addr)
{
    struct ebpf_command *cmd = malloc(sizeof(struct ebpf_command));
    cmd->opcode = opcode;
    cmd->length = length;
    cmd->addr = addr;

    int res = ioctl(eo->ebpf_fd, 0x0, cmd);
    free(cmd);
    return res;
}

static void ebpf_dma_program(struct ebpf_offload *eo)
{
    /* Get program size */
    int prog_size = lseek(eo->prog_fd, 0, SEEK_END);;
    lseek(eo->prog_fd, 0, SEEK_SET);

    void *prog_addr = mmap(NULL, prog_size, PROT_READ, MAP_SHARED, eo->prog_fd, 0);
    ebpf_send_command(eo, EBPF_OFFLOAD_OPCODE_DMA_TEXT, prog_size, (uint64_t) prog_addr);
    munmap(prog_addr, prog_size);
}

static void ebpf_dma_data(struct ebpf_offload *eo)
{
    int data_size = eo->chunks * eo->chunk_size;
    void *data_addr = mmap(NULL, data_size, PROT_READ, MAP_SHARED, eo->data_fd, 0);
    ebpf_send_command(eo, EBPF_OFFLOAD_OPCODE_DMA_DATA, data_size, (uint64_t) data_addr);
    munmap(data_addr, data_size);
}

static int ebpf_execute(struct ebpf_offload *eo, uint64_t offset)
{
    volatile int *ready_ptr = (int32_t*) (eo->ebpf_buffer + eo->ready_offset);
    volatile int *ret_ptr = (int32_t*) (eo->ebpf_buffer + eo->ret_offset);

    *ready_ptr = EBPF_NOT_READY;
    ebpf_send_command(eo, EBPF_OFFLOAD_OPCODE_RUN_PROG, 0, offset);

    /* Wait until eBPF program finishes */
    while (!*ready_ptr);

    return *ret_ptr;
}

/* Write registers to offset 'offset' (starting from the beginning of the ebpf_buffer */
void ebpf_get_registers(struct ebpf_offload *eo, uint64_t addr)
{
    ebpf_send_command(eo, EBPF_OFFLOAD_OPCODE_GET_REGS, EBPF_NREGS * sizeof(uint64_t), addr);
}

void ebpf_run(struct ebpf_offload *eo, int *result)
{
    /* DMA program */
    ebpf_dma_program(eo);

    /* DMA data */
    ebpf_dma_data(eo);

    /* Run program */
    for (int i = 0; i < eo->chunks; i++) {
        int res = ebpf_execute(eo, i * eo->chunk_size);
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
