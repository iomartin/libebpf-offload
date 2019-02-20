struct ebpf_offload {
    int nvme_fd;
    char *nvme_filename;
    int p2pmem_fd;
    char *p2pmem_filename;
    int ebpf_fd;
    char *ebpf_filename;
    int prog_fd;
    char *prog_filename;
    int data_fd;
    char *data_filename;
    void     *p2pmem_buffer;
    size_t   p2pmem_size;
    char     *ebpf_buffer;
    size_t   ebpf_size;
    size_t   chunk_size;
    size_t   chunks;

    /*
     * The NVMe device can either be in raw block io format or it can be a file
     * system. In raw mode, we copy the file to address 0x0 of the NVMe device
     * and then p2pdma it. In filesystem mode, we don't need to copy the file,
     * since it is already there.
     */
    bool use_raw_io;

    size_t prog_len_offset;
    size_t mem_len_offset;
    size_t prog_offset;
    size_t control_prog_offset;
    size_t ret_offset;
    size_t ready_offset;
    size_t regs_offset;
    size_t mem_offset;
};

struct ebpf_offload *ebpf_create();
void ebpf_use_raw_io(struct ebpf_offload *eo, bool use_raw_io);
int ebpf_set_nvme(struct ebpf_offload *eo, const char *fname);
int ebpf_set_p2pmem(struct ebpf_offload *eo, const char *fname);
int ebpf_set_ebpf(struct ebpf_offload *eo, const char *fname, size_t size);
int ebpf_set_prog(struct ebpf_offload *eo, const char *fname);
int ebpf_set_data(struct ebpf_offload *eo, const char *fname);
void ebpf_set_chunks(struct ebpf_offload *eo, size_t chunks);
void ebpf_set_chunk_size(struct ebpf_offload *eo, size_t chunk_size);
int ebpf_init(struct ebpf_offload *eo);
void ebpf_run(struct ebpf_offload *eo, int *result);
void ebpf_destroy(struct ebpf_offload *eo);
