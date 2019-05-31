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

#define KB (1024)
#define MB (1024 * KB)

#define EBPF_NREGS 16
#define EBPF_BAR_SIZE (16 * MB)

#define EBPF_OFFLOAD_OPCODE_DMA_TEXT      0x00
#define EBPF_OFFLOAD_OPCODE_MOVE_P2P_TEXT 0x01
#define EBPF_OFFLOAD_OPCODE_DMA_DATA      0x02
#define EBPF_OFFLOAD_OPCODE_MOVE_P2P_DATA 0x03
#define EBPF_OFFLOAD_OPCODE_RUN_PROG      0x04
#define EBPF_OFFLOAD_OPCODE_GET_REGS      0x05
#define EBPF_OFFLOAD_OPCODE_DUMP_MEM      0xff

#define EBPF_CTRL_START     0x1
#define EBPF_CTRL_DMA_DONE  0x4

#define EBPF_TEXT_LEN_OFFSET    0x100000
#define EBPF_MEM_LEN_OFFSET     0x100004
#define EBPF_TEXT_OFFSET        0x100100
#define EBPF_RET_OFFSET         0x200000
#define EBPF_READY_OFFSET       0x200004
#define EBPF_REGS_OFFSET        0x200008
#define EBPF_MEM_OFFSET         0x400000
#define EBPF_P2P_OFFSET         0x800000

struct ebpf_command {
    uint8_t opcode;
    uint32_t length;
    uint64_t addr;
};

struct ebpf_offload *ebpf_create(void);
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
void ebpf_get_registers(struct ebpf_offload *eo, uint64_t addr);
void ebpf_destroy(struct ebpf_offload *eo);

int ebpf_send_command(struct ebpf_offload *eo, char opcode, uint32_t length, uint64_t addr);
