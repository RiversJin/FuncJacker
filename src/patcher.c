#include "patcher.h"
#include "hash_table.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>



typedef struct mock_stub{
    void* target_addr;
    void* new_addr;
    void* pre_addr;
    void* post_addr;
    uint8_t origin_code[16];
    bool is_short_call;
} mock_stub_t;

enum {
    MOCK_STUB_MAX = 1024,
    MOCK_STUB_INVALID = -1,
};

struct trap_frame;
static void jump() __attribute__((naked, used));
static void save_registers() __attribute__((naked, used));
static void (*save_registers_ptr)() = save_registers;


struct trap_frame{
// return address
void* origin_address;

// callee-saved registers
uint64_t rdi, rsi, rdx, rcx, r8, r9;
// non-volatile registers
uint64_t rbp, rbx, r12, r13, r14, r15;

uint64_t xmm0[2], xmm1[2], xmm2[2], xmm3[2], xmm4[2], xmm5[2], xmm6[2], xmm7[2];
uint64_t ymm0[4], ymm1[4], ymm2[4], ymm3[4], ymm4[4], ymm5[4], ymm6[4], ymm7[4];
};
const int trap_frame_size = sizeof(struct trap_frame);

void save_registers(){
    __asm__(
        "pop %rax\n\t" // return address(the address of the patched function)
        "push %rax\n\t" // may be it could be omitted

        "push %rdi\n\t" // rdi
        "push %rsi\n\t" // rsi
        "push %rdx\n\t" // rdx
        "push %rcx\n\t" // rcx
        "push %r8\n\t" // r8
        "push %r9\n\t" // r9

        "push %rbp\n\t" // rbp
        "push %rbx\n\t" // rbx
        "push %r12\n\t" // r12
        "push %r13\n\t" // r13
        "push %r14\n\t" // r14
        "push %r15\n\t" // r15

        // save xmm0-xmm7 and ymm0-ymm7 size = 8 * 16 + 8 * 32 = 384
        "sub $384, %rsp\n\t"
        "movdqu %xmm0, (%rsp)\n\t"
        "movdqu %xmm1, 16(%rsp)\n\t"
        "movdqu %xmm2, 32(%rsp)\n\t"
        "movdqu %xmm3, 48(%rsp)\n\t"
        "movdqu %xmm4, 64(%rsp)\n\t"
        "movdqu %xmm5, 80(%rsp)\n\t"
        "movdqu %xmm6, 96(%rsp)\n\t"
        "movdqu %xmm7, 112(%rsp)\n\t"

        "movdqu %ymm0, (%rsp)\n\t"
        "movdqu %ymm1, 32(%rsp)\n\t"
        "movdqu %ymm2, 64(%rsp)\n\t"
        "movdqu %ymm3, 96(%rsp)\n\t"
        "movdqu %ymm4, 128(%rsp)\n\t"
        "movdqu %ymm5, 160(%rsp)\n\t"
        "movdqu %ymm6, 192(%rsp)\n\t"
        "movdqu %ymm7, 224(%rsp)\n\t"

    );
    // call handle_patched(tf)
    // if pic is enabled, then use plt, otherwise use absolute address
#ifdef __PIC__
    __asm__(
        "call handle_patched@PLT\n\t"
    );
#else
    __asm__(
        "call handle_patched\n\t"
    );
#endif

    // release stack and return

    __asm__(
        "add %0, %%rsp\n\t"
        "ret\n\t"
        :
        : "r"(trap_frame_size)
    );
}

typedef struct {
    uint8_t call_op;
    uint32_t offset;
}__attribute__((packed)) short_call_t;

// make a short call
// call to - from - sizeof(short_call_t)
static short_call_t make_short_call(void* from, void* to){
    short_call_t ret;
    ret.call_op = 0xe8;
    ret.offset = (uint32_t)(to - from - sizeof(short_call_t));
    return ret;
}

typedef struct {
    uint16_t mov_op;
    uint64_t mov_addr;
    uint16_t call_op;
}__attribute__((packed)) long_call_t;

// make a long call
// mov %rax, to
// call *%rax
static long_call_t make_long_call(void* from, void* to){
    long_call_t ret;
    ret.mov_op = 0xb848;
    ret.mov_addr = (uint64_t)to;
    ret.call_op = 0xd0ff;
    return ret;
}



static int install_jumper(mock_stub_t* mock_stub){
    void* from = mock_stub->target_addr;
    void* to = save_registers;


    int ret = 0;
    // firstly, make the target("from") writable, use mprotect
    static uint64_t page_size;
    if(page_size == 0){
        page_size = sysconf(_SC_PAGESIZE);
    }
    uint64_t page_start = (uint64_t)from & ~(page_size - 1);

    if(ret = mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0, ret != 0){
        printf("mprotect failed, err = %s\n", strerror(errno));
        return ret;
    }

    if((uint64_t)from - (uint64_t)to > 0x7fffffff || (uint64_t)from - (uint64_t)to < -0x7fffffff){
        // too far, use call *%rax
        long_call_t long_call = make_long_call(from, to);
        // save origin code
        memcpy(mock_stub->origin_code, from, sizeof(long_call_t));
        // write new code
        *((long_call_t*)from) = long_call;
        mock_stub->is_short_call = false;
    } else {
        short_call_t short_call = make_short_call(from, to);
        // save origin code
        memcpy(mock_stub->origin_code, from, sizeof(short_call_t));
        // write new code
        *((short_call_t*)from) = short_call;
        mock_stub->is_short_call = true;
    }

    // restore the protection
    if(ret = mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC) != 0, ret != 0){
        printf("mprotect failed, err = %s\n", strerror(errno));
        return ret;
    }

    return 0;
}

static int uninstall_jumper(mock_stub_t* stub){
    void* from = stub->target_addr;
    int ret = 0;
    // firstly, make the target("from") writable, use mprotect
    static uint64_t page_size;
    if(page_size == 0){
        page_size = sysconf(_SC_PAGESIZE);
    }
    uint64_t page_start = (uint64_t)from & ~(page_size - 1);
    if(ret = mprotect((void*)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0, ret != 0){
        printf("mprotect failed, err = %s\n", strerror(errno));
        return ret;
    }
    // restore the origin code
    memcpy(from, stub->origin_code, stub->is_short_call ? sizeof(short_call_t) : sizeof(long_call_t));
    // restore the protection
    if(ret = mprotect((void*)page_start, page_size, PROT_READ | PROT_EXEC) != 0, ret != 0){
        printf("mprotect failed, err = %s\n", strerror(errno));
        return ret;
    }
    return 0;
}

static bool is_inited = false;
static hash_table_t* mock_stub_table = NULL;

static void handle_patched(struct trap_frame *tf){
    if(!is_inited){
        return;
    }

    // first, find the mock_stub_t
    mock_stub_t* mock_stub = hash_table_get(mock_stub_table, &tf->origin_address);
    if(mock_stub == NULL){
        // not found
        return;
    }
    uint64_t old_rsp;
    // call pre
    __asm__(
    // firstly, set stack to origin stack
        "mov %%rsp, %0\n\t"
        "mov %1, %%rsp\n\t"
        :"=r"(old_rsp)
        :"r"(tf)
    );
    if(mock_stub->pre_addr != NULL){
        __asm__(
            "call *%0\n\t"
            :
            : "r"(mock_stub->pre_addr)
        );
    }
    if(mock_stub->new_addr != NULL){
        __asm__(
            "call *%0\n\t"
            :
            : "r"(mock_stub->new_addr)
        );
    }
    // call post
    if(mock_stub->post_addr != NULL){
        __asm__(
            "call *%0\n\t"
            :
            : "r"(mock_stub->post_addr)
        );
    }
    // restore stack
    __asm__(
        "mov %0, %%rsp\n\t"
        :
        : "r"(old_rsp)
    );
}



static int address_equal(const void* a, const void* b){
    return a == b;
}

int patch(void *target_func, void *new_func, void *pre_func, void *post_func){
    
    if(!is_inited){
        mock_stub_table = hash_table_create(1024, sizeof(void*), address_equal, NULL);
        if (mock_stub_table == NULL){
            return -1;
        }
        is_inited = true;
    }

    mock_stub_t* mock_stub = hash_table_get(mock_stub_table, &target_func);
    if(mock_stub != NULL){
        // already patched
        if(mock_stub->new_addr == new_func){
            // already patched to the same function
            return 0;
        }

        // uninstall the old jumper
        int ret = uninstall_jumper(mock_stub);
        if(ret != 0){
            return ret;
        }

        // install the new jumper
        mock_stub->new_addr = new_func;
        ret = install_jumper(mock_stub);
        if(ret != 0){
            return ret;
        }
        return 0;
    }
    
    // not patched yet
    // create a new mock_stub_t
    mock_stub = malloc(sizeof(mock_stub_t));
    if(mock_stub == NULL){
        return -1;
    }
    memset(mock_stub, 0, sizeof(mock_stub_t));
    mock_stub->target_addr = target_func;
    mock_stub->new_addr = new_func;
    mock_stub->pre_addr = pre_func;
    mock_stub->post_addr = post_func;
    // install the jumper
    int ret = install_jumper(mock_stub);
    if(ret != 0){
        free(mock_stub);
        return ret;
    }
    // add to mock_stub_table
    void **key = malloc(sizeof(void*));
    if(key == NULL){
        free(mock_stub);
        uninstall_jumper(mock_stub);
        return -1;
    }
    *key = target_func;

    ret = hash_table_put(mock_stub_table, key, mock_stub);
    if(ret != 0){
        free(key);
        free(mock_stub);
        uninstall_jumper(mock_stub);
        return ret;
    }
    return 0;
}

int unpatch(void* target_func){
    if(!is_inited){
        return 0;
    }

    mock_stub_t* mock_stub = hash_table_remove(mock_stub_table, &target_func);
    if(mock_stub == NULL){
        return 0;
    }
    int ret = uninstall_jumper(mock_stub);
    if(ret != 0){
        return ret;
    }
    free(mock_stub);
    return 0;
}

static int unpatch_call_back(void* key, void* value){
    mock_stub_t* mock_stub = value;
    int ret = uninstall_jumper(mock_stub);
    if(ret != 0){
        return ret;
    }
    memset(mock_stub, 0, sizeof(mock_stub_t));
    return 0;
}

int unpatch_all(){
    if(!is_inited){
        return 0;
    }
    int n_patched = hash_table_count(mock_stub_table);
    if(n_patched == 0){
        return 0;
    }
    int rets[n_patched];
    memset(rets, 0, sizeof(int) * n_patched);

    hash_table_for_each(mock_stub_table, unpatch_call_back, n_patched, rets);
    for(int i = 0; i < n_patched; i++){
        if(rets[i] != 0){
            return rets[i];
        }
    }
    return 0;
}