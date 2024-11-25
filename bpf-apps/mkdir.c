#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "mkdir.skel.h"

int main(int argc, char **argv)
{
    struct mkdir_bpf *obj;
    int err = 0;

    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    err = setrlimit(RLIMIT_MEMLOCK, &rlim_new);
    if (err) {
        fprintf(stderr, "failed to change rlimit\n");
        return 1;
    }
    obj = mkdir_bpf__open();
    if (!obj) {
        fprintf(stderr, "failed to open and/or load BPF object\n");
        return 1;
    }

    err = mkdir_bpf__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object %d\n", err);
        goto cleanup;
    }

    err = mkdir_bpf__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF programs\n");
        goto cleanup;
    }

    printf
        ("Successfully started! Tracing /sys/kernel/debug/tracing/trace_pipe...\n");

    system("cat /sys/kernel/debug/tracing/trace_pipe");

    cleanup:
       mkdir_bpf__destroy(obj);
    return err != 0;
}