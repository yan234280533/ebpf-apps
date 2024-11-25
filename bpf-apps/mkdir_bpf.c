/* SPDX-License-Identifier: GPL-2.0 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>


SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(void *ctx)
{
    bpf_printk("kprobe,mkdir (vfs hook point)\n");
    return 0;
};

SEC("kretprobe/vfs_mkdir")
int kretpobe_mkdir(void *ctx)
{
    bpf_printk("kretprobe,mkdir (vfs hook point)\n");
    return 0;
};

char _license[] SEC("license") = "GPL";

