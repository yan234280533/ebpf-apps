/* SPDX-License-Identifier: GPL-2.0 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


SEC("kprobe/vfs_mkdir")
int kprobe_vfs_mkdir(struct pt_regs *ctx)
{
    struct dentry copyDentry;
    struct dentry* dentry;
    dentry = (struct dentry*)PT_REGS_PARM3(ctx);

    if (!dentry)
    {
        return 0;
    }

    bpf_probe_read(&copyDentry, sizeof(copyDentry), dentry);

    bpf_printk("kprobe ,mkdir (vfs hook point) %s---%s %d\n",copyDentry.d_iname,copyDentry.d_name.name,copyDentry.d_name.len);

    struct dentry copyDentryParent;
    if (!(copyDentry.d_parent))
    {
        return 0;
    }

    bpf_probe_read(&copyDentryParent, sizeof(copyDentryParent), copyDentry.d_parent);

    bpf_printk("kprobe parent,mkdir (vfs hook point) %s---%s %d\n",copyDentryParent.d_iname,copyDentryParent.d_name.name,copyDentryParent.d_name.len);
    return 0;
};

SEC("kretprobe/vfs_mkdir")
int kretpobe_mkdir(struct pt_regs *ctx)
{
    bpf_printk("kretprobe,mkdir (vfs hook point)\n");
    return 0;
};

char _license[] SEC("license") = "GPL";

