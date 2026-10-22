// SPDX-License-Identifier: (GPL-2.0-only OR MIT)
/*
 * file.bpf.c — kernel-enforced file access policy (Phase 4).
 * Included by rk.bpf.c; see docs/design/phase-4.md.
 *
 * rk_file_protect holds the protected objects of every profile, keyed by
 * (slot << 31 | profile, device, inode) and double-buffered by generation
 * slot like the network and exec rules.
 */

#define RK_FILE_EPERM 1
#define RK_ATTR_SIZE 8
#define RK_O_TRUNC 01000
#define RK_FMODE_READ 0x1
#define RK_FMODE_WRITE 0x2
#define RK_FMODE_EXEC 0x20

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct rk_file_key);
    __type(value, struct rk_file_rule);
    __uint(max_entries, 65536);
} rk_file_protect SEC(".maps");

static __always_inline void rk_file_key_of(struct rk_file_key *key, const struct rk_gov *g, struct inode *inode)
{
    key->scope = g->scope;
    key->_pad = 0;
    key->dev = BPF_CORE_READ(inode, i_sb, s_dev);
    key->ino = BPF_CORE_READ(inode, i_ino);
}

static __always_inline int rk_file_check(
    const struct rk_gov *g,
    struct inode *inode,
    struct dentry *start_dentry,
    struct dentry *name_dentry,
    __u32 access,
    __u16 hook)
{
    struct rk_scratch_msg *msg;
    struct rk_payload_file_deny *body;
    struct rk_file_key key = {};
    __u32 rule_id = 0;
    __u8 action = RK_ACTION_ALLOW;
    __u8 event_flags = 0;

    rk_file_key_of(&key, g, inode);

    /* 1. Direct match on the object itself */
    struct rk_file_rule *rule = bpf_map_lookup_elem(&rk_file_protect, &key);
    if (rule && (rule->deny_mask & access)) {
        action = RK_ACTION_DENY;
        rule_id = rule->rule_id;
        if (rule->flags & RK_FILE_SUBTREE)
            event_flags |= RK_FILE_EV_SUBTREE;
        goto decided;
    }

    /* 2. Ancestor walk up to RK_FILE_MAX_DEPTH (32) for subtree rules */
    if (start_dentry) {
        struct dentry *curr = start_dentry;
        int hit_root = 0;

        #pragma unroll
        for (int i = 0; i < RK_FILE_MAX_DEPTH; i++) {
            struct dentry *parent = BPF_CORE_READ(curr, d_parent);
            if (!parent || parent == curr) {
                hit_root = 1;
                break;
            }
            curr = parent;
            struct inode *p_inode = BPF_CORE_READ(curr, d_inode);
            if (!p_inode) {
                hit_root = 1;
                break;
            }

            struct rk_file_key p_key = {};
            rk_file_key_of(&p_key, g, p_inode);
            struct rk_file_rule *p_rule = bpf_map_lookup_elem(&rk_file_protect, &p_key);
            if (p_rule && (p_rule->flags & RK_FILE_SUBTREE) && (p_rule->deny_mask & access)) {
                action = RK_ACTION_DENY;
                rule_id = p_rule->rule_id;
                event_flags |= RK_FILE_EV_SUBTREE;
                goto decided;
            }
        }

        /* 3. Fail closed on depth if 32 levels reached without hitting root */
        if (!hit_root) {
            action = RK_ACTION_DENY;
            rule_id = 0;
            event_flags |= RK_FILE_EV_DEPTH_EXCEEDED;
            goto decided;
        }
    }

decided:
    if (rk_effective_deny(g, action)) {
        msg = rk_scratch();
        if (msg) {
            rk_fill_hdr(&msg->hdr, g->cgroup_id, g->policy_gen, RK_EV_FILE_DENY,
                        rk_reported_verdict(g, action), rk_rule(g, action, rule_id));
            rk_fill_task(&msg->hdr);
            body = (struct rk_payload_file_deny *)msg->payload;
            __builtin_memset(body, 0, sizeof(*body));
            body->file_dev = key.dev;
            body->file_ino = key.ino;
            body->access = access;
            body->hook = hook;
            body->flags = event_flags;
            body->str_count = 1;
            msg->payload_len = sizeof(*body);
            if (name_dentry)
                rk_append_kstr(msg, BPF_CORE_READ(name_dentry, d_name.name), 256);
            else
                rk_append_kstr(msg, "", 1);
            rk_emit(msg);
        }
    }

    int deny = rk_enforced_deny(g, action);
    barrier_var(deny);
    if (deny)
        return -RK_FILE_EPERM;
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(rk_file_open, struct file *file, int ret)
{
    struct rk_gov g = {};

    if (ret)
        return ret;
    if (!rk_governance(&g))
        return 0;

    struct inode *inode = BPF_CORE_READ(file, f_inode);
    if (!inode)
        return 0;

    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);

    fmode_t f_mode = BPF_CORE_READ(file, f_mode);
    unsigned int f_flags = BPF_CORE_READ(file, f_flags);

    __u32 access = 0;
    if (f_mode & RK_FMODE_READ)
        access |= RK_FILE_READ;
    if (f_mode & RK_FMODE_WRITE)
        access |= RK_FILE_WRITE;
    if (f_mode & RK_FMODE_EXEC)
        access |= RK_FILE_EXEC;
    if (f_flags & RK_O_TRUNC)
        access |= RK_FILE_TRUNCATE;

    if (!access)
        return 0;

    return rk_file_check(&g, inode, dentry, dentry, access, RK_FILE_HOOK_OPEN);
}

SEC("lsm/inode_unlink")
int BPF_PROG(rk_file_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
    struct rk_gov g = {};
    (void)dir;

    if (ret)
        return ret;
    if (!rk_governance(&g))
        return 0;

    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return 0;

    return rk_file_check(&g, inode, dentry, dentry, RK_FILE_DELETE, RK_FILE_HOOK_UNLINK);
}

SEC("lsm/inode_rmdir")
int BPF_PROG(rk_file_rmdir, struct inode *dir, struct dentry *dentry, int ret)
{
    struct rk_gov g = {};
    (void)dir;

    if (ret)
        return ret;
    if (!rk_governance(&g))
        return 0;

    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return 0;

    return rk_file_check(&g, inode, dentry, dentry, RK_FILE_DELETE, RK_FILE_HOOK_UNLINK);
}

SEC("lsm/inode_rename")
int BPF_PROG(rk_file_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, int ret)
{
    struct rk_gov g = {};
    (void)old_dir;
    (void)new_dir;

    if (ret)
        return ret;
    if (!rk_governance(&g))
        return 0;

    struct inode *old_inode = BPF_CORE_READ(old_dentry, d_inode);
    if (old_inode) {
        int err = rk_file_check(&g, old_inode, old_dentry, old_dentry, RK_FILE_RENAME, RK_FILE_HOOK_RENAME);
        if (err)
            return err;
    }

    struct inode *new_inode = BPF_CORE_READ(new_dentry, d_inode);
    if (new_inode) {
        int err = rk_file_check(&g, new_inode, new_dentry, new_dentry, RK_FILE_DELETE | RK_FILE_RENAME, RK_FILE_HOOK_RENAME);
        if (err)
            return err;
    }

    return 0;
}

SEC("lsm/inode_link")
int BPF_PROG(rk_file_link, struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry, int ret)
{
    struct rk_gov g = {};
    (void)dir;
    (void)new_dentry;

    if (ret)
        return ret;
    if (!rk_governance(&g))
        return 0;

    struct inode *inode = BPF_CORE_READ(old_dentry, d_inode);
    if (!inode)
        return 0;

    return rk_file_check(&g, inode, old_dentry, old_dentry, RK_FILE_LINK, RK_FILE_HOOK_LINK);
}

static __always_inline int rk_create_check(struct inode *dir, struct dentry *dentry, int ret)
{
    struct rk_gov g = {};

    if (ret)
        return ret;
    if (!rk_governance(&g))
        return 0;
    if (!dir)
        return 0;

    struct dentry *dir_dentry = dentry ? BPF_CORE_READ(dentry, d_parent) : 0;
    return rk_file_check(&g, dir, dir_dentry, dentry, RK_FILE_CREATE, RK_FILE_HOOK_CREATE);
}

SEC("lsm/inode_create")
int BPF_PROG(rk_file_create, struct inode *dir, struct dentry *dentry, umode_t mode, int ret)
{
    (void)mode;
    return rk_create_check(dir, dentry, ret);
}

SEC("lsm/inode_mkdir")
int BPF_PROG(rk_file_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode, int ret)
{
    (void)mode;
    return rk_create_check(dir, dentry, ret);
}

static __always_inline int rk_setattr_check(const struct rk_gov *g, struct dentry *dentry, struct iattr *attr)
{
    struct inode *inode = BPF_CORE_READ(dentry, d_inode);
    if (!inode)
        return 0;

    __u32 ia_valid = BPF_CORE_READ(attr, ia_valid);
    __u32 access = 0;
    if (ia_valid & RK_ATTR_SIZE)
        access |= RK_FILE_TRUNCATE;
    if (!(ia_valid & RK_ATTR_SIZE) || (ia_valid & 0x187))
        access |= RK_FILE_SETATTR;

    return rk_file_check(g, inode, dentry, dentry, access, RK_FILE_HOOK_SETATTR);
}

SEC("lsm/inode_setattr")
int BPF_PROG(rk_file_setattr_v1, struct dentry *dentry, struct iattr *attr, int ret)
{
    struct rk_gov g = {};

    if (ret)
        return ret;
    if (!rk_governance(&g))
        return 0;

    return rk_setattr_check(&g, dentry, attr);
}

SEC("lsm/inode_setattr")
int BPF_PROG(rk_file_setattr_v2, struct mnt_idmap *idmap, struct dentry *dentry,
             struct iattr *attr, int ret)
{
    struct rk_gov g = {};
    (void)idmap;

    if (ret)
        return ret;
    if (!rk_governance(&g))
        return 0;

    return rk_setattr_check(&g, dentry, attr);
}
