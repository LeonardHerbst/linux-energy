#ifndef _LINUX_ENERGY_DEFS_H
#define _LINUX_ENERGY_DEFS_H

struct energy_cgroup_callbacks {
        void (*member_scheduled)(struct task_struct *next, struct task_struct *prev);
};

#if !IS_ENABLED(CONFIG_CGROUP_ENERGY)

void empty_callback(struct task_struct *next, struct task_struct *prev) {
        return;
}

struct energy_cgroup_callbacks energy_cgroup_callbacks = {
        .member_scheduled       = empty_callback,     
};

#endif

#endif // _LINUX_ENERGY_DEFS_H
