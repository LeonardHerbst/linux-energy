#define pr_fmt(fmt)     "Energy Cgroup: " fmt

#include <linux/kernel.h>
#include <linux/threads.h>
#include <linux/atomic.h>
#include <linux/cgroup.h>
#include <linux/slab.h>
#include <linux/sched/task.h>
#include <linux/energy-defs.h>
#include <asm/msr.h>
#include <linux/llist.h>
#include <linux/percpu-defs.h>
#include <linux/smp.h>
#include <linux/timekeeping.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/math.h>
#include <linux/timer.h>
#include <linux/reboot.h>
#include <asm/cpufeature.h>

// TODO: remove
/* #define MOCK_INTERVAL 100 */

struct rapl_counters;
struct energy_counters;
struct energy_cgroup;
struct energy_cgroup_callbacks;
struct energy_history_entry;
struct running_css;
struct accounting_period;
struct accounting_work;

static struct timer_list accounting_timer;

/* Accounting related */
static struct rapl_counters last_measurement;
static struct accounting_work deferred_accounting;
static atomic64_t accounting_period_duration;
static DEFINE_SPINLOCK(accounting_lock);

/* Tracking related */
DEFINE_PER_CPU(struct running_css, per_core_running_css);
static struct llist_head energy_history;
static bool accounting_active = false;

/* cgroup related */
static atomic64_t accounting_intervall_ms;
static u32 unit;
static struct notifier_block energy_notifier;

/* RAPL Counter operations */
void (*read_rapl_counters)(struct rapl_counters*);

static void init_rapl_counters(struct rapl_counters* counters); 
static void init_energy_counters(struct energy_counters *counters);
static void read_rapl_counters_intel(struct rapl_counters* counters);
static void read_rapl_counters_amd(struct rapl_counters* counters);
/* static void read_rapl_counters_mocking(struct rapl_counters* counters); */
static void read_unit(u32* unit);

/* Energy Counter operations */
static void rapl_counters_to_energy_counters(struct rapl_counters *rapl_counters, struct energy_counters *energy_consumption, u32 unit);
static void add_to_energy_counters(struct energy_counters *left, struct energy_counters *right);
static void energy_counters_multiply_scalar(struct energy_counters *energy_counters, u64 scalar);
static void energy_counters_div_round_up(struct energy_counters *left, u64 sclar);
static void rapl_counters_diff(struct rapl_counters *res, struct rapl_counters *start, struct rapl_counters *end);

/* Accounting related functions*/
static void accounting_tic(struct timer_list *timer_list);
static void accounting(struct work_struct *work);
static int construct_energy_history_entry(struct energy_history_entry **entry, struct energy_cgroup *energy, ktime_t start, ktime_t end);
static bool entry_invalid(struct energy_history_entry *entry);

static int energy_shutdown_handler(struct notifier_block *nb, unsigned long event, void *data);

// TODO: remove
/* Data structures for mocking */
/*
static ktime_t mock_time;
static struct rapl_counters mock_rapl;
*/

struct rapl_counters {
        u32 core;
        u32 uncore;
};

struct energy_counters {
        u64 core_uj;
        u64 uncore_uj;
};

struct energy_cgroup {
        struct cgroup_subsys_state      css;

        struct energy_counters          energy_consumption;
        struct llist_node               siblings;
};

struct energy_history_entry {
        struct llist_node siblings;
        struct energy_cgroup *energy;
        
        ktime_t start;
        ktime_t end;
};

struct running_css {
        spinlock_t running_css_lock;

        struct energy_cgroup *energy;
        ktime_t start;
};

struct accounting_period {
        struct llist_node siblings;

        struct energy_counters total_energy_consumption;
        struct llist_node *first;
        u64 time_period;
};

struct accounting_work {
        struct work_struct      work;
        struct llist_head       accounting_period_list;
        struct llist_head       deletion_list;
        struct energy_counters  idle_task;
        bool                    abort;
        // TODO: remove
        atomic64_t total_energy_consumption_core_uj;
        atomic64_t total_energy_consumption_uncore_uj;
};

/* The MSR numbers of the different RAPL counters. */
enum {
        /* The different counters. */
        INTEL_ENERGY_PKG = MSR_PKG_ENERGY_STATUS,
        INTEL_ENERGY_DRAM = MSR_DRAM_ENERGY_STATUS,
        INTEL_ENERGY_CORE = MSR_PP0_ENERGY_STATUS,
        INTEL_ENERGY_GPU = MSR_PP1_ENERGY_STATUS,
        AMD_ENERGY_PKG = MSR_AMD_PKG_ENERGY_STATUS,
        AMD_ENERGY_CORE = MSR_AMD_CORE_ENERGY_STATUS,

        /* The unit for the energy counters. */
        INTEL_ENERGY_UNIT = MSR_RAPL_POWER_UNIT,
        AMD_ENERGY_UNIT = MSR_AMD_RAPL_POWER_UNIT,
        ENERGY_UNIT = AMD_ENERGY_UNIT
};

/* Offsets and masks for the RAPL counters. */
enum {
        /* The different counters. */
        MASK_PKG = 0xffffffff,          /* Bits 31-0 */
        OFFSET_PKG = 0,                 /* No shift needed. */

        MASK_DRAM = MASK_PKG,
        OFFSET_DRAM = OFFSET_PKG,

        MASK_CORE = MASK_PKG,
        OFFSET_CORE = OFFSET_PKG,

        MASK_GPU = MASK_PKG,
        OFFSET_GPU = OFFSET_PKG,

        /* The unit for the energy counters. */
        MASK_UNIT = 0x1f00,             /* Bits 12-8 */
        OFFSET_UNIT = 8                 /* Shift by 8 bits. */
};

/*
 * Initialize the necessary data structures 
 */
static void __init init_energy_cgroup_cpu_local(void *dummy)
{
        struct running_css *running_css = this_cpu_ptr(&per_core_running_css);

        running_css->energy = NULL;
        running_css->start = ktime_get();
        spin_lock_init(&running_css->running_css_lock);

        pr_info("Infrastructure for accounting energy consumption has been initialized on core %d\n", smp_processor_id());
}

static int __init init_energy_cgroup(void)
{
        u64 interval;

        on_each_cpu(init_energy_cgroup_cpu_local, NULL, 1);

        /* cgroup related*/
        atomic64_set(&accounting_intervall_ms, 10);

        /* tracking related */
        init_llist_head(&energy_history);

        /* accounting related */
        atomic64_set(&accounting_period_duration, 0);

        init_llist_head(&deferred_accounting.accounting_period_list);
        init_llist_head(&deferred_accounting.deletion_list);
        INIT_WORK(&deferred_accounting.work, accounting);
        WRITE_ONCE(deferred_accounting.abort, false);
        init_energy_counters(&deferred_accounting.idle_task);

        energy_notifier.notifier_call   = energy_shutdown_handler;
        energy_notifier.next            = NULL;
        energy_notifier.priority        = 0;

        register_reboot_notifier(&energy_notifier);

        
        // TODO: remove
        /*
        mock_time = ktime_get() + MOCK_INTERVAL/2;
        init_rapl_counters(&mock_rapl);
        */

        // TODO: remove
        atomic64_set(&deferred_accounting.total_energy_consumption_core_uj, 0);
        atomic64_set(&deferred_accounting.total_energy_consumption_uncore_uj, 0);


        read_unit(&unit);

        /* detecting cpu vendor */
        if (boot_cpu_data.x86_vendor == X86_VENDOR_INTEL) {
                pr_info("Running on an intel system.\n");
                read_rapl_counters = read_rapl_counters_intel;
        } else if (boot_cpu_data.x86_vendor == X86_VENDOR_AMD) {
                pr_info("Running on an amd system.\n");
                read_rapl_counters = read_rapl_counters_amd;
        } else {
                pr_info("Cpu vendor not known. No energy accounting!\n");
                return 0;
                /*
                read_rapl_counters = read_rapl_counters_mocking;
                unit = 1;
                */
        }


        init_rapl_counters(&last_measurement);
        read_rapl_counters(&last_measurement);

        timer_setup(&accounting_timer, accounting_tic, 0);

	WRITE_ONCE(accounting_active, true);

        interval = (u64)atomic64_read(&accounting_intervall_ms);

        mod_timer(&accounting_timer, jiffies + msecs_to_jiffies(interval));
        pr_info("Energy accounting has been initialized.\n");
        return 0;
}
late_initcall(init_energy_cgroup);

static int energy_shutdown_handler(struct notifier_block *nb, unsigned long event, void *data)
{
        pr_info("Stopping accounting!\n");
        WRITE_ONCE(accounting_active, false);
        WRITE_ONCE(deferred_accounting.abort, true); 
        cancel_work_sync(&deferred_accounting.work);
        del_timer_sync(&accounting_timer);

        return 0;
}

/* cgroup "member" functions */
static struct energy_cgroup *css_energy(struct cgroup_subsys_state *css)
{
        return container_of(css, struct energy_cgroup, css);
}

static struct cgroup_subsys_state *
energy_css_alloc(struct cgroup_subsys_state *parent)
{
        struct energy_cgroup *energy;

        energy = kzalloc(sizeof(struct energy_cgroup), GFP_KERNEL);
        if (!energy)
                return ERR_PTR(-ENOMEM);

        WRITE_ONCE(energy->energy_consumption.core_uj, 0);
        WRITE_ONCE(energy->energy_consumption.uncore_uj, 0);

        return &energy->css;
}

static void energy_css_free(struct cgroup_subsys_state *css)
{
        llist_add(&css_energy(css)->siblings, &deferred_accounting.deletion_list); 
}

static void energy_attach(struct cgroup_taskset *tset)
{
        struct task_struct *task;
        struct cgroup_subsys_state *css;
        struct energy_history_entry *new_entry;
        struct running_css *running_css;
        ktime_t end = ktime_get();
        ktime_t start;

        int err;

        if(!READ_ONCE(accounting_active))
                return;


        cgroup_taskset_for_each(task, css, tset) {
                
                if(!task_is_running(task) || (task->tgid == 0 && task->pid == 0))
                        continue;

                err = construct_energy_history_entry(&new_entry, NULL, 0, end);

                running_css = per_cpu_ptr(&per_core_running_css, task_cpu(task));

                spin_lock(&running_css->running_css_lock);

                if(!task_is_running(task) || ktime_after(running_css->start, end)) {
                        /*
                         * Another task has been scheduled
                         * or the accounting_tic ran while we migrated and added the entry
                         */
                        kfree(new_entry);
                        spin_unlock(&running_css->running_css_lock);
                        continue;
                }

                start = running_css->start;
                running_css->start = end;
                running_css->energy = css_energy(css);

                if (err) {
                        spin_unlock(&running_css->running_css_lock);
                        continue;
                }

                new_entry->energy = running_css->energy;
                new_entry->start = start;

                spin_unlock(&running_css->running_css_lock);

                if (entry_invalid(new_entry)) {
                        /**
                         * entry became invalid while we waited for the 
                         * running_css_lock.
                         * The running_css->start changed, which implies that
                         * the entry was very short to begin with.
                         */
                        kfree(new_entry);
                        continue;
                }
                llist_add(&new_entry->siblings, &energy_history);
                atomic64_add(ktime_sub(end, new_entry->start), &accounting_period_duration);
        }
}

static void __energy_recursive_read(struct cgroup_subsys_state *css,
struct energy_counters *total_energy_consumption)
{
        struct cgroup_subsys_state *current_child;
        struct energy_cgroup *energy = css_energy(css);
        struct energy_counters tmp;

        list_for_each_entry(current_child, &css->children, sibling) {
                __energy_recursive_read(current_child, total_energy_consumption);
        }
        
        tmp.core_uj = READ_ONCE(energy->energy_consumption.core_uj);
        tmp.uncore_uj = READ_ONCE(energy->energy_consumption.uncore_uj);
        add_to_energy_counters(total_energy_consumption, &tmp);
}

/* called when reading energy.consumption */
static int energy_consumption_read(struct seq_file *sf, void *v) {
        struct energy_counters total_energy_consumption;
        init_energy_counters(&total_energy_consumption);
        __energy_recursive_read(seq_css(sf), &total_energy_consumption);

        seq_printf(sf, "core  : %lluµj\nuncore: %lluµj\n", 
                total_energy_consumption.core_uj, total_energy_consumption.uncore_uj);

        return 0;
}

static int energy_consumption_read_json(struct seq_file *sf, void *v) {
        struct energy_counters total_energy_consumption;
        init_energy_counters(&total_energy_consumption);
        __energy_recursive_read(seq_css(sf), &total_energy_consumption);

        seq_printf(sf, "{ \"core\": %llu, \"uncore\": %llu, \"unit\" :\"µj\"}", 
                total_energy_consumption.core_uj, total_energy_consumption.uncore_uj);

        return 0;
}

/* called when writing to energy.interval on the default hierarchy */
static ssize_t energy_accounting_inverval_write(struct kernfs_open_file *of,
char *buf, size_t nbytes, loff_t off)
{
        int err;
        int64_t interval;

        buf = strstrip(buf);
        err = kstrtoll(buf, 0, &interval);

        if(err)
                return err;

        atomic64_set(&accounting_intervall_ms, interval);
        return nbytes;
}

static int energy_accounting_inverval_show(struct seq_file *sf, void *v) {
        u64 interval = (u64)atomic64_read(&accounting_intervall_ms);
        seq_printf(sf, "%llums\n", interval);

        return 0;
}

/* called when reading energy.idle_consumption on the default hierarchy */
static int energy_idle_task_consumption_show(struct seq_file *sf, void *v) {
        seq_printf(sf, "core  : %lluµj\nuncore: %lluµj\n", 
                deferred_accounting.idle_task.core_uj,
                deferred_accounting.idle_task.uncore_uj);

        return 0;
}
static int energy_idle_task_consumption_show_json(struct seq_file *sf, void *v) {
        seq_printf(sf, "{\"core\": %llu, \"uncore\": %llu, \"unit\" :\"µj\"}", 
                deferred_accounting.idle_task.core_uj,
                deferred_accounting.idle_task.uncore_uj);

        return 0;
}

/* called when reading energy.RAPL -> used for debugging*/
static int read_rapl(struct seq_file *sf, void *v)
{
        struct rapl_counters rc;
        struct energy_counters ec;

        init_rapl_counters(&rc);
        read_rapl_counters(&rc);

        rapl_counters_to_energy_counters(&rc, &ec, unit);

        seq_printf(sf, "RAPL:\n    core  : %u\n    uncore: %u\n", rc.core, rc.uncore);
        seq_printf(sf, "Energy:\n    core  : %lluµj\n    uncore: %lluµj\n", ec.core_uj, ec.uncore_uj);
        seq_printf(sf, "Unit: %u\n", unit);
        // TODO: remove
        seq_printf(sf, "Energy:\n    core  : %lluµj\n    uncore: %lluµj\n", (u64)atomic64_read(&deferred_accounting.total_energy_consumption_core_uj), (u64)atomic64_read(&deferred_accounting.total_energy_consumption_uncore_uj));
        return 0;
}

/** 
 * called by schedule()
 * creates energy history entries and adds them to the history
 */
static void energy_cgroup_task_scheduled(struct task_struct *next, struct task_struct *prev)
{        
        struct energy_history_entry *new_entry;
        struct energy_cgroup *tmp;
        struct running_css *running_css = this_cpu_ptr(&per_core_running_css);
        ktime_t end = ktime_get();
        ktime_t start;
        int err;

        if (!READ_ONCE(accounting_active) || task_css(prev, energy_cgrp_id)->id == task_css(next, energy_cgrp_id)->id) {
                /* Same CSS or not active*/
                return;
        }

        tmp = (prev->tgid == 0 || prev->pid == 0) ? NULL : css_energy(task_css(prev, energy_cgrp_id));
        err = construct_energy_history_entry(&new_entry, tmp, 0, end);

        if (!spin_trylock(&running_css->running_css_lock)) {
                /** 
                 * Contention on that lock indicates that the accounting function is running or the task is being migrated.
                 * In both cases a energy_history_entry will be added.
                 * we can simply free and return
                 * */
                kfree(new_entry);
                return;
        }

        start = running_css->start;
        running_css->energy = (next->tgid == 0 || next->pid == 0) ? NULL : css_energy(task_css(next, energy_cgrp_id));
        running_css->start = end;

        spin_unlock(&running_css->running_css_lock);

        if (err) 
                return;

        new_entry->start = start;

        if (entry_invalid(new_entry)) {
                kfree(new_entry);
                return;
        }
        
        llist_add(&new_entry->siblings, &energy_history);
        atomic64_add(ktime_sub(end, new_entry->start), &accounting_period_duration);

}

/**
 * Callback of the accounting_timer.
 * Creates an accounting_period based on the history and the RAPL counters,
 * adds it to the deferred_accounting->accounting_list
 * and start the accounting for that period by scheduling accounting_work.
 */
static void accounting_tic(struct timer_list *) {
        struct rapl_counters current_measurement;
        struct running_css *cpu_local_running_css;
        struct energy_history_entry *new_entry;
        struct accounting_period *accounting_period;
        ktime_t end = ktime_get();
        u64 interval = (u64)atomic64_read(&accounting_intervall_ms);
        int err;

        if(!spin_trylock(&accounting_lock)) {
                /* accounting tic already running */
                return;
        }

        mod_timer(&accounting_timer, jiffies + msecs_to_jiffies(interval));


        /**
         * Creating an energy history entry for the tasks currently running
         * on the respective core.
         */
        for (int i = num_active_cpus() - 1; i >= 0; i--) {

                cpu_local_running_css = per_cpu_ptr(&per_core_running_css, i);

                spin_lock(&cpu_local_running_css->running_css_lock);

                if (ktime_after(cpu_local_running_css->start, end)) {
                        /*
                         * While we waited for the lock energy_cgroup_task_scheduled
                         * run on that core or the task has been migrated.
                         * Either way an energy_history_entry has been added.
                         */
                        spin_unlock(&cpu_local_running_css->running_css_lock);
                        continue;
                }

                err = construct_energy_history_entry(&new_entry, cpu_local_running_css->energy, cpu_local_running_css->start, end);
                cpu_local_running_css->start = end;

                spin_unlock(&cpu_local_running_css->running_css_lock);

                if (err)
                        continue;

                if (entry_invalid(new_entry)) {
                        kfree(new_entry);
                        return;
                }

                llist_add(&new_entry->siblings, &energy_history);
                atomic64_add(ktime_sub(end, new_entry->start), &accounting_period_duration);
        }


        accounting_period = kzalloc(sizeof(struct accounting_period), GFP_KERNEL);
        if (!accounting_period) {
                pr_err("Failed to allocate memory for the current accounting period. Skipping accounting!");
                spin_unlock(&accounting_lock); 
                return;
        }

        init_rapl_counters(&current_measurement);
        read_rapl_counters(&current_measurement);

        rapl_counters_diff(&last_measurement, &last_measurement, &current_measurement);
        
        rapl_counters_to_energy_counters(&last_measurement, &accounting_period->total_energy_consumption, unit);
        last_measurement = current_measurement;


        accounting_period->first = llist_del_all(&energy_history);
        accounting_period->time_period = (u64)atomic64_read(&accounting_period_duration);

        llist_add(&accounting_period->siblings, &deferred_accounting.accounting_period_list);
        schedule_work(&deferred_accounting.work);

        atomic64_set(&accounting_period_duration, 0);
        spin_unlock(&accounting_lock);
        return;
}

/**
 * Callback function of the accounting_work.
 * Takes the first element of the deferred_accounting->accounting_list,
 * does time proportional accounting 
 * and adds the consumption the the respective energy_cgroup.
 */
static void accounting(struct work_struct *work)
{
        struct energy_counters energy_accumulator;

        struct energy_history_entry *pos; 
        struct energy_history_entry *tmp;
        struct energy_cgroup *deletion_candidate;
        struct energy_cgroup *tmp_energy_cgroup;
        struct cgroup_subsys_state *parent;

        struct accounting_work *accounting_work;
        struct accounting_period *current_period;
        struct llist_node *deletion_list_first;
        struct llist_node *period_list_first;

        accounting_work         = container_of(work, struct accounting_work, work);
        deletion_list_first     = llist_del_all(&accounting_work->deletion_list);
        period_list_first       = llist_del_first(&accounting_work->accounting_period_list);
        current_period          = llist_entry(period_list_first, struct accounting_period, siblings);

        llist_for_each_entry_safe(pos, tmp, current_period->first, siblings) {

                if (unlikely(accounting_work->abort))
                        return;

                energy_accumulator = current_period->total_energy_consumption;
                energy_counters_multiply_scalar(&energy_accumulator, ktime_sub(pos->end, pos->start));
                energy_counters_div_round_up(&energy_accumulator, current_period->time_period);

                if (pos->energy == NULL) 
                        add_to_energy_counters(&accounting_work->idle_task, &energy_accumulator);
                else
                        add_to_energy_counters(&pos->energy->energy_consumption, &energy_accumulator);

                kfree(pos);
        }

        // TODO: remove
        atomic64_add(current_period->total_energy_consumption.core_uj, &accounting_work->total_energy_consumption_core_uj);
        atomic64_add(current_period->total_energy_consumption.uncore_uj, &accounting_work->total_energy_consumption_uncore_uj);

        llist_for_each_entry_safe(deletion_candidate, tmp_energy_cgroup, deletion_list_first, siblings) {
                parent = deletion_candidate->css.parent;
                if (!parent)
                        continue;
                add_to_energy_counters(&css_energy(parent)->energy_consumption, &deletion_candidate->energy_consumption);
                kfree(deletion_candidate);
        }
}

static bool entry_invalid(struct energy_history_entry *entry)
{
        return ktime_after(entry->start, entry->end);
}

static int construct_energy_history_entry(struct energy_history_entry **new_entry, struct energy_cgroup *energy, ktime_t start, ktime_t end)
{
        *new_entry = kzalloc(sizeof(struct energy_history_entry), GFP_KERNEL);
        if(!*new_entry) {
                pr_err("Failed to allocate memory for an energy history entry.\n");
                return -ENOMEM;
        }

        (*new_entry)->energy = energy;
        (*new_entry)->start = start;
        (*new_entry)->end = end;

        return 0;
}

static struct cftype energy_files[] = {
        {
                .name = "consumption",
                .seq_show = energy_consumption_read,
        },
        {
                .name = "json_consumption",
                .seq_show = energy_consumption_read_json,
        },
        {
                .name = "RAPL", 
                .seq_show = read_rapl,
        },
        {
                .name = "interval",
                .write = energy_accounting_inverval_write,
                .seq_show = energy_accounting_inverval_show,
                .flags = CFTYPE_ONLY_ON_ROOT,
        },
        {
                .name = "idle_consumption",
                .seq_show = energy_idle_task_consumption_show,
                .flags = CFTYPE_ONLY_ON_ROOT,
        },
        {
                .name = "idle_consumption_json",
                .seq_show = energy_idle_task_consumption_show_json,
                .flags = CFTYPE_ONLY_ON_ROOT,
        },
        { }
};

struct cgroup_subsys energy_cgrp_subsys = {
        .css_alloc              = energy_css_alloc, 
        .css_free               = energy_css_free,
        .attach                 = energy_attach, 
        .legacy_cftypes         = energy_files, 
        .dfl_cftypes            = energy_files, 
        .threaded               = true,
        .implicit_on_dfl        = true,
};

/* schedule() calls member_scheduled */
struct energy_cgroup_callbacks energy_cgroup_callbacks = {
        .member_scheduled       = energy_cgroup_task_scheduled,     
};

static void init_rapl_counters(struct rapl_counters* counters)
{
        counters->core = 0;
        counters->uncore = 0;
}

static void init_energy_counters(struct energy_counters *counters)
{
        counters->core_uj = 0;
        counters->uncore_uj = 0;
}

static inline int __read_rapl_msr(u32* value, u32 msr_nr, u64 mask, u64 offset)
{
        u64 val;
        int err;

        if (!value) {
                return -EINVAL;
        }

        if ((err = rdmsrl_safe(msr_nr, &val)) != 0) {
                return err;
        }

        *value = ((val & mask) >> offset);
        return 0;
}

static inline int __read_rapl_unit(u32* unit)
{
        u32 val = 0;
        int err;

        if ((err = __read_rapl_msr(&val, ENERGY_UNIT, MASK_UNIT, OFFSET_UNIT)) != 0) {
                return err;
        }

        /* The corresponding unit is (1/2) ^ val Joules. Hence I calculate (10 ^ 7) /
         * (2 ^ val) and thereby get micro Joules with one digit after the comma. */
        *unit = 10000000 / (1 << val);

        return 0;
}

static void read_unit(u32* unit)
{
        __read_rapl_unit(unit);
}


static void read_rapl_counters_intel(struct rapl_counters* counters)
{

        u32 dram = 0;
        u32 package = 0;
        u32 gpu = 0;

        __read_rapl_msr(&(counters->core), INTEL_ENERGY_CORE, MASK_CORE, OFFSET_CORE);
        
        __read_rapl_msr(&package, INTEL_ENERGY_PKG, MASK_PKG, OFFSET_PKG);
        __read_rapl_msr(&dram, INTEL_ENERGY_DRAM, MASK_DRAM, OFFSET_DRAM);
        __read_rapl_msr(&gpu, INTEL_ENERGY_GPU, MASK_GPU, OFFSET_GPU);

        counters->uncore = dram + gpu + package - counters->core;
}


static void read_rapl_counters_amd(struct rapl_counters* counters)
{
        u32 core;
        u32 package; 

        __read_rapl_msr(&core, AMD_ENERGY_CORE, MASK_CORE, OFFSET_CORE);
        __read_rapl_msr(&package, AMD_ENERGY_PKG, MASK_PKG, OFFSET_PKG);

        counters->core = core;
        counters->uncore = package - core;
}

// TODO: remove
/*
static void read_rapl_counters_mocking(struct rapl_counters* counters)
{
        ktime_t tmp = ktime_get();
        while (ktime_after(tmp, mock_time)){
                mock_time = ktime_add_ms(mock_time, MOCK_INTERVAL);
                mock_rapl.core   += 100000;
                mock_rapl.uncore += 10000;
        }
        *counters = mock_rapl;
}
*/

/**
 * rapl_counters_to_energy_counters - converts RAPL counters to energy counters
 * @rapl_counters: source counters
 * @energy_consumption: result counters
 * @unit: the unit used for the conversion
 */
static void rapl_counters_to_energy_counters(struct rapl_counters *rapl_counters, struct energy_counters *energy_consumption, u32 unit)
{
        energy_consumption->core_uj = rapl_counters->core * unit;
        energy_consumption->uncore_uj = rapl_counters->uncore * unit;
}

/**
 * add_to_energy_counters - adds right to left in place
 * @left: first summand and location of the result of the addition
 * @right: second summand
 */
static void add_to_energy_counters(struct energy_counters *left, struct energy_counters *right)
{
       left->core_uj    = left->core_uj    + right->core_uj;
       left->uncore_uj  = left->uncore_uj  + right->uncore_uj;

}

/**
 * energy_counters_multiply_scalar - multiplies a scalar value to each energy counter
 * @energy_counters: target counter
 * @scalar: scalar used for multiplication
 */
static void energy_counters_multiply_scalar(struct energy_counters *energy_counters, u64 scalar)
{
       energy_counters->core_uj   = energy_counters->core_uj   * scalar;
       energy_counters->uncore_uj = energy_counters->uncore_uj * scalar;
}

/**
 * energy_counters_div_round_up - divides each counter by the scalar and rounds up
 * @energy_counters: target counter
 * @scalar: divisor
 */
static void energy_counters_div_round_up(struct energy_counters *energy_counters, u64 scalar)
{
       energy_counters->core_uj   = DIV_ROUND_UP(energy_counters->core_uj, scalar);
       energy_counters->uncore_uj = DIV_ROUND_UP(energy_counters->uncore_uj, scalar);
}

/**
 * rapl_counters_diff - difference between two rapl_counters considering overflows
 * @res: rapl_counters for the result
 * @star: rapl_counters at start of the period
 * @end: rapl_counters at the end of the period
 */
static void rapl_counters_diff(struct rapl_counters *res, struct rapl_counters *start, struct rapl_counters *end)
{
        /* end - start considering overflows */
        if (end->core < start->core)
                res->core = U32_MAX - start->core + end->core;
        else
                res->core = end->core - start->core;

        if (end->uncore < start->uncore)
                res->uncore = U32_MAX - start->uncore + end->uncore;
        else
                res->uncore = end->uncore - start->uncore;
        
}
