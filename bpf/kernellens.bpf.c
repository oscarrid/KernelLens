// two in-kernel latency probes
#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

#define KL_OFFCPU 1
#define KL_BLOCKIO 2
#define COMM_LEN 16
#define TASK_RUNNING 0

// 48 bytes with no tail padding
struct evt {
  __u64 ts;
  __u64 delta_ns;
  __u32 pid;
  __u32 kind;
  __u32 aux;  // cpu for off-cpu events
  __u32 err;
  char comm[COMM_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 2);
  __type(key, __u32);
  __type(value, __u64);
} cfg SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 20480);
  __type(key, __u32);
  __type(value, __u64);
} offcpu SEC(".maps");

struct iokey {
  __u32 dev;
  __u32 pad;
  __u64 sector;
};

struct ioval {
  __u64 ts;
  __u32 pid;
  char comm[COMM_LEN];
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 20480);
  __type(key, struct iokey);
  __type(value, struct ioval);
} inflight SEC(".maps");

static __always_inline __u64 threshold(__u32 idx) {
  __u64 *v = bpf_map_lookup_elem(&cfg, &idx);
  return v ? *v : 0;
}

static __always_inline void submit(__u64 ts, __u64 delta, __u32 pid, __u32 kind, __u32 aux,
                                   __u32 err, const char *comm) {
  struct evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e) return;
  e->ts = ts;
  e->delta_ns = delta;
  e->pid = pid;
  e->kind = kind;
  e->aux = aux;
  e->err = err;
  __builtin_memcpy(e->comm, comm, COMM_LEN);
  bpf_ringbuf_submit(e, 0);
}

// field layout of /sys/kernel/tracing/events/sched/sched_switch/format
struct sched_switch_args {
  __u64 __pad;
  char prev_comm[COMM_LEN];
  __s32 prev_pid;
  __s32 prev_prio;
  __s64 prev_state;
  char next_comm[COMM_LEN];
  __s32 next_pid;
  __s32 next_prio;
};

SEC("tracepoint/sched/sched_switch")
int on_sched_switch(struct sched_switch_args *ctx) {
  __u64 now = bpf_ktime_get_ns();
  __u32 prev = (__u32)ctx->prev_pid;
  __u32 next = (__u32)ctx->next_pid;

  // switched out while still runnable: it lost the cpu to someone else.
  if (ctx->prev_state == TASK_RUNNING && prev)
    bpf_map_update_elem(&offcpu, &prev, &now, BPF_ANY);

  if (!next) return 0;
  __u64 *since = bpf_map_lookup_elem(&offcpu, &next);
  if (!since) return 0;
  __u64 delta = now - *since;
  bpf_map_delete_elem(&offcpu, &next);
  if (delta >= threshold(0))
    submit(now, delta, next, KL_OFFCPU, bpf_get_smp_processor_id(), 0, ctx->next_comm);
  return 0;
}

struct blk_issue_args {
  __u64 __pad;
  __u32 dev;
  __u64 sector;
  __u32 nr_sector;
  __u32 bytes;
  char rwbs[8];
  char comm[COMM_LEN];
};

struct blk_complete_args {
  __u64 __pad;
  __u32 dev;
  __u64 sector;
  __u32 nr_sector;
  __s32 error;
  char rwbs[8];
};

SEC("tracepoint/block/block_rq_issue")
int on_block_rq_issue(struct blk_issue_args *ctx) {
  struct iokey k = {};
  struct ioval v = {};
  k.dev = ctx->dev;
  k.sector = ctx->sector;
  v.ts = bpf_ktime_get_ns();
  v.pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
  __builtin_memcpy(v.comm, ctx->comm, COMM_LEN);
  bpf_map_update_elem(&inflight, &k, &v, BPF_ANY);
  return 0;
}

SEC("tracepoint/block/block_rq_complete")
int on_block_rq_complete(struct blk_complete_args *ctx) {
  struct iokey k = {};
  k.dev = ctx->dev;
  k.sector = ctx->sector;
  struct ioval *v = bpf_map_lookup_elem(&inflight, &k);
  if (!v) return 0;
  __u64 now = bpf_ktime_get_ns();
  __u64 delta = now - v->ts;
  __u32 pid = v->pid;
  char comm[COMM_LEN];
  __builtin_memcpy(comm, v->comm, COMM_LEN);
  bpf_map_delete_elem(&inflight, &k);
  if (delta >= threshold(1) || ctx->error)
    submit(now, delta, pid, KL_BLOCKIO, ctx->dev, (__u32)ctx->error, comm);
  return 0;
}
