## Futex in Kernel Implementation (1) - futex_wait

This article demonstrates kernel implementation of futex. 

_<kernel/futex/syscalls.c>_
```
SYSCALL_DEFINE6(futex, u32 __user *, uaddr, int, op, u32, val,
		const struct __kernel_timespec __user *, utime,
		u32 __user *, uaddr2, u32, val3)
{
	int ret, cmd = op & FUTEX_CMD_MASK;
	ktime_t t, *tp = NULL;
	struct timespec64 ts;
    
	if (utime && futex_cmd_has_timeout(cmd)) {
		if (unlikely(should_fail_futex(!(op & FUTEX_PRIVATE_FLAG))))
			return -EFAULT;
		if (get_timespec64(&ts, utime))
			return -EFAULT;
		ret = futex_init_timeout(cmd, op, &ts, &t);
		if (ret)
			return ret;
		tp = &t;
	}

	return do_futex(uaddr, op, val, tp, uaddr2, (unsigned long)utime, val3);
}
```

Until 5.15 kernel, futex has been implemented in _kernel/futex.c_ file. However, from 5.16 kernel, futex has dedicated directory (_kernel/futex_), and it's implementation is separated into multiple file. 

The entry point of futex syscall is defined at _syscalls.c_. All of futex operation is multiflex via _do\_futex_() function, although the community is considering defining syscall for each operation [link](https://linuxplumbersconf.org/event/11/contributions/1058/attachments/788/1481/futex_lpc2021.pdf).

_<kernel/futex/syscalls.c>_
```
long do_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout,
		u32 __user *uaddr2, u32 val2, u32 val3)
{ ...
	switch (cmd) {
	case FUTEX_WAIT:
		val3 = FUTEX_BITSET_MATCH_ANY;
		fallthrough;
	case FUTEX_WAIT_BITSET:
		return futex_wait(uaddr, flags, val, timeout, val3);
	case FUTEX_WAKE:
		val3 = FUTEX_BITSET_MATCH_ANY;
		fallthrough;
	case FUTEX_WAKE_BITSET:
		return futex_wake(uaddr, flags, val, val3);
	case FUTEX_REQUEUE:
```
In _do\_futex_(), the request is, with appropriate flag being set, routed to corresponding function. This article only deals with futex_wait and futex_wake.

_<kernel/futex/waitwake.c>_
```
int futex_wait(u32 __user *uaddr, unsigned int flags, u32 val, ktime_t *abs_time, u32 bitset)
{
	struct hrtimer_sleeper timeout, *to;
	struct restart_block *restart;
	struct futex_hash_bucket *hb;
	struct futex_q q = futex_q_init;
	int ret;

	if (!bitset)
		return -EINVAL;
	q.bitset = bitset;

	to = futex_setup_timer(abs_time, &timeout, flags,
			       current->timer_slack_ns);
retry:
	ret = futex_wait_setup(uaddr, val, flags, &q, &hb);
	if (ret)
		goto out;

	futex_wait_queue(hb, &q, to);

	ret = 0;
	if (!futex_unqueue(&q))
		goto out;
	ret = -ETIMEDOUT;
	if (to && !to->task)
		goto out;

	if (!signal_pending(current))
		goto retry;

	ret = -ERESTARTSYS;
	if (!abs_time)
		goto out;

	restart = &current->restart_block;
	restart->futex.uaddr = uaddr;
	restart->futex.val = val;
	restart->futex.time = *abs_time;
	restart->futex.bitset = bitset;
	restart->futex.flags = flags | FLAGS_HAS_TIMEOUT;

	ret = set_restart_fn(restart, futex_wait_restart);

out:
	if (to) {
		hrtimer_cancel(&to->timer);
		destroy_hrtimer_on_stack(&to->timer);
	}
	return ret;
}
```

_<kernel/futex/futex.h>_
```
struct futex_q {
	struct plist_node list;

	struct task_struct *task;
	spinlock_t *lock_ptr;
	union futex_key key;
	struct futex_pi_state *pi_state;
	struct rt_mutex_waiter *rt_waiter;
	union futex_key *requeue_pi_key;
	u32 bitset;
	atomic_t requeue_state;
#ifdef CONFIG_PREEMPT_RT
	struct rcuwait requeue_wait;
#endif
} __randomize_layout;
```


futex_wait is routed to _futex\_wait_() in waitwait.c. Here, we allocate a futex_q data structure. _futex\_q_ is futex's hashed queue entry defined for each waiting task. In futex_wait, the task enqueues a _futex\_q_, and when another thread calls futex_wake, dequeue an _futex\_q_ entry and wakes up sleeping thread. 

_<kernel/futex/waitwake.c>_
```
int futex_wait_setup(u32 __user *uaddr, u32 val, unsigned int flags,
		     struct futex_q *q, struct futex_hash_bucket **hb)
{
	u32 uval;
	int ret;
retry:
	ret = get_futex_key(uaddr, flags & FLAGS_SHARED, &q->key, FUTEX_READ);
	if (unlikely(ret != 0))
		return ret;

retry_private:
	*hb = futex_q_lock(q);

	ret = futex_get_value_locked(&uval, uaddr);

	if (ret) {
		futex_q_unlock(*hb);

		ret = get_user(uval, uaddr);
		if (ret)
			return ret;

		if (!(flags & FLAGS_SHARED))
			goto retry_private;

		goto retry;
	}

	if (uval != val) {
		futex_q_unlock(*hb);
		ret = -EWOULDBLOCK;
	}

	return ret;
}
```

_futex\_wait\_setup_() prepares to wait on the futex by generating appropriate futex key, and loading it into futex_q. Then it compares _addr_'s value with expected value (_val_). If returns 0 if expected value matchs, and returns 1 if doesn't.

_<kernel/futex/core.c>_
```
int get_futex_key(u32 __user *uaddr, bool fshared, union futex_key *key,
		  enum futex_access rw)
{
	unsigned long address = (unsigned long)uaddr;
	struct mm_struct *mm = current->mm;
	struct page *page, *tail;
	struct address_space *mapping;
	int err, ro = 0;

`	...

	if (!fshared) {
		key->private.mm = mm;
		key->private.address = address;
		return 0;
	}
	
    ...
    
	if (PageAnon(page)) {
		if (unlikely(should_fail_futex(true)) || ro) {
			err = -EFAULT;
			goto out;
		}

		key->both.offset |= FUT_OFF_MMSHARED; /* ref taken on mm */
		key->private.mm = mm;
		key->private.address = address;

	} 
    
    else {
		struct inode *inode;
		
        ...

		key->both.offset |= FUT_OFF_INODE; /* inode-based key */
		key->shared.i_seq = get_inode_sequence_number(inode);
		key->shared.pgoff = page_to_pgoff(tail);
		rcu_read_unlock();
	}

out:
	put_page(page);
	return err;
}
```
| ![futex hash table](https://github.com/wanyaworld/wanyaworld.github.io/blob/master/_posts/dvh-futexes.png) |
| :--: |
| futex hash table |


There are three cases by which futex key is generated. 

First, if futex is private futex (futex is shared among only threads in same process), it is enough to use virtual address of the futex variable (_uaddr_).

Second, if (global) futex variable is on anon-page, since addr is not enough to uniquely identify futex, we use curren thread's _mm\_struct_ and _addr_.

Lastly, if (global) futex variable is file-backed, we use inode number and page offset.

_<kernel/futex/core.c>_
```
struct futex_hash_bucket *futex_q_lock(struct futex_q *q)
	__acquires(&hb->lock)
{
	struct futex_hash_bucket *hb;

	hb = futex_hash(&q->key);

	futex_hb_waiters_inc(hb);

	q->lock_ptr = &hb->lock;

	spin_lock(&hb->lock);
	return hb;
}
```
_futex\_q\_lock_() increases corresponding hash bucket's waiter counter and acquires hash bucket's spin lock. It increses counter before acquiring hash bucket lock. 

The change of order might cause wake to miss a waiter waiting for the hash bucket lock, because waker firstly checks the hash bucket's wainter count and if it is zero, does not perform any wake-ups. 

Back to futex_wait, if futex_wait_setup returns non-zero value, meaning futex variable equals the expected value and there's no need to sleep, it goes to out and returns and control is switched to user-space.

If not, it enqueues its _futex\_q_ and sleeps.

_<kernel/futex/waitwake.c>_
```
void futex_wait_queue(struct futex_hash_bucket *hb, struct futex_q *q,
			    struct hrtimer_sleeper *timeout)
{
	set_current_state(TASK_INTERRUPTIBLE);
	futex_queue(q, hb);

	...

	if (likely(!plist_node_empty(&q->list))) {
		if (!timeout || timeout->task)
			freezable_schedule();
	}
	__set_current_state(TASK_RUNNING);
}
```
Before sleeping it changes the threads' scheduling status to _TASK\_INTERRUPTIBLE_ (although the process state does not change before it calls _schedule_()) , then enqueues _futex\_q_ in _futex\_queue_(), then _schedules_().
