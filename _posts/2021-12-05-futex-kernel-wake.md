---
layout: post
title: "Futex in Kernel Implementation (2) - futex_wake"
---

## Futex in Kernel Implementation (2) - futex_wake

In this article, we're going to look over futex_wake linux kernel implementation. I recommend you to read my article about futex_wait before reading [this article](https://wanyaworld.github.io/2021/12/04/futex-kernel.html).

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

Like futex_wait, user's futex_wake call is initailly handled in futex syscall in _syscalls.c_, then routed to _futex\_wake_. 

_<kernel/futex/waitwake.c>_
```
int futex_wake(u32 __user *uaddr, unsigned int flags, int nr_wake, u32 bitset)
{
	struct futex_hash_bucket *hb;
	struct futex_q *this, *next;
	union futex_key key = FUTEX_KEY_INIT;
	int ret;
	DEFINE_WAKE_Q(wake_q);

	if (!bitset)
		return -EINVAL;

	ret = get_futex_key(uaddr, flags & FLAGS_SHARED, &key, FUTEX_READ);
	if (unlikely(ret != 0))
		return ret;

	hb = futex_hash(&key);

	if (!futex_hb_waiters_pending(hb))
		return ret;

	spin_lock(&hb->lock);

	plist_for_each_entry_safe(this, next, &hb->chain, list) {
		if (futex_match (&this->key, &key)) {
			if (this->pi_state || this->rt_waiter) {
				ret = -EINVAL;
				break;
			}

			/* Check if one of the bits is set in both bitsets */
			if (!(this->bitset & bitset))
				continue;

			futex_wake_mark(&wake_q, this);
			if (++ret >= nr_wake)
				break;
		}
	}

	spin_unlock(&hb->lock);
	wake_up_q(&wake_q);
	return ret;
}
```

In _futex\_wake_, futex key is loaded to _futex\_q_ like it was in _futex\_wait_. Then, if there are some waiter for the corresponding hash bucket, we mark these waites and finally wake them up in _wake\_up_q_. If not, we simply return.

_<kernel/futex/waitwake.c>_
```
/* In futex wake up scenarios where no tasks are blocked on a futex, taking
 * the hb spinlock can be avoided and simply return. In order for this
 * optimization to work, ordering guarantees must exist so that the waiter
 * being added to the list is acknowledged when the list is concurrently being
 * checked by the waker, avoiding scenarios like the following:
 *
 * CPU 0                               CPU 1
 * val = *futex;
 * sys_futex(WAIT, futex, val);
 *   futex_wait(futex, val);
 *   uval = *futex;
 *                                     *futex = newval;
 *                                     sys_futex(WAKE, futex);
 *                                       futex_wake(futex);
 *                                       if (queue_empty())
 *                                         return;
 *   if (uval == val)
 *      lock(hash_bucket(futex));
 *      queue();
 *     unlock(hash_bucket(futex));
 *     schedule();
 *
 * This would cause the waiter on CPU 0 to wait forever because it
 * missed the transition of the user space value from val to newval
 * and the waker did not find the waiter in the hash bucket queue.
 *
 * The correct serialization ensures that a waiter either observes
 * the changed user space value before blocking or is woken by a
 * concurrent waker:
 *
 * CPU 0                                 CPU 1
 * val = *futex;
 * sys_futex(WAIT, futex, val);
 *   futex_wait(futex, val);
 *
 *   waiters++; (a)
 *   smp_mb(); (A) <-- paired with -.
 *                                  |
 *   lock(hash_bucket(futex));      |
 *                                  |
 *   uval = *futex;                 |
 *                                  |        *futex = newval;
 *                                  |        sys_futex(WAKE, futex);
 *                                  |          futex_wake(futex);
 *                                  |
 *                                  `--------> smp_mb(); (B)
 *   if (uval == val)
 *     queue();
 *     unlock(hash_bucket(futex));
 *     schedule();                         if (waiters)
 *                                           lock(hash_bucket(futex));
 *   else                                    wake_waiters(futex);
 *     waiters--; (b)                        unlock(hash_bucket(futex));
 */
 ```
 
For that optimization to work properly, we need to synchronize some memory instruction for waiter and waker using barrier. Waiter must guarantee that increment of the number of waiters happens before reading value of futex variable. On the other hand, waker must guerantee that update of the futex variable happens before checking the number of waiters. 

To understand the need of barrier, consider the following example.

A water issues the following instruction:
1. increment of the number of waiters
2. reading value of futex variable. 

And a waker issues the following instruction:
3. update of the futex variable
4. checking the number of waiters.

Since there is not any dependency between 1 and 2, 3 and 4, compilers or machines are free to reorder instructions. Suppose, as a result of instruction reordering, instruction sequence is like following: 2 - 4 - 1 - 3.

Waiter reads futex variable and finds out that it is the expected value. Waker checks the number of waiters and finds out there is not waiter on the hash bucket. Then, waiter increments _waiters_, queues itself and sleeps. Waker updates the futex variable, and since there is not waiter, simply returns. Now waiter might sleeps indefinetly even though the futex variable is not the expected value.

_<kernel/futex/futex.h>_
```
static inline int futex_hb_waiters_pending(struct futex_hash_bucket *hb)
{
	smp_mb();
	return atomic_read(&hb->waiters);
}

static inline void futex_hb_waiters_inc(struct futex_hash_bucket *hb)
{
	atomic_inc(&hb->waiters);
	smp_mb__after_atomic();
}
```

We can see barrier instruction in _futex\_hb\_waiters\_pending_ and _futex\_hb\_waiters\_inc_.

_<kernel/futex/futex.h>_
```
static inline int futex_match(union futex_key *key1, union futex_key *key2)
{
	return (key1 && key2
		&& key1->both.word == key2->both.word
		&& key1->both.ptr == key2->both.ptr
		&& key1->both.offset == key2->both.offset);
}
```
Back to _futex\_wake_,for each _futex\_q_ entry, we check if the entry's key matches our futex in _futex_match_. As I explained in [previous article](https://wanyaworld.github.io/2021/12/04/futex-kernel.html), futex key is defined in three different scenarios (private futex, global futex in anonymous page, global futex in file-backed page). We match futex key in the same way regardless of the scenario.

_<kernel/sched/core.c>_
```
void wake_up_q(struct wake_q_head *head)
{
	struct wake_q_node *node = head->first;

	while (node != WAKE_Q_TAIL) {
		struct task_struct *task;

		task = container_of(node, struct task_struct, wake_q);
		/* Task can safely be re-inserted now: */
		node = node->next;
		task->wake_q.next = NULL;

		/*
		 * wake_up_process() executes a full barrier, which pairs with
		 * the queueing in wake_q_add() so as not to miss wakeups.
		 */
		wake_up_process(task);
		put_task_struct(task);
	}
}
```
If the key matches, we enqueue the task into scheduler's wake-up queue.
