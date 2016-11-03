#ifdef CONFIG_ARCH_MSM8610
struct task_struct * mutex_get_owner(struct mutex *lock)
{
	struct task_struct *owner;
	unsigned long flags;

	spin_lock_mutex(&lock->wait_lock, flags);
	owner = lock->owner;
	spin_unlock_mutex(&lock->wait_lock, flags);

	return owner;
}
EXPORT_SYMBOL(mutex_get_owner);
#endif
