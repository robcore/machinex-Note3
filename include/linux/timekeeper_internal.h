/*
 * You SHOULD NOT be including this unless you're vsyscall
 * handling code or timekeeping internal code!
 */

#ifndef _LINUX_TIMEKEEPER_INTERNAL_H
#define _LINUX_TIMEKEEPER_INTERNAL_H

#include <linux/clocksource.h>
#include <linux/jiffies.h>
#include <linux/time.h>

extern ktime_t ntp_get_next_leap(void);
extern int __do_adjtimex(struct timex *);

/* Structure holding internal timekeeping values. */
struct timekeeper {
	/* Current clocksource used for timekeeping. */
	struct clocksource *clock;
	/* NTP adjusted clock multiplier */
	u32	mult;
	/* The shift value of the current clocksource. */
	int	shift;

	/* CLOCK_MONOTONIC time value of a pending leap-second*/
	ktime_t	next_leap_ktime;
	/* Number of clock cycles in one NTP interval. */
	cycle_t cycle_interval;
	/* Number of clock shifted nano seconds in one NTP interval. */
	u64	xtime_interval;
	/* shifted nano seconds left over when rounding cycle_interval */
	s64	xtime_remainder;
	/* Raw nano seconds accumulated per NTP interval. */
	u32	raw_interval;

	/* Clock shifted nano seconds remainder not stored in xtime.tv_nsec. */
	u64	xtime_nsec;
	/* Difference between accumulated time and NTP time in ntp
	 * shifted nano seconds. */
	s64	ntp_error;
	/* Shift conversion between clock shifted nano seconds and
	 * ntp shifted nano seconds. */
	int	ntp_error_shift;

	/* The current time */
	struct timespec xtime;
	/*
	 * wall_to_monotonic is what we need to add to xtime (or xtime corrected
	 * for sub jiffie times) to get to monotonic time.  Monotonic is pegged
	 * at zero at system boot time, so wall_to_monotonic will be negative,
	 * however, we will ALWAYS keep the tv_nsec part positive so we can use
	 * the usual normalization.
	 *
	 * wall_to_monotonic is moved after resume from suspend for the
	 * monotonic time not to jump. We need to add total_sleep_time to
	 * wall_to_monotonic to get the real boot based time offset.
	 *
	 * - wall_to_monotonic is no longer the boot time, getboottime must be
	 * used instead.
	 */
	struct timespec wall_to_monotonic;
	/* time spent in suspend */
	struct timespec total_sleep_time;
	/* The raw monotonic time for the CLOCK_MONOTONIC_RAW posix clock. */
	struct timespec raw_time;

	/* Offset clock monotonic -> clock realtime */
	ktime_t offs_real;

	/* Offset clock monotonic -> clock boottime */
	ktime_t offs_boot;

	/* Seqlock for all timekeeper values */
	seqlock_t lock;
};
#endif /* _LINUX_TIMEKEEPER_INTERNAL_H */
