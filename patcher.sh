#!/bin/bash
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0226-sched-Don-t-mix-use-of-typedef-ctl_table-and-struct-.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0227-sched-Update-cpu-load-after-task_tick.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0228-posix-cpu-timers-don-t-account-cpu-timer-after-stopp.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0229-sched-__wake_up_sync_key-Fix-nr_exclusive-tasks-whic.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0230-sched-Consolidate-open-coded-preemptible-check.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0231-sched-fix-the-theoretical-signal_wake_up-vs-schedule.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0232-cpumask-Fix-cpumask-leak-in-partition_sched_domains.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0233-sched-Remove-one-division-operation-in-find_busiest_.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0234-sched-fair-Fix-the-sd_parent_degenerate-code.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0235-sched-rt-Add-missing-rmb.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0236-sched-Move-cputime-code-to-its-own-file.patch