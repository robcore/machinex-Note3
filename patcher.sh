#!/bin/bash

patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0237-cputime-Move-thread_group_cputime-to-sched-code.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0238-cputime-Rename-thread_group_times-to-thread_group_cp.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0239-cputime-Consolidate-cputime-adjustment-code.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0240-cputime-Comment-cputime-s-adjusting-code.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0241-cputime-Move-default-nsecs_to_cputime-to-jiffies-bas.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0242-random-Mix-cputime-from-each-thread-that-exits-to-th.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0243-cputime-Use-accessors-to-read-task-cputime-stats.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0244-cputime-Avoid-multiplication-overflow-on-utime-scali.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0245-sched-Lower-chances-of-cputime-scaling-overflow.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0246-sched-cputime-Fix-accounting-on-multi-threaded-proce.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0247-sched-Avoid-cputime-scaling-overflow.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0248-sched-Do-not-account-bogus-utime.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0249-sched-Avoid-prev-stime-underflow.patch
patch -p1 -N < /media/root/robcore/android/DORIMANX_NEW/patches/patches3/0250-sched-Use-swap-macro-in-scale_stime.patch