/*
    A simple spin lock to prevent race condition on accessing
    and cleaning up the thread_info regions.
    
    This spinlock does not require (de-)initialization, where
    a value of 0 just means it can be aquired. And can also be
    implicitly unlocked when zeroing out the ldb_thread_info_t
*/

#ifndef LDB_LOCK_H
#define LDB_LOCK_H

#include <stdatomic.h>
#include <stdbool.h>

typedef struct {
    atomic_int counter; // positive: number of readers, -1: writer holds the lock
} ldb_thread_info_lock_t;

// try to acquire read lock (non-blocking)
inline __attribute__((always_inline)) bool ldb_thread_info_lock_try_acquire_read(ldb_thread_info_lock_t *lock) {
    int count = atomic_load_explicit(&lock->counter, memory_order_acquire);
    if (count < 0) {
        // writer holds the lock; cannot acquire read lock
        return false;
    }
    // attempt to increment the reader count
    if (atomic_compare_exchange_strong_explicit(
            &lock->counter, &count, count + 1,
            memory_order_acquire, memory_order_relaxed)) {
        // acquired read lock
        return true;
    }
    // failed to acquire read lock
    return false;
}

// acquire read lock (blocking)
inline __attribute__((always_inline)) void ldb_thread_info_lock_acquire_read(ldb_thread_info_lock_t *lock) {
    while (true) {
        int count = atomic_load_explicit(&lock->counter, memory_order_acquire);
        if (count < 0) {
            // writer holds lock, keep spinning
            continue;
        }
        if (atomic_compare_exchange_weak_explicit(
                &lock->counter, &count, count + 1,
                memory_order_acquire, memory_order_relaxed)) {
            // successfully acquired read lock
            return;
        }
    }
}

// release read lock
inline __attribute__((always_inline)) void ldb_thread_info_lock_release_read(ldb_thread_info_lock_t *lock) {
    atomic_fetch_sub_explicit(&lock->counter, 1, memory_order_release);
}

// acquire write lock (blocking)
inline __attribute__((always_inline)) void ldb_thread_info_lock_acquire_write(ldb_thread_info_lock_t *lock) {
    int expected;
    do {
        expected = 0;
        // attempt to set counter from 0 to -1
    } while (!atomic_compare_exchange_strong_explicit(
                &lock->counter, &expected, -1,
                memory_order_acquire, memory_order_relaxed));
}

// release write lock
inline __attribute__((always_inline)) void ldb_thread_info_lock_release_write(ldb_thread_info_lock_t *lock) {
    atomic_store_explicit(&lock->counter, 0, memory_order_release);
}

#endif // LDB_LOCK_H
