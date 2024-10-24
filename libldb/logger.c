#define _GNU_SOURCE
#include "common.h"
#include "ldb/logger.h"
#include "lock.h"

#define LDB_EVENT_OUTPUT "ldb.data"

extern ldb_shmseg *ldb_shared;
extern bool running;
bool reset;

void *logger_main(void *arg) {
  FILE *ldb_fout = fopen(LDB_EVENT_OUTPUT, "wb");
  char cmd_map_buf[128];
  ldb_event_buffer_t *ebuf;
  int head;
  int len;

  printf("logger thread starts\n");

  cpu_set_t cpuset;

  CPU_ZERO(&cpuset);
  CPU_SET(1, &cpuset);
  pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

  // store maps
  pid_t pid_self = syscall(SYS_getpid);
  sprintf(cmd_map_buf, "cat /proc/%d/maps > maps.data", pid_self);
  // does map information changes over time?
  system(cmd_map_buf);

  while (running) {
    if (unlikely(reset)) {
      fclose(ldb_fout);
      ldb_fout = fopen(LDB_EVENT_OUTPUT, "wb");
      reset = false;
    }

    for (int tidx = 0; tidx < ldb_shared->ldb_max_idx; ++tidx) {
      ldb_thread_info_t *thread_info = &ldb_shared->ldb_thread_infos[tidx];

      if (!ldb_thread_info_lock_try_acquire_read(&thread_info->lock)) {
        continue;
      }

      // Skip if event buffer is not valid
      if (thread_info->ebuf == NULL) {
        ldb_thread_info_lock_release_read(&thread_info->lock);
        continue;
      }

      ebuf = thread_info->ebuf;
      head = ebuf->head;
      barrier();
      len = ebuf->tail - head;

      if (len <= 0) {
        ldb_thread_info_lock_release_read(&thread_info->lock);
        continue;
      }
      int end = LDB_EVENT_BUF_SIZE - (head % LDB_EVENT_BUF_SIZE);
      if (len > end) len = end;

      fwrite(&ebuf->events[head % LDB_EVENT_BUF_SIZE], sizeof(ldb_event_entry), len, ldb_fout);
      fflush(ldb_fout);

      ebuf->head = head + len;

      ldb_thread_info_lock_release_read(&thread_info->lock);
    }// for
  }// while (running)

  fclose(ldb_fout);

  printf("logger thread exiting...\n");
  return NULL;
}

void logger_reset() {
  reset = true;
}
