#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
/* 修改 */
struct thread; /* 前置声明，防止报错 */

int GetRetFromSonsList(struct thread *t, tid_t tid);
int CloseFile(struct thread *t, int fd, int bAll);
void record_ret(struct thread *t, int tid, int ret);
void ExitStatus(int status);

#endif /* userprog/process.h */
