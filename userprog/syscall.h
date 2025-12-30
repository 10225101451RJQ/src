#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

/* 【新增】文件系统锁接口 */
void filesys_lock_acquire(void);
void filesys_lock_release(void);

#endif /* userprog/syscall.h */
