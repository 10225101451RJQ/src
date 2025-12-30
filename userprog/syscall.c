#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "userprog/process.h"
#include <string.h>
#include "devices/shutdown.h"
#include "threads/malloc.h"
#include "userprog/pagedir.h"

#define MAXCALL 21
#define MaxFiles 200

/* 文件系统全局锁 */
static struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);
typedef void (*CALL_PROC)(struct intr_frame*);
CALL_PROC pfn[MAXCALL];

/* 函数声明 */
void IWrite(struct intr_frame*);
void IExit(struct intr_frame *f);
void ExitStatus(int status);
void ICreate(struct intr_frame *f);
void IOpen(struct intr_frame *f);
void IClose(struct intr_frame *f);
void IRead(struct intr_frame *f);
void IFileSize(struct intr_frame *f);
void IExec(struct intr_frame *f);
void IWait(struct intr_frame *f);
void ISeek(struct intr_frame *f);
void IRemove(struct intr_frame *f);
void ITell(struct intr_frame *f);
void IHalt(struct intr_frame *f);

/* 【完整】指针验证和参数检查函数 */
static void check_user_ptr(const void *ptr);
static void check_user_buffer(const void *buffer, unsigned size);
static void check_user_string(const char *str);
static int32_t get_arg(int *esp, int offset);

struct file_node *GetFile(struct thread *t, int fd);
extern int CloseFile(struct thread *t, int fd, int bAll);

void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  
  /* 初始化文件系统锁 */
  lock_init(&filesys_lock);
  
  int i;
  for(i = 0; i < MAXCALL; i++)
    pfn[i] = NULL;
    
  pfn[SYS_WRITE] = IWrite;
  pfn[SYS_EXIT] = IExit;
  pfn[SYS_CREATE] = ICreate;
  pfn[SYS_OPEN] = IOpen;
  pfn[SYS_CLOSE] = IClose;
  pfn[SYS_READ] = IRead;
  pfn[SYS_FILESIZE] = IFileSize;
  pfn[SYS_EXEC] = IExec;
  pfn[SYS_WAIT] = IWait;
  pfn[SYS_SEEK] = ISeek;
  pfn[SYS_REMOVE] = IRemove;
  pfn[SYS_TELL] = ITell;
  pfn[SYS_HALT] = IHalt;
}

/* ==================== 参数验证辅助函数 ==================== */

/* 检查单个指针是否有效 */
static void 
check_user_ptr(const void *ptr)
{
  if (ptr == NULL || !is_user_vaddr(ptr) ||
      pagedir_get_page(thread_current()->pagedir, ptr) == NULL) {
    ExitStatus(-1);
  }
}

/* 检查缓冲区：检查首尾地址 */
static void
check_user_buffer(const void *buffer, unsigned size)
{
  if (buffer == NULL || size == 0)
    return;
    
  check_user_ptr(buffer);
  if (size > 1)
    check_user_ptr((char *)buffer + size - 1);
}

/* 检查字符串：至少检查起始地址，实际访问时会触发页错误 */
static void
check_user_string(const char *str)
{
  check_user_ptr(str);
  
  /* 可选：额外检查字符串不会跨越到内核空间 */
  const char *p = str;
  while (is_user_vaddr(p)) {
    if (pagedir_get_page(thread_current()->pagedir, p) == NULL)
      ExitStatus(-1);
    
    /* 找到字符串结尾就返回 */
    if (*p == '\0')
      return;
    
    p++;
    
    /* 防止无限循环：字符串最多 4KB */
    if (p - str > PGSIZE)
      ExitStatus(-1);
  }
  
  /* 字符串延伸到内核空间 */
  ExitStatus(-1);
}

/* 安全地获取系统调用参数 */
static int32_t
get_arg(int *esp, int offset)
{
  check_user_ptr(esp + offset);
  return *(esp + offset);
}

/* 文件系统锁接口 */
void filesys_lock_acquire(void)
{
  lock_acquire(&filesys_lock);
}

void filesys_lock_release(void)
{
  lock_release(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f)
{
  /* 检查栈指针 */
  check_user_ptr(f->esp);
  
  int *esp = (int *)f->esp;
  int No = *esp;
  
  if (No >= MAXCALL || No < 0) {
    ExitStatus(-1);
  }
  
  if (pfn[No] == NULL) {
    ExitStatus(-1);
  }
  
  pfn[No](f);
}

void IWrite(struct intr_frame *f)
{
  int *esp = (int *)f->esp;
  
  /* 使用 get_arg 安全获取参数 */
  int fd = get_arg(esp, 1);
  char *buffer = (char *)get_arg(esp, 2);
  unsigned size = (unsigned)get_arg(esp, 3);
  
  /* 检查缓冲区 */
  check_user_buffer(buffer, size);
  
  if (fd == STDOUT_FILENO) {
    putbuf (buffer, size);
    f->eax = size;
  } else {
    struct thread *cur = thread_current();
    struct file_node *fn = GetFile(cur, fd);
    if (fn == NULL) {
      f->eax = 0;
      return;
    }
    
    filesys_lock_acquire();
    f->eax = file_write(fn->f, buffer, size);
    filesys_lock_release();
  }
}

void IExit(struct intr_frame *f)
{
  int *esp = (int *)f->esp;
  int status = get_arg(esp, 1);
    
  struct thread *cur = thread_current();
  cur->ret = status;
  f->eax = 0;
  thread_exit();
}

void ExitStatus(int status)
{
  struct thread *cur = thread_current();
  cur->ret = status;
  thread_exit();
}

void ICreate(struct intr_frame *f)
{
  int *esp = (int *)f->esp;
  
  char *fileName = (char *)get_arg(esp, 1);
  unsigned initial_size = (unsigned)get_arg(esp, 2);
  
  /* 检查文件名字符串 */
  check_user_string(fileName);
  
  filesys_lock_acquire();
  bool ret = filesys_create(fileName, initial_size);
  filesys_lock_release();
  
  f->eax = ret;
}

void IOpen(struct intr_frame *f)
{
  int *esp = (int *)f->esp;
  
  const char *FileName = (char *)get_arg(esp, 1);
  
  /* 检查文件名字符串 */
  check_user_string(FileName);
  
  struct thread *cur = thread_current();
  if (cur->FileNum >= MaxFiles) {
    f->eax = -1;
    return;
  }
  
  struct file_node *fn = (struct file_node *)malloc(sizeof(struct file_node));
  if (fn == NULL) {
    f->eax = -1;
    return;
  }
  
  filesys_lock_acquire();
  fn->f = filesys_open(FileName);
  filesys_lock_release();
  
  if (fn->f == NULL) {
    free(fn);
    f->eax = -1;
  } else {
    fn->fd = ++cur->maxfd;
    cur->FileNum++;
    list_push_back(&cur->file_list, &fn->elem);
    f->eax = fn->fd;
  }
}

void IClose(struct intr_frame *f)
{
  int *esp = (int *)f->esp;
  int fd = get_arg(esp, 1);
    
  struct thread *cur = thread_current();
  
  filesys_lock_acquire();
  f->eax = CloseFile(cur, fd, false);
  filesys_lock_release();
}

void IRead(struct intr_frame *f)
{
  int *esp = (int *)f->esp;
  
  int fd = get_arg(esp, 1);
  char *buffer = (char *)get_arg(esp, 2);
  unsigned size = (unsigned)get_arg(esp, 3);
  
  /* 检查缓冲区 */
  check_user_buffer(buffer, size);
  
  struct thread *cur = thread_current();
  unsigned int i;
  
  if (fd == STDIN_FILENO) {
    for (i = 0; i < size; i++)
      buffer[i] = input_getc();
    f->eax = size;
  } else {
    struct file_node *fn = GetFile(cur, fd);
    if (fn == NULL) {
      f->eax = -1;
      return;
    }
    
    filesys_lock_acquire();
    f->eax = file_read(fn->f, buffer, size);
    filesys_lock_release();
  }
}

void IFileSize(struct intr_frame *f)
{
  int *esp = (int *)f->esp;
  int fd = get_arg(esp, 1);
    
  struct thread *cur = thread_current();
  struct file_node *fn = GetFile(cur, fd);
  
  if (fn == NULL) {
    f->eax = -1;
    return;
  }
  
  filesys_lock_acquire();
  f->eax = file_length(fn->f);
  filesys_lock_release();
}

void IExec(struct intr_frame *f)
{
  int *esp = (int *)f->esp;
  
  const char *file = (char *)get_arg(esp, 1);
  
  /* 检查文件名字符串 */
  check_user_string(file);
  
  tid_t tid = process_execute(file);
  
  if (tid == TID_ERROR) {
    f->eax = -1;
    return;
  }
  
  /* 等待子进程加载完成 */
  struct thread *child = GetThreadFromTid(tid);
  if (child != NULL) {
    sema_down(&child->SemaWaitSuccess);
    if (child->tid == TID_ERROR) {
      f->eax = -1;
    } else {
      f->eax = tid;
    }
  } else {
    f->eax = -1;
  }
}

void IWait(struct intr_frame *f)
{
  int *esp = (int *)f->esp;
  tid_t tid = (tid_t)get_arg(esp, 1);
  
  f->eax = process_wait(tid);
}

void ISeek(struct intr_frame *f)
{
  int *esp = (int *)f->esp;
  
  int fd = get_arg(esp, 1);
  unsigned int pos = (unsigned)get_arg(esp, 2);
  
  struct file_node *fl = GetFile(thread_current(), fd);
  if (fl != NULL) {
    filesys_lock_acquire();
    file_seek(fl->f, pos);
    filesys_lock_release();
  }
}

void IRemove(struct intr_frame *f)
{
  int *esp = (int *)f->esp;
  
  char *fl = (char *)get_arg(esp, 1);
  
  /* 检查文件名字符串 */
  check_user_string(fl);
  
  filesys_lock_acquire();
  f->eax = filesys_remove(fl);
  filesys_lock_release();
}

void ITell(struct intr_frame *f)
{
  int *esp = (int *)f->esp;
  int fd = get_arg(esp, 1);
    
  struct file_node *fl = GetFile(thread_current(), fd);
  
  if (fl == NULL || fl->f == NULL) {
    f->eax = -1;
    return;
  }
  
  filesys_lock_acquire();
  f->eax = file_tell(fl->f);
  filesys_lock_release();
}

void IHalt(struct intr_frame *f)
{
  shutdown_power_off();
  f->eax = 0;
}

struct file_node *GetFile(struct thread *t, int fd)
{
  struct list_elem *e;
  for (e = list_begin (&t->file_list); e != list_end (&t->file_list); 
       e = list_next (e)) {
    struct file_node *fn = list_entry (e, struct file_node, elem);
    if (fn->fd == fd)
      return fn;
  }
  return NULL;
}
