#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <string.h>
#include "threads/malloc.h"
#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);
void push_arguments (void **esp, char *cmd_line);

/* 【修复1】添加最大参数数量限制 */
#define MAX_ARGS 128

/* 【修复2】改进 process_execute，添加更好的错误处理 */
tid_t
process_execute (const char *file_name)
{
  char *fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  /* 【修复】使用栈内存而不是局部数组，更安全 */
  char thread_name[NAME_MAX + 2];
  strlcpy (thread_name, file_name, sizeof thread_name);
  
  char *real_name, *save_ptr;
  real_name = strtok_r (thread_name, " ", &save_ptr);
  
  if (real_name == NULL) {
    palloc_free_page(fn_copy);
    return TID_ERROR;  /* 【修复】返回 TID_ERROR 而不是 -1 */
  }

  /* 【修复】保存父进程指针，建立父子关系 */
  struct thread *cur = thread_current();
  
  tid = thread_create (real_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR) {
    palloc_free_page (fn_copy);
    return TID_ERROR;
  }
  
  /* 【修复】设置父子关系 */
  struct thread *child = GetThreadFromTid(tid);
  if (child != NULL) {
    child->father = cur;
  }
  
  return tid;
}

/* 【修复3】改进 start_process，修复内存管理和参数解析 */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;
  char *token = NULL, *save_ptr = NULL;
  
  /* 【修复】使用动态数组替代整页分配，节省内存 */
  char **argv = malloc(sizeof(char *) * MAX_ARGS);
  if (argv == NULL) {
    palloc_free_page(file_name);
    thread_current()->tid = TID_ERROR;
    sema_up(&thread_current()->SemaWaitSuccess);
    ExitStatus(-1);
  }
  
  token = strtok_r (file_name, " ", &save_ptr);

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (token, &if_.eip, &if_.esp);
  
  struct thread *t = thread_current();
  if (!success) {
    palloc_free_page (file_name);
    free(argv);  /* 【修复】释放 argv */
    t->tid = TID_ERROR;  /* 【修复】使用 TID_ERROR */
    sema_up(&t->SemaWaitSuccess);
    ExitStatus(-1);
  }

  /* 【修复】先通知父进程加载成功，再继续 */
  sema_up(&t->SemaWaitSuccess);
  
  /* 【修复】添加文件系统锁保护 */
  filesys_lock_acquire();
  t->FileSelf = filesys_open(token);
  if (t->FileSelf != NULL)
    file_deny_write(t->FileSelf);
  filesys_lock_release();
  
  /* 【修复】改进参数解析，添加边界检查 */
  char *esp = (char *)if_.esp;
  int argc = 0;
  
  /* 解析所有参数 */
  for (; token != NULL && argc < MAX_ARGS; 
       token = strtok_r (NULL, " ", &save_ptr)) {
    size_t len = strlen(token) + 1;
    esp -= len;
    strlcpy(esp, token, len);
    argv[argc++] = esp;
  }
  
  /* 字对齐 */
  while ((int)esp % 4) {
    esp--;
    *esp = 0;
  }
  
  /* 压入 NULL 哨兵 */
  esp -= 4;
  *(char **)esp = NULL;
  
  /* 压入参数指针（逆序） */
  int i;
  for (i = argc - 1; i >= 0; i--) {
    esp -= 4;
    *(char **)esp = argv[i];
  }
  
  /* 压入 argv */
  char **argv_base = (char **)esp;
  esp -= 4;
  *(char ***)esp = argv_base;
  
  /* 压入 argc */
  esp -= 4;
  *(int *)esp = argc;
  
  /* 压入伪返回地址 */
  esp -= 4;
  *(void **)esp = NULL;
  
  if_.esp = esp;
  
  /* 【修复】清理资源 */
  palloc_free_page(file_name);
  free(argv);
  
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* 【修复4】彻底重写 process_wait，修复同步问题 */
int
process_wait (tid_t child_tid)
{
  struct thread *cur = thread_current();
  int ret = -1;

  /* 1. 先检查"账本"(sons_ret 列表) */
  ret = GetRetFromSonsList(cur, child_tid);
  if (ret != -1) {
    return ret;  /* 子进程已经退出，直接返回 */
  }

  /* 2. 检查子进程是否存在且是自己的孩子 */
  struct thread *child = GetThreadFromTid(child_tid);
  
  if (child == NULL || child->father != cur) {
    return -1;  /* 不是自己的孩子或已经不存在 */
  }
  
  /* 【修复】检查是否已经被 wait 过 */
  if (child->bWait) {
    return -1;  /* 已经被 wait 过了 */
  }

  /* 3. 标记正在等待这个子进程 */
  child->bWait = true;

  /* 4. 【关键修复】阻塞在父进程自己的信号量上 */
  sema_down(&cur->SemaWait);
  
  /* 5. 被唤醒后，从账本获取返回值 */
  ret = GetRetFromSonsList(cur, child_tid);
  
  /* 【修复】如果还是没找到（不应该发生），返回 -1 */
  if (ret == -1) {
    ret = -1;
  }

  return ret;
}

void
process_activate (void)
{
  struct thread *t = thread_current ();

  if (t->pagedir != NULL)
    pagedir_activate (t->pagedir);

  tss_update ();
}

/* ELF 相关定义保持不变 */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

#define PE32Wx PRIx32
#define PE32Ax PRIx32
#define PE32Ox PRIx32
#define PE32Hx PRIx16

struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

#define PT_NULL    0
#define PT_LOAD    1
#define PT_DYNAMIC 2
#define PT_INTERP  3
#define PT_NOTE    4
#define PT_SHLIB   5
#define PT_PHDR    6
#define PT_STACK   0x6474e551

#define PF_X 1
#define PF_W 2
#define PF_R 4

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* 【修复5】load 函数添加文件系统锁保护 */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* 【修复】添加文件系统锁 */
  filesys_lock_acquire();
  file = filesys_open (file_name); 
  filesys_lock_release();
  
  if (file == NULL) {
    printf ("load: %s: open failed\n", file_name);
    goto done; 
  }

  /* Read and verify executable header. */
  filesys_lock_acquire();
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) {
    filesys_lock_release();
    printf ("load: %s: error loading executable\n", file_name);
    goto done; 
  }
  filesys_lock_release();

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length (file))
      goto done;
    
    filesys_lock_acquire();
    file_seek (file, file_ofs);
    if (file_read (file, &phdr, sizeof phdr) != sizeof phdr) {
      filesys_lock_release();
      goto done;
    }
    filesys_lock_release();
    
    file_ofs += sizeof phdr;

    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment (&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                          - read_bytes);
          } else {
            read_bytes = 0;
            zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment (file, file_page, (void *) mem_page,
                             read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* 【修复】添加文件系统锁保护 */
  if (file != NULL) {
    filesys_lock_acquire();
    file_close (file);
    filesys_lock_release();
  }
  return success;
}

static bool install_page (void *upage, void *kpage, bool writable);

static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  if (phdr->p_memsz == 0)
    return false;
  
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  if (phdr->p_vaddr < PGSIZE)
    return false;

  return true;
}

static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  filesys_lock_acquire();
  file_seek (file, ofs);
  filesys_lock_release();
  
  while (read_bytes > 0 || zero_bytes > 0) {
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    uint8_t *kpage = palloc_get_page (PAL_USER);
    if (kpage == NULL)
      return false;

    filesys_lock_acquire();
    if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes) {
      filesys_lock_release();
      palloc_free_page (kpage);
      return false; 
    }
    filesys_lock_release();
    
    memset (kpage + page_read_bytes, 0, page_zero_bytes);

    if (!install_page (upage, kpage, writable)) {
      palloc_free_page (kpage);
      return false; 
    }

    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page (kpage);
  }
  return success;
}

static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

/* 【修复6】改进 process_exit，修复资源清理顺序 */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

  pd = cur->pagedir;

  if (pd != NULL) {
    /* 【修复】添加文件系统锁保护 */
    filesys_lock_acquire();
    CloseFile(cur, -1, true);  /* 关闭所有打开的文件 */

    if (cur->FileSelf != NULL) {
      file_allow_write(cur->FileSelf);
      file_close (cur->FileSelf);
      cur->FileSelf = NULL;
    }
    filesys_lock_release();
    
    printf("%s: exit(%d)\n", cur->name, cur->ret);
    
    /* 【修复】保存返回值到父进程 */
    if (cur->father != NULL) {
      record_ret(cur->father, cur->tid, cur->ret);
      cur->SaveData = true;
      
      /* 【修复】唤醒父进程（如果在等待） */
      if (cur->bWait) {
        sema_up(&cur->father->SemaWait);
      }
    }
    
    /* 【修复】清理子进程返回值列表 */
    while (!list_empty(&cur->sons_ret)) {
      struct ret_data *rd = list_entry(list_pop_front(&cur->sons_ret),
                                       struct ret_data, elem);
      free(rd);
    }
    
    cur->pagedir = NULL;
    pagedir_activate (NULL);
    pagedir_destroy (pd);
  }
}

void record_ret(struct thread *t, int tid, int ret)
{
  if (t == NULL)
    return;
    
  struct ret_data *rd = (struct ret_data *)malloc(sizeof(struct ret_data));
  if (rd == NULL)
    return;  /* 【修复】检查 malloc 失败 */
    
  rd->ret = ret;
  rd->tid = tid;
  list_push_back(&t->sons_ret, &rd->elem);
}

/* 【修复7】改进 GetRetFromSonsList，添加删除逻辑 */
int GetRetFromSonsList(struct thread *t, tid_t tid)
{
  struct list_elem *e;
  int ret = -1;
  
  for (e = list_begin(&t->sons_ret); e != list_end(&t->sons_ret); 
       e = list_next(e)) {
    struct ret_data *rd = list_entry(e, struct ret_data, elem);
    if (rd->tid == tid) {
      ret = rd->ret;
      /* 【修复】找到后删除，确保只能 wait 一次 */
      list_remove(e);
      free(rd);
      break;
    }
  }
  return ret;
}

int CloseFile(struct thread *t, int fd, int bAll)
{
  struct list_elem *e;
  
  if (bAll) {
    while (!list_empty(&t->file_list)) {
      struct file_node *fn = list_entry (list_pop_front(&t->file_list), 
                                        struct file_node, elem);
      file_close(fn->f);
      free(fn);
    }
    t->FileNum = 0;
    return 0;
  }

  for (e = list_begin (&t->file_list); e != list_end (&t->file_list);) {
    struct file_node *fn = list_entry (e, struct file_node, elem);
    if (fn->fd == fd) {
      list_remove(e);
      if (fd == t->maxfd)
        t->maxfd--;
      t->FileNum--;
      file_close(fn->f);
      free(fn);
      return 0;
    } else {
      e = list_next(e);
    }
  }
  return -1;
}
