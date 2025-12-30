#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include "userprog/gdt.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

void
exception_init (void) 
{
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill,
                     "#BR BOUND Range Exceeded Exception");

  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill,
                     "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill,
                     "#XF SIMD Floating-Point Exception");

  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

static void
kill (struct intr_frame *f) 
{
  switch (f->cs)
    {
    case SEL_UCSEG:
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      thread_exit ();
    }
}

/* 【简化版】页错误处理 */
static void
page_fault (struct intr_frame *f) 
{
  bool not_present;
  bool write;
  bool user;
  void *fault_addr;

  /* 获取触发页错误的地址 */
  asm ("movl %%cr2, %0" : "=r" (fault_addr));

  /* 重新开启中断 */
  intr_enable ();

  /* 统计 */
  page_fault_cnt++;

  /* 解析错误码 */
  not_present = (f->error_code & PF_P) == 0;
  write = (f->error_code & PF_W) != 0;
  user = (f->error_code & PF_U) != 0;

  /* 
   * 【关键】处理四种情况：
   * 1. 用户程序访问内核地址 -> 终止用户进程
   * 2. 用户程序访问无效用户地址 -> 终止用户进程
   * 3. 内核访问无效用户地址（系统调用验证指针）-> 终止用户进程
   * 4. 内核访问无效内核地址 -> 内核 bug，panic
   */

  /* 情况 1 & 2：用户态触发的页错误，直接终止进程 */
  if (user) {
    ExitStatus(-1);
    NOT_REACHED();
  }

  /* 情况 3：内核在访问用户地址时出错（通常是系统调用）*/
  if (!user && is_user_vaddr(fault_addr)) {
    /* 这是因为用户传入了无效指针 */
    /* 终止用户进程，不是内核 bug */
    f->eax = 0xffffffff;  /* 标记错误 */
    ExitStatus(-1);
    NOT_REACHED();
  }

  /* 情况 4：内核访问内核地址失败 -> 真正的内核 bug */
  printf ("Page fault at %p: %s error %s page in %s context.\n",
          fault_addr,
          not_present ? "not present" : "rights violation",
          write ? "writing" : "reading",
          user ? "user" : "kernel");
  kill (f);
}
