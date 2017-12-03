/* 
 * This file is derived from source code for the Pintos
 * instructional operating system which is itself derived
 * from the Nachos instructional operating system. The 
 * Nachos copyright notice is reproduced in full below. 
 *
 * Copyright (C) 1992-1996 The Regents of the University of California.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software
 * and its documentation for any purpose, without fee, and
 * without written agreement is hereby granted, provided that the
 * above copyright notice and the following two paragraphs appear
 * in all copies of this software.
 *
 * IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
 * ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
 * CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
 * AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
 * HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
 * BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
 * PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
 * MODIFICATIONS.
 *
 * Modifications Copyright (C) 2017 David C. Harrison. All rights reserved.
 */

#include <stdio.h>
#include <syscall-nr.h>
#include <list.h>

#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/lock.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/umem.h"
#include "userprog/utils.h"

static void syscall_handler(struct intr_frame *);

static void write_handler(struct intr_frame *);
static void exit_handler(struct intr_frame *);

static void create_handler(struct intr_frame *);
static void open_handler(struct intr_frame *);
static void read_handler(struct intr_frame *);
static void filesize_handler(struct intr_frame *);
static void close_handler(struct intr_frame *);
static void exec_handler(struct intr_frame *);
static void wait_handler(struct intr_frame *);


struct lock fs_lock;

void
syscall_init (void)
{
  lock_init(&fs_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler(struct intr_frame *f)
{
  int syscall;
  ASSERT( sizeof(syscall) == 4 ); // assuming x86

  // The system call number is in the 32-bit word at the caller's stack pointer.
  umem_read(f->esp, &syscall, sizeof(syscall));

  // Store the stack pointer esp, which is needed in the page fault handler.
  // Do NOT remove this line
  thread_current()->current_esp = f->esp;
      
  switch (syscall) {
    case SYS_HALT: 
        shutdown_power_off();
        break;

    case SYS_EXIT: 
        exit_handler(f);
        break;
      
    case SYS_WRITE: 
        write_handler(f);
        break;
    
    case SYS_CREATE:
        lock_acquire(&fs_lock);
        create_handler(f);
        lock_release(&fs_lock);
        break;
        
    case SYS_OPEN:
        lock_acquire(&fs_lock);
        open_handler(f);
        lock_release(&fs_lock);
        break;
        
    case SYS_READ:
        lock_acquire(&fs_lock);
        read_handler(f);
        lock_release(&fs_lock);
        break;
          
    case SYS_FILESIZE:
        lock_acquire(&fs_lock);
        filesize_handler(f);
        lock_release(&fs_lock);
        break;
        
    case SYS_CLOSE:
        lock_acquire(&fs_lock);
        close_handler(f);
        lock_release(&fs_lock);
        break;
    
    case SYS_EXEC:
        lock_acquire(&fs_lock);
        exec_handler(f);
        lock_release(&fs_lock);
        break;
      
    case SYS_WAIT:
        lock_acquire(&fs_lock);
        wait_handler(f);
        lock_release(&fs_lock);
        break;

    default:
        printf("[ERROR] system call %d is unimplemented!\n", syscall);
        thread_exit();
        break;
  }
}

/****************** System Call Implementations ********************/

// *****************************************************************
// CMPS111 Lab 3 : Put your new system call implementatons in your 
// own source file. Define them in your header file and include 
// that .h in this .c file.
// *****************************************************************

void sys_exit(int status) 
{   
  struct thread *parent = thread_current()->parent;
  
//  printf("\n");
//  printf("In sys_exit\n");
//  printf("STATUS: %d\n", status);
//  printf("\n");
  
  // Return exit status to parent
  thread_current()->parent->exit_status = status;
  thread_current()->parent->exit_process = true;
  
  if(list_size(&parent->wait_on_child.waiters) >= 1)
  {
      semaphore_up(&thread_current()->parent->wait_on_child);
  }

  list_remove(&thread_current()->child_elem);
  
  
  
  printf("%s: exit(%d)\n", thread_current()->name, status);  
  thread_exit();
}

static void exit_handler(struct intr_frame *f) 
{   
  int exitcode;
  umem_read(f->esp + 4, &exitcode, sizeof(exitcode));

  sys_exit(exitcode);
}

/*
 * BUFFER+0 and BUFFER+size should be valid user adresses
 */
static uint32_t sys_write(int fd, const void *buffer, unsigned size)
{
  umem_check((const uint8_t*) buffer);
  umem_check((const uint8_t*) buffer + size - 1);

  int bytes_written = -1;

  if (fd == 1) // write to stdout
  { 
    putbuf(buffer, size);
    bytes_written = size;
  }
  else
  {
    lock_acquire(&fs_lock);  
      
    struct thread *current = thread_current();
    
    struct list_elem *e;
    for (e = list_begin (&current->file_list); e != list_end (&current->file_list);
         e = list_next (e))
      {
        struct file *f = list_entry (e, struct file, file_elem);
        
        if(f->fd == fd)
        {               
            bytes_written = file_write(f, buffer, size);
            break;
        }
      }
    
    return bytes_written;
    
    lock_release(&fs_lock);
  }

  return (uint32_t) bytes_written;
}

static void write_handler(struct intr_frame *f)
{
    int fd;
    const void *buffer;
    unsigned size;

    umem_read(f->esp + 4, &fd, sizeof(fd));
    umem_read(f->esp + 8, &buffer, sizeof(buffer));
    umem_read(f->esp + 12, &size, sizeof(size));

    f->eax = sys_write(fd, buffer, size);
}


static uint32_t sys_create(const char* file, unsigned size)
{
    bool success = filesys_create(file, size, false);
    return success;
}

static void create_handler(struct intr_frame *f)
{
    const char *file;
    unsigned size;
    
    umem_read(f->esp + 4, &file, sizeof(file));
    umem_read(f->esp + 8, &size, sizeof(size));
    
    f->eax = sys_create(file, size);
}

static uint32_t sys_open(const char* file)
{
    struct file *f = filesys_open(file);
     
    if(f != NULL)
    {        
        f->fd = thread_current()->fd;
        thread_current()->fd++;
        list_push_back(&thread_current()->file_list, &f->file_elem);
        return f->fd;
    }
    else
    {
        return -1;
    }
}

static void open_handler(struct intr_frame *f)
{   
    const char *file;
    
    umem_read(f->esp + 4, &file, sizeof(file));
    
    f->eax = sys_open(file);
}

static uint32_t sys_read(int fd, void *buffer, unsigned size)
{
  umem_check((const uint8_t*) buffer);
  umem_check((const uint8_t*) buffer + size - 1);
    
  struct thread *current = thread_current();
  uint32_t bytes_read = 0;
  
  struct list_elem *e;
  for (e = list_begin (&current->file_list); e != list_end (&current->file_list);
         e = list_next (e))
      {
        struct file *f = list_entry (e, struct file, file_elem);
        
        if(f->fd == fd)
        {   
            bytes_read = file_read(f, buffer, size);
        }
      }
  
  return bytes_read;
}

static void read_handler(struct intr_frame *f)
{
    int fd;
    char *buffer;
    unsigned size;
    
    umem_read(f->esp + 4, &fd, sizeof(fd));
    umem_read(f->esp + 8, &buffer, sizeof(buffer));
    umem_read(f->esp + 12, &size, sizeof(size));
    
    f->eax = sys_read(fd, buffer, size);
}

static uint32_t sys_filesize(int fd)
{
    uint32_t file_size = 0;
    struct thread *current = thread_current();
    
    struct list_elem *e;
    for (e = list_begin (&current->file_list); e != list_end (&current->file_list);
         e = list_next (e))
      {
        struct file *f = list_entry (e, struct file, file_elem);
        
        if(f->fd == fd)
        {            
            file_size = file_length(f);
        }
      }
    
    return file_size;
}

static void filesize_handler(struct intr_frame *f)
{   
    int fd;
    
    umem_read(f->esp + 4, &fd, sizeof(fd));
    
    f->eax = sys_filesize(fd);
}

static void sys_close(int fd)
{
    struct thread *current = thread_current();
    
    struct list_elem *e;
    for (e = list_begin (&current->file_list); e != list_end (&current->file_list);
         e = list_next (e))
      {
        struct file *f = list_entry (e, struct file, file_elem);
        
        if(f->fd == fd)
        {               
            list_remove(&f->file_elem);
            file_close(f);
            break;
        }
      }
    
}

static void close_handler(struct intr_frame *f)
{   
    int fd;
    
    umem_read(f->esp + 4, &fd, sizeof(fd));
    
    sys_close(fd);
}

static uint32_t sys_exec(const char *file)
{       
    int tid = process_execute(file);
    return tid;
}

static void exec_handler(struct intr_frame *f)
{   
    const char *file;
    
    umem_read(f->esp + 4, &file, sizeof(file));
    
    sys_exec(file);
}

static uint32_t sys_wait(int pid)
{
    int wait_pid = process_wait(pid);
    return wait_pid;
}

static void wait_handler(struct intr_frame *f)
{   
    int pid;
    
    umem_read(f->esp + 4, &pid, sizeof(pid));
    
    f->eax = sys_wait(pid);
}
