typedef unsigned int size_t;
typedef unsigned char __u_char;
typedef unsigned short int __u_short;
typedef unsigned int __u_int;
typedef unsigned long int __u_long;
typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;
__extension__ typedef signed long long int __int64_t;
__extension__ typedef unsigned long long int __uint64_t;
__extension__ typedef long long int __quad_t;
__extension__ typedef unsigned long long int __u_quad_t;
typedef unsigned long long int __dev_t;
typedef unsigned int __uid_t;
typedef unsigned int __gid_t;
typedef unsigned long int __ino_t;
typedef unsigned long long int __ino64_t;
typedef unsigned int __mode_t;
typedef unsigned int __nlink_t;
typedef long int __off_t;
typedef long long int __off64_t;
typedef int __pid_t;
typedef struct { int __val[2]; } __fsid_t;
typedef long int __clock_t;
typedef unsigned long int __rlim_t;
typedef unsigned long long int __rlim64_t;
typedef unsigned int __id_t;
typedef long int __time_t;
typedef unsigned int __useconds_t;
typedef long int __suseconds_t;
typedef int __daddr_t;
typedef long int __swblk_t;
typedef int __key_t;
typedef int __clockid_t;
typedef int __timer_t;
typedef long int __blksize_t;
typedef long int __blkcnt_t;
typedef long long int __blkcnt64_t;
typedef unsigned long int __fsblkcnt_t;
typedef unsigned long long int __fsblkcnt64_t;
typedef unsigned long int __fsfilcnt_t;
typedef unsigned long long int __fsfilcnt64_t;
typedef int __ssize_t;
typedef __off64_t __loff_t;
typedef __quad_t *__qaddr_t;
typedef char *__caddr_t;
typedef int __intptr_t;
typedef unsigned int __socklen_t;
typedef struct _IO_FILE FILE;
typedef struct _IO_FILE __FILE;
typedef long int wchar_t;
typedef unsigned int wint_t;
typedef struct
{
  int __count;
  union
  {
    wint_t __wch;
    char __wchb[4];
  } __value;
} __mbstate_t;
typedef struct
{
  __off_t __pos;
  __mbstate_t __state;
} _G_fpos_t;
typedef struct
{
  __off64_t __pos;
  __mbstate_t __state;
} _G_fpos64_t;
enum
{
  __GCONV_OK = 0,
  __GCONV_NOCONV,
  __GCONV_NODB,
  __GCONV_NOMEM,
  __GCONV_EMPTY_INPUT,
  __GCONV_FULL_OUTPUT,
  __GCONV_ILLEGAL_INPUT,
  __GCONV_INCOMPLETE_INPUT,
  __GCONV_ILLEGAL_DESCRIPTOR,
  __GCONV_INTERNAL_ERROR
};
enum
{
  __GCONV_IS_LAST = 0x0001,
  __GCONV_IGNORE_ERRORS = 0x0002
};
struct __gconv_step;
struct __gconv_step_data;
struct __gconv_loaded_object;
struct __gconv_trans_data;
typedef int (*__gconv_fct) (struct __gconv_step *, struct __gconv_step_data *,
                            __const unsigned char **, __const unsigned char *,
                            unsigned char **, size_t *, int, int);
typedef wint_t (*__gconv_btowc_fct) (struct __gconv_step *, unsigned char);
typedef int (*__gconv_init_fct) (struct __gconv_step *);
typedef void (*__gconv_end_fct) (struct __gconv_step *);
typedef int (*__gconv_trans_fct) (struct __gconv_step *,
                                  struct __gconv_step_data *, void *,
                                  __const unsigned char *,
                                  __const unsigned char **,
                                  __const unsigned char *, unsigned char **,
                                  size_t *);
typedef int (*__gconv_trans_context_fct) (void *, __const unsigned char *,
                                          __const unsigned char *,
                                          unsigned char *, unsigned char *);
typedef int (*__gconv_trans_query_fct) (__const char *, __const char ***,
                                        size_t *);
typedef int (*__gconv_trans_init_fct) (void **, const char *);
typedef void (*__gconv_trans_end_fct) (void *);
struct __gconv_trans_data
{
  __gconv_trans_fct __trans_fct;
  __gconv_trans_context_fct __trans_context_fct;
  __gconv_trans_end_fct __trans_end_fct;
  void *__data;
  struct __gconv_trans_data *__next;
};
struct __gconv_step
{
  struct __gconv_loaded_object *__shlib_handle;
  __const char *__modname;
  int __counter;
  char *__from_name;
  char *__to_name;
  __gconv_fct __fct;
  __gconv_btowc_fct __btowc_fct;
  __gconv_init_fct __init_fct;
  __gconv_end_fct __end_fct;
  int __min_needed_from;
  int __max_needed_from;
  int __min_needed_to;
  int __max_needed_to;
  int __stateful;
  void *__data;
};
struct __gconv_step_data
{
  unsigned char *__outbuf;
  unsigned char *__outbufend;
  int __flags;
  int __invocation_counter;
  int __internal_use;
  __mbstate_t *__statep;
  __mbstate_t __state;
  struct __gconv_trans_data *__trans;
};
typedef struct __gconv_info
{
  size_t __nsteps;
  struct __gconv_step *__steps;
  __extension__ struct __gconv_step_data __data [0];
} *__gconv_t;
typedef union
{
  struct __gconv_info __cd;
  struct
  {
    struct __gconv_info __cd;
    struct __gconv_step_data __data;
  } __combined;
} _G_iconv_t;
typedef int _G_int16_t __attribute__ ((__mode__ (__HI__)));
typedef int _G_int32_t __attribute__ ((__mode__ (__SI__)));
typedef unsigned int _G_uint16_t __attribute__ ((__mode__ (__HI__)));
typedef unsigned int _G_uint32_t __attribute__ ((__mode__ (__SI__)));
typedef __builtin_va_list __gnuc_va_list;
struct _IO_jump_t; struct _IO_FILE;
typedef void _IO_lock_t;
struct _IO_marker {
  struct _IO_marker *_next;
  struct _IO_FILE *_sbuf;
  int _pos;
};
enum __codecvt_result
{
  __codecvt_ok,
  __codecvt_partial,
  __codecvt_error,
  __codecvt_noconv
};
struct _IO_FILE {
  int _flags;
  char* _IO_read_ptr;
  char* _IO_read_end;
  char* _IO_read_base;
  char* _IO_write_base;
  char* _IO_write_ptr;
  char* _IO_write_end;
  char* _IO_buf_base;
  char* _IO_buf_end;
  char *_IO_save_base;
  char *_IO_backup_base;
  char *_IO_save_end;
  struct _IO_marker *_markers;
  struct _IO_FILE *_chain;
  int _fileno;
  int _flags2;
  __off_t _old_offset;
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];
  _IO_lock_t *_lock;
  __off64_t _offset;
  void *__pad1;
  void *__pad2;
  int _mode;
  char _unused2[15 * sizeof (int) - 2 * sizeof (void *)];
};
typedef struct _IO_FILE _IO_FILE;
struct _IO_FILE_plus;
extern struct _IO_FILE_plus _IO_2_1_stdin_;
extern struct _IO_FILE_plus _IO_2_1_stdout_;
extern struct _IO_FILE_plus _IO_2_1_stderr_;
typedef __ssize_t __io_read_fn (void *__cookie, char *__buf, size_t __nbytes);
typedef __ssize_t __io_write_fn (void *__cookie, __const char *__buf,
                                 size_t __n);
typedef int __io_seek_fn (void *__cookie, __off64_t *__pos, int __w);
typedef int __io_close_fn (void *__cookie);
extern int __underflow (_IO_FILE *) ;
extern int __uflow (_IO_FILE *) ;
extern int __overflow (_IO_FILE *, int) ;
extern wint_t __wunderflow (_IO_FILE *) ;
extern wint_t __wuflow (_IO_FILE *) ;
extern wint_t __woverflow (_IO_FILE *, wint_t) ;
extern int _IO_getc (_IO_FILE *__fp) ;
extern int _IO_putc (int __c, _IO_FILE *__fp) ;
extern int _IO_feof (_IO_FILE *__fp) ;
extern int _IO_ferror (_IO_FILE *__fp) ;
extern int _IO_peekc_locked (_IO_FILE *__fp) ;
extern void _IO_flockfile (_IO_FILE *) ;
extern void _IO_funlockfile (_IO_FILE *) ;
extern int _IO_ftrylockfile (_IO_FILE *) ;
extern int _IO_vfscanf (_IO_FILE * __restrict, const char * __restrict,
                        __gnuc_va_list, int *__restrict) ;
extern int _IO_vfprintf (_IO_FILE *__restrict, const char *__restrict,
                         __gnuc_va_list) ;
extern __ssize_t _IO_padn (_IO_FILE *, int, __ssize_t) ;
extern size_t _IO_sgetn (_IO_FILE *, void *, size_t) ;
extern __off64_t _IO_seekoff (_IO_FILE *, __off64_t, int, int) ;
extern __off64_t _IO_seekpos (_IO_FILE *, __off64_t, int) ;
extern void _IO_free_backup_area (_IO_FILE *) ;
typedef _G_fpos_t fpos_t;
extern struct _IO_FILE *stdin;
extern struct _IO_FILE *stdout;
extern struct _IO_FILE *stderr;
extern int remove (__const char *__filename) ;
extern int rename (__const char *__old, __const char *__new) ;
extern FILE *tmpfile (void) ;
extern char *tmpnam (char *__s) ;
extern char *tmpnam_r (char *__s) ;
extern char *tempnam (__const char *__dir, __const char *__pfx)
             __attribute__ ((__malloc__));
extern int fclose (FILE *__stream) ;
extern int fflush (FILE *__stream) ;
extern int fflush_unlocked (FILE *__stream) ;
extern FILE *fopen (__const char *__restrict __filename,
                    __const char *__restrict __modes) ;
extern FILE *freopen (__const char *__restrict __filename,
                      __const char *__restrict __modes,
                      FILE *__restrict __stream) ;
extern FILE *fdopen (int __fd, __const char *__modes) ;
extern void setbuf (FILE *__restrict __stream, char *__restrict __buf) ;
extern int setvbuf (FILE *__restrict __stream, char *__restrict __buf,
                    int __modes, size_t __n) ;
extern void setbuffer (FILE *__restrict __stream, char *__restrict __buf,
                       size_t __size) ;
extern void setlinebuf (FILE *__stream) ;
extern int fprintf (FILE *__restrict __stream,
                    __const char *__restrict __format, ...) ;
extern int printf (__const char *__restrict __format, ...) ;
extern int sprintf (char *__restrict __s,
                    __const char *__restrict __format, ...) ;
extern int vfprintf (FILE *__restrict __s, __const char *__restrict __format,
                     __gnuc_va_list __arg) ;
extern int vprintf (__const char *__restrict __format, __gnuc_va_list __arg)
            ;
extern int vsprintf (char *__restrict __s, __const char *__restrict __format,
                     __gnuc_va_list __arg) ;
extern int snprintf (char *__restrict __s, size_t __maxlen,
                     __const char *__restrict __format, ...)
             __attribute__ ((__format__ (__printf__, 3, 4)));
extern int vsnprintf (char *__restrict __s, size_t __maxlen,
                      __const char *__restrict __format, __gnuc_va_list __arg)
             __attribute__ ((__format__ (__printf__, 3, 0)));
extern int fscanf (FILE *__restrict __stream,
                   __const char *__restrict __format, ...) ;
extern int scanf (__const char *__restrict __format, ...) ;
extern int sscanf (__const char *__restrict __s,
                   __const char *__restrict __format, ...) ;
extern int fgetc (FILE *__stream) ;
extern int getc (FILE *__stream) ;
extern int getchar (void) ;
extern int getc_unlocked (FILE *__stream) ;
extern int getchar_unlocked (void) ;
extern int fgetc_unlocked (FILE *__stream) ;
extern int fputc (int __c, FILE *__stream) ;
extern int putc (int __c, FILE *__stream) ;
extern int putchar (int __c) ;
extern int fputc_unlocked (int __c, FILE *__stream) ;
extern int putc_unlocked (int __c, FILE *__stream) ;
extern int putchar_unlocked (int __c) ;
extern int getw (FILE *__stream) ;
extern int putw (int __w, FILE *__stream) ;
extern char *fgets (char *__restrict __s, int __n, FILE *__restrict __stream)
            ;
extern char *gets (char *__s) ;
extern int fputs (__const char *__restrict __s, FILE *__restrict __stream)
            ;
extern int puts (__const char *__s) ;
extern int ungetc (int __c, FILE *__stream) ;
extern size_t fread (void *__restrict __ptr, size_t __size,
                     size_t __n, FILE *__restrict __stream) ;
extern size_t fwrite (__const void *__restrict __ptr, size_t __size,
                      size_t __n, FILE *__restrict __s) ;
extern size_t fread_unlocked (void *__restrict __ptr, size_t __size,
                              size_t __n, FILE *__restrict __stream) ;
extern size_t fwrite_unlocked (__const void *__restrict __ptr, size_t __size,
                               size_t __n, FILE *__restrict __stream) ;
extern int fseek (FILE *__stream, long int __off, int __whence) ;
extern long int ftell (FILE *__stream) ;
extern void rewind (FILE *__stream) ;
extern int fgetpos (FILE *__restrict __stream, fpos_t *__restrict __pos)
            ;
extern int fsetpos (FILE *__stream, __const fpos_t *__pos) ;
extern void clearerr (FILE *__stream) ;
extern int feof (FILE *__stream) ;
extern int ferror (FILE *__stream) ;
extern void clearerr_unlocked (FILE *__stream) ;
extern int feof_unlocked (FILE *__stream) ;
extern int ferror_unlocked (FILE *__stream) ;
extern void perror (__const char *__s) ;
extern int sys_nerr;
extern __const char *__const sys_errlist[];
extern int fileno (FILE *__stream) ;
extern int fileno_unlocked (FILE *__stream) ;
extern FILE *popen (__const char *__command, __const char *__modes) ;
extern int pclose (FILE *__stream) ;
extern char *ctermid (char *__s) ;
extern void flockfile (FILE *__stream) ;
extern int ftrylockfile (FILE *__stream) ;
extern void funlockfile (FILE *__stream) ;
extern __inline int
vprintf (__const char *__restrict __fmt, __gnuc_va_list __arg)
{
  return vfprintf (stdout, __fmt, __arg);
}
extern __inline int
getchar (void)
{
  return _IO_getc (stdin);
}
extern __inline int
getc_unlocked (FILE *__fp)
{
  return ((__fp)->_IO_read_ptr >= (__fp)->_IO_read_end ? __uflow (__fp) : *(unsigned char *) (__fp)->_IO_read_ptr++);
}
extern __inline int
getchar_unlocked (void)
{
  return ((stdin)->_IO_read_ptr >= (stdin)->_IO_read_end ? __uflow (stdin) : *(unsigned char *) (stdin)->_IO_read_ptr++);
}
extern __inline int
putchar (int __c)
{
  return _IO_putc (__c, stdout);
}
extern __inline int
fputc_unlocked (int __c, FILE *__stream)
{
  return (((__stream)->_IO_write_ptr >= (__stream)->_IO_write_end) ? __overflow (__stream, (unsigned char) (__c)) : (unsigned char) (*(__stream)->_IO_write_ptr++ = (__c)));
}
extern __inline int
putc_unlocked (int __c, FILE *__stream)
{
  return (((__stream)->_IO_write_ptr >= (__stream)->_IO_write_end) ? __overflow (__stream, (unsigned char) (__c)) : (unsigned char) (*(__stream)->_IO_write_ptr++ = (__c)));
}
extern __inline int
putchar_unlocked (int __c)
{
  return (((stdout)->_IO_write_ptr >= (stdout)->_IO_write_end) ? __overflow (stdout, (unsigned char) (__c)) : (unsigned char) (*(stdout)->_IO_write_ptr++ = (__c)));
}
extern __inline int
feof_unlocked (FILE *__stream)
{
  return (((__stream)->_flags & 0x10) != 0);
}
extern __inline int
ferror_unlocked (FILE *__stream)
{
  return (((__stream)->_flags & 0x20) != 0);
}
typedef struct
  {
    int quot;
    int rem;
  } div_t;
typedef struct
  {
    long int quot;
    long int rem;
  } ldiv_t;
extern size_t __ctype_get_mb_cur_max (void) ;
extern double atof (__const char *__nptr) __attribute__ ((__pure__));
extern int atoi (__const char *__nptr) __attribute__ ((__pure__));
extern long int atol (__const char *__nptr) __attribute__ ((__pure__));
__extension__ extern long long int atoll (__const char *__nptr)
             __attribute__ ((__pure__));
extern double strtod (__const char *__restrict __nptr,
                      char **__restrict __endptr) ;
extern long int strtol (__const char *__restrict __nptr,
                        char **__restrict __endptr, int __base) ;
extern unsigned long int strtoul (__const char *__restrict __nptr,
                                  char **__restrict __endptr, int __base)
            ;
__extension__
extern long long int strtoq (__const char *__restrict __nptr,
                             char **__restrict __endptr, int __base) ;
__extension__
extern unsigned long long int strtouq (__const char *__restrict __nptr,
                                       char **__restrict __endptr, int __base)
            ;
__extension__
extern long long int strtoll (__const char *__restrict __nptr,
                              char **__restrict __endptr, int __base) ;
__extension__
extern unsigned long long int strtoull (__const char *__restrict __nptr,
                                        char **__restrict __endptr, int __base)
            ;
extern double __strtod_internal (__const char *__restrict __nptr,
                                 char **__restrict __endptr, int __group)
            ;
extern float __strtof_internal (__const char *__restrict __nptr,
                                char **__restrict __endptr, int __group)
            ;
extern long double __strtold_internal (__const char *__restrict __nptr,
                                       char **__restrict __endptr,
                                       int __group) ;
extern long int __strtol_internal (__const char *__restrict __nptr,
                                   char **__restrict __endptr,
                                   int __base, int __group) ;
extern unsigned long int __strtoul_internal (__const char *__restrict __nptr,
                                             char **__restrict __endptr,
                                             int __base, int __group) ;
__extension__
extern long long int __strtoll_internal (__const char *__restrict __nptr,
                                         char **__restrict __endptr,
                                         int __base, int __group) ;
__extension__
extern unsigned long long int __strtoull_internal (__const char *
                                                   __restrict __nptr,
                                                   char **__restrict __endptr,
                                                   int __base, int __group)
            ;
extern __inline double
strtod (__const char *__restrict __nptr, char **__restrict __endptr)
{
  return __strtod_internal (__nptr, __endptr, 0);
}
extern __inline long int
strtol (__const char *__restrict __nptr, char **__restrict __endptr,
        int __base)
{
  return __strtol_internal (__nptr, __endptr, __base, 0);
}
extern __inline unsigned long int
strtoul (__const char *__restrict __nptr, char **__restrict __endptr,
         int __base)
{
  return __strtoul_internal (__nptr, __endptr, __base, 0);
}
__extension__ extern __inline long long int
strtoq (__const char *__restrict __nptr, char **__restrict __endptr,
        int __base)
{
  return __strtoll_internal (__nptr, __endptr, __base, 0);
}
__extension__ extern __inline unsigned long long int
strtouq (__const char *__restrict __nptr, char **__restrict __endptr,
         int __base)
{
  return __strtoull_internal (__nptr, __endptr, __base, 0);
}
__extension__ extern __inline long long int
strtoll (__const char *__restrict __nptr, char **__restrict __endptr,
         int __base)
{
  return __strtoll_internal (__nptr, __endptr, __base, 0);
}
__extension__ extern __inline unsigned long long int
strtoull (__const char * __restrict __nptr, char **__restrict __endptr,
          int __base)
{
  return __strtoull_internal (__nptr, __endptr, __base, 0);
}
extern __inline double
atof (__const char *__nptr)
{
  return strtod (__nptr, (char **) ((void *)0));
}
extern __inline int
atoi (__const char *__nptr)
{
  return (int) strtol (__nptr, (char **) ((void *)0), 10);
}
extern __inline long int
atol (__const char *__nptr)
{
  return strtol (__nptr, (char **) ((void *)0), 10);
}
__extension__ extern __inline long long int
atoll (__const char *__nptr)
{
  return strtoll (__nptr, (char **) ((void *)0), 10);
}
extern char *l64a (long int __n) ;
extern long int a64l (__const char *__s) __attribute__ ((__pure__));
typedef __u_char u_char;
typedef __u_short u_short;
typedef __u_int u_int;
typedef __u_long u_long;
typedef __quad_t quad_t;
typedef __u_quad_t u_quad_t;
typedef __fsid_t fsid_t;
typedef __loff_t loff_t;
typedef __ino_t ino_t;
typedef __dev_t dev_t;
typedef __gid_t gid_t;
typedef __mode_t mode_t;
typedef __nlink_t nlink_t;
typedef __uid_t uid_t;
typedef __off_t off_t;
typedef __pid_t pid_t;
typedef __id_t id_t;
typedef __ssize_t ssize_t;
typedef __daddr_t daddr_t;
typedef __caddr_t caddr_t;
typedef __key_t key_t;
typedef __time_t time_t;
typedef __clockid_t clockid_t;
typedef __timer_t timer_t;
typedef unsigned long int ulong;
typedef unsigned short int ushort;
typedef unsigned int uint;
typedef int int8_t __attribute__ ((__mode__ (__QI__)));
typedef int int16_t __attribute__ ((__mode__ (__HI__)));
typedef int int32_t __attribute__ ((__mode__ (__SI__)));
typedef int int64_t __attribute__ ((__mode__ (__DI__)));
typedef unsigned int u_int8_t __attribute__ ((__mode__ (__QI__)));
typedef unsigned int u_int16_t __attribute__ ((__mode__ (__HI__)));
typedef unsigned int u_int32_t __attribute__ ((__mode__ (__SI__)));
typedef unsigned int u_int64_t __attribute__ ((__mode__ (__DI__)));
typedef int register_t __attribute__ ((__mode__ (__word__)));
typedef int __sig_atomic_t;
typedef struct
  {
    unsigned long int __val[(1024 / (8 * sizeof (unsigned long int)))];
  } __sigset_t;
typedef __sigset_t sigset_t;
struct timespec
  {
    __time_t tv_sec;
    long int tv_nsec;
  };
struct timeval
  {
    __time_t tv_sec;
    __suseconds_t tv_usec;
  };
typedef __suseconds_t suseconds_t;
typedef long int __fd_mask;
typedef struct
  {
    __fd_mask __fds_bits[1024 / (8 * sizeof (__fd_mask))];
  } fd_set;
typedef __fd_mask fd_mask;
extern int select (int __nfds, fd_set *__restrict __readfds,
                   fd_set *__restrict __writefds,
                   fd_set *__restrict __exceptfds,
                   struct timeval *__restrict __timeout) ;
typedef __blkcnt_t blkcnt_t;
typedef __fsblkcnt_t fsblkcnt_t;
typedef __fsfilcnt_t fsfilcnt_t;
struct __sched_param
  {
    int __sched_priority;
  };
struct _pthread_fastlock
{
  long int __status;
  int __spinlock;
};
typedef struct _pthread_descr_struct *_pthread_descr;
typedef struct __pthread_attr_s
{
  int __detachstate;
  int __schedpolicy;
  struct __sched_param __schedparam;
  int __inheritsched;
  int __scope;
  size_t __guardsize;
  int __stackaddr_set;
  void *__stackaddr;
  size_t __stacksize;
} pthread_attr_t;
__extension__ typedef long long __pthread_cond_align_t;
typedef struct
{
  struct _pthread_fastlock __c_lock;
  _pthread_descr __c_waiting;
  char __padding[48 - sizeof (struct _pthread_fastlock)
                 - sizeof (_pthread_descr) - sizeof (__pthread_cond_align_t)];
  __pthread_cond_align_t __align;
} pthread_cond_t;
typedef struct
{
  int __dummy;
} pthread_condattr_t;
typedef unsigned int pthread_key_t;
typedef struct
{
  int __m_reserved;
  int __m_count;
  _pthread_descr __m_owner;
  int __m_kind;
  struct _pthread_fastlock __m_lock;
} pthread_mutex_t;
typedef struct
{
  int __mutexkind;
} pthread_mutexattr_t;
typedef int pthread_once_t;
typedef unsigned long int pthread_t;
extern long int random (void) ;
extern void srandom (unsigned int __seed) ;
extern char *initstate (unsigned int __seed, char *__statebuf,
                        size_t __statelen) ;
extern char *setstate (char *__statebuf) ;
struct random_data
  {
    int32_t *fptr;
    int32_t *rptr;
    int32_t *state;
    int rand_type;
    int rand_deg;
    int rand_sep;
    int32_t *end_ptr;
  };
extern int random_r (struct random_data *__restrict __buf,
                     int32_t *__restrict __result) ;
extern int srandom_r (unsigned int __seed, struct random_data *__buf) ;
extern int initstate_r (unsigned int __seed, char *__restrict __statebuf,
                        size_t __statelen,
                        struct random_data *__restrict __buf) ;
extern int setstate_r (char *__restrict __statebuf,
                       struct random_data *__restrict __buf) ;
extern int rand (void) ;
extern void srand (unsigned int __seed) ;
extern int rand_r (unsigned int *__seed) ;
extern double drand48 (void) ;
extern double erand48 (unsigned short int __xsubi[3]) ;
extern long int lrand48 (void) ;
extern long int nrand48 (unsigned short int __xsubi[3]) ;
extern long int mrand48 (void) ;
extern long int jrand48 (unsigned short int __xsubi[3]) ;
extern void srand48 (long int __seedval) ;
extern unsigned short int *seed48 (unsigned short int __seed16v[3]) ;
extern void lcong48 (unsigned short int __param[7]) ;
struct drand48_data
  {
    unsigned short int __x[3];
    unsigned short int __old_x[3];
    unsigned short int __c;
    unsigned short int __init;
    unsigned long long int __a;
  };
extern int drand48_r (struct drand48_data *__restrict __buffer,
                      double *__restrict __result) ;
extern int erand48_r (unsigned short int __xsubi[3],
                      struct drand48_data *__restrict __buffer,
                      double *__restrict __result) ;
extern int lrand48_r (struct drand48_data *__restrict __buffer,
                      long int *__restrict __result) ;
extern int nrand48_r (unsigned short int __xsubi[3],
                      struct drand48_data *__restrict __buffer,
                      long int *__restrict __result) ;
extern int mrand48_r (struct drand48_data *__restrict __buffer,
                      long int *__restrict __result) ;
extern int jrand48_r (unsigned short int __xsubi[3],
                      struct drand48_data *__restrict __buffer,
                      long int *__restrict __result) ;
extern int srand48_r (long int __seedval, struct drand48_data *__buffer)
            ;
extern int seed48_r (unsigned short int __seed16v[3],
                     struct drand48_data *__buffer) ;
extern int lcong48_r (unsigned short int __param[7],
                      struct drand48_data *__buffer) ;
extern void *malloc (size_t __size) __attribute__ ((__malloc__));
extern void *calloc (size_t __nmemb, size_t __size)
             __attribute__ ((__malloc__));
extern void *realloc (void *__ptr, size_t __size) __attribute__ ((__malloc__));
extern void free (void *__ptr) ;
extern void cfree (void *__ptr) ;
extern void *alloca (size_t __size) ;
extern void *valloc (size_t __size) __attribute__ ((__malloc__));
extern void abort (void) __attribute__ ((__noreturn__));
extern int atexit (void (*__func) (void)) ;
extern int on_exit (void (*__func) (int __status, void *__arg), void *__arg)
            ;
extern void exit (int __status) __attribute__ ((__noreturn__));
extern char *getenv (__const char *__name) ;
extern char *__secure_getenv (__const char *__name) ;
extern int putenv (char *__string) ;
extern int setenv (__const char *__name, __const char *__value, int __replace)
            ;
extern int unsetenv (__const char *__name) ;
extern int clearenv (void) ;
extern char *mktemp (char *__template) ;
extern int mkstemp (char *__template) ;
extern char *mkdtemp (char *__template) ;
extern int system (__const char *__command) ;
extern char *realpath (__const char *__restrict __name,
                       char *__restrict __resolved) ;
typedef int (*__compar_fn_t) (__const void *, __const void *);
extern void *bsearch (__const void *__key, __const void *__base,
                      size_t __nmemb, size_t __size, __compar_fn_t __compar);
extern void qsort (void *__base, size_t __nmemb, size_t __size,
                   __compar_fn_t __compar);
extern int abs (int __x) __attribute__ ((__const__));
extern long int labs (long int __x) __attribute__ ((__const__));
extern div_t div (int __numer, int __denom)
             __attribute__ ((__const__));
extern ldiv_t ldiv (long int __numer, long int __denom)
             __attribute__ ((__const__));
extern char *ecvt (double __value, int __ndigit, int *__restrict __decpt,
                   int *__restrict __sign) ;
extern char *fcvt (double __value, int __ndigit, int *__restrict __decpt,
                   int *__restrict __sign) ;
extern char *gcvt (double __value, int __ndigit, char *__buf) ;
extern char *qecvt (long double __value, int __ndigit,
                    int *__restrict __decpt, int *__restrict __sign) ;
extern char *qfcvt (long double __value, int __ndigit,
                    int *__restrict __decpt, int *__restrict __sign) ;
extern char *qgcvt (long double __value, int __ndigit, char *__buf) ;
extern int ecvt_r (double __value, int __ndigit, int *__restrict __decpt,
                   int *__restrict __sign, char *__restrict __buf,
                   size_t __len) ;
extern int fcvt_r (double __value, int __ndigit, int *__restrict __decpt,
                   int *__restrict __sign, char *__restrict __buf,
                   size_t __len) ;
extern int qecvt_r (long double __value, int __ndigit,
                    int *__restrict __decpt, int *__restrict __sign,
                    char *__restrict __buf, size_t __len) ;
extern int qfcvt_r (long double __value, int __ndigit,
                    int *__restrict __decpt, int *__restrict __sign,
                    char *__restrict __buf, size_t __len) ;
extern int mblen (__const char *__s, size_t __n) ;
extern int mbtowc (wchar_t *__restrict __pwc,
                   __const char *__restrict __s, size_t __n) ;
extern int wctomb (char *__s, wchar_t __wchar) ;
extern size_t mbstowcs (wchar_t *__restrict __pwcs,
                        __const char *__restrict __s, size_t __n) ;
extern size_t wcstombs (char *__restrict __s,
                        __const wchar_t *__restrict __pwcs, size_t __n)
            ;
extern int rpmatch (__const char *__response) ;
extern int getloadavg (double __loadavg[], int __nelem) ;
extern void *memcpy (void *__restrict __dest,
                     __const void *__restrict __src, size_t __n) ;
extern void *memmove (void *__dest, __const void *__src, size_t __n)
            ;
extern void *memccpy (void *__restrict __dest, __const void *__restrict __src,
                      int __c, size_t __n)
            ;
extern void *memset (void *__s, int __c, size_t __n) ;
extern int memcmp (__const void *__s1, __const void *__s2, size_t __n)
             __attribute__ ((__pure__));
extern void *memchr (__const void *__s, int __c, size_t __n)
              __attribute__ ((__pure__));
extern char *strcpy (char *__restrict __dest, __const char *__restrict __src)
            ;
extern char *strncpy (char *__restrict __dest,
                      __const char *__restrict __src, size_t __n) ;
extern char *strcat (char *__restrict __dest, __const char *__restrict __src)
            ;
extern char *strncat (char *__restrict __dest, __const char *__restrict __src,
                      size_t __n) ;
extern int strcmp (__const char *__s1, __const char *__s2)
             __attribute__ ((__pure__));
extern int strncmp (__const char *__s1, __const char *__s2, size_t __n)
             __attribute__ ((__pure__));
extern int strcoll (__const char *__s1, __const char *__s2)
             __attribute__ ((__pure__));
extern size_t strxfrm (char *__restrict __dest,
                       __const char *__restrict __src, size_t __n) ;
extern char *strdup (__const char *__s) __attribute__ ((__malloc__));
extern char *strchr (__const char *__s, int __c) __attribute__ ((__pure__));
extern char *strrchr (__const char *__s, int __c) __attribute__ ((__pure__));
extern size_t strcspn (__const char *__s, __const char *__reject)
             __attribute__ ((__pure__));
extern size_t strspn (__const char *__s, __const char *__accept)
             __attribute__ ((__pure__));
extern char *strpbrk (__const char *__s, __const char *__accept)
             __attribute__ ((__pure__));
extern char *strstr (__const char *__haystack, __const char *__needle)
             __attribute__ ((__pure__));
extern char *strtok (char *__restrict __s, __const char *__restrict __delim)
            ;
extern char *__strtok_r (char *__restrict __s,
                         __const char *__restrict __delim,
                         char **__restrict __save_ptr) ;
extern char *strtok_r (char *__restrict __s, __const char *__restrict __delim,
                       char **__restrict __save_ptr) ;
extern size_t strlen (__const char *__s) __attribute__ ((__pure__));
extern char *strerror (int __errnum) ;
extern char *strerror_r (int __errnum, char *__buf, size_t __buflen) ;
extern void __bzero (void *__s, size_t __n) ;
extern void bcopy (__const void *__src, void *__dest, size_t __n) ;
extern void bzero (void *__s, size_t __n) ;
extern int bcmp (__const void *__s1, __const void *__s2, size_t __n)
             __attribute__ ((__pure__));
extern char *index (__const char *__s, int __c) __attribute__ ((__pure__));
extern char *rindex (__const char *__s, int __c) __attribute__ ((__pure__));
extern int ffs (int __i) __attribute__ ((__const__));
extern int strcasecmp (__const char *__s1, __const char *__s2)
             __attribute__ ((__pure__));
extern int strncasecmp (__const char *__s1, __const char *__s2, size_t __n)
             __attribute__ ((__pure__));
extern char *strsep (char **__restrict __stringp,
                     __const char *__restrict __delim) ;
extern void *__rawmemchr (const void *__s, int __c);
extern __inline char *__strcpy_small (char *, __uint16_t, __uint16_t,
                                      __uint32_t, __uint32_t, size_t);
extern __inline char *
__strcpy_small (char *__dest,
                __uint16_t __src0_2, __uint16_t __src4_2,
                __uint32_t __src0_4, __uint32_t __src4_4,
                size_t __srclen)
{
  union {
    __uint32_t __ui;
    __uint16_t __usi;
    unsigned char __uc;
  } *__u = (void *) __dest;
  switch ((unsigned int) __srclen)
    {
    case 1:
      __u->__uc = '\0';
      break;
    case 2:
      __u->__usi = __src0_2;
      break;
    case 3:
      __u->__usi = __src0_2;
      __u = __extension__ ((void *) __u + 2);
      __u->__uc = '\0';
      break;
    case 4:
      __u->__ui = __src0_4;
      break;
    case 5:
      __u->__ui = __src0_4;
      __u = __extension__ ((void *) __u + 4);
      __u->__uc = '\0';
      break;
    case 6:
      __u->__ui = __src0_4;
      __u = __extension__ ((void *) __u + 4);
      __u->__usi = __src4_2;
      break;
    case 7:
      __u->__ui = __src0_4;
      __u = __extension__ ((void *) __u + 4);
      __u->__usi = __src4_2;
      __u = __extension__ ((void *) __u + 2);
      __u->__uc = '\0';
      break;
    case 8:
      __u->__ui = __src0_4;
      __u = __extension__ ((void *) __u + 4);
      __u->__ui = __src4_4;
      break;
    }
  return __dest;
}
extern __inline size_t __strcspn_c1 (__const char *__s, int __reject);
extern __inline size_t
__strcspn_c1 (__const char *__s, int __reject)
{
  register size_t __result = 0;
  while (__s[__result] != '\0' && __s[__result] != __reject)
    ++__result;
  return __result;
}
extern __inline size_t __strcspn_c2 (__const char *__s, int __reject1,
                                     int __reject2);
extern __inline size_t
__strcspn_c2 (__const char *__s, int __reject1, int __reject2)
{
  register size_t __result = 0;
  while (__s[__result] != '\0' && __s[__result] != __reject1
         && __s[__result] != __reject2)
    ++__result;
  return __result;
}
extern __inline size_t __strcspn_c3 (__const char *__s, int __reject1,
                                     int __reject2, int __reject3);
extern __inline size_t
__strcspn_c3 (__const char *__s, int __reject1, int __reject2,
              int __reject3)
{
  register size_t __result = 0;
  while (__s[__result] != '\0' && __s[__result] != __reject1
         && __s[__result] != __reject2 && __s[__result] != __reject3)
    ++__result;
  return __result;
}
extern __inline size_t __strspn_c1 (__const char *__s, int __accept);
extern __inline size_t
__strspn_c1 (__const char *__s, int __accept)
{
  register size_t __result = 0;
  while (__s[__result] == __accept)
    ++__result;
  return __result;
}
extern __inline size_t __strspn_c2 (__const char *__s, int __accept1,
                                    int __accept2);
extern __inline size_t
__strspn_c2 (__const char *__s, int __accept1, int __accept2)
{
  register size_t __result = 0;
  while (__s[__result] == __accept1 || __s[__result] == __accept2)
    ++__result;
  return __result;
}
extern __inline size_t __strspn_c3 (__const char *__s, int __accept1,
                                    int __accept2, int __accept3);
extern __inline size_t
__strspn_c3 (__const char *__s, int __accept1, int __accept2, int __accept3)
{
  register size_t __result = 0;
  while (__s[__result] == __accept1 || __s[__result] == __accept2
         || __s[__result] == __accept3)
    ++__result;
  return __result;
}
extern __inline char *__strpbrk_c2 (__const char *__s, int __accept1,
                                     int __accept2);
extern __inline char *
__strpbrk_c2 (__const char *__s, int __accept1, int __accept2)
{
  while (*__s != '\0' && *__s != __accept1 && *__s != __accept2)
    ++__s;
  return *__s == '\0' ? ((void *)0) : (char *) (size_t) __s;
}
extern __inline char *__strpbrk_c3 (__const char *__s, int __accept1,
                                     int __accept2, int __accept3);
extern __inline char *
__strpbrk_c3 (__const char *__s, int __accept1, int __accept2,
              int __accept3)
{
  while (*__s != '\0' && *__s != __accept1 && *__s != __accept2
         && *__s != __accept3)
    ++__s;
  return *__s == '\0' ? ((void *)0) : (char *) (size_t) __s;
}
extern __inline char *__strtok_r_1c (char *__s, char __sep, char **__nextp);
extern __inline char *
__strtok_r_1c (char *__s, char __sep, char **__nextp)
{
  char *__result;
  if (__s == ((void *)0))
    __s = *__nextp;
  while (*__s == __sep)
    ++__s;
  __result = ((void *)0);
  if (*__s != '\0')
    {
      __result = __s++;
      while (*__s != '\0')
        if (*__s++ == __sep)
          {
            __s[-1] = '\0';
            break;
          }
      *__nextp = __s;
    }
  return __result;
}
extern char *__strsep_g (char **__stringp, __const char *__delim);
extern __inline char *__strsep_1c (char **__s, char __reject);
extern __inline char *
__strsep_1c (char **__s, char __reject)
{
  register char *__retval = *__s;
  if (__retval != ((void *)0) && (*__s = (__extension__ (__builtin_constant_p (__reject) && (__reject) == '\0' ? (char *) __rawmemchr (__retval, __reject) : strchr (__retval, __reject)))) != ((void *)0))
    *(*__s)++ = '\0';
  return __retval;
}
extern __inline char *__strsep_2c (char **__s, char __reject1, char __reject2);
extern __inline char *
__strsep_2c (char **__s, char __reject1, char __reject2)
{
  register char *__retval = *__s;
  if (__retval != ((void *)0))
    {
      register char *__cp = __retval;
      while (1)
        {
          if (*__cp == '\0')
            {
              __cp = ((void *)0);
          break;
            }
          if (*__cp == __reject1 || *__cp == __reject2)
            {
              *__cp++ = '\0';
              break;
            }
          ++__cp;
        }
      *__s = __cp;
    }
  return __retval;
}
extern __inline char *__strsep_3c (char **__s, char __reject1, char __reject2,
                                   char __reject3);
extern __inline char *
__strsep_3c (char **__s, char __reject1, char __reject2, char __reject3)
{
  register char *__retval = *__s;
  if (__retval != ((void *)0))
    {
      register char *__cp = __retval;
      while (1)
        {
          if (*__cp == '\0')
            {
              __cp = ((void *)0);
          break;
            }
          if (*__cp == __reject1 || *__cp == __reject2 || *__cp == __reject3)
            {
              *__cp++ = '\0';
              break;
            }
          ++__cp;
        }
      *__s = __cp;
    }
  return __retval;
}
extern char *__strdup (__const char *__string) __attribute__ ((__malloc__));
extern char *__strndup (__const char *__string, size_t __n)
             __attribute__ ((__malloc__));
extern void __assert_fail (__const char *__assertion, __const char *__file,
                           unsigned int __line, __const char *__function)
             __attribute__ ((__noreturn__));
extern void __assert_perror_fail (int __errnum, __const char *__file,
                                  unsigned int __line,
                                  __const char *__function)
             __attribute__ ((__noreturn__));
extern void __assert (const char *__assertion, const char *__file, int __line)
             __attribute__ ((__noreturn__));
typedef __gnuc_va_list va_list;
typedef struct region_ *region;
extern region permanent;
void region_init(void);
region newregion(void);
region newsubregion(region parent);
typedef int type_t;
void *__rc_typed_ralloc(region r, size_t size, type_t type);
void *__rc_typed_rarrayalloc(region r, size_t n, size_t size, type_t type);
void *__rc_typed_rarrayextend(region r, void *old, size_t n, size_t size, type_t type);
void typed_rarraycopy(void *to, void *from, size_t n, size_t size, type_t type);
void *__rc_ralloc_small0(region r, size_t size);
char *__rc_rstralloc(region r, size_t size);
char *__rc_rstralloc0(region r, size_t size);
char *__rc_rstrdup(region r, const char *s);
char *__rc_rstrextend(region r, const char *old, size_t newsize);
char *__rc_rstrextend0(region r, const char *old, size_t newsize);
void deleteregion(region r);
void deleteregion_ptr(region *r);
void deleteregion_array(int n, region *regions);
region regionof(void *ptr);
typedef void (*nomem_handler)(void);
nomem_handler set_nomem_handler(nomem_handler newhandler);
void findrefs(region r, void *from, void *to);
void findgrefs(region r);
void findrrefs(region r, region from);
typedef unsigned char bool;
typedef struct {
  char *data;
  int length;
} cstring;
cstring make_cstring(region r, const char *s, int l);
cstring str2cstring(region r, const char *s);
typedef long long largest_int;
typedef unsigned long long largest_uint;
struct array;
struct array *new_array(region r, size_t initialsize,
                        size_t typesize, type_t typeinfo);
void *array_extend(struct array *a, int by);
void array_reset(struct array *a);
size_t array_length(struct array *a);
void *array_data(struct array *a);
typedef struct wchar_array_a *wchar_array; wchar_array new_wchar_array(region r, size_t initialsize); wchar_t *wchar_array_extend(wchar_array a, int by); void wchar_array_reset(wchar_array a); size_t wchar_array_length(wchar_array a); wchar_t *wchar_array_data(wchar_array a);
extern void __assert_fail (__const char *__assertion, __const char *__file,
                           unsigned int __line, __const char *__function)
             __attribute__ ((__noreturn__));
extern void __assert_perror_fail (int __errnum, __const char *__file,
                                  unsigned int __line,
                                  __const char *__function)
             __attribute__ ((__noreturn__));
extern void __assert (const char *__assertion, const char *__file, int __line)
             __attribute__ ((__noreturn__));
typedef int (*dd_cmp_fn) (void*, void*);
typedef struct dd_list *dd_list;
typedef struct dd_list_pos
{
  struct dd_list_pos *next;
  struct dd_list_pos *previous;
  void *data;
} *dd_list_pos;
dd_list dd_new_list(region r);
void dd_add_first(region r, dd_list l, void *data);
void dd_add_last(region r, dd_list l, void *data);
void dd_insert_before(region r, dd_list_pos where, void *data);
void dd_insert_after(region r, dd_list_pos where, void *data);
void dd_remove(dd_list_pos what);
dd_list_pos dd_first(dd_list l);
dd_list_pos dd_last(dd_list l);
unsigned long dd_length(dd_list l);
void dd_append(dd_list l1, dd_list l2);
dd_list dd_copy(region r, dd_list l);
void dd_free_list(dd_list l, void (*delete)(dd_list_pos p));
dd_list_pos dd_find(dd_list l, void *find);
dd_list_pos dd_search(dd_list l, dd_cmp_fn f, void *find);
void dd_sort (dd_list l, dd_cmp_fn f);
void dd_remove_all_matches_from(dd_list_pos begin, dd_cmp_fn f, void* find);
void dd_remove_dups(dd_list l, dd_cmp_fn f);
static inline dd_list dd_fix_null(region r, dd_list l)
{
  if (l == ((void *)0))
    return dd_new_list(r);
  else
    return l;
}
typedef int (*set_cmp_fn)(void *e1, void *e2);
typedef struct Location
{
  char *filename;
  unsigned long lineno;
  unsigned long filepos;
  bool in_system_header;
  int location_index;
} *location;
unsigned long location_hash(location loc);
bool location_eq(location loc1, location loc2);
int location_cmp(location loc1, location loc2);
int location_index(location loc);
typedef dd_list loc_set; typedef dd_list_pos loc_set_scanner; static inline loc_set empty_loc_set (region r) { return dd_new_list(r); } static inline loc_set loc_set_copy(region r, loc_set s) { if (s == ((void *)0)) return ((void *)0); else return dd_copy(r, s); } static inline bool loc_set_empty(loc_set s) { return s == ((void *)0) || ((!(dd_first((s)))->next)); } static inline bool loc_set_member(loc_set s, location elt) { return s != ((void *)0) && dd_search(s, (dd_cmp_fn) location_cmp, (void *) elt) != ((void *)0); } static inline int loc_set_size(loc_set s) { if (s == ((void *)0)) return 0; else return dd_length(s); } static inline bool loc_set_insert(region r, loc_set *s, location elt) { *s = dd_fix_null(r, *s); if (! loc_set_member(*s, elt)) { dd_add_first(r, *s, (void *) elt); return 1; } return 0; } static inline bool loc_set_insert_last(region r, loc_set *s, location elt) { *s = dd_fix_null(r, *s); if (! loc_set_member(*s, elt)) { dd_add_last(r, *s, (void *) elt); return 1; } return 0; } static inline bool loc_set_insert_nocheck(region r, loc_set *s, location elt) { *s = dd_fix_null(r, *s); dd_add_first(r, *s, (void *) elt); return 1; } static inline bool loc_set_insert_last_nocheck(region r, loc_set *s, location elt) { *s = dd_fix_null(r, *s); dd_add_last(r, *s, (void *) elt); return 1; } static inline void loc_set_remove(loc_set *s, location elt) { if (*s) dd_remove_all_matches_from(dd_first(*s), (dd_cmp_fn) location_cmp, (void *) elt); } static inline loc_set loc_set_union(loc_set s1, loc_set s2) { if (s1 == ((void *)0)) return s2; else if (s2 == ((void *)0)) return s1; dd_append(s1, s2); dd_remove_dups(s1, (dd_cmp_fn)location_cmp); return s1; } static inline loc_set loc_set_union_nocheck(loc_set s1, loc_set s2) { if (s1 == ((void *)0)) return s2; else if (s2 == ((void *)0)) return s1; dd_append(s1, s2); return s1; } static inline bool loc_set_single(loc_set s) { return loc_set_size(s) == 1; } static inline void loc_set_sort(loc_set s) { if (s) dd_sort(s, (set_cmp_fn) location_cmp); } static inline void loc_set_remove_dups(int (*cmp)(location, location), loc_set s) { if (s) dd_remove_dups(s, (dd_cmp_fn)cmp); } static inline void loc_set_scan(loc_set s, loc_set_scanner *ss) { if (s) *ss = dd_first(s); else *ss = ((void *)0); } static inline location loc_set_next(loc_set_scanner *ss) { location result; if (*ss == ((void *)0) || (!(*ss)->next)) return ((void *)0); result = ((location)((*ss)->data)); *ss = ((*ss)->next); return result; };
void *xmalloc(size_t size);
void *xrealloc(void *p, size_t newsize);
unsigned long align_to(unsigned long n, unsigned long alignment);
unsigned long lcm(unsigned long x, unsigned long y);
void __fail(const char *file, unsigned int line,
            const char *func, const char *fmt, ...) __attribute__ ((__noreturn__));
void __user_error(const char *file, unsigned int line,
                  const char *func, const char *fmt, ...)
  __attribute__ ((__noreturn__));
char *rstrcat(region, const char *, const char *);
char *rstrscat(region, ...);
const char *inttostr(region r, int);
char *rsprintf(region r, const char *fmt, ...);
char *rvsprintf(region r, const char *fmt, va_list args);
char *ptr_to_ascii(void *ptr);
unsigned long ptr_hash(void *ptr);
bool ptr_eq(void *ptr1, void *ptr2);
unsigned long string_hash(const char *str);
bool string_eq(const char *s1, const char *s2);
int ptr_cmp(void *ptr1, void *ptr2);
const char *name_with_loc(region r, const char *name, location loc);
typedef int id_declaration_list;
typedef struct typelist *typelist;
typedef struct type *type;
typedef struct known_cst *known_cst;
typedef struct AST_node *node;
typedef struct AST_declaration *declaration;
typedef struct AST_statement *statement;
typedef struct AST_expression *expression;
typedef struct AST_type_element *type_element;
typedef struct AST_declarator *declarator;
typedef struct AST_label *label;
typedef struct AST_asm_decl *asm_decl;
typedef struct AST_data_decl *data_decl;
typedef struct AST_extension_decl *extension_decl;
typedef struct AST_ellipsis_decl *ellipsis_decl;
typedef struct AST_enumerator *enumerator;
typedef struct AST_oldidentifier_decl *oldidentifier_decl;
typedef struct AST_function_decl *function_decl;
typedef struct AST_implicit_decl *implicit_decl;
typedef struct AST_variable_decl *variable_decl;
typedef struct AST_field_decl *field_decl;
typedef struct AST_asttype *asttype;
typedef struct AST_typename *typename;
typedef struct AST_type_variable *type_variable;
typedef struct AST_typeof_expr *typeof_expr;
typedef struct AST_typeof_type *typeof_type;
typedef struct AST_attribute *attribute;
typedef struct AST_rid *rid;
typedef struct AST_user_qual *user_qual;
typedef struct AST_qualifier *qualifier;
typedef struct AST_tag_ref *tag_ref;
typedef struct AST_function_declarator *function_declarator;
typedef struct AST_pointer_declarator *pointer_declarator;
typedef struct AST_array_declarator *array_declarator;
typedef struct AST_identifier_declarator *identifier_declarator;
typedef struct AST_asm_stmt *asm_stmt;
typedef struct AST_compound_stmt *compound_stmt;
typedef struct AST_if_stmt *if_stmt;
typedef struct AST_labeled_stmt *labeled_stmt;
typedef struct AST_expression_stmt *expression_stmt;
typedef struct AST_breakable_stmt *breakable_stmt;
typedef struct AST_conditional_stmt *conditional_stmt;
typedef struct AST_switch_stmt *switch_stmt;
typedef struct AST_for_stmt *for_stmt;
typedef struct AST_break_stmt *break_stmt;
typedef struct AST_continue_stmt *continue_stmt;
typedef struct AST_return_stmt *return_stmt;
typedef struct AST_goto_stmt *goto_stmt;
typedef struct AST_computed_goto_stmt *computed_goto_stmt;
typedef struct AST_empty_stmt *empty_stmt;
typedef struct AST_assert_type_stmt *assert_type_stmt;
typedef struct AST_change_type_stmt *change_type_stmt;
typedef struct AST_deep_restrict_stmt *deep_restrict_stmt;
typedef struct AST_unary *unary;
typedef struct AST_binary *binary;
typedef struct AST_comma *comma;
typedef struct AST_sizeof_type *sizeof_type;
typedef struct AST_alignof_type *alignof_type;
typedef struct AST_label_address *label_address;
typedef struct AST_cast *cast;
typedef struct AST_cast_list *cast_list;
typedef struct AST_conditional *conditional;
typedef struct AST_identifier *identifier;
typedef struct AST_compound_expr *compound_expr;
typedef struct AST_function_call *function_call;
typedef struct AST_array_ref *array_ref;
typedef struct AST_field_ref *field_ref;
typedef struct AST_init_list *init_list;
typedef struct AST_init_index *init_index;
typedef struct AST_init_field *init_field;
typedef struct AST_lexical_cst *lexical_cst;
typedef struct AST_string_cst *string_cst;
typedef struct AST_string *string;
typedef struct AST_id_label *id_label;
typedef struct AST_case_label *case_label;
typedef struct AST_default_label *default_label;
typedef struct AST_word *word;
typedef struct AST_asm_operand *asm_operand;
typedef struct AST_declaration *error_decl;
typedef struct AST_tag_ref *struct_ref;
typedef struct AST_tag_ref *union_ref;
typedef struct AST_tag_ref *enum_ref;
typedef struct AST_statement *error_stmt;
typedef struct AST_conditional_stmt *while_stmt;
typedef struct AST_conditional_stmt *dowhile_stmt;
typedef struct AST_expression *error_expr;
typedef struct AST_unary *dereference;
typedef struct AST_unary *extension_expr;
typedef struct AST_unary *sizeof_expr;
typedef struct AST_unary *alignof_expr;
typedef struct AST_unary *realpart;
typedef struct AST_unary *imagpart;
typedef struct AST_unary *address_of;
typedef struct AST_unary *unary_minus;
typedef struct AST_unary *unary_plus;
typedef struct AST_unary *conjugate;
typedef struct AST_unary *preincrement;
typedef struct AST_unary *predecrement;
typedef struct AST_unary *postincrement;
typedef struct AST_unary *postdecrement;
typedef struct AST_unary *bitnot;
typedef struct AST_unary *not;
typedef struct AST_binary *plus;
typedef struct AST_binary *minus;
typedef struct AST_binary *times;
typedef struct AST_binary *divide;
typedef struct AST_binary *modulo;
typedef struct AST_binary *lshift;
typedef struct AST_binary *rshift;
typedef struct AST_binary *leq;
typedef struct AST_binary *geq;
typedef struct AST_binary *lt;
typedef struct AST_binary *gt;
typedef struct AST_binary *eq;
typedef struct AST_binary *ne;
typedef struct AST_binary *bitand;
typedef struct AST_binary *bitor;
typedef struct AST_binary *bitxor;
typedef struct AST_binary *andand;
typedef struct AST_binary *oror;
typedef struct AST_binary *assign;
typedef struct AST_binary *plus_assign;
typedef struct AST_binary *minus_assign;
typedef struct AST_binary *times_assign;
typedef struct AST_binary *divide_assign;
typedef struct AST_binary *modulo_assign;
typedef struct AST_binary *lshift_assign;
typedef struct AST_binary *rshift_assign;
typedef struct AST_binary *bitand_assign;
typedef struct AST_binary *bitor_assign;
typedef struct AST_binary *bitxor_assign;
typedef enum {
  kind_node = 42,
  postkind_node = 168,
  kind_declaration = 43,
  postkind_declaration = 54,
  kind_statement = 55,
  postkind_statement = 76,
  kind_expression = 77,
  postkind_expression = 143,
  kind_type_element = 144,
  postkind_type_element = 156,
  kind_declarator = 157,
  postkind_declarator = 161,
  kind_label = 162,
  postkind_label = 165,
  kind_asm_decl = 44,
  postkind_asm_decl = 44,
  kind_data_decl = 45,
  postkind_data_decl = 45,
  kind_extension_decl = 46,
  postkind_extension_decl = 46,
  kind_ellipsis_decl = 47,
  postkind_ellipsis_decl = 47,
  kind_enumerator = 48,
  postkind_enumerator = 48,
  kind_oldidentifier_decl = 49,
  postkind_oldidentifier_decl = 49,
  kind_function_decl = 50,
  postkind_function_decl = 50,
  kind_implicit_decl = 51,
  postkind_implicit_decl = 51,
  kind_variable_decl = 52,
  postkind_variable_decl = 52,
  kind_field_decl = 53,
  postkind_field_decl = 53,
  kind_asttype = 166,
  postkind_asttype = 166,
  kind_typename = 145,
  postkind_typename = 145,
  kind_type_variable = 146,
  postkind_type_variable = 146,
  kind_typeof_expr = 147,
  postkind_typeof_expr = 147,
  kind_typeof_type = 148,
  postkind_typeof_type = 148,
  kind_attribute = 149,
  postkind_attribute = 149,
  kind_rid = 150,
  postkind_rid = 150,
  kind_user_qual = 151,
  postkind_user_qual = 151,
  kind_qualifier = 152,
  postkind_qualifier = 152,
  kind_tag_ref = 153,
  postkind_tag_ref = 156,
  kind_function_declarator = 158,
  postkind_function_declarator = 158,
  kind_pointer_declarator = 159,
  postkind_pointer_declarator = 159,
  kind_array_declarator = 160,
  postkind_array_declarator = 160,
  kind_identifier_declarator = 161,
  postkind_identifier_declarator = 161,
  kind_asm_stmt = 56,
  postkind_asm_stmt = 56,
  kind_compound_stmt = 57,
  postkind_compound_stmt = 57,
  kind_if_stmt = 58,
  postkind_if_stmt = 58,
  kind_labeled_stmt = 59,
  postkind_labeled_stmt = 59,
  kind_expression_stmt = 60,
  postkind_expression_stmt = 60,
  kind_breakable_stmt = 61,
  postkind_breakable_stmt = 66,
  kind_conditional_stmt = 62,
  postkind_conditional_stmt = 65,
  kind_switch_stmt = 63,
  postkind_switch_stmt = 63,
  kind_for_stmt = 66,
  postkind_for_stmt = 66,
  kind_break_stmt = 67,
  postkind_break_stmt = 67,
  kind_continue_stmt = 68,
  postkind_continue_stmt = 68,
  kind_return_stmt = 69,
  postkind_return_stmt = 69,
  kind_goto_stmt = 70,
  postkind_goto_stmt = 70,
  kind_computed_goto_stmt = 71,
  postkind_computed_goto_stmt = 71,
  kind_empty_stmt = 72,
  postkind_empty_stmt = 72,
  kind_assert_type_stmt = 73,
  postkind_assert_type_stmt = 73,
  kind_change_type_stmt = 74,
  postkind_change_type_stmt = 74,
  kind_deep_restrict_stmt = 75,
  postkind_deep_restrict_stmt = 75,
  kind_unary = 78,
  postkind_unary = 96,
  kind_binary = 97,
  postkind_binary = 127,
  kind_comma = 128,
  postkind_comma = 128,
  kind_sizeof_type = 129,
  postkind_sizeof_type = 129,
  kind_alignof_type = 130,
  postkind_alignof_type = 130,
  kind_label_address = 131,
  postkind_label_address = 131,
  kind_cast = 79,
  postkind_cast = 79,
  kind_cast_list = 132,
  postkind_cast_list = 132,
  kind_conditional = 133,
  postkind_conditional = 133,
  kind_identifier = 134,
  postkind_identifier = 134,
  kind_compound_expr = 135,
  postkind_compound_expr = 135,
  kind_function_call = 136,
  postkind_function_call = 136,
  kind_array_ref = 98,
  postkind_array_ref = 98,
  kind_field_ref = 80,
  postkind_field_ref = 80,
  kind_init_list = 137,
  postkind_init_list = 137,
  kind_init_index = 138,
  postkind_init_index = 138,
  kind_init_field = 139,
  postkind_init_field = 139,
  kind_lexical_cst = 140,
  postkind_lexical_cst = 141,
  kind_string_cst = 141,
  postkind_string_cst = 141,
  kind_string = 142,
  postkind_string = 142,
  kind_id_label = 163,
  postkind_id_label = 163,
  kind_case_label = 164,
  postkind_case_label = 164,
  kind_default_label = 165,
  postkind_default_label = 165,
  kind_word = 167,
  postkind_word = 167,
  kind_asm_operand = 168,
  postkind_asm_operand = 168,
  kind_error_decl = 54,
  postkind_error_decl = 54,
  kind_struct_ref = 154,
  postkind_struct_ref = 154,
  kind_union_ref = 155,
  postkind_union_ref = 155,
  kind_enum_ref = 156,
  postkind_enum_ref = 156,
  kind_error_stmt = 76,
  postkind_error_stmt = 76,
  kind_while_stmt = 64,
  postkind_while_stmt = 64,
  kind_dowhile_stmt = 65,
  postkind_dowhile_stmt = 65,
  kind_error_expr = 143,
  postkind_error_expr = 143,
  kind_dereference = 81,
  postkind_dereference = 81,
  kind_extension_expr = 82,
  postkind_extension_expr = 82,
  kind_sizeof_expr = 83,
  postkind_sizeof_expr = 83,
  kind_alignof_expr = 84,
  postkind_alignof_expr = 84,
  kind_realpart = 85,
  postkind_realpart = 85,
  kind_imagpart = 86,
  postkind_imagpart = 86,
  kind_address_of = 87,
  postkind_address_of = 87,
  kind_unary_minus = 88,
  postkind_unary_minus = 88,
  kind_unary_plus = 89,
  postkind_unary_plus = 89,
  kind_conjugate = 90,
  postkind_conjugate = 90,
  kind_preincrement = 91,
  postkind_preincrement = 91,
  kind_predecrement = 92,
  postkind_predecrement = 92,
  kind_postincrement = 93,
  postkind_postincrement = 93,
  kind_postdecrement = 94,
  postkind_postdecrement = 94,
  kind_bitnot = 95,
  postkind_bitnot = 95,
  kind_not = 96,
  postkind_not = 96,
  kind_plus = 99,
  postkind_plus = 99,
  kind_minus = 100,
  postkind_minus = 100,
  kind_times = 101,
  postkind_times = 101,
  kind_divide = 102,
  postkind_divide = 102,
  kind_modulo = 103,
  postkind_modulo = 103,
  kind_lshift = 104,
  postkind_lshift = 104,
  kind_rshift = 105,
  postkind_rshift = 105,
  kind_leq = 106,
  postkind_leq = 106,
  kind_geq = 107,
  postkind_geq = 107,
  kind_lt = 108,
  postkind_lt = 108,
  kind_gt = 109,
  postkind_gt = 109,
  kind_eq = 110,
  postkind_eq = 110,
  kind_ne = 111,
  postkind_ne = 111,
  kind_bitand = 112,
  postkind_bitand = 112,
  kind_bitor = 113,
  postkind_bitor = 113,
  kind_bitxor = 114,
  postkind_bitxor = 114,
  kind_andand = 115,
  postkind_andand = 115,
  kind_oror = 116,
  postkind_oror = 116,
  kind_assign = 117,
  postkind_assign = 117,
  kind_plus_assign = 118,
  postkind_plus_assign = 118,
  kind_minus_assign = 119,
  postkind_minus_assign = 119,
  kind_times_assign = 120,
  postkind_times_assign = 120,
  kind_divide_assign = 121,
  postkind_divide_assign = 121,
  kind_modulo_assign = 122,
  postkind_modulo_assign = 122,
  kind_lshift_assign = 123,
  postkind_lshift_assign = 123,
  kind_rshift_assign = 124,
  postkind_rshift_assign = 124,
  kind_bitand_assign = 125,
  postkind_bitand_assign = 125,
  kind_bitor_assign = 126,
  postkind_bitor_assign = 126,
  kind_bitxor_assign = 127,
  postkind_bitxor_assign = 127
} ast_kind;
extern location last_location, dummy_location;
enum rid
{
  RID_UNUSED,
  RID_INT,
  RID_CHAR,
  RID_FLOAT,
  RID_DOUBLE,
  RID_VOID,
  RID_UNSIGNED,
  RID_SHORT,
  RID_LONG,
  RID_SIGNED,
  RID_INLINE,
  RID_COMPLEX,
  RID_AUTO,
  RID_STATIC,
  RID_EXTERN,
  RID_REGISTER,
  RID_TYPEDEF,
  RID_MAX
};
extern char * token_buffer;
extern bool in_system_header;
extern bool in_prelude;
int yylex(void);
void init_lex(void);
typedef unsigned char uint8_t;
typedef unsigned short int uint16_t;
typedef unsigned int uint32_t;
__extension__
typedef unsigned long long int uint64_t;
typedef signed char int_least8_t;
typedef short int int_least16_t;
typedef int int_least32_t;
__extension__
typedef long long int int_least64_t;
typedef unsigned char uint_least8_t;
typedef unsigned short int uint_least16_t;
typedef unsigned int uint_least32_t;
__extension__
typedef unsigned long long int uint_least64_t;
typedef signed char int_fast8_t;
typedef int int_fast16_t;
typedef int int_fast32_t;
__extension__
typedef long long int int_fast64_t;
typedef unsigned char uint_fast8_t;
typedef unsigned int uint_fast16_t;
typedef unsigned int uint_fast32_t;
__extension__
typedef unsigned long long int uint_fast64_t;
typedef int intptr_t;
typedef unsigned int uintptr_t;
__extension__
typedef long long int intmax_t;
__extension__
typedef unsigned long long int uintmax_t;
typedef unsigned int *bitset;
unsigned int sizeof_bitset(unsigned int nbits);
bitset bitset_new(region r, unsigned int nbits);
bitset bitset_copy(region r, bitset b);
void bitset_assign(bitset b1, bitset b2);
bool bitset_empty(bitset b);
bool bitset_empty_range(bitset b, unsigned int first, unsigned int last);
bool bitset_full_range(bitset b, unsigned int first, unsigned int last);
void bitset_insert_all(bitset b);
bool bitset_insert(bitset b, unsigned int elt);
bool bitset_remove(bitset b, unsigned int elt);
bool bitset_member(bitset b, unsigned int elt);
bool bitset_intersect(bitset b1, const bitset b2);
void bitset_print(bitset b);
unsigned long bitset_hash(bitset b);
bool bitset_eq(bitset b1, bitset b2);
typedef struct growbuf *growbuf;
growbuf growbuf_new(region, int);
void growbuf_reset(growbuf);
int gprintf(growbuf, const char *, ...);
int gvprintf(growbuf, const char *, va_list);
char *growbuf_contents(growbuf);
bool growbuf_empty(growbuf);
typedef struct Qtype *qtype;
typedef struct Abstract_loc *aloc;
typedef struct Effect *effect;
typedef struct Store *store;
typedef struct Rinfo *rinfo;
typedef struct Drinfo *drinfo;
typedef struct ExprDrinfoPair *exprdrinfo;
typedef int (*printf_func)(const char *fmt, ...);
typedef enum {p_neg = -1, p_non = 0, p_pos = 1, p_sub = 2} polarity;
typedef enum {
  eff_any = 0,
  eff_rwr,
  eff_r,
  eff_wr,
  eff_alloc,
  eff_last = eff_alloc } eff_kind;
void load_config_file_quals(const char *);
typedef void *hash_key;
typedef void *hash_data;
typedef unsigned long (*hash_fn)(hash_key k);
typedef bool (*keyeq_fn)(hash_key k1, hash_key k2);
typedef void (*hash_apply_fn)(hash_key k, hash_data d, void *arg);
typedef hash_data (*hash_map_fn)(hash_key k, hash_data d, void *arg);
typedef struct Hash_table *hash_table;
hash_table make_hash_table(region rhash, unsigned long size, hash_fn hash,
                           keyeq_fn cmp);
hash_table make_string_hash_table(region rhash, unsigned long size);
void hash_table_reset(hash_table ht);
unsigned long hash_table_size(hash_table ht);
bool hash_table_hash_search(hash_table ht, keyeq_fn cmp,
                            hash_key k, hash_data *d);
bool hash_table_lookup(hash_table ht, hash_key k, hash_data *d);
bool hash_table_insert(hash_table ht, hash_key k, hash_data d);
bool hash_table_remove(hash_table ht, hash_key k);
hash_table hash_table_copy(region rhash, hash_table ht);
hash_table hash_table_map(region r, hash_table ht, hash_map_fn f, void *arg);
typedef struct bucket *bucket;
typedef struct
{
  hash_table ht;
  unsigned long i;
  bucket cur;
} hash_table_scanner;
void hash_table_scan(hash_table ht, hash_table_scanner *);
bool hash_table_next(hash_table_scanner *, hash_key *k, hash_data *d);
typedef int (*keycmp_fn)(hash_key k1, hash_key k2);
struct sorted_entry
{
  hash_key k;
  hash_data d;
};
typedef struct
{
  region r;
  unsigned long i;
  unsigned long size;
  struct sorted_entry *entries;
} hash_table_scanner_sorted;
void hash_table_scan_sorted(hash_table ht, keycmp_fn f,
                            hash_table_scanner_sorted *htss);
bool hash_table_next_sorted(hash_table_scanner_sorted *htss, hash_key *k,
                            hash_data *d);
typedef struct env *env;
env new_env(region r, env parent);
env env_parent(env e);
region env_region(env e);
void *env_lookup(env e, const char *s, bool this_level_only);
void env_add(env e, const char *s, void *value);
typedef hash_table_scanner env_scanner;
void env_scan(env e, env_scanner *scanner);
bool env_next(env_scanner *scanner, const char **name, void **value);
typedef struct Aloctype *aloctype;
typedef struct Alocreftype *alocreftype;
typedef struct Alocfntype *alocfntype;
typedef struct Effecttype *effecttype;
typedef struct Rinf_const *rinf_const;
extern effecttype effecttype_empty;
void init_aloctypes(void);
aloctype make_aloctype(alocreftype tau, alocfntype fn);
aloctype make_aloctype_fresh(void);
void unify_aloctype(aloctype al1, aloctype al2);
void mkleq_aloctype(aloctype al1, aloctype al2);
alocreftype proj_tau(aloctype al);
alocfntype proj_lam(aloctype al);
int print_aloctype(printf_func pf, aloctype al, int depth);
alocreftype alocreftype_fresh(void);
alocreftype alocreftype_var(const char * name);
alocreftype alocreftype_ref(aloctype pointsto);
void unify_alocreftype(alocreftype alref1, alocreftype alref2);
void mkleq_alocreftype(alocreftype alref1, alocreftype alref2);
aloctype deref(alocreftype tau);
int print_alocreftype(printf_func pf, alocreftype alref, int depth);
alocfntype alocfntype_fresh(void);
alocfntype alocfntype_var(const char * name);
alocfntype alocfntype_fn(aloctype * params, effecttype eff, aloctype returns);
void unify_alocfntype(alocfntype alfn1, alocfntype alfn2);
void mkleq_alocfntype(alocfntype alfn1, alocfntype alfn2);
int print_alocfntype(printf_func pf, alocfntype alfn, int depth);
effecttype effecttype_read(alocreftype base);
effecttype effecttype_write(alocreftype base);
effecttype effecttype_any(alocreftype base);
effecttype effecttype_read_reach(alocreftype base);
effecttype effecttype_write_reach(alocreftype base);
effecttype effecttype_any_reach(alocreftype base);
effecttype effecttype_union(effecttype e1, effecttype e2);
effecttype effecttype_inter(effecttype e1, effecttype e2);
effecttype effecttype_var(const char * name);
effecttype effecttype_fresh(void);
void mkleq_effecttype(effecttype e1, effecttype e2);
void mkeq_effecttype(effecttype e1, effecttype e2);
void unify_effecttype(effecttype e1, effecttype e2);
int print_effecttype(printf_func pf, effecttype e);
rinf_const mk_rinf_const(location loc,
                         alocreftype r_al, alocreftype old_al,
                         alocreftype top_al,
                         effecttype r_type, effecttype pointsto_type,
                         effecttype r_body, effecttype body, effecttype env);
void check_rinf_consts(void);
bool is_rinf_satisfied(rinf_const c);
bool is_rinf_used(rinf_const c);
int print_rinf_info(printf_func pf, rinf_const c);
typedef struct field_declaration {
  struct field_declaration *next;
  const char *name;
  type type;
  field_decl ast;
  int bitwidth;
  size_t offset;
  bool offset_cc:1;
  bool packed:1;
} *field_declaration;
typedef struct tag_declaration {
  int kind;
  const char *name;
  type reptype;
  env fields;
  field_declaration fieldlist;
  tag_ref ast;
  struct tag_declaration *shadowed;
  bool defined:1;
  bool being_defined:1;
  bool fields_const:1;
  bool fields_volatile:1;
  bool transparent_union:1;
  bool size_cc:1;
  bool packed:1;
  size_t size, alignment;
  qtype qtype;
} *tag_declaration;
typedef enum { decl_variable, decl_constant, decl_function,
               decl_typedef, decl_error, decl_magic_string } data_kind;
typedef struct data_declaration {
  data_kind kind;
  const char *name;
  type type;
  struct data_declaration *shadowed;
  struct data_declaration *global;
  declaration definition;
  declaration ast;
  expression initialiser;
  bool islimbo:1;
  bool isexternalscope:1;
  bool isfilescoperef:1;
  bool needsmemory:1;
  bool isused:1;
  bool in_system_header:1;
  bool in_prelude:1;
  bool defined:1;
  bool isallocated:1;
  bool addresstaken:1;
  bool __init:1;
  enum { function_implicit, function_normal, function_static, function_nested }
    ftype:2;
  bool isinline:1;
  bool isexterninline:1;
  bool noreturn:1;
  typelist oldstyle_args;
  char * alias;
  enum { variable_register, variable_static, variable_normal } vtype:2;
  bool islocal:1;
  bool isparameter:1;
  known_cst value;
  const wchar_t *chars;
  size_t chars_length;
  qtype qtype;
  qtype fs_qtype;
  alocreftype alref;
  compound_stmt cs;
} *data_declaration;
typedef struct label_declaration {
  const char *name;
  bool explicitly_declared:1;
  bool used:1;
  id_label firstuse;
  id_label definition;
  function_decl containing_function;
} *label_declaration;
typedef struct environment
{
  struct environment * parent;
  function_decl fdecl;
  bool parm_level;
  env id_env;
  env tag_env;
} *environment;
extern data_declaration bad_decl;
typedef struct {
  enum { cval_variable, cval_unk, cval_address,
         cval_float, cval_float_complex,
         cval_uint, cval_uint_complex,
         cval_sint, cval_sint_complex } kind;
  union {
    struct {
      long double d, d_i;
    } fl;
    struct {
      size_t isize;
      union {
        largest_int si;
        largest_uint ui;
      } real;
      union {
        largest_int si_i;
        largest_uint ui_i;
        struct {
          struct data_declaration *ddecl;
          struct label_declaration *ldecl;
        } addr;
      } imag;
    } i;
  } u;
} cval;
extern cval cval_top;
extern cval cval_unknown;
extern cval cval_zero;
void cval_init(void);
cval make_cval_signed(largest_int i, type t);
cval make_cval_unsigned(largest_uint i, type t);
cval make_cval_float(long double d);
cval make_cval_complex(cval r, cval i);
cval make_cval_address(data_declaration ddecl, label_declaration ldecl,
                       largest_int offset);
bool cval_isinteger(cval c);
bool cval_iscomplex(cval c);
bool cval_knownbool(cval c);
bool cval_boolvalue(cval c);
bool cval_knownvalue(cval c);
largest_uint cval_uint_value(cval c);
largest_int cval_sint_value(cval c);
long double cval_float_value(cval c);
bool cval_isone(cval c);
cval cval_cast(cval c, type to);
cval cval_not(cval c);
cval cval_negate(cval c);
cval cval_bitnot(cval c);
cval cval_conjugate(cval c);
cval cval_realpart(cval c);
cval cval_imagpart(cval c);
cval cval_add(cval c1, cval c2);
cval cval_sub(cval c1, cval c2);
cval cval_times(cval c1, cval c2);
cval cval_divide(cval c1, cval c2);
cval cval_modulo(cval c1, cval c2);
cval cval_lshift(cval c1, cval c2);
cval cval_rshift(cval c1, cval c2);
cval cval_bitand(cval c1, cval c2);
cval cval_bitor(cval c1, cval c2);
cval cval_bitxor(cval c1, cval c2);
cval cval_eq(cval c1, cval c2);
cval cval_leq(cval c1, cval c2);
bool uint_inrange(largest_uint x, type t);
bool sint_inrange(largest_int x, type t);
bool cval_inrange(cval c, type t);
largest_int cval_intcompare(cval c1, cval c2);
extern region parse_region;
typedef enum
{
  no_qualifiers = 0,
  transparent_qualifier = 1,
const_qualifier = 2,
volatile_qualifier = 4,
restrict_qualifier = 8,
  last_qualifier
} type_quals;
typedef struct user_qual_list
{
  user_qual qual;
  struct user_qual_list *next;
} *user_qual_list;
user_qual_list new_user_qual_list(user_qual, user_qual_list);
user_qual_list copy_user_qual_list(user_qual_list l);
bool member_user_qual_list(user_qual_list l, char *q);
user_qual_list union_user_qual_list(user_qual_list left,
                                    user_qual_list right);
bool empty_user_qual_list(user_qual_list);
user_qual_list type_user_quals(type t);
extern type float_type, double_type, long_double_type,
  int_type, unsigned_int_type, long_type, unsigned_long_type,
  long_long_type, unsigned_long_long_type, short_type, unsigned_short_type,
  char_type, char_array_type, wchar_type, wchar_array_type,
  unsigned_char_type, signed_char_type, void_type, ptr_void_type,
  size_t_type, ptrdiff_t_type, intptr_type;
extern type error_type;
void init_types(void);
type make_complex_type(type t);
type make_base_type(type t);
type make_qualified_type(type t, type_quals qualifiers,
                         user_qual_list user_quals);
type qualify_type1(type t, type t1);
type qualify_type2(type t, type t1, type t2);
type align_type(type t, int new_alignment);
type make_pointer_type(type t);
type make_array_type(type t, expression size);
type make_function_type(type t, typelist argtypes, bool varargs, type_quals varargs_quals, user_qual_list varargs_user_quals, bool oldstyle);
type make_tagged_type(tag_declaration d);
typelist new_typelist(region r);
void typelist_append(typelist l, type t);
bool empty_typelist(typelist l);
typedef struct typelist_element *typelist_scanner;
void typelist_scan(typelist tl, typelist_scanner *scanner);
type typelist_next(typelist_scanner *scanner);
size_t type_size(type t);
size_t type_alignment(type t);
bool type_has_size(type t);
bool type_size_cc(type t);
type common_type(type t1, type t2);
bool type_equal(type t1, type t2);
bool type_equal_unqualified(type t1, type t2);
bool type_compatible(type t1, type t2);
bool type_compatible_unqualified(type t1, type t2);
bool type_self_promoting(type t);
bool type_incomplete(type t);
char *qualifier_name(type_quals q);
type_quals type_qualifiers(type t);
bool qual_const(type_quals q);
bool qual_volatile(type_quals q);
bool qual_restrict(type_quals q);
bool force_qual_const(type_quals q);
bool force_qual_volatile(type_quals q);
bool force_qual_restrict(type_quals q);
bool type_const(type t);
bool type_volatile(type t);
bool type_restrict(type t);
bool type_transparent(type t);
bool type_readonly(type t);
bool type_atomic(type t);
bool type_plain_char(type t);
bool type_signed_char(type t);
bool type_unsigned_char(type t);
bool type_short(type t);
bool type_unsigned_short(type t);
bool type_int(type t);
bool type_unsigned_int(type t);
bool type_long(type t);
bool type_unsigned_long(type t);
bool type_long_long(type t);
bool type_unsigned_long_long(type t);
bool type_long_double(type t);
bool type_tagged(type t);
bool type_integral(type t);
bool type_floating(type t);
bool type_complex(type t);
bool type_float(type t);
bool type_double(type t);
bool type_void(type t);
bool type_char(type t);
bool type_function(type t);
bool type_array(type t);
bool type_pointer(type t);
bool type_enum(type t);
bool type_struct(type t);
bool type_union(type t);
bool type_integer(type t);
bool type_unsigned(type t);
bool type_smallerthanint(type t);
bool type_real(type t);
bool type_arithmetic(type t);
bool type_scalar(type t);
bool type_aggregate(type t);
type make_unsigned_type(type t);
type type_function_return_type(type t);
typelist type_function_arguments(type t);
bool type_function_varargs(type t);
type_quals type_function_varargs_quals(type t);
user_qual_list type_function_varargs_user_quals(type t);
bool type_function_oldstyle(type t);
bool self_promoting_args(type fntype);
type type_points_to(type t);
type type_array_of(type t);
type type_array_of_base(type t);
expression type_array_size(type t);
tag_declaration type_tag(type t);
type type_base(type t);
qtype tag_decl_qtype(tag_declaration td);
tag_ref tag_decl_to_tag_ref(tag_declaration td);
void tag_decl_set_qtype(tag_declaration td, qtype qt);
bool tag_decl_is_defined(tag_declaration td);
const char * tag_decl_name(tag_declaration td);
const char * field_decl_name(field_declaration fd);
typedef field_declaration tag_decl_scanner;
void tag_decl_scan(tag_declaration, tag_decl_scanner *);
field_declaration tag_decl_next(tag_decl_scanner *);
void type2ast(region r, location loc, type t, declarator inside,
              declarator *d, type_element *modifiers);
bool type_contains_pointers(type t);
bool type_contains_union_with_pointers(type t);
bool type_contains_quals(type t);
bool type_contains_user_quals(type t);
type type_default_conversion(type from);
type function_call_type(function_call fcall);
void name_tag(tag_declaration tag);
type type_for_size(int size, bool isunsigned);
type type_for_cval(cval c, bool isunsigned);
type make_type_var(cstring cs);
bool type_var(type t);
const char *type_name(type t);
         enum { struct_type, union_type, enum_type };
node new_node(region r, location loc);
declaration new_declaration(region r, location loc);
statement new_statement(region r, location loc);
expression new_expression(region r, location loc);
type_element new_type_element(region r, location loc);
declarator new_declarator(region r, location loc);
label new_label(region r, location loc);
asm_decl new_asm_decl(region r, location loc, asm_stmt asm_stmt);
data_decl new_data_decl(region r, location loc, type_element modifiers, attribute attributes, declaration decls);
extension_decl new_extension_decl(region r, location loc, declaration decl);
ellipsis_decl new_ellipsis_decl(region r, location loc, type_element qualifiers);
enumerator new_enumerator(region r, location loc, cstring cstring, expression arg1, data_declaration ddecl);
oldidentifier_decl new_oldidentifier_decl(region r, location loc, cstring cstring, data_declaration ddecl);
function_decl new_function_decl(region r, location loc, declarator declarator, type_element qualifiers, attribute attributes, declaration old_parms, statement stmt, function_decl parent_function, data_declaration ddecl);
implicit_decl new_implicit_decl(region r, location loc, identifier ident);
variable_decl new_variable_decl(region r, location loc, declarator declarator, attribute attributes, expression arg1, asm_stmt asm_stmt, data_declaration ddecl);
field_decl new_field_decl(region r, location loc, declarator declarator, attribute attributes, expression arg1);
asttype new_asttype(region r, location loc, declarator declarator, type_element qualifiers);
typename new_typename(region r, location loc, data_declaration ddecl);
type_variable new_type_variable(region r, location loc, cstring cstring);
typeof_expr new_typeof_expr(region r, location loc, expression arg1);
typeof_type new_typeof_type(region r, location loc, asttype asttype);
attribute new_attribute(region r, location loc, word word1, word word2, expression args);
rid new_rid(region r, location loc, enum rid id);
user_qual new_user_qual(region r, location loc, cstring cstring);
qualifier new_qualifier(region r, location loc, enum rid id);
tag_ref new_tag_ref(region r, location loc, word word1, attribute attributes, declaration fields, bool defined);
function_declarator new_function_declarator(region r, location loc, declarator declarator, declaration parms, type_element qualifiers, environment env);
pointer_declarator new_pointer_declarator(region r, location loc, declarator declarator, type_element qualifiers);
array_declarator new_array_declarator(region r, location loc, declarator declarator, expression arg1);
identifier_declarator new_identifier_declarator(region r, location loc, cstring cstring);
asm_stmt new_asm_stmt(region r, location loc, expression arg1, asm_operand asm_operands1, asm_operand asm_operands2, string asm_clobbers, type_element qualifiers);
compound_stmt new_compound_stmt(region r, location loc, id_label id_labels, declaration decls, statement stmts, environment env);
if_stmt new_if_stmt(region r, location loc, expression condition, statement stmt1, statement stmt2);
labeled_stmt new_labeled_stmt(region r, location loc, label label, statement stmt);
expression_stmt new_expression_stmt(region r, location loc, expression arg1);
breakable_stmt new_breakable_stmt(region r, location loc);
conditional_stmt new_conditional_stmt(region r, location loc, expression condition, statement stmt);
switch_stmt new_switch_stmt(region r, location loc, expression condition, statement stmt);
for_stmt new_for_stmt(region r, location loc, expression arg1, expression arg2, expression arg3, statement stmt);
break_stmt new_break_stmt(region r, location loc);
continue_stmt new_continue_stmt(region r, location loc);
return_stmt new_return_stmt(region r, location loc, expression arg1);
goto_stmt new_goto_stmt(region r, location loc, id_label id_label);
computed_goto_stmt new_computed_goto_stmt(region r, location loc, expression arg1);
empty_stmt new_empty_stmt(region r, location loc);
assert_type_stmt new_assert_type_stmt(region r, location loc, expression arg1, asttype asttype);
change_type_stmt new_change_type_stmt(region r, location loc, expression arg1, asttype asttype);
deep_restrict_stmt new_deep_restrict_stmt(region r, location loc, expression arg1, statement stmt);
unary new_unary(region r, location loc, expression arg1);
binary new_binary(region r, location loc, expression arg1, expression arg2);
comma new_comma(region r, location loc, expression arg1);
sizeof_type new_sizeof_type(region r, location loc, asttype asttype);
alignof_type new_alignof_type(region r, location loc, asttype asttype);
label_address new_label_address(region r, location loc, id_label id_label);
cast new_cast(region r, location loc, expression arg1, asttype asttype);
cast_list new_cast_list(region r, location loc, asttype asttype, expression init_expr);
conditional new_conditional(region r, location loc, expression condition, expression arg1, expression arg2);
identifier new_identifier(region r, location loc, cstring cstring, data_declaration ddecl);
compound_expr new_compound_expr(region r, location loc, statement stmt);
function_call new_function_call(region r, location loc, expression arg1, expression args, asttype va_arg_call);
array_ref new_array_ref(region r, location loc, expression arg1, expression arg2);
field_ref new_field_ref(region r, location loc, expression arg1, cstring cstring, location cstring_loc);
init_list new_init_list(region r, location loc, expression args);
init_index new_init_index(region r, location loc, expression arg1, expression arg2, expression init_expr);
init_field new_init_field(region r, location loc, word word1, expression init_expr);
lexical_cst new_lexical_cst(region r, location loc, cstring cstring);
string_cst new_string_cst(region r, location loc, cstring cstring, wchar_t * chars, size_t length);
string new_string(region r, location loc, expression strings, data_declaration ddecl);
id_label new_id_label(region r, location loc, cstring cstring);
case_label new_case_label(region r, location loc, expression arg1, expression arg2);
default_label new_default_label(region r, location loc);
word new_word(region r, location loc, cstring cstring);
asm_operand new_asm_operand(region r, location loc, string string, expression arg1);
error_decl new_error_decl(region r, location loc);
struct_ref new_struct_ref(region r, location loc, word word1, attribute attributes, declaration fields, bool defined);
union_ref new_union_ref(region r, location loc, word word1, attribute attributes, declaration fields, bool defined);
enum_ref new_enum_ref(region r, location loc, word word1, attribute attributes, declaration fields, bool defined);
error_stmt new_error_stmt(region r, location loc);
while_stmt new_while_stmt(region r, location loc, expression condition, statement stmt);
dowhile_stmt new_dowhile_stmt(region r, location loc, expression condition, statement stmt);
error_expr new_error_expr(region r, location loc);
dereference new_dereference(region r, location loc, expression arg1);
extension_expr new_extension_expr(region r, location loc, expression arg1);
sizeof_expr new_sizeof_expr(region r, location loc, expression arg1);
alignof_expr new_alignof_expr(region r, location loc, expression arg1);
realpart new_realpart(region r, location loc, expression arg1);
imagpart new_imagpart(region r, location loc, expression arg1);
address_of new_address_of(region r, location loc, expression arg1);
unary_minus new_unary_minus(region r, location loc, expression arg1);
unary_plus new_unary_plus(region r, location loc, expression arg1);
conjugate new_conjugate(region r, location loc, expression arg1);
preincrement new_preincrement(region r, location loc, expression arg1);
predecrement new_predecrement(region r, location loc, expression arg1);
postincrement new_postincrement(region r, location loc, expression arg1);
postdecrement new_postdecrement(region r, location loc, expression arg1);
bitnot new_bitnot(region r, location loc, expression arg1);
not new_not(region r, location loc, expression arg1);
plus new_plus(region r, location loc, expression arg1, expression arg2);
minus new_minus(region r, location loc, expression arg1, expression arg2);
times new_times(region r, location loc, expression arg1, expression arg2);
divide new_divide(region r, location loc, expression arg1, expression arg2);
modulo new_modulo(region r, location loc, expression arg1, expression arg2);
lshift new_lshift(region r, location loc, expression arg1, expression arg2);
rshift new_rshift(region r, location loc, expression arg1, expression arg2);
leq new_leq(region r, location loc, expression arg1, expression arg2);
geq new_geq(region r, location loc, expression arg1, expression arg2);
lt new_lt(region r, location loc, expression arg1, expression arg2);
gt new_gt(region r, location loc, expression arg1, expression arg2);
eq new_eq(region r, location loc, expression arg1, expression arg2);
ne new_ne(region r, location loc, expression arg1, expression arg2);
bitand new_bitand(region r, location loc, expression arg1, expression arg2);
bitor new_bitor(region r, location loc, expression arg1, expression arg2);
bitxor new_bitxor(region r, location loc, expression arg1, expression arg2);
andand new_andand(region r, location loc, expression arg1, expression arg2);
oror new_oror(region r, location loc, expression arg1, expression arg2);
assign new_assign(region r, location loc, expression arg1, expression arg2);
plus_assign new_plus_assign(region r, location loc, expression arg1, expression arg2);
minus_assign new_minus_assign(region r, location loc, expression arg1, expression arg2);
times_assign new_times_assign(region r, location loc, expression arg1, expression arg2);
divide_assign new_divide_assign(region r, location loc, expression arg1, expression arg2);
modulo_assign new_modulo_assign(region r, location loc, expression arg1, expression arg2);
lshift_assign new_lshift_assign(region r, location loc, expression arg1, expression arg2);
rshift_assign new_rshift_assign(region r, location loc, expression arg1, expression arg2);
bitand_assign new_bitand_assign(region r, location loc, expression arg1, expression arg2);
bitor_assign new_bitor_assign(region r, location loc, expression arg1, expression arg2);
bitxor_assign new_bitxor_assign(region r, location loc, expression arg1, expression arg2);
struct AST_node {
  ast_kind kind;
  location loc;
  node next;
  node parent;
};
struct AST_declaration {
  ast_kind kind;
  location loc;
  node next;
  node parent;
};
struct AST_statement {
  ast_kind kind;
  location loc;
  node next;
  node parent;
};
struct AST_expression {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
};
struct AST_type_element {
  ast_kind kind;
  location loc;
  node next;
  node parent;
};
struct AST_declarator {
  ast_kind kind;
  location loc;
  node next;
  node parent;
};
struct AST_label {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  label next_label;
  compound_stmt enclosing_cs;
  store store_in;
};
struct AST_asm_decl {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  asm_stmt asm_stmt;
};
struct AST_data_decl {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type_element modifiers;
  attribute attributes;
  declaration decls;
};
struct AST_extension_decl {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  declaration decl;
};
struct AST_ellipsis_decl {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type_element qualifiers;
};
struct AST_enumerator {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  cstring cstring;
  expression arg1;
  data_declaration ddecl;
};
struct AST_oldidentifier_decl {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  cstring cstring;
  data_declaration ddecl;
};
struct AST_function_decl {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  declarator declarator;
  type_element qualifiers;
  attribute attributes;
  declaration old_parms;
  statement stmt;
  function_decl parent_function;
  data_declaration ddecl;
  function_declarator fdeclarator;
  type declared_type;
  env undeclared_variables;
  env base_labels;
  env scoped_labels;
  breakable_stmt current_loop;
  int nlocals;
  effect scope_env;
};
struct AST_implicit_decl {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  identifier ident;
};
struct AST_variable_decl {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  declarator declarator;
  attribute attributes;
  expression arg1;
  asm_stmt asm_stmt;
  data_declaration ddecl;
  type declared_type;
  bool forward;
  effect arg1_eff;
  rinfo rinfo;
};
struct AST_field_decl {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  declarator declarator;
  attribute attributes;
  expression arg1;
};
struct AST_asttype {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  declarator declarator;
  type_element qualifiers;
  type type;
};
struct AST_typename {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  data_declaration ddecl;
};
struct AST_type_variable {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  cstring cstring;
};
struct AST_typeof_expr {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  expression arg1;
};
struct AST_typeof_type {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  asttype asttype;
};
struct AST_attribute {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  word word1;
  word word2;
  expression args;
};
struct AST_rid {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  enum rid id;
};
struct AST_user_qual {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  cstring cstring;
};
struct AST_qualifier {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  enum rid id;
};
struct AST_tag_ref {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  word word1;
  attribute attributes;
  declaration fields;
  bool defined;
  tag_declaration tdecl;
};
struct AST_function_declarator {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  declarator declarator;
  declaration parms;
  type_element qualifiers;
  environment env;
};
struct AST_pointer_declarator {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  declarator declarator;
  type_element qualifiers;
};
struct AST_array_declarator {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  declarator declarator;
  expression arg1;
};
struct AST_identifier_declarator {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  cstring cstring;
};
struct AST_asm_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  expression arg1;
  asm_operand asm_operands1;
  asm_operand asm_operands2;
  string asm_clobbers;
  type_element qualifiers;
};
struct AST_compound_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  id_label id_labels;
  declaration decls;
  statement stmts;
  compound_stmt enclosing_cs;
  int visited;
  environment env;
  effect scope_env;
  effect filter_env;
  dd_list confine_expressions;
  dd_list drinfolist;
};
struct AST_if_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  expression condition;
  statement stmt1;
  statement stmt2;
};
struct AST_labeled_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  label label;
  statement stmt;
};
struct AST_expression_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  expression arg1;
};
struct AST_breakable_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  compound_stmt enclosing_cs;
  breakable_stmt parent_loop;
  store break_dest;
  store continue_dest;
};
struct AST_conditional_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  compound_stmt enclosing_cs;
  breakable_stmt parent_loop;
  store break_dest;
  store continue_dest;
  expression condition;
  statement stmt;
};
struct AST_switch_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  compound_stmt enclosing_cs;
  breakable_stmt parent_loop;
  store break_dest;
  store continue_dest;
  expression condition;
  statement stmt;
  label next_label;
};
struct AST_for_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  compound_stmt enclosing_cs;
  breakable_stmt parent_loop;
  store break_dest;
  store continue_dest;
  expression arg1;
  expression arg2;
  expression arg3;
  statement stmt;
};
struct AST_break_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  breakable_stmt parent_loop;
  compound_stmt enclosing_cs;
};
struct AST_continue_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  breakable_stmt parent_loop;
  compound_stmt enclosing_cs;
};
struct AST_return_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  expression arg1;
  compound_stmt enclosing_cs;
};
struct AST_goto_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  id_label id_label;
  compound_stmt enclosing_cs;
};
struct AST_computed_goto_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  expression arg1;
};
struct AST_empty_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
};
struct AST_assert_type_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  expression arg1;
  asttype asttype;
  qtype qtype;
};
struct AST_change_type_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  expression arg1;
  asttype asttype;
  qtype qtype;
};
struct AST_deep_restrict_stmt {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  expression arg1;
  statement stmt;
  drinfo drinfo;
};
struct AST_unary {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  expression arg1;
};
struct AST_binary {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  expression arg1;
  expression arg2;
};
struct AST_comma {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  expression arg1;
};
struct AST_sizeof_type {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  asttype asttype;
};
struct AST_alignof_type {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  asttype asttype;
};
struct AST_label_address {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  id_label id_label;
};
struct AST_cast {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  expression arg1;
  asttype asttype;
};
struct AST_cast_list {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  asttype asttype;
  qtype astqtype;
  expression init_expr;
};
struct AST_conditional {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  expression condition;
  expression arg1;
  expression arg2;
};
struct AST_identifier {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  cstring cstring;
  data_declaration ddecl;
  aloc aloc;
};
struct AST_compound_expr {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  statement stmt;
  effect filter_env;
};
struct AST_function_call {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  expression arg1;
  expression args;
  asttype va_arg_call;
};
struct AST_array_ref {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  expression arg1;
  expression arg2;
  expression alt;
};
struct AST_field_ref {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  expression arg1;
  cstring cstring;
  location cstring_loc;
};
struct AST_init_list {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  expression args;
};
struct AST_init_index {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  expression arg1;
  expression arg2;
  expression init_expr;
};
struct AST_init_field {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  word word1;
  expression init_expr;
};
struct AST_lexical_cst {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  cstring cstring;
};
struct AST_string_cst {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  cstring cstring;
  wchar_t * chars;
  size_t length;
};
struct AST_string {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  type type;
  bool lvalue;
  bool side_effects;
  known_cst cst;
  bool bitfield;
  bool isregister;
  known_cst static_address;
  qtype qtype;
  expression strings;
  data_declaration ddecl;
};
struct AST_id_label {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  label next_label;
  compound_stmt enclosing_cs;
  store store_in;
  cstring cstring;
  label_declaration ldecl;
};
struct AST_case_label {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  label next_label;
  compound_stmt enclosing_cs;
  store store_in;
  expression arg1;
  expression arg2;
};
struct AST_default_label {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  label next_label;
  compound_stmt enclosing_cs;
  store store_in;
};
struct AST_word {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  cstring cstring;
};
struct AST_asm_operand {
  ast_kind kind;
  location loc;
  node next;
  node parent;
  string string;
  expression arg1;
};
node node_chain(node l1, node l2);
declaration declaration_chain(declaration l1, declaration l2);
statement statement_chain(statement l1, statement l2);
expression expression_chain(expression l1, expression l2);
type_element type_element_chain(type_element l1, type_element l2);
declarator declarator_chain(declarator l1, declarator l2);
label label_chain(label l1, label l2);
asm_decl asm_decl_chain(asm_decl l1, asm_decl l2);
data_decl data_decl_chain(data_decl l1, data_decl l2);
extension_decl extension_decl_chain(extension_decl l1, extension_decl l2);
ellipsis_decl ellipsis_decl_chain(ellipsis_decl l1, ellipsis_decl l2);
enumerator enumerator_chain(enumerator l1, enumerator l2);
oldidentifier_decl oldidentifier_decl_chain(oldidentifier_decl l1, oldidentifier_decl l2);
function_decl function_decl_chain(function_decl l1, function_decl l2);
implicit_decl implicit_decl_chain(implicit_decl l1, implicit_decl l2);
variable_decl variable_decl_chain(variable_decl l1, variable_decl l2);
field_decl field_decl_chain(field_decl l1, field_decl l2);
asttype asttype_chain(asttype l1, asttype l2);
typename typename_chain(typename l1, typename l2);
type_variable type_variable_chain(type_variable l1, type_variable l2);
typeof_expr typeof_expr_chain(typeof_expr l1, typeof_expr l2);
typeof_type typeof_type_chain(typeof_type l1, typeof_type l2);
attribute attribute_chain(attribute l1, attribute l2);
rid rid_chain(rid l1, rid l2);
user_qual user_qual_chain(user_qual l1, user_qual l2);
qualifier qualifier_chain(qualifier l1, qualifier l2);
tag_ref tag_ref_chain(tag_ref l1, tag_ref l2);
function_declarator function_declarator_chain(function_declarator l1, function_declarator l2);
pointer_declarator pointer_declarator_chain(pointer_declarator l1, pointer_declarator l2);
array_declarator array_declarator_chain(array_declarator l1, array_declarator l2);
identifier_declarator identifier_declarator_chain(identifier_declarator l1, identifier_declarator l2);
asm_stmt asm_stmt_chain(asm_stmt l1, asm_stmt l2);
compound_stmt compound_stmt_chain(compound_stmt l1, compound_stmt l2);
if_stmt if_stmt_chain(if_stmt l1, if_stmt l2);
labeled_stmt labeled_stmt_chain(labeled_stmt l1, labeled_stmt l2);
expression_stmt expression_stmt_chain(expression_stmt l1, expression_stmt l2);
breakable_stmt breakable_stmt_chain(breakable_stmt l1, breakable_stmt l2);
conditional_stmt conditional_stmt_chain(conditional_stmt l1, conditional_stmt l2);
switch_stmt switch_stmt_chain(switch_stmt l1, switch_stmt l2);
for_stmt for_stmt_chain(for_stmt l1, for_stmt l2);
break_stmt break_stmt_chain(break_stmt l1, break_stmt l2);
continue_stmt continue_stmt_chain(continue_stmt l1, continue_stmt l2);
return_stmt return_stmt_chain(return_stmt l1, return_stmt l2);
goto_stmt goto_stmt_chain(goto_stmt l1, goto_stmt l2);
computed_goto_stmt computed_goto_stmt_chain(computed_goto_stmt l1, computed_goto_stmt l2);
empty_stmt empty_stmt_chain(empty_stmt l1, empty_stmt l2);
assert_type_stmt assert_type_stmt_chain(assert_type_stmt l1, assert_type_stmt l2);
change_type_stmt change_type_stmt_chain(change_type_stmt l1, change_type_stmt l2);
deep_restrict_stmt deep_restrict_stmt_chain(deep_restrict_stmt l1, deep_restrict_stmt l2);
unary unary_chain(unary l1, unary l2);
binary binary_chain(binary l1, binary l2);
comma comma_chain(comma l1, comma l2);
sizeof_type sizeof_type_chain(sizeof_type l1, sizeof_type l2);
alignof_type alignof_type_chain(alignof_type l1, alignof_type l2);
label_address label_address_chain(label_address l1, label_address l2);
cast cast_chain(cast l1, cast l2);
cast_list cast_list_chain(cast_list l1, cast_list l2);
conditional conditional_chain(conditional l1, conditional l2);
identifier identifier_chain(identifier l1, identifier l2);
compound_expr compound_expr_chain(compound_expr l1, compound_expr l2);
function_call function_call_chain(function_call l1, function_call l2);
array_ref array_ref_chain(array_ref l1, array_ref l2);
field_ref field_ref_chain(field_ref l1, field_ref l2);
init_list init_list_chain(init_list l1, init_list l2);
init_index init_index_chain(init_index l1, init_index l2);
init_field init_field_chain(init_field l1, init_field l2);
lexical_cst lexical_cst_chain(lexical_cst l1, lexical_cst l2);
string_cst string_cst_chain(string_cst l1, string_cst l2);
string string_chain(string l1, string l2);
id_label id_label_chain(id_label l1, id_label l2);
case_label case_label_chain(case_label l1, case_label l2);
default_label default_label_chain(default_label l1, default_label l2);
word word_chain(word l1, word l2);
asm_operand asm_operand_chain(asm_operand l1, asm_operand l2);
error_decl error_decl_chain(error_decl l1, error_decl l2);
struct_ref struct_ref_chain(struct_ref l1, struct_ref l2);
union_ref union_ref_chain(union_ref l1, union_ref l2);
enum_ref enum_ref_chain(enum_ref l1, enum_ref l2);
error_stmt error_stmt_chain(error_stmt l1, error_stmt l2);
while_stmt while_stmt_chain(while_stmt l1, while_stmt l2);
dowhile_stmt dowhile_stmt_chain(dowhile_stmt l1, dowhile_stmt l2);
error_expr error_expr_chain(error_expr l1, error_expr l2);
dereference dereference_chain(dereference l1, dereference l2);
extension_expr extension_expr_chain(extension_expr l1, extension_expr l2);
sizeof_expr sizeof_expr_chain(sizeof_expr l1, sizeof_expr l2);
alignof_expr alignof_expr_chain(alignof_expr l1, alignof_expr l2);
realpart realpart_chain(realpart l1, realpart l2);
imagpart imagpart_chain(imagpart l1, imagpart l2);
address_of address_of_chain(address_of l1, address_of l2);
unary_minus unary_minus_chain(unary_minus l1, unary_minus l2);
unary_plus unary_plus_chain(unary_plus l1, unary_plus l2);
conjugate conjugate_chain(conjugate l1, conjugate l2);
preincrement preincrement_chain(preincrement l1, preincrement l2);
predecrement predecrement_chain(predecrement l1, predecrement l2);
postincrement postincrement_chain(postincrement l1, postincrement l2);
postdecrement postdecrement_chain(postdecrement l1, postdecrement l2);
bitnot bitnot_chain(bitnot l1, bitnot l2);
not not_chain(not l1, not l2);
plus plus_chain(plus l1, plus l2);
minus minus_chain(minus l1, minus l2);
times times_chain(times l1, times l2);
divide divide_chain(divide l1, divide l2);
modulo modulo_chain(modulo l1, modulo l2);
lshift lshift_chain(lshift l1, lshift l2);
rshift rshift_chain(rshift l1, rshift l2);
leq leq_chain(leq l1, leq l2);
geq geq_chain(geq l1, geq l2);
lt lt_chain(lt l1, lt l2);
gt gt_chain(gt l1, gt l2);
eq eq_chain(eq l1, eq l2);
ne ne_chain(ne l1, ne l2);
bitand bitand_chain(bitand l1, bitand l2);
bitor bitor_chain(bitor l1, bitor l2);
bitxor bitxor_chain(bitxor l1, bitxor l2);
andand andand_chain(andand l1, andand l2);
oror oror_chain(oror l1, oror l2);
assign assign_chain(assign l1, assign l2);
plus_assign plus_assign_chain(plus_assign l1, plus_assign l2);
minus_assign minus_assign_chain(minus_assign l1, minus_assign l2);
times_assign times_assign_chain(times_assign l1, times_assign l2);
divide_assign divide_assign_chain(divide_assign l1, divide_assign l2);
modulo_assign modulo_assign_chain(modulo_assign l1, modulo_assign l2);
lshift_assign lshift_assign_chain(lshift_assign l1, lshift_assign l2);
rshift_assign rshift_assign_chain(rshift_assign l1, rshift_assign l2);
bitand_assign bitand_assign_chain(bitand_assign l1, bitand_assign l2);
bitor_assign bitor_assign_chain(bitor_assign l1, bitor_assign l2);
bitxor_assign bitxor_assign_chain(bitxor_assign l1, bitxor_assign l2);
typedef struct AST_ast_generic
{
  ast_kind kind;
} *ast_generic;
extern declaration the_program;
unary newkind_unary(region r, ast_kind kind, location location, expression arg1);
binary newkind_binary(region r, ast_kind kind, location location,
                      expression arg1, expression arg2);
tag_ref newkind_tag_ref(region r, ast_kind kind, location location, word word1, attribute attributes, declaration fields, bool defined);
node last_node(node n);
int chain_length(node n);
node ast_chain(node l1, node l2);
void insert_before(node *list, node before, node n);
node ast_reverse(node l);
void AST_set_parents(node n);
void AST_print(node n);
typedef dd_list identifier_set; typedef dd_list_pos identifier_set_scanner; static inline identifier_set empty_identifier_set(region r) { return dd_new_list(r); } static inline identifier_set identifier_set_copy(region r, identifier_set s) { if (s == ((void *)0)) return ((void *)0); return dd_copy(r, s); } static inline bool identifier_set_empty(identifier_set s) { return s == ((void *)0) || ((!(dd_first((s)))->next)); } static inline bool identifier_set_member(int (*cmp)(identifier, identifier), identifier_set s, identifier elt) { return s != ((void *)0) && dd_search(s, (dd_cmp_fn) cmp, (void *) elt) != ((void *)0); } static inline int identifier_set_size(identifier_set s) { if (s == ((void *)0)) return 0; return dd_length(s); } static inline bool identifier_set_insert(region r, identifier_set *s, identifier elt) { *s = dd_fix_null(r, *s); dd_add_first(r, *s, (void *) elt); return 1; } static inline bool identifier_set_insert_last(region r, identifier_set *s, identifier elt) { *s = dd_fix_null(r, *s); dd_add_last(r, *s, (void *) elt); return 1; } static inline identifier_set identifier_set_union(identifier_set s1, identifier_set s2) { if (s1 == ((void *)0)) return s2; else if (s2 == ((void *)0)) return s1; dd_append(s1, s2); return s1; } static inline bool identifier_set_single(identifier_set s) { return identifier_set_size(s) == 1; } static inline void identifier_set_sort(int (*cmp)(identifier, identifier), identifier_set s) { if (s == ((void *)0)) return; dd_sort(s, (set_cmp_fn) cmp); } static inline void identifier_set_remove_dups(int (*cmp)(identifier, identifier), identifier_set s) { if (s == ((void *)0)) return; dd_remove_dups(s, (dd_cmp_fn)cmp); } static inline void identifier_set_scan(identifier_set s, identifier_set_scanner *ss) { if (s == ((void *)0)) *ss = ((void *)0); else *ss = dd_first(s); } static inline identifier identifier_set_next(identifier_set_scanner *ss) { identifier result; if (*ss == ((void *)0) || (!(*ss)->next)) return ((void *)0); result = ((identifier)((*ss)->data)); *ss = ((*ss)->next); return result; };
extern int flag_volatile;
extern int flag_volatile_global;
extern int flag_syntax_only;
extern int flag_pedantic_errors;
extern int flag_pack_struct;
extern int inhibit_warnings;
extern int extra_warnings;
extern int warnings_are_errors;
extern int warn_unused;
extern int warn_uninitialized;
extern int warn_shadow;
extern int error_shadow;
extern int warn_switch;
extern int warn_return_type;
extern int warn_cast_align;
extern int warn_id_clash;
extern unsigned id_clash_len;
extern int warn_larger_than;
extern unsigned larger_than_size;
extern int warn_inline;
extern int warn_aggregate_return;
extern int dollars_in_ident;
extern int flag_cond_mismatch;
extern int flag_no_asm;
extern int flag_hosted;
extern int warn_implicit;
extern int warn_write_strings;
extern int warn_pointer_arith;
extern int warn_strict_prototypes;
extern int warn_redundant_decls;
extern int warn_nested_externs;
extern int warn_cast_qual;
extern int warn_bad_function_cast;
extern int warn_traditional;
extern int warn_format;
extern int warn_char_subscripts;
extern int warn_conversion;
extern int warn_main;
extern int warn_multichar;
extern int flag_traditional;
extern int flag_allow_single_precision;
extern int warn_parentheses;
extern int warn_missing_braces;
extern int warn_sign_compare;
extern int mesg_implicit_function_declaration;
extern bool pedantic;
extern int warn_implicit_int;
extern int warn_missing_prototypes;
extern int warn_missing_declarations;
extern int quiet_flag;
extern int flag_signed_char;
extern int flag_short_enums;
extern int flag_signed_bitfields;
extern int explicit_flag_signed_bitfields;
extern int flag_parse_only;
extern int flag_pam_mode;
extern int flag_pam_html;
extern int flag_print_quals_graph;
extern int flag_strict_const;
extern int flag_print_results;
extern int flag_casts_preserve;
extern int flag_const_subtyping;
extern int flag_flow_sensitive;
extern int flag_poly;
extern int flag_aloc_subtyping;
extern int flag_force_flow_sensitive;
extern int flag_print_lin;
extern int flag_driver;
extern int flag_casts_warn;
extern int flag_ugly;
extern int flag_statistics;
extern int flag_print_stores;
extern int flag_confine_inf;
extern int flag_discover_scopes;
extern int flag_confine_inf_aggressive;
extern int flag_restrict_inf;
extern int flag_print_assert_type_failures;
int flag_strong_updates;
extern int flag_errors_only;
extern int flag_context_summary;
extern int flag_warn_dangerous_globals;
extern int flag_measure_consts;
extern int errorcount;
extern int warningcount;
void verror_with_file_and_line(const char *filename, int lineno,
                               const char *format, va_list args);
void verror_with_location(location l, const char *format, va_list args);
void verror_with_decl(declaration d, const char *format, va_list args);
void verror(const char *format, va_list args);
void error(const char *format, ...);
void error_with_decl(declaration d, const char *format, ...);
void error_with_location(location l, const char *format, ...);
void vfatal(const char *format, va_list args);
void fatal(const char *format, ...);
void vwarning_with_file_and_line(const char *filename, int lineno,
                                 const char *format, va_list args);
void vwarning_with_location(location l, const char *format, va_list args);
void vwarning_with_decl(declaration d, const char *format, va_list args);
void vwarning(const char *format, va_list args);
void warning(const char *format, ...);
void warning_with_file_and_line(const char *filename, int lineno,
                                const char *format, ...);
void warning_with_decl(declaration d, const char *format, ...);
void warning_with_location(location l, const char *format, ...);
void warning_or_error(bool iswarning, const char *format, ...);
void warning_or_error_with_file_and_line(bool iswarning,
                                         const char *filename, int lineno,
                                         const char *format, ...);
void warning_or_error_with_decl(bool iswarning, declaration d,
                                const char *format, ...);
void warning_or_error_with_location(bool iswarning, location l,
                                    const char *format, ...);
void pedwarn(const char *format, ...);
void pedwarn_with_decl(declaration d, const char *format, ...);
void pedwarn_with_location(location l, const char *format, ...);
extern char *progname;
extern int copy_argc;
extern char **copy_argv;
extern type builtin_va_list_type;
extern data_declaration builtin_va_arg_decl;
void pending_xref_error(void);
void init_semantics(void);
extern environment current_env;
data_declaration lookup_id(const char *s, bool this_level_only);
data_declaration lookup_global_id(const char *s);
void shadow_tag(type_element elements);
void shadow_tag_warned(type_element elements, int warned);
declarator make_function_declarator(location l, declarator d, declaration parms, type_element quals);
bool start_function(type_element elements, declarator d, attribute attribs,
                    bool nested);
void store_parm_decls(declaration old_parms);
declaration finish_function(statement body);
extern function_decl current_function_decl;
void pushlevel(bool parm_level);
environment poplevel(void);
enum { var_typedef, var_register, var_normal, var_static, var_extern };
void split_type_elements(type_element tlist, type_element *declspecs,
                         attribute *attributes);
declaration start_decl(declarator d, asm_stmt astmt, type_element elements,
                       bool initialised, attribute extra_attributes,
                       attribute attributes);
declaration finish_decl(declaration decl, expression init);
declaration declare_parameter(declarator d, type_element elements,
                              attribute extra_attributes,
                              attribute attributes,
                              bool abstract);
void mark_forward_parameters(declaration parms);
declaration declare_old_parameter(location l, cstring id);
type_element start_struct(location l, ast_kind skind, word tag);
type_element finish_struct(type_element t, declaration fields,
                           attribute attribs);
type_element xref_tag(location l, ast_kind skind, word tag);
type_element start_enum(location l, word tag);
type_element finish_enum(type_element t, declaration names,
                         attribute attribs);
declaration make_field(declarator d, expression bitfield,
                       type_element elements, attribute extra_attributes,
                       attribute attributes);
declaration make_enumerator(location loc, cstring id, expression value);
asttype make_type(type_element elements, declarator d);
int save_directive(char *directive);
char *rid_name(rid r);
statement chain_with_labels(statement l1, statement l2);
const char *declarator_name(declarator d);
data_declaration lookup_id(const char *s, bool this_level_only);
extern function_decl current_function_decl;
data_declaration implicitly_declare(identifier fnid);
void push_label_level(void);
void pop_label_level(void);
void init_data_declaration(data_declaration dd, declaration ast,
                           const char *name, type t);
data_declaration declare(environment env, data_declaration from,
                         bool ignore_shadow);
data_declaration declare_string(const char *name, bool wide, size_t length);
environment new_environment(region r, environment parent, bool parm_level);
tag_declaration declare_tag(tag_ref t);
tag_declaration lookup_tag(tag_ref t, bool this_level_only);
tag_declaration declare_global_tag(tag_ref t);
tag_declaration lookup_global_tag(tag_ref t);
declaration the_program;
node ast_chain(node l1, node l2)
{
  if (!l1) return l2;
  last_node(l1)->next = l2;
  return l1;
}
node last_node(node n)
{
  if (!n) return ((void *)0);
  while (n->next) n = n->next;
  return n;
}
int chain_length(node n)
{
  int l = 0;
  while (n)
    {
      n = n->next;
      l++;
    }
  return l;
}
node ast_reverse(node l)
{
  node last = ((void *)0), next;
  for (;;)
    {
      if (!l)
        return last;
      next = l->next;
      l->next = last;
      last = l;
      l = next;
    }
}
void insert_before(node *list, node before, node n)
{
  while (*list != before)
    list = &(*list)->next;
  *list = n;
  n->next = before;
}
unary newkind_unary(region r, ast_kind kind, location location, expression arg1)
{
  unary obj = new_unary(r, location, arg1);
  obj->kind = kind;
  return obj;
}
binary newkind_binary(region r, ast_kind kind, location location,
                      expression arg1, expression arg2)
{
  if (kind == kind_assign)
    return ({ast_generic tEmPcast = (ast_generic)(new_assign(r, location, arg1, arg2)); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_binary && (tEmPcast)->kind <= postkind_binary)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_binary && (tEmPcast)->kind <= postkind_binary)", "AST.c", 87, __PRETTY_FUNCTION__), 0))); (binary)(tEmPcast); });
  else
    {
      binary obj = new_binary(r, location, arg1, arg2);
      obj->kind = kind;
      return obj;
    }
}
tag_ref newkind_tag_ref(region r, ast_kind kind, location location, word word1, attribute attributes, declaration fields, bool defined)
{
  tag_ref obj = new_tag_ref(r, location, word1, attributes, fields, defined);
  obj->kind = kind;
  return obj;
}
node new_node(region r, location loc)
{
  node obj = (sizeof(struct AST_node) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_node)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_node), 0));
  obj->kind = kind_node;
  obj->loc = loc;
  return obj;
}
declaration new_declaration(region r, location loc)
{
  declaration obj = (sizeof(struct AST_declaration) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_declaration)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_declaration), 0));
  obj->kind = kind_declaration;
  obj->loc = loc;
  return obj;
}
statement new_statement(region r, location loc)
{
  statement obj = (sizeof(struct AST_statement) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_statement)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_statement), 0));
  obj->kind = kind_statement;
  obj->loc = loc;
  return obj;
}
expression new_expression(region r, location loc)
{
  expression obj = (sizeof(struct AST_expression) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_expression)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_expression), 0));
  obj->kind = kind_expression;
  obj->loc = loc;
  return obj;
}
type_element new_type_element(region r, location loc)
{
  type_element obj = (sizeof(struct AST_type_element) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_type_element)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_type_element), 0));
  obj->kind = kind_type_element;
  obj->loc = loc;
  return obj;
}
declarator new_declarator(region r, location loc)
{
  declarator obj = (sizeof(struct AST_declarator) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_declarator)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_declarator), 0));
  obj->kind = kind_declarator;
  obj->loc = loc;
  return obj;
}
label new_label(region r, location loc)
{
  label obj = (sizeof(struct AST_label) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_label)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_label), 0));
  obj->kind = kind_label;
  obj->loc = loc;
  return obj;
}
asm_decl new_asm_decl(region r, location loc, asm_stmt asm_stmt)
{
  asm_decl obj = (sizeof(struct AST_asm_decl) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_asm_decl)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_asm_decl), 0));
  obj->kind = kind_asm_decl;
  obj->loc = loc;
  obj->asm_stmt = asm_stmt;
  return obj;
}
data_decl new_data_decl(region r, location loc, type_element modifiers, attribute attributes, declaration decls)
{
  data_decl obj = (sizeof(struct AST_data_decl) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_data_decl)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_data_decl), 0));
  obj->kind = kind_data_decl;
  obj->loc = loc;
  obj->modifiers = modifiers;
  obj->attributes = attributes;
  obj->decls = decls;
  return obj;
}
extension_decl new_extension_decl(region r, location loc, declaration decl)
{
  extension_decl obj = (sizeof(struct AST_extension_decl) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_extension_decl)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_extension_decl), 0));
  obj->kind = kind_extension_decl;
  obj->loc = loc;
  obj->decl = decl;
  return obj;
}
ellipsis_decl new_ellipsis_decl(region r, location loc, type_element qualifiers)
{
  ellipsis_decl obj = (sizeof(struct AST_ellipsis_decl) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_ellipsis_decl)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_ellipsis_decl), 0));
  obj->kind = kind_ellipsis_decl;
  obj->loc = loc;
  obj->qualifiers = qualifiers;
  return obj;
}
enumerator new_enumerator(region r, location loc, cstring cstring, expression arg1, data_declaration ddecl)
{
  enumerator obj = (sizeof(struct AST_enumerator) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_enumerator)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_enumerator), 0));
  obj->kind = kind_enumerator;
  obj->loc = loc;
  obj->cstring = cstring;
  obj->arg1 = arg1;
  obj->ddecl = ddecl;
  return obj;
}
oldidentifier_decl new_oldidentifier_decl(region r, location loc, cstring cstring, data_declaration ddecl)
{
  oldidentifier_decl obj = (sizeof(struct AST_oldidentifier_decl) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_oldidentifier_decl)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_oldidentifier_decl), 0));
  obj->kind = kind_oldidentifier_decl;
  obj->loc = loc;
  obj->cstring = cstring;
  obj->ddecl = ddecl;
  return obj;
}
function_decl new_function_decl(region r, location loc, declarator declarator, type_element qualifiers, attribute attributes, declaration old_parms, statement stmt, function_decl parent_function, data_declaration ddecl)
{
  function_decl obj = (sizeof(struct AST_function_decl) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_function_decl)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_function_decl), 0));
  obj->kind = kind_function_decl;
  obj->loc = loc;
  obj->declarator = declarator;
  obj->qualifiers = qualifiers;
  obj->attributes = attributes;
  obj->old_parms = old_parms;
  obj->stmt = stmt;
  obj->parent_function = parent_function;
  obj->ddecl = ddecl;
  return obj;
}
implicit_decl new_implicit_decl(region r, location loc, identifier ident)
{
  implicit_decl obj = (sizeof(struct AST_implicit_decl) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_implicit_decl)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_implicit_decl), 0));
  obj->kind = kind_implicit_decl;
  obj->loc = loc;
  obj->ident = ident;
  return obj;
}
variable_decl new_variable_decl(region r, location loc, declarator declarator, attribute attributes, expression arg1, asm_stmt asm_stmt, data_declaration ddecl)
{
  variable_decl obj = (sizeof(struct AST_variable_decl) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_variable_decl)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_variable_decl), 0));
  obj->kind = kind_variable_decl;
  obj->loc = loc;
  obj->declarator = declarator;
  obj->attributes = attributes;
  obj->arg1 = arg1;
  obj->asm_stmt = asm_stmt;
  obj->ddecl = ddecl;
  return obj;
}
field_decl new_field_decl(region r, location loc, declarator declarator, attribute attributes, expression arg1)
{
  field_decl obj = (sizeof(struct AST_field_decl) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_field_decl)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_field_decl), 0));
  obj->kind = kind_field_decl;
  obj->loc = loc;
  obj->declarator = declarator;
  obj->attributes = attributes;
  obj->arg1 = arg1;
  return obj;
}
asttype new_asttype(region r, location loc, declarator declarator, type_element qualifiers)
{
  asttype obj = (sizeof(struct AST_asttype) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_asttype)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_asttype), 0));
  obj->kind = kind_asttype;
  obj->loc = loc;
  obj->declarator = declarator;
  obj->qualifiers = qualifiers;
  return obj;
}
typename new_typename(region r, location loc, data_declaration ddecl)
{
  typename obj = (sizeof(struct AST_typename) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_typename)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_typename), 0));
  obj->kind = kind_typename;
  obj->loc = loc;
  obj->ddecl = ddecl;
  return obj;
}
type_variable new_type_variable(region r, location loc, cstring cstring)
{
  type_variable obj = (sizeof(struct AST_type_variable) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_type_variable)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_type_variable), 0));
  obj->kind = kind_type_variable;
  obj->loc = loc;
  obj->cstring = cstring;
  return obj;
}
typeof_expr new_typeof_expr(region r, location loc, expression arg1)
{
  typeof_expr obj = (sizeof(struct AST_typeof_expr) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_typeof_expr)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_typeof_expr), 0));
  obj->kind = kind_typeof_expr;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
typeof_type new_typeof_type(region r, location loc, asttype asttype)
{
  typeof_type obj = (sizeof(struct AST_typeof_type) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_typeof_type)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_typeof_type), 0));
  obj->kind = kind_typeof_type;
  obj->loc = loc;
  obj->asttype = asttype;
  return obj;
}
attribute new_attribute(region r, location loc, word word1, word word2, expression args)
{
  attribute obj = (sizeof(struct AST_attribute) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_attribute)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_attribute), 0));
  obj->kind = kind_attribute;
  obj->loc = loc;
  obj->word1 = word1;
  obj->word2 = word2;
  obj->args = args;
  return obj;
}
rid new_rid(region r, location loc, enum rid id)
{
  rid obj = (sizeof(struct AST_rid) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_rid)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_rid), 0));
  obj->kind = kind_rid;
  obj->loc = loc;
  obj->id = id;
  return obj;
}
user_qual new_user_qual(region r, location loc, cstring cstring)
{
  user_qual obj = (sizeof(struct AST_user_qual) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_user_qual)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_user_qual), 0));
  obj->kind = kind_user_qual;
  obj->loc = loc;
  obj->cstring = cstring;
  return obj;
}
qualifier new_qualifier(region r, location loc, enum rid id)
{
  qualifier obj = (sizeof(struct AST_qualifier) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_qualifier)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_qualifier), 0));
  obj->kind = kind_qualifier;
  obj->loc = loc;
  obj->id = id;
  return obj;
}
tag_ref new_tag_ref(region r, location loc, word word1, attribute attributes, declaration fields, bool defined)
{
  tag_ref obj = (sizeof(struct AST_tag_ref) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_tag_ref)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_tag_ref), 0));
  obj->kind = kind_tag_ref;
  obj->loc = loc;
  obj->word1 = word1;
  obj->attributes = attributes;
  obj->fields = fields;
  obj->defined = defined;
  return obj;
}
function_declarator new_function_declarator(region r, location loc, declarator declarator, declaration parms, type_element qualifiers, environment env)
{
  function_declarator obj = (sizeof(struct AST_function_declarator) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_function_declarator)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_function_declarator), 0));
  obj->kind = kind_function_declarator;
  obj->loc = loc;
  obj->declarator = declarator;
  obj->parms = parms;
  obj->qualifiers = qualifiers;
  obj->env = env;
  return obj;
}
pointer_declarator new_pointer_declarator(region r, location loc, declarator declarator, type_element qualifiers)
{
  pointer_declarator obj = (sizeof(struct AST_pointer_declarator) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_pointer_declarator)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_pointer_declarator), 0));
  obj->kind = kind_pointer_declarator;
  obj->loc = loc;
  obj->declarator = declarator;
  obj->qualifiers = qualifiers;
  return obj;
}
array_declarator new_array_declarator(region r, location loc, declarator declarator, expression arg1)
{
  array_declarator obj = (sizeof(struct AST_array_declarator) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_array_declarator)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_array_declarator), 0));
  obj->kind = kind_array_declarator;
  obj->loc = loc;
  obj->declarator = declarator;
  obj->arg1 = arg1;
  return obj;
}
identifier_declarator new_identifier_declarator(region r, location loc, cstring cstring)
{
  identifier_declarator obj = (sizeof(struct AST_identifier_declarator) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_identifier_declarator)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_identifier_declarator), 0));
  obj->kind = kind_identifier_declarator;
  obj->loc = loc;
  obj->cstring = cstring;
  return obj;
}
asm_stmt new_asm_stmt(region r, location loc, expression arg1, asm_operand asm_operands1, asm_operand asm_operands2, string asm_clobbers, type_element qualifiers)
{
  asm_stmt obj = (sizeof(struct AST_asm_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_asm_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_asm_stmt), 0));
  obj->kind = kind_asm_stmt;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->asm_operands1 = asm_operands1;
  obj->asm_operands2 = asm_operands2;
  obj->asm_clobbers = asm_clobbers;
  obj->qualifiers = qualifiers;
  return obj;
}
compound_stmt new_compound_stmt(region r, location loc, id_label id_labels, declaration decls, statement stmts, environment env)
{
  compound_stmt obj = (sizeof(struct AST_compound_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_compound_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_compound_stmt), 0));
  obj->kind = kind_compound_stmt;
  obj->loc = loc;
  obj->id_labels = id_labels;
  obj->decls = decls;
  obj->stmts = stmts;
  obj->env = env;
  return obj;
}
if_stmt new_if_stmt(region r, location loc, expression condition, statement stmt1, statement stmt2)
{
  if_stmt obj = (sizeof(struct AST_if_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_if_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_if_stmt), 0));
  obj->kind = kind_if_stmt;
  obj->loc = loc;
  obj->condition = condition;
  obj->stmt1 = stmt1;
  obj->stmt2 = stmt2;
  return obj;
}
labeled_stmt new_labeled_stmt(region r, location loc, label label, statement stmt)
{
  labeled_stmt obj = (sizeof(struct AST_labeled_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_labeled_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_labeled_stmt), 0));
  obj->kind = kind_labeled_stmt;
  obj->loc = loc;
  obj->label = label;
  obj->stmt = stmt;
  return obj;
}
expression_stmt new_expression_stmt(region r, location loc, expression arg1)
{
  expression_stmt obj = (sizeof(struct AST_expression_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_expression_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_expression_stmt), 0));
  obj->kind = kind_expression_stmt;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
breakable_stmt new_breakable_stmt(region r, location loc)
{
  breakable_stmt obj = (sizeof(struct AST_breakable_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_breakable_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_breakable_stmt), 0));
  obj->kind = kind_breakable_stmt;
  obj->loc = loc;
  return obj;
}
conditional_stmt new_conditional_stmt(region r, location loc, expression condition, statement stmt)
{
  conditional_stmt obj = (sizeof(struct AST_conditional_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_conditional_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_conditional_stmt), 0));
  obj->kind = kind_conditional_stmt;
  obj->loc = loc;
  obj->condition = condition;
  obj->stmt = stmt;
  return obj;
}
switch_stmt new_switch_stmt(region r, location loc, expression condition, statement stmt)
{
  switch_stmt obj = (sizeof(struct AST_switch_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_switch_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_switch_stmt), 0));
  obj->kind = kind_switch_stmt;
  obj->loc = loc;
  obj->condition = condition;
  obj->stmt = stmt;
  return obj;
}
for_stmt new_for_stmt(region r, location loc, expression arg1, expression arg2, expression arg3, statement stmt)
{
  for_stmt obj = (sizeof(struct AST_for_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_for_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_for_stmt), 0));
  obj->kind = kind_for_stmt;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  obj->arg3 = arg3;
  obj->stmt = stmt;
  return obj;
}
break_stmt new_break_stmt(region r, location loc)
{
  break_stmt obj = (sizeof(struct AST_break_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_break_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_break_stmt), 0));
  obj->kind = kind_break_stmt;
  obj->loc = loc;
  return obj;
}
continue_stmt new_continue_stmt(region r, location loc)
{
  continue_stmt obj = (sizeof(struct AST_continue_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_continue_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_continue_stmt), 0));
  obj->kind = kind_continue_stmt;
  obj->loc = loc;
  return obj;
}
return_stmt new_return_stmt(region r, location loc, expression arg1)
{
  return_stmt obj = (sizeof(struct AST_return_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_return_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_return_stmt), 0));
  obj->kind = kind_return_stmt;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
goto_stmt new_goto_stmt(region r, location loc, id_label id_label)
{
  goto_stmt obj = (sizeof(struct AST_goto_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_goto_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_goto_stmt), 0));
  obj->kind = kind_goto_stmt;
  obj->loc = loc;
  obj->id_label = id_label;
  return obj;
}
computed_goto_stmt new_computed_goto_stmt(region r, location loc, expression arg1)
{
  computed_goto_stmt obj = (sizeof(struct AST_computed_goto_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_computed_goto_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_computed_goto_stmt), 0));
  obj->kind = kind_computed_goto_stmt;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
empty_stmt new_empty_stmt(region r, location loc)
{
  empty_stmt obj = (sizeof(struct AST_empty_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_empty_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_empty_stmt), 0));
  obj->kind = kind_empty_stmt;
  obj->loc = loc;
  return obj;
}
assert_type_stmt new_assert_type_stmt(region r, location loc, expression arg1, asttype asttype)
{
  assert_type_stmt obj = (sizeof(struct AST_assert_type_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_assert_type_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_assert_type_stmt), 0));
  obj->kind = kind_assert_type_stmt;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->asttype = asttype;
  return obj;
}
change_type_stmt new_change_type_stmt(region r, location loc, expression arg1, asttype asttype)
{
  change_type_stmt obj = (sizeof(struct AST_change_type_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_change_type_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_change_type_stmt), 0));
  obj->kind = kind_change_type_stmt;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->asttype = asttype;
  return obj;
}
deep_restrict_stmt new_deep_restrict_stmt(region r, location loc, expression arg1, statement stmt)
{
  deep_restrict_stmt obj = (sizeof(struct AST_deep_restrict_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_deep_restrict_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_deep_restrict_stmt), 0));
  obj->kind = kind_deep_restrict_stmt;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->stmt = stmt;
  return obj;
}
unary new_unary(region r, location loc, expression arg1)
{
  unary obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_unary;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
binary new_binary(region r, location loc, expression arg1, expression arg2)
{
  binary obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_binary;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
comma new_comma(region r, location loc, expression arg1)
{
  comma obj = (sizeof(struct AST_comma) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_comma)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_comma), 0));
  obj->kind = kind_comma;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
sizeof_type new_sizeof_type(region r, location loc, asttype asttype)
{
  sizeof_type obj = (sizeof(struct AST_sizeof_type) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_sizeof_type)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_sizeof_type), 0));
  obj->kind = kind_sizeof_type;
  obj->loc = loc;
  obj->asttype = asttype;
  return obj;
}
alignof_type new_alignof_type(region r, location loc, asttype asttype)
{
  alignof_type obj = (sizeof(struct AST_alignof_type) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_alignof_type)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_alignof_type), 0));
  obj->kind = kind_alignof_type;
  obj->loc = loc;
  obj->asttype = asttype;
  return obj;
}
label_address new_label_address(region r, location loc, id_label id_label)
{
  label_address obj = (sizeof(struct AST_label_address) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_label_address)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_label_address), 0));
  obj->kind = kind_label_address;
  obj->loc = loc;
  obj->id_label = id_label;
  return obj;
}
cast new_cast(region r, location loc, expression arg1, asttype asttype)
{
  cast obj = (sizeof(struct AST_cast) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_cast)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_cast), 0));
  obj->kind = kind_cast;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->asttype = asttype;
  return obj;
}
cast_list new_cast_list(region r, location loc, asttype asttype, expression init_expr)
{
  cast_list obj = (sizeof(struct AST_cast_list) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_cast_list)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_cast_list), 0));
  obj->kind = kind_cast_list;
  obj->loc = loc;
  obj->asttype = asttype;
  obj->init_expr = init_expr;
  return obj;
}
conditional new_conditional(region r, location loc, expression condition, expression arg1, expression arg2)
{
  conditional obj = (sizeof(struct AST_conditional) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_conditional)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_conditional), 0));
  obj->kind = kind_conditional;
  obj->loc = loc;
  obj->condition = condition;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
identifier new_identifier(region r, location loc, cstring cstring, data_declaration ddecl)
{
  identifier obj = (sizeof(struct AST_identifier) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_identifier)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_identifier), 0));
  obj->kind = kind_identifier;
  obj->loc = loc;
  obj->cstring = cstring;
  obj->ddecl = ddecl;
  return obj;
}
compound_expr new_compound_expr(region r, location loc, statement stmt)
{
  compound_expr obj = (sizeof(struct AST_compound_expr) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_compound_expr)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_compound_expr), 0));
  obj->kind = kind_compound_expr;
  obj->loc = loc;
  obj->stmt = stmt;
  return obj;
}
function_call new_function_call(region r, location loc, expression arg1, expression args, asttype va_arg_call)
{
  function_call obj = (sizeof(struct AST_function_call) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_function_call)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_function_call), 0));
  obj->kind = kind_function_call;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->args = args;
  obj->va_arg_call = va_arg_call;
  return obj;
}
array_ref new_array_ref(region r, location loc, expression arg1, expression arg2)
{
  array_ref obj = (sizeof(struct AST_array_ref) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_array_ref)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_array_ref), 0));
  obj->kind = kind_array_ref;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
field_ref new_field_ref(region r, location loc, expression arg1, cstring cstring, location cstring_loc)
{
  field_ref obj = (sizeof(struct AST_field_ref) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_field_ref)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_field_ref), 0));
  obj->kind = kind_field_ref;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->cstring = cstring;
  obj->cstring_loc = cstring_loc;
  return obj;
}
init_list new_init_list(region r, location loc, expression args)
{
  init_list obj = (sizeof(struct AST_init_list) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_init_list)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_init_list), 0));
  obj->kind = kind_init_list;
  obj->loc = loc;
  obj->args = args;
  return obj;
}
init_index new_init_index(region r, location loc, expression arg1, expression arg2, expression init_expr)
{
  init_index obj = (sizeof(struct AST_init_index) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_init_index)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_init_index), 0));
  obj->kind = kind_init_index;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  obj->init_expr = init_expr;
  return obj;
}
init_field new_init_field(region r, location loc, word word1, expression init_expr)
{
  init_field obj = (sizeof(struct AST_init_field) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_init_field)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_init_field), 0));
  obj->kind = kind_init_field;
  obj->loc = loc;
  obj->word1 = word1;
  obj->init_expr = init_expr;
  return obj;
}
lexical_cst new_lexical_cst(region r, location loc, cstring cstring)
{
  lexical_cst obj = (sizeof(struct AST_lexical_cst) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_lexical_cst)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_lexical_cst), 0));
  obj->kind = kind_lexical_cst;
  obj->loc = loc;
  obj->cstring = cstring;
  return obj;
}
string_cst new_string_cst(region r, location loc, cstring cstring, wchar_t * chars, size_t length)
{
  string_cst obj = (sizeof(struct AST_string_cst) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_string_cst)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_string_cst), 0));
  obj->kind = kind_string_cst;
  obj->loc = loc;
  obj->cstring = cstring;
  obj->chars = chars;
  obj->length = length;
  return obj;
}
string new_string(region r, location loc, expression strings, data_declaration ddecl)
{
  string obj = (sizeof(struct AST_string) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_string)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_string), 0));
  obj->kind = kind_string;
  obj->loc = loc;
  obj->strings = strings;
  obj->ddecl = ddecl;
  return obj;
}
id_label new_id_label(region r, location loc, cstring cstring)
{
  id_label obj = (sizeof(struct AST_id_label) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_id_label)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_id_label), 0));
  obj->kind = kind_id_label;
  obj->loc = loc;
  obj->cstring = cstring;
  return obj;
}
case_label new_case_label(region r, location loc, expression arg1, expression arg2)
{
  case_label obj = (sizeof(struct AST_case_label) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_case_label)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_case_label), 0));
  obj->kind = kind_case_label;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
default_label new_default_label(region r, location loc)
{
  default_label obj = (sizeof(struct AST_default_label) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_default_label)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_default_label), 0));
  obj->kind = kind_default_label;
  obj->loc = loc;
  return obj;
}
word new_word(region r, location loc, cstring cstring)
{
  word obj = (sizeof(struct AST_word) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_word)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_word), 0));
  obj->kind = kind_word;
  obj->loc = loc;
  obj->cstring = cstring;
  return obj;
}
asm_operand new_asm_operand(region r, location loc, string string, expression arg1)
{
  asm_operand obj = (sizeof(struct AST_asm_operand) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_asm_operand)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_asm_operand), 0));
  obj->kind = kind_asm_operand;
  obj->loc = loc;
  obj->string = string;
  obj->arg1 = arg1;
  return obj;
}
error_decl new_error_decl(region r, location loc)
{
  error_decl obj = (sizeof(struct AST_declaration) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_declaration)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_declaration), 0));
  obj->kind = kind_error_decl;
  obj->loc = loc;
  return obj;
}
struct_ref new_struct_ref(region r, location loc, word word1, attribute attributes, declaration fields, bool defined)
{
  struct_ref obj = (sizeof(struct AST_tag_ref) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_tag_ref)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_tag_ref), 0));
  obj->kind = kind_struct_ref;
  obj->loc = loc;
  obj->word1 = word1;
  obj->attributes = attributes;
  obj->fields = fields;
  obj->defined = defined;
  return obj;
}
union_ref new_union_ref(region r, location loc, word word1, attribute attributes, declaration fields, bool defined)
{
  union_ref obj = (sizeof(struct AST_tag_ref) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_tag_ref)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_tag_ref), 0));
  obj->kind = kind_union_ref;
  obj->loc = loc;
  obj->word1 = word1;
  obj->attributes = attributes;
  obj->fields = fields;
  obj->defined = defined;
  return obj;
}
enum_ref new_enum_ref(region r, location loc, word word1, attribute attributes, declaration fields, bool defined)
{
  enum_ref obj = (sizeof(struct AST_tag_ref) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_tag_ref)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_tag_ref), 0));
  obj->kind = kind_enum_ref;
  obj->loc = loc;
  obj->word1 = word1;
  obj->attributes = attributes;
  obj->fields = fields;
  obj->defined = defined;
  return obj;
}
error_stmt new_error_stmt(region r, location loc)
{
  error_stmt obj = (sizeof(struct AST_statement) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_statement)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_statement), 0));
  obj->kind = kind_error_stmt;
  obj->loc = loc;
  return obj;
}
while_stmt new_while_stmt(region r, location loc, expression condition, statement stmt)
{
  while_stmt obj = (sizeof(struct AST_conditional_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_conditional_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_conditional_stmt), 0));
  obj->kind = kind_while_stmt;
  obj->loc = loc;
  obj->condition = condition;
  obj->stmt = stmt;
  return obj;
}
dowhile_stmt new_dowhile_stmt(region r, location loc, expression condition, statement stmt)
{
  dowhile_stmt obj = (sizeof(struct AST_conditional_stmt) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_conditional_stmt)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_conditional_stmt), 0));
  obj->kind = kind_dowhile_stmt;
  obj->loc = loc;
  obj->condition = condition;
  obj->stmt = stmt;
  return obj;
}
error_expr new_error_expr(region r, location loc)
{
  error_expr obj = (sizeof(struct AST_expression) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_expression)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_expression), 0));
  obj->kind = kind_error_expr;
  obj->loc = loc;
  return obj;
}
dereference new_dereference(region r, location loc, expression arg1)
{
  dereference obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_dereference;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
extension_expr new_extension_expr(region r, location loc, expression arg1)
{
  extension_expr obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_extension_expr;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
sizeof_expr new_sizeof_expr(region r, location loc, expression arg1)
{
  sizeof_expr obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_sizeof_expr;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
alignof_expr new_alignof_expr(region r, location loc, expression arg1)
{
  alignof_expr obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_alignof_expr;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
realpart new_realpart(region r, location loc, expression arg1)
{
  realpart obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_realpart;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
imagpart new_imagpart(region r, location loc, expression arg1)
{
  imagpart obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_imagpart;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
address_of new_address_of(region r, location loc, expression arg1)
{
  address_of obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_address_of;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
unary_minus new_unary_minus(region r, location loc, expression arg1)
{
  unary_minus obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_unary_minus;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
unary_plus new_unary_plus(region r, location loc, expression arg1)
{
  unary_plus obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_unary_plus;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
conjugate new_conjugate(region r, location loc, expression arg1)
{
  conjugate obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_conjugate;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
preincrement new_preincrement(region r, location loc, expression arg1)
{
  preincrement obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_preincrement;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
predecrement new_predecrement(region r, location loc, expression arg1)
{
  predecrement obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_predecrement;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
postincrement new_postincrement(region r, location loc, expression arg1)
{
  postincrement obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_postincrement;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
postdecrement new_postdecrement(region r, location loc, expression arg1)
{
  postdecrement obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_postdecrement;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
bitnot new_bitnot(region r, location loc, expression arg1)
{
  bitnot obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_bitnot;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
not new_not(region r, location loc, expression arg1)
{
  not obj = (sizeof(struct AST_unary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_unary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_unary), 0));
  obj->kind = kind_not;
  obj->loc = loc;
  obj->arg1 = arg1;
  return obj;
}
plus new_plus(region r, location loc, expression arg1, expression arg2)
{
  plus obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_plus;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
minus new_minus(region r, location loc, expression arg1, expression arg2)
{
  minus obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_minus;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
times new_times(region r, location loc, expression arg1, expression arg2)
{
  times obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_times;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
divide new_divide(region r, location loc, expression arg1, expression arg2)
{
  divide obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_divide;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
modulo new_modulo(region r, location loc, expression arg1, expression arg2)
{
  modulo obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_modulo;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
lshift new_lshift(region r, location loc, expression arg1, expression arg2)
{
  lshift obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_lshift;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
rshift new_rshift(region r, location loc, expression arg1, expression arg2)
{
  rshift obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_rshift;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
leq new_leq(region r, location loc, expression arg1, expression arg2)
{
  leq obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_leq;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
geq new_geq(region r, location loc, expression arg1, expression arg2)
{
  geq obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_geq;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
lt new_lt(region r, location loc, expression arg1, expression arg2)
{
  lt obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_lt;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
gt new_gt(region r, location loc, expression arg1, expression arg2)
{
  gt obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_gt;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
eq new_eq(region r, location loc, expression arg1, expression arg2)
{
  eq obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_eq;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
ne new_ne(region r, location loc, expression arg1, expression arg2)
{
  ne obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_ne;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
bitand new_bitand(region r, location loc, expression arg1, expression arg2)
{
  bitand obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_bitand;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
bitor new_bitor(region r, location loc, expression arg1, expression arg2)
{
  bitor obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_bitor;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
bitxor new_bitxor(region r, location loc, expression arg1, expression arg2)
{
  bitxor obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_bitxor;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
andand new_andand(region r, location loc, expression arg1, expression arg2)
{
  andand obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_andand;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
oror new_oror(region r, location loc, expression arg1, expression arg2)
{
  oror obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_oror;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
assign new_assign(region r, location loc, expression arg1, expression arg2)
{
  assign obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_assign;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
plus_assign new_plus_assign(region r, location loc, expression arg1, expression arg2)
{
  plus_assign obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_plus_assign;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
minus_assign new_minus_assign(region r, location loc, expression arg1, expression arg2)
{
  minus_assign obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_minus_assign;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
times_assign new_times_assign(region r, location loc, expression arg1, expression arg2)
{
  times_assign obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_times_assign;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
divide_assign new_divide_assign(region r, location loc, expression arg1, expression arg2)
{
  divide_assign obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_divide_assign;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
modulo_assign new_modulo_assign(region r, location loc, expression arg1, expression arg2)
{
  modulo_assign obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_modulo_assign;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
lshift_assign new_lshift_assign(region r, location loc, expression arg1, expression arg2)
{
  lshift_assign obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_lshift_assign;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
rshift_assign new_rshift_assign(region r, location loc, expression arg1, expression arg2)
{
  rshift_assign obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_rshift_assign;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
bitand_assign new_bitand_assign(region r, location loc, expression arg1, expression arg2)
{
  bitand_assign obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_bitand_assign;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
bitor_assign new_bitor_assign(region r, location loc, expression arg1, expression arg2)
{
  bitor_assign obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_bitor_assign;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
bitxor_assign new_bitxor_assign(region r, location loc, expression arg1, expression arg2)
{
  bitxor_assign obj = (sizeof(struct AST_binary) < (1 << (13 - 3)) ? (((void)0), __rc_ralloc_small0)((r), sizeof(struct AST_binary)) : (((void)0), __rc_typed_ralloc)((r), sizeof(struct AST_binary), 0));
  obj->kind = kind_bitxor_assign;
  obj->loc = loc;
  obj->arg1 = arg1;
  obj->arg2 = arg2;
  return obj;
}
node node_chain(node l1, node l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1494, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1494, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1494, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }); }
declaration declaration_chain(declaration l1, declaration l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1497, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1497, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_declaration && (tEmPcast)->kind <= postkind_declaration)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_declaration && (tEmPcast)->kind <= postkind_declaration)", "AST_defs.c", 1497, __PRETTY_FUNCTION__), 0))); (declaration)(tEmPcast); }); }
statement statement_chain(statement l1, statement l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1500, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1500, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_statement && (tEmPcast)->kind <= postkind_statement)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_statement && (tEmPcast)->kind <= postkind_statement)", "AST_defs.c", 1500, __PRETTY_FUNCTION__), 0))); (statement)(tEmPcast); }); }
expression expression_chain(expression l1, expression l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1503, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1503, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_expression && (tEmPcast)->kind <= postkind_expression)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_expression && (tEmPcast)->kind <= postkind_expression)", "AST_defs.c", 1503, __PRETTY_FUNCTION__), 0))); (expression)(tEmPcast); }); }
type_element type_element_chain(type_element l1, type_element l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1506, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1506, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_type_element && (tEmPcast)->kind <= postkind_type_element)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_type_element && (tEmPcast)->kind <= postkind_type_element)", "AST_defs.c", 1506, __PRETTY_FUNCTION__), 0))); (type_element)(tEmPcast); }); }
declarator declarator_chain(declarator l1, declarator l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1509, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1509, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_declarator && (tEmPcast)->kind <= postkind_declarator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_declarator && (tEmPcast)->kind <= postkind_declarator)", "AST_defs.c", 1509, __PRETTY_FUNCTION__), 0))); (declarator)(tEmPcast); }); }
label label_chain(label l1, label l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1512, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1512, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_label && (tEmPcast)->kind <= postkind_label)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_label && (tEmPcast)->kind <= postkind_label)", "AST_defs.c", 1512, __PRETTY_FUNCTION__), 0))); (label)(tEmPcast); }); }
asm_decl asm_decl_chain(asm_decl l1, asm_decl l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1515, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1515, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_asm_decl && (tEmPcast)->kind <= postkind_asm_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_asm_decl && (tEmPcast)->kind <= postkind_asm_decl)", "AST_defs.c", 1515, __PRETTY_FUNCTION__), 0))); (asm_decl)(tEmPcast); }); }
data_decl data_decl_chain(data_decl l1, data_decl l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1518, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1518, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_data_decl && (tEmPcast)->kind <= postkind_data_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_data_decl && (tEmPcast)->kind <= postkind_data_decl)", "AST_defs.c", 1518, __PRETTY_FUNCTION__), 0))); (data_decl)(tEmPcast); }); }
extension_decl extension_decl_chain(extension_decl l1, extension_decl l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1521, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1521, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_extension_decl && (tEmPcast)->kind <= postkind_extension_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_extension_decl && (tEmPcast)->kind <= postkind_extension_decl)", "AST_defs.c", 1521, __PRETTY_FUNCTION__), 0))); (extension_decl)(tEmPcast); }); }
ellipsis_decl ellipsis_decl_chain(ellipsis_decl l1, ellipsis_decl l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1524, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1524, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_ellipsis_decl && (tEmPcast)->kind <= postkind_ellipsis_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_ellipsis_decl && (tEmPcast)->kind <= postkind_ellipsis_decl)", "AST_defs.c", 1524, __PRETTY_FUNCTION__), 0))); (ellipsis_decl)(tEmPcast); }); }
enumerator enumerator_chain(enumerator l1, enumerator l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1527, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1527, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_enumerator && (tEmPcast)->kind <= postkind_enumerator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_enumerator && (tEmPcast)->kind <= postkind_enumerator)", "AST_defs.c", 1527, __PRETTY_FUNCTION__), 0))); (enumerator)(tEmPcast); }); }
oldidentifier_decl oldidentifier_decl_chain(oldidentifier_decl l1, oldidentifier_decl l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1530, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1530, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_oldidentifier_decl && (tEmPcast)->kind <= postkind_oldidentifier_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_oldidentifier_decl && (tEmPcast)->kind <= postkind_oldidentifier_decl)", "AST_defs.c", 1530, __PRETTY_FUNCTION__), 0))); (oldidentifier_decl)(tEmPcast); }); }
function_decl function_decl_chain(function_decl l1, function_decl l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1533, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1533, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_function_decl && (tEmPcast)->kind <= postkind_function_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_function_decl && (tEmPcast)->kind <= postkind_function_decl)", "AST_defs.c", 1533, __PRETTY_FUNCTION__), 0))); (function_decl)(tEmPcast); }); }
implicit_decl implicit_decl_chain(implicit_decl l1, implicit_decl l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1536, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1536, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_implicit_decl && (tEmPcast)->kind <= postkind_implicit_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_implicit_decl && (tEmPcast)->kind <= postkind_implicit_decl)", "AST_defs.c", 1536, __PRETTY_FUNCTION__), 0))); (implicit_decl)(tEmPcast); }); }
variable_decl variable_decl_chain(variable_decl l1, variable_decl l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1539, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1539, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_variable_decl && (tEmPcast)->kind <= postkind_variable_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_variable_decl && (tEmPcast)->kind <= postkind_variable_decl)", "AST_defs.c", 1539, __PRETTY_FUNCTION__), 0))); (variable_decl)(tEmPcast); }); }
field_decl field_decl_chain(field_decl l1, field_decl l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1542, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1542, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_field_decl && (tEmPcast)->kind <= postkind_field_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_field_decl && (tEmPcast)->kind <= postkind_field_decl)", "AST_defs.c", 1542, __PRETTY_FUNCTION__), 0))); (field_decl)(tEmPcast); }); }
asttype asttype_chain(asttype l1, asttype l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1545, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1545, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_asttype && (tEmPcast)->kind <= postkind_asttype)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_asttype && (tEmPcast)->kind <= postkind_asttype)", "AST_defs.c", 1545, __PRETTY_FUNCTION__), 0))); (asttype)(tEmPcast); }); }
typename typename_chain(typename l1, typename l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1548, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1548, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_typename && (tEmPcast)->kind <= postkind_typename)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_typename && (tEmPcast)->kind <= postkind_typename)", "AST_defs.c", 1548, __PRETTY_FUNCTION__), 0))); (typename)(tEmPcast); }); }
type_variable type_variable_chain(type_variable l1, type_variable l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1551, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1551, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_type_variable && (tEmPcast)->kind <= postkind_type_variable)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_type_variable && (tEmPcast)->kind <= postkind_type_variable)", "AST_defs.c", 1551, __PRETTY_FUNCTION__), 0))); (type_variable)(tEmPcast); }); }
typeof_expr typeof_expr_chain(typeof_expr l1, typeof_expr l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1554, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1554, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_typeof_expr && (tEmPcast)->kind <= postkind_typeof_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_typeof_expr && (tEmPcast)->kind <= postkind_typeof_expr)", "AST_defs.c", 1554, __PRETTY_FUNCTION__), 0))); (typeof_expr)(tEmPcast); }); }
typeof_type typeof_type_chain(typeof_type l1, typeof_type l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1557, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1557, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_typeof_type && (tEmPcast)->kind <= postkind_typeof_type)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_typeof_type && (tEmPcast)->kind <= postkind_typeof_type)", "AST_defs.c", 1557, __PRETTY_FUNCTION__), 0))); (typeof_type)(tEmPcast); }); }
attribute attribute_chain(attribute l1, attribute l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1560, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1560, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_attribute && (tEmPcast)->kind <= postkind_attribute)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_attribute && (tEmPcast)->kind <= postkind_attribute)", "AST_defs.c", 1560, __PRETTY_FUNCTION__), 0))); (attribute)(tEmPcast); }); }
rid rid_chain(rid l1, rid l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1563, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1563, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_rid && (tEmPcast)->kind <= postkind_rid)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_rid && (tEmPcast)->kind <= postkind_rid)", "AST_defs.c", 1563, __PRETTY_FUNCTION__), 0))); (rid)(tEmPcast); }); }
user_qual user_qual_chain(user_qual l1, user_qual l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1566, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1566, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_user_qual && (tEmPcast)->kind <= postkind_user_qual)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_user_qual && (tEmPcast)->kind <= postkind_user_qual)", "AST_defs.c", 1566, __PRETTY_FUNCTION__), 0))); (user_qual)(tEmPcast); }); }
qualifier qualifier_chain(qualifier l1, qualifier l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1569, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1569, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_qualifier && (tEmPcast)->kind <= postkind_qualifier)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_qualifier && (tEmPcast)->kind <= postkind_qualifier)", "AST_defs.c", 1569, __PRETTY_FUNCTION__), 0))); (qualifier)(tEmPcast); }); }
tag_ref tag_ref_chain(tag_ref l1, tag_ref l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1572, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1572, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_tag_ref && (tEmPcast)->kind <= postkind_tag_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_tag_ref && (tEmPcast)->kind <= postkind_tag_ref)", "AST_defs.c", 1572, __PRETTY_FUNCTION__), 0))); (tag_ref)(tEmPcast); }); }
function_declarator function_declarator_chain(function_declarator l1, function_declarator l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1575, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1575, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_function_declarator && (tEmPcast)->kind <= postkind_function_declarator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_function_declarator && (tEmPcast)->kind <= postkind_function_declarator)", "AST_defs.c", 1575, __PRETTY_FUNCTION__), 0))); (function_declarator)(tEmPcast); }); }
pointer_declarator pointer_declarator_chain(pointer_declarator l1, pointer_declarator l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1578, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1578, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_pointer_declarator && (tEmPcast)->kind <= postkind_pointer_declarator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_pointer_declarator && (tEmPcast)->kind <= postkind_pointer_declarator)", "AST_defs.c", 1578, __PRETTY_FUNCTION__), 0))); (pointer_declarator)(tEmPcast); }); }
array_declarator array_declarator_chain(array_declarator l1, array_declarator l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1581, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1581, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_array_declarator && (tEmPcast)->kind <= postkind_array_declarator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_array_declarator && (tEmPcast)->kind <= postkind_array_declarator)", "AST_defs.c", 1581, __PRETTY_FUNCTION__), 0))); (array_declarator)(tEmPcast); }); }
identifier_declarator identifier_declarator_chain(identifier_declarator l1, identifier_declarator l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1584, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1584, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_identifier_declarator && (tEmPcast)->kind <= postkind_identifier_declarator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_identifier_declarator && (tEmPcast)->kind <= postkind_identifier_declarator)", "AST_defs.c", 1584, __PRETTY_FUNCTION__), 0))); (identifier_declarator)(tEmPcast); }); }
asm_stmt asm_stmt_chain(asm_stmt l1, asm_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1587, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1587, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_asm_stmt && (tEmPcast)->kind <= postkind_asm_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_asm_stmt && (tEmPcast)->kind <= postkind_asm_stmt)", "AST_defs.c", 1587, __PRETTY_FUNCTION__), 0))); (asm_stmt)(tEmPcast); }); }
compound_stmt compound_stmt_chain(compound_stmt l1, compound_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1590, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1590, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_compound_stmt && (tEmPcast)->kind <= postkind_compound_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_compound_stmt && (tEmPcast)->kind <= postkind_compound_stmt)", "AST_defs.c", 1590, __PRETTY_FUNCTION__), 0))); (compound_stmt)(tEmPcast); }); }
if_stmt if_stmt_chain(if_stmt l1, if_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1593, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1593, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_if_stmt && (tEmPcast)->kind <= postkind_if_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_if_stmt && (tEmPcast)->kind <= postkind_if_stmt)", "AST_defs.c", 1593, __PRETTY_FUNCTION__), 0))); (if_stmt)(tEmPcast); }); }
labeled_stmt labeled_stmt_chain(labeled_stmt l1, labeled_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1596, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1596, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_labeled_stmt && (tEmPcast)->kind <= postkind_labeled_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_labeled_stmt && (tEmPcast)->kind <= postkind_labeled_stmt)", "AST_defs.c", 1596, __PRETTY_FUNCTION__), 0))); (labeled_stmt)(tEmPcast); }); }
expression_stmt expression_stmt_chain(expression_stmt l1, expression_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1599, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1599, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_expression_stmt && (tEmPcast)->kind <= postkind_expression_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_expression_stmt && (tEmPcast)->kind <= postkind_expression_stmt)", "AST_defs.c", 1599, __PRETTY_FUNCTION__), 0))); (expression_stmt)(tEmPcast); }); }
breakable_stmt breakable_stmt_chain(breakable_stmt l1, breakable_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1602, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1602, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_breakable_stmt && (tEmPcast)->kind <= postkind_breakable_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_breakable_stmt && (tEmPcast)->kind <= postkind_breakable_stmt)", "AST_defs.c", 1602, __PRETTY_FUNCTION__), 0))); (breakable_stmt)(tEmPcast); }); }
conditional_stmt conditional_stmt_chain(conditional_stmt l1, conditional_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1605, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1605, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_conditional_stmt && (tEmPcast)->kind <= postkind_conditional_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_conditional_stmt && (tEmPcast)->kind <= postkind_conditional_stmt)", "AST_defs.c", 1605, __PRETTY_FUNCTION__), 0))); (conditional_stmt)(tEmPcast); }); }
switch_stmt switch_stmt_chain(switch_stmt l1, switch_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1608, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1608, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_switch_stmt && (tEmPcast)->kind <= postkind_switch_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_switch_stmt && (tEmPcast)->kind <= postkind_switch_stmt)", "AST_defs.c", 1608, __PRETTY_FUNCTION__), 0))); (switch_stmt)(tEmPcast); }); }
for_stmt for_stmt_chain(for_stmt l1, for_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1611, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1611, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_for_stmt && (tEmPcast)->kind <= postkind_for_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_for_stmt && (tEmPcast)->kind <= postkind_for_stmt)", "AST_defs.c", 1611, __PRETTY_FUNCTION__), 0))); (for_stmt)(tEmPcast); }); }
break_stmt break_stmt_chain(break_stmt l1, break_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1614, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1614, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_break_stmt && (tEmPcast)->kind <= postkind_break_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_break_stmt && (tEmPcast)->kind <= postkind_break_stmt)", "AST_defs.c", 1614, __PRETTY_FUNCTION__), 0))); (break_stmt)(tEmPcast); }); }
continue_stmt continue_stmt_chain(continue_stmt l1, continue_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1617, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1617, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_continue_stmt && (tEmPcast)->kind <= postkind_continue_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_continue_stmt && (tEmPcast)->kind <= postkind_continue_stmt)", "AST_defs.c", 1617, __PRETTY_FUNCTION__), 0))); (continue_stmt)(tEmPcast); }); }
return_stmt return_stmt_chain(return_stmt l1, return_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1620, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1620, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_return_stmt && (tEmPcast)->kind <= postkind_return_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_return_stmt && (tEmPcast)->kind <= postkind_return_stmt)", "AST_defs.c", 1620, __PRETTY_FUNCTION__), 0))); (return_stmt)(tEmPcast); }); }
goto_stmt goto_stmt_chain(goto_stmt l1, goto_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1623, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1623, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_goto_stmt && (tEmPcast)->kind <= postkind_goto_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_goto_stmt && (tEmPcast)->kind <= postkind_goto_stmt)", "AST_defs.c", 1623, __PRETTY_FUNCTION__), 0))); (goto_stmt)(tEmPcast); }); }
computed_goto_stmt computed_goto_stmt_chain(computed_goto_stmt l1, computed_goto_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1626, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1626, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_computed_goto_stmt && (tEmPcast)->kind <= postkind_computed_goto_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_computed_goto_stmt && (tEmPcast)->kind <= postkind_computed_goto_stmt)", "AST_defs.c", 1626, __PRETTY_FUNCTION__), 0))); (computed_goto_stmt)(tEmPcast); }); }
empty_stmt empty_stmt_chain(empty_stmt l1, empty_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1629, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1629, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_empty_stmt && (tEmPcast)->kind <= postkind_empty_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_empty_stmt && (tEmPcast)->kind <= postkind_empty_stmt)", "AST_defs.c", 1629, __PRETTY_FUNCTION__), 0))); (empty_stmt)(tEmPcast); }); }
assert_type_stmt assert_type_stmt_chain(assert_type_stmt l1, assert_type_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1632, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1632, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_assert_type_stmt && (tEmPcast)->kind <= postkind_assert_type_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_assert_type_stmt && (tEmPcast)->kind <= postkind_assert_type_stmt)", "AST_defs.c", 1632, __PRETTY_FUNCTION__), 0))); (assert_type_stmt)(tEmPcast); }); }
change_type_stmt change_type_stmt_chain(change_type_stmt l1, change_type_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1635, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1635, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_change_type_stmt && (tEmPcast)->kind <= postkind_change_type_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_change_type_stmt && (tEmPcast)->kind <= postkind_change_type_stmt)", "AST_defs.c", 1635, __PRETTY_FUNCTION__), 0))); (change_type_stmt)(tEmPcast); }); }
deep_restrict_stmt deep_restrict_stmt_chain(deep_restrict_stmt l1, deep_restrict_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1638, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1638, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_deep_restrict_stmt && (tEmPcast)->kind <= postkind_deep_restrict_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_deep_restrict_stmt && (tEmPcast)->kind <= postkind_deep_restrict_stmt)", "AST_defs.c", 1638, __PRETTY_FUNCTION__), 0))); (deep_restrict_stmt)(tEmPcast); }); }
unary unary_chain(unary l1, unary l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1641, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1641, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_unary && (tEmPcast)->kind <= postkind_unary)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_unary && (tEmPcast)->kind <= postkind_unary)", "AST_defs.c", 1641, __PRETTY_FUNCTION__), 0))); (unary)(tEmPcast); }); }
binary binary_chain(binary l1, binary l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1644, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1644, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_binary && (tEmPcast)->kind <= postkind_binary)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_binary && (tEmPcast)->kind <= postkind_binary)", "AST_defs.c", 1644, __PRETTY_FUNCTION__), 0))); (binary)(tEmPcast); }); }
comma comma_chain(comma l1, comma l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1647, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1647, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_comma && (tEmPcast)->kind <= postkind_comma)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_comma && (tEmPcast)->kind <= postkind_comma)", "AST_defs.c", 1647, __PRETTY_FUNCTION__), 0))); (comma)(tEmPcast); }); }
sizeof_type sizeof_type_chain(sizeof_type l1, sizeof_type l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1650, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1650, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_sizeof_type && (tEmPcast)->kind <= postkind_sizeof_type)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_sizeof_type && (tEmPcast)->kind <= postkind_sizeof_type)", "AST_defs.c", 1650, __PRETTY_FUNCTION__), 0))); (sizeof_type)(tEmPcast); }); }
alignof_type alignof_type_chain(alignof_type l1, alignof_type l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1653, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1653, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_alignof_type && (tEmPcast)->kind <= postkind_alignof_type)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_alignof_type && (tEmPcast)->kind <= postkind_alignof_type)", "AST_defs.c", 1653, __PRETTY_FUNCTION__), 0))); (alignof_type)(tEmPcast); }); }
label_address label_address_chain(label_address l1, label_address l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1656, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1656, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_label_address && (tEmPcast)->kind <= postkind_label_address)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_label_address && (tEmPcast)->kind <= postkind_label_address)", "AST_defs.c", 1656, __PRETTY_FUNCTION__), 0))); (label_address)(tEmPcast); }); }
cast cast_chain(cast l1, cast l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1659, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1659, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_cast && (tEmPcast)->kind <= postkind_cast)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_cast && (tEmPcast)->kind <= postkind_cast)", "AST_defs.c", 1659, __PRETTY_FUNCTION__), 0))); (cast)(tEmPcast); }); }
cast_list cast_list_chain(cast_list l1, cast_list l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1662, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1662, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_cast_list && (tEmPcast)->kind <= postkind_cast_list)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_cast_list && (tEmPcast)->kind <= postkind_cast_list)", "AST_defs.c", 1662, __PRETTY_FUNCTION__), 0))); (cast_list)(tEmPcast); }); }
conditional conditional_chain(conditional l1, conditional l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1665, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1665, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_conditional && (tEmPcast)->kind <= postkind_conditional)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_conditional && (tEmPcast)->kind <= postkind_conditional)", "AST_defs.c", 1665, __PRETTY_FUNCTION__), 0))); (conditional)(tEmPcast); }); }
identifier identifier_chain(identifier l1, identifier l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1668, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1668, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_identifier && (tEmPcast)->kind <= postkind_identifier)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_identifier && (tEmPcast)->kind <= postkind_identifier)", "AST_defs.c", 1668, __PRETTY_FUNCTION__), 0))); (identifier)(tEmPcast); }); }
compound_expr compound_expr_chain(compound_expr l1, compound_expr l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1671, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1671, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_compound_expr && (tEmPcast)->kind <= postkind_compound_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_compound_expr && (tEmPcast)->kind <= postkind_compound_expr)", "AST_defs.c", 1671, __PRETTY_FUNCTION__), 0))); (compound_expr)(tEmPcast); }); }
function_call function_call_chain(function_call l1, function_call l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1674, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1674, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_function_call && (tEmPcast)->kind <= postkind_function_call)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_function_call && (tEmPcast)->kind <= postkind_function_call)", "AST_defs.c", 1674, __PRETTY_FUNCTION__), 0))); (function_call)(tEmPcast); }); }
array_ref array_ref_chain(array_ref l1, array_ref l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1677, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1677, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_array_ref && (tEmPcast)->kind <= postkind_array_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_array_ref && (tEmPcast)->kind <= postkind_array_ref)", "AST_defs.c", 1677, __PRETTY_FUNCTION__), 0))); (array_ref)(tEmPcast); }); }
field_ref field_ref_chain(field_ref l1, field_ref l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1680, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1680, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_field_ref && (tEmPcast)->kind <= postkind_field_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_field_ref && (tEmPcast)->kind <= postkind_field_ref)", "AST_defs.c", 1680, __PRETTY_FUNCTION__), 0))); (field_ref)(tEmPcast); }); }
init_list init_list_chain(init_list l1, init_list l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1683, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1683, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_init_list && (tEmPcast)->kind <= postkind_init_list)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_init_list && (tEmPcast)->kind <= postkind_init_list)", "AST_defs.c", 1683, __PRETTY_FUNCTION__), 0))); (init_list)(tEmPcast); }); }
init_index init_index_chain(init_index l1, init_index l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1686, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1686, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_init_index && (tEmPcast)->kind <= postkind_init_index)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_init_index && (tEmPcast)->kind <= postkind_init_index)", "AST_defs.c", 1686, __PRETTY_FUNCTION__), 0))); (init_index)(tEmPcast); }); }
init_field init_field_chain(init_field l1, init_field l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1689, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1689, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_init_field && (tEmPcast)->kind <= postkind_init_field)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_init_field && (tEmPcast)->kind <= postkind_init_field)", "AST_defs.c", 1689, __PRETTY_FUNCTION__), 0))); (init_field)(tEmPcast); }); }
lexical_cst lexical_cst_chain(lexical_cst l1, lexical_cst l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1692, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1692, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_lexical_cst && (tEmPcast)->kind <= postkind_lexical_cst)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_lexical_cst && (tEmPcast)->kind <= postkind_lexical_cst)", "AST_defs.c", 1692, __PRETTY_FUNCTION__), 0))); (lexical_cst)(tEmPcast); }); }
string_cst string_cst_chain(string_cst l1, string_cst l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1695, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1695, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_string_cst && (tEmPcast)->kind <= postkind_string_cst)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_string_cst && (tEmPcast)->kind <= postkind_string_cst)", "AST_defs.c", 1695, __PRETTY_FUNCTION__), 0))); (string_cst)(tEmPcast); }); }
string string_chain(string l1, string l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1698, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1698, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_string && (tEmPcast)->kind <= postkind_string)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_string && (tEmPcast)->kind <= postkind_string)", "AST_defs.c", 1698, __PRETTY_FUNCTION__), 0))); (string)(tEmPcast); }); }
id_label id_label_chain(id_label l1, id_label l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1701, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1701, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_id_label && (tEmPcast)->kind <= postkind_id_label)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_id_label && (tEmPcast)->kind <= postkind_id_label)", "AST_defs.c", 1701, __PRETTY_FUNCTION__), 0))); (id_label)(tEmPcast); }); }
case_label case_label_chain(case_label l1, case_label l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1704, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1704, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_case_label && (tEmPcast)->kind <= postkind_case_label)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_case_label && (tEmPcast)->kind <= postkind_case_label)", "AST_defs.c", 1704, __PRETTY_FUNCTION__), 0))); (case_label)(tEmPcast); }); }
default_label default_label_chain(default_label l1, default_label l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1707, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1707, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_default_label && (tEmPcast)->kind <= postkind_default_label)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_default_label && (tEmPcast)->kind <= postkind_default_label)", "AST_defs.c", 1707, __PRETTY_FUNCTION__), 0))); (default_label)(tEmPcast); }); }
word word_chain(word l1, word l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1710, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1710, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_word && (tEmPcast)->kind <= postkind_word)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_word && (tEmPcast)->kind <= postkind_word)", "AST_defs.c", 1710, __PRETTY_FUNCTION__), 0))); (word)(tEmPcast); }); }
asm_operand asm_operand_chain(asm_operand l1, asm_operand l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1713, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1713, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_asm_operand && (tEmPcast)->kind <= postkind_asm_operand)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_asm_operand && (tEmPcast)->kind <= postkind_asm_operand)", "AST_defs.c", 1713, __PRETTY_FUNCTION__), 0))); (asm_operand)(tEmPcast); }); }
error_decl error_decl_chain(error_decl l1, error_decl l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1716, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1716, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_error_decl && (tEmPcast)->kind <= postkind_error_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_error_decl && (tEmPcast)->kind <= postkind_error_decl)", "AST_defs.c", 1716, __PRETTY_FUNCTION__), 0))); (error_decl)(tEmPcast); }); }
struct_ref struct_ref_chain(struct_ref l1, struct_ref l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1719, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1719, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_struct_ref && (tEmPcast)->kind <= postkind_struct_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_struct_ref && (tEmPcast)->kind <= postkind_struct_ref)", "AST_defs.c", 1719, __PRETTY_FUNCTION__), 0))); (struct_ref)(tEmPcast); }); }
union_ref union_ref_chain(union_ref l1, union_ref l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1722, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1722, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_union_ref && (tEmPcast)->kind <= postkind_union_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_union_ref && (tEmPcast)->kind <= postkind_union_ref)", "AST_defs.c", 1722, __PRETTY_FUNCTION__), 0))); (union_ref)(tEmPcast); }); }
enum_ref enum_ref_chain(enum_ref l1, enum_ref l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1725, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1725, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_enum_ref && (tEmPcast)->kind <= postkind_enum_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_enum_ref && (tEmPcast)->kind <= postkind_enum_ref)", "AST_defs.c", 1725, __PRETTY_FUNCTION__), 0))); (enum_ref)(tEmPcast); }); }
error_stmt error_stmt_chain(error_stmt l1, error_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1728, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1728, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_error_stmt && (tEmPcast)->kind <= postkind_error_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_error_stmt && (tEmPcast)->kind <= postkind_error_stmt)", "AST_defs.c", 1728, __PRETTY_FUNCTION__), 0))); (error_stmt)(tEmPcast); }); }
while_stmt while_stmt_chain(while_stmt l1, while_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1731, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1731, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_while_stmt && (tEmPcast)->kind <= postkind_while_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_while_stmt && (tEmPcast)->kind <= postkind_while_stmt)", "AST_defs.c", 1731, __PRETTY_FUNCTION__), 0))); (while_stmt)(tEmPcast); }); }
dowhile_stmt dowhile_stmt_chain(dowhile_stmt l1, dowhile_stmt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1734, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1734, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_dowhile_stmt && (tEmPcast)->kind <= postkind_dowhile_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_dowhile_stmt && (tEmPcast)->kind <= postkind_dowhile_stmt)", "AST_defs.c", 1734, __PRETTY_FUNCTION__), 0))); (dowhile_stmt)(tEmPcast); }); }
error_expr error_expr_chain(error_expr l1, error_expr l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1737, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1737, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_error_expr && (tEmPcast)->kind <= postkind_error_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_error_expr && (tEmPcast)->kind <= postkind_error_expr)", "AST_defs.c", 1737, __PRETTY_FUNCTION__), 0))); (error_expr)(tEmPcast); }); }
dereference dereference_chain(dereference l1, dereference l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1740, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1740, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_dereference && (tEmPcast)->kind <= postkind_dereference)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_dereference && (tEmPcast)->kind <= postkind_dereference)", "AST_defs.c", 1740, __PRETTY_FUNCTION__), 0))); (dereference)(tEmPcast); }); }
extension_expr extension_expr_chain(extension_expr l1, extension_expr l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1743, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1743, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_extension_expr && (tEmPcast)->kind <= postkind_extension_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_extension_expr && (tEmPcast)->kind <= postkind_extension_expr)", "AST_defs.c", 1743, __PRETTY_FUNCTION__), 0))); (extension_expr)(tEmPcast); }); }
sizeof_expr sizeof_expr_chain(sizeof_expr l1, sizeof_expr l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1746, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1746, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_sizeof_expr && (tEmPcast)->kind <= postkind_sizeof_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_sizeof_expr && (tEmPcast)->kind <= postkind_sizeof_expr)", "AST_defs.c", 1746, __PRETTY_FUNCTION__), 0))); (sizeof_expr)(tEmPcast); }); }
alignof_expr alignof_expr_chain(alignof_expr l1, alignof_expr l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1749, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1749, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_alignof_expr && (tEmPcast)->kind <= postkind_alignof_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_alignof_expr && (tEmPcast)->kind <= postkind_alignof_expr)", "AST_defs.c", 1749, __PRETTY_FUNCTION__), 0))); (alignof_expr)(tEmPcast); }); }
realpart realpart_chain(realpart l1, realpart l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1752, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1752, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_realpart && (tEmPcast)->kind <= postkind_realpart)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_realpart && (tEmPcast)->kind <= postkind_realpart)", "AST_defs.c", 1752, __PRETTY_FUNCTION__), 0))); (realpart)(tEmPcast); }); }
imagpart imagpart_chain(imagpart l1, imagpart l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1755, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1755, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_imagpart && (tEmPcast)->kind <= postkind_imagpart)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_imagpart && (tEmPcast)->kind <= postkind_imagpart)", "AST_defs.c", 1755, __PRETTY_FUNCTION__), 0))); (imagpart)(tEmPcast); }); }
address_of address_of_chain(address_of l1, address_of l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1758, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1758, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_address_of && (tEmPcast)->kind <= postkind_address_of)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_address_of && (tEmPcast)->kind <= postkind_address_of)", "AST_defs.c", 1758, __PRETTY_FUNCTION__), 0))); (address_of)(tEmPcast); }); }
unary_minus unary_minus_chain(unary_minus l1, unary_minus l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1761, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1761, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_unary_minus && (tEmPcast)->kind <= postkind_unary_minus)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_unary_minus && (tEmPcast)->kind <= postkind_unary_minus)", "AST_defs.c", 1761, __PRETTY_FUNCTION__), 0))); (unary_minus)(tEmPcast); }); }
unary_plus unary_plus_chain(unary_plus l1, unary_plus l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1764, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1764, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_unary_plus && (tEmPcast)->kind <= postkind_unary_plus)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_unary_plus && (tEmPcast)->kind <= postkind_unary_plus)", "AST_defs.c", 1764, __PRETTY_FUNCTION__), 0))); (unary_plus)(tEmPcast); }); }
conjugate conjugate_chain(conjugate l1, conjugate l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1767, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1767, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_conjugate && (tEmPcast)->kind <= postkind_conjugate)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_conjugate && (tEmPcast)->kind <= postkind_conjugate)", "AST_defs.c", 1767, __PRETTY_FUNCTION__), 0))); (conjugate)(tEmPcast); }); }
preincrement preincrement_chain(preincrement l1, preincrement l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1770, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1770, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_preincrement && (tEmPcast)->kind <= postkind_preincrement)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_preincrement && (tEmPcast)->kind <= postkind_preincrement)", "AST_defs.c", 1770, __PRETTY_FUNCTION__), 0))); (preincrement)(tEmPcast); }); }
predecrement predecrement_chain(predecrement l1, predecrement l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1773, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1773, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_predecrement && (tEmPcast)->kind <= postkind_predecrement)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_predecrement && (tEmPcast)->kind <= postkind_predecrement)", "AST_defs.c", 1773, __PRETTY_FUNCTION__), 0))); (predecrement)(tEmPcast); }); }
postincrement postincrement_chain(postincrement l1, postincrement l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1776, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1776, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_postincrement && (tEmPcast)->kind <= postkind_postincrement)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_postincrement && (tEmPcast)->kind <= postkind_postincrement)", "AST_defs.c", 1776, __PRETTY_FUNCTION__), 0))); (postincrement)(tEmPcast); }); }
postdecrement postdecrement_chain(postdecrement l1, postdecrement l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1779, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1779, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_postdecrement && (tEmPcast)->kind <= postkind_postdecrement)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_postdecrement && (tEmPcast)->kind <= postkind_postdecrement)", "AST_defs.c", 1779, __PRETTY_FUNCTION__), 0))); (postdecrement)(tEmPcast); }); }
bitnot bitnot_chain(bitnot l1, bitnot l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1782, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1782, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitnot && (tEmPcast)->kind <= postkind_bitnot)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitnot && (tEmPcast)->kind <= postkind_bitnot)", "AST_defs.c", 1782, __PRETTY_FUNCTION__), 0))); (bitnot)(tEmPcast); }); }
not not_chain(not l1, not l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1785, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1785, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_not && (tEmPcast)->kind <= postkind_not)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_not && (tEmPcast)->kind <= postkind_not)", "AST_defs.c", 1785, __PRETTY_FUNCTION__), 0))); (not)(tEmPcast); }); }
plus plus_chain(plus l1, plus l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1788, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1788, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_plus && (tEmPcast)->kind <= postkind_plus)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_plus && (tEmPcast)->kind <= postkind_plus)", "AST_defs.c", 1788, __PRETTY_FUNCTION__), 0))); (plus)(tEmPcast); }); }
minus minus_chain(minus l1, minus l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1791, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1791, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_minus && (tEmPcast)->kind <= postkind_minus)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_minus && (tEmPcast)->kind <= postkind_minus)", "AST_defs.c", 1791, __PRETTY_FUNCTION__), 0))); (minus)(tEmPcast); }); }
times times_chain(times l1, times l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1794, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1794, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_times && (tEmPcast)->kind <= postkind_times)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_times && (tEmPcast)->kind <= postkind_times)", "AST_defs.c", 1794, __PRETTY_FUNCTION__), 0))); (times)(tEmPcast); }); }
divide divide_chain(divide l1, divide l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1797, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1797, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_divide && (tEmPcast)->kind <= postkind_divide)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_divide && (tEmPcast)->kind <= postkind_divide)", "AST_defs.c", 1797, __PRETTY_FUNCTION__), 0))); (divide)(tEmPcast); }); }
modulo modulo_chain(modulo l1, modulo l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1800, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1800, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_modulo && (tEmPcast)->kind <= postkind_modulo)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_modulo && (tEmPcast)->kind <= postkind_modulo)", "AST_defs.c", 1800, __PRETTY_FUNCTION__), 0))); (modulo)(tEmPcast); }); }
lshift lshift_chain(lshift l1, lshift l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1803, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1803, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_lshift && (tEmPcast)->kind <= postkind_lshift)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_lshift && (tEmPcast)->kind <= postkind_lshift)", "AST_defs.c", 1803, __PRETTY_FUNCTION__), 0))); (lshift)(tEmPcast); }); }
rshift rshift_chain(rshift l1, rshift l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1806, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1806, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_rshift && (tEmPcast)->kind <= postkind_rshift)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_rshift && (tEmPcast)->kind <= postkind_rshift)", "AST_defs.c", 1806, __PRETTY_FUNCTION__), 0))); (rshift)(tEmPcast); }); }
leq leq_chain(leq l1, leq l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1809, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1809, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_leq && (tEmPcast)->kind <= postkind_leq)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_leq && (tEmPcast)->kind <= postkind_leq)", "AST_defs.c", 1809, __PRETTY_FUNCTION__), 0))); (leq)(tEmPcast); }); }
geq geq_chain(geq l1, geq l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1812, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1812, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_geq && (tEmPcast)->kind <= postkind_geq)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_geq && (tEmPcast)->kind <= postkind_geq)", "AST_defs.c", 1812, __PRETTY_FUNCTION__), 0))); (geq)(tEmPcast); }); }
lt lt_chain(lt l1, lt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1815, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1815, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_lt && (tEmPcast)->kind <= postkind_lt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_lt && (tEmPcast)->kind <= postkind_lt)", "AST_defs.c", 1815, __PRETTY_FUNCTION__), 0))); (lt)(tEmPcast); }); }
gt gt_chain(gt l1, gt l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1818, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1818, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_gt && (tEmPcast)->kind <= postkind_gt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_gt && (tEmPcast)->kind <= postkind_gt)", "AST_defs.c", 1818, __PRETTY_FUNCTION__), 0))); (gt)(tEmPcast); }); }
eq eq_chain(eq l1, eq l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1821, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1821, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_eq && (tEmPcast)->kind <= postkind_eq)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_eq && (tEmPcast)->kind <= postkind_eq)", "AST_defs.c", 1821, __PRETTY_FUNCTION__), 0))); (eq)(tEmPcast); }); }
ne ne_chain(ne l1, ne l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1824, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1824, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_ne && (tEmPcast)->kind <= postkind_ne)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_ne && (tEmPcast)->kind <= postkind_ne)", "AST_defs.c", 1824, __PRETTY_FUNCTION__), 0))); (ne)(tEmPcast); }); }
bitand bitand_chain(bitand l1, bitand l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1827, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1827, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitand && (tEmPcast)->kind <= postkind_bitand)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitand && (tEmPcast)->kind <= postkind_bitand)", "AST_defs.c", 1827, __PRETTY_FUNCTION__), 0))); (bitand)(tEmPcast); }); }
bitor bitor_chain(bitor l1, bitor l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1830, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1830, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitor && (tEmPcast)->kind <= postkind_bitor)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitor && (tEmPcast)->kind <= postkind_bitor)", "AST_defs.c", 1830, __PRETTY_FUNCTION__), 0))); (bitor)(tEmPcast); }); }
bitxor bitxor_chain(bitxor l1, bitxor l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1833, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1833, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitxor && (tEmPcast)->kind <= postkind_bitxor)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitxor && (tEmPcast)->kind <= postkind_bitxor)", "AST_defs.c", 1833, __PRETTY_FUNCTION__), 0))); (bitxor)(tEmPcast); }); }
andand andand_chain(andand l1, andand l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1836, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1836, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_andand && (tEmPcast)->kind <= postkind_andand)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_andand && (tEmPcast)->kind <= postkind_andand)", "AST_defs.c", 1836, __PRETTY_FUNCTION__), 0))); (andand)(tEmPcast); }); }
oror oror_chain(oror l1, oror l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1839, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1839, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_oror && (tEmPcast)->kind <= postkind_oror)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_oror && (tEmPcast)->kind <= postkind_oror)", "AST_defs.c", 1839, __PRETTY_FUNCTION__), 0))); (oror)(tEmPcast); }); }
assign assign_chain(assign l1, assign l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1842, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1842, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_assign && (tEmPcast)->kind <= postkind_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_assign && (tEmPcast)->kind <= postkind_assign)", "AST_defs.c", 1842, __PRETTY_FUNCTION__), 0))); (assign)(tEmPcast); }); }
plus_assign plus_assign_chain(plus_assign l1, plus_assign l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1845, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1845, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_plus_assign && (tEmPcast)->kind <= postkind_plus_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_plus_assign && (tEmPcast)->kind <= postkind_plus_assign)", "AST_defs.c", 1845, __PRETTY_FUNCTION__), 0))); (plus_assign)(tEmPcast); }); }
minus_assign minus_assign_chain(minus_assign l1, minus_assign l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1848, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1848, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_minus_assign && (tEmPcast)->kind <= postkind_minus_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_minus_assign && (tEmPcast)->kind <= postkind_minus_assign)", "AST_defs.c", 1848, __PRETTY_FUNCTION__), 0))); (minus_assign)(tEmPcast); }); }
times_assign times_assign_chain(times_assign l1, times_assign l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1851, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1851, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_times_assign && (tEmPcast)->kind <= postkind_times_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_times_assign && (tEmPcast)->kind <= postkind_times_assign)", "AST_defs.c", 1851, __PRETTY_FUNCTION__), 0))); (times_assign)(tEmPcast); }); }
divide_assign divide_assign_chain(divide_assign l1, divide_assign l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1854, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1854, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_divide_assign && (tEmPcast)->kind <= postkind_divide_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_divide_assign && (tEmPcast)->kind <= postkind_divide_assign)", "AST_defs.c", 1854, __PRETTY_FUNCTION__), 0))); (divide_assign)(tEmPcast); }); }
modulo_assign modulo_assign_chain(modulo_assign l1, modulo_assign l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1857, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1857, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_modulo_assign && (tEmPcast)->kind <= postkind_modulo_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_modulo_assign && (tEmPcast)->kind <= postkind_modulo_assign)", "AST_defs.c", 1857, __PRETTY_FUNCTION__), 0))); (modulo_assign)(tEmPcast); }); }
lshift_assign lshift_assign_chain(lshift_assign l1, lshift_assign l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1860, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1860, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_lshift_assign && (tEmPcast)->kind <= postkind_lshift_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_lshift_assign && (tEmPcast)->kind <= postkind_lshift_assign)", "AST_defs.c", 1860, __PRETTY_FUNCTION__), 0))); (lshift_assign)(tEmPcast); }); }
rshift_assign rshift_assign_chain(rshift_assign l1, rshift_assign l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1863, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1863, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_rshift_assign && (tEmPcast)->kind <= postkind_rshift_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_rshift_assign && (tEmPcast)->kind <= postkind_rshift_assign)", "AST_defs.c", 1863, __PRETTY_FUNCTION__), 0))); (rshift_assign)(tEmPcast); }); }
bitand_assign bitand_assign_chain(bitand_assign l1, bitand_assign l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1866, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1866, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitand_assign && (tEmPcast)->kind <= postkind_bitand_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitand_assign && (tEmPcast)->kind <= postkind_bitand_assign)", "AST_defs.c", 1866, __PRETTY_FUNCTION__), 0))); (bitand_assign)(tEmPcast); }); }
bitor_assign bitor_assign_chain(bitor_assign l1, bitor_assign l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1869, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1869, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitor_assign && (tEmPcast)->kind <= postkind_bitor_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitor_assign && (tEmPcast)->kind <= postkind_bitor_assign)", "AST_defs.c", 1869, __PRETTY_FUNCTION__), 0))); (bitor_assign)(tEmPcast); }); }
bitxor_assign bitxor_assign_chain(bitxor_assign l1, bitxor_assign l2)
{ return ({ast_generic tEmPcast = (ast_generic)(ast_chain(({ast_generic tEmPcast = (ast_generic)(l1); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1872, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }), ({ast_generic tEmPcast = (ast_generic)(l2); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST_defs.c", 1872, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); }))); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitxor_assign && (tEmPcast)->kind <= postkind_bitxor_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitxor_assign && (tEmPcast)->kind <= postkind_bitxor_assign)", "AST_defs.c", 1872, __PRETTY_FUNCTION__), 0))); (bitxor_assign)(tEmPcast); }); }
static void AST_set_parent(node *nptr, node parent)
{
  (*nptr)->parent = parent;
}
void set_parent(node *nptr, node parent)
{
  (*nptr)->parent = parent;
}
void set_parent_list(node *list, node parent)
{
  while (*list)
    {
      set_parent(list, parent);
      list = &(*list)->next;
    }
}
static void AST_set_parent_list(void *vnptr, node parent);
static void AST_set_parent1(node *nptr, node parent)
{
  node n = *nptr;
  if (parent)
    AST_set_parent(nptr, parent);
  switch (n->kind)
    {
case kind_node: break;
case kind_declaration: case kind_error_decl: break;
case kind_statement: case kind_error_stmt: break;
case kind_expression: case kind_error_expr: break;
case kind_type_element: break;
case kind_declarator: break;
case kind_label: break;
case kind_asm_decl: {
  asm_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_asm_decl && (tEmPcast)->kind <= postkind_asm_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_asm_decl && (tEmPcast)->kind <= postkind_asm_decl)", "AST_parent.c", 12, __PRETTY_FUNCTION__), 0))); (asm_decl)(tEmPcast); });
  AST_set_parent_list(&x->asm_stmt, n);
  break;
}
case kind_data_decl: {
  data_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_data_decl && (tEmPcast)->kind <= postkind_data_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_data_decl && (tEmPcast)->kind <= postkind_data_decl)", "AST_parent.c", 18, __PRETTY_FUNCTION__), 0))); (data_decl)(tEmPcast); });
  AST_set_parent_list(&x->modifiers, n);
  AST_set_parent_list(&x->attributes, n);
  AST_set_parent_list(&x->decls, n);
  break;
}
case kind_extension_decl: {
  extension_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_extension_decl && (tEmPcast)->kind <= postkind_extension_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_extension_decl && (tEmPcast)->kind <= postkind_extension_decl)", "AST_parent.c", 26, __PRETTY_FUNCTION__), 0))); (extension_decl)(tEmPcast); });
  AST_set_parent_list(&x->decl, n);
  break;
}
case kind_ellipsis_decl: {
  ellipsis_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_ellipsis_decl && (tEmPcast)->kind <= postkind_ellipsis_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_ellipsis_decl && (tEmPcast)->kind <= postkind_ellipsis_decl)", "AST_parent.c", 32, __PRETTY_FUNCTION__), 0))); (ellipsis_decl)(tEmPcast); });
  AST_set_parent_list(&x->qualifiers, n);
  break;
}
case kind_enumerator: {
  enumerator x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_enumerator && (tEmPcast)->kind <= postkind_enumerator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_enumerator && (tEmPcast)->kind <= postkind_enumerator)", "AST_parent.c", 38, __PRETTY_FUNCTION__), 0))); (enumerator)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  break;
}
case kind_oldidentifier_decl: break;
case kind_function_decl: {
  function_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_function_decl && (tEmPcast)->kind <= postkind_function_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_function_decl && (tEmPcast)->kind <= postkind_function_decl)", "AST_parent.c", 45, __PRETTY_FUNCTION__), 0))); (function_decl)(tEmPcast); });
  AST_set_parent_list(&x->declarator, n);
  AST_set_parent_list(&x->qualifiers, n);
  AST_set_parent_list(&x->attributes, n);
  AST_set_parent_list(&x->stmt, n);
  break;
}
case kind_implicit_decl: break;
case kind_variable_decl: {
  variable_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_variable_decl && (tEmPcast)->kind <= postkind_variable_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_variable_decl && (tEmPcast)->kind <= postkind_variable_decl)", "AST_parent.c", 55, __PRETTY_FUNCTION__), 0))); (variable_decl)(tEmPcast); });
  AST_set_parent_list(&x->declarator, n);
  AST_set_parent_list(&x->attributes, n);
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->asm_stmt, n);
  break;
}
case kind_field_decl: {
  field_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_field_decl && (tEmPcast)->kind <= postkind_field_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_field_decl && (tEmPcast)->kind <= postkind_field_decl)", "AST_parent.c", 64, __PRETTY_FUNCTION__), 0))); (field_decl)(tEmPcast); });
  AST_set_parent_list(&x->declarator, n);
  AST_set_parent_list(&x->attributes, n);
  AST_set_parent_list(&x->arg1, n);
  break;
}
case kind_asttype: {
  asttype x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_asttype && (tEmPcast)->kind <= postkind_asttype)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_asttype && (tEmPcast)->kind <= postkind_asttype)", "AST_parent.c", 72, __PRETTY_FUNCTION__), 0))); (asttype)(tEmPcast); });
  AST_set_parent_list(&x->declarator, n);
  AST_set_parent_list(&x->qualifiers, n);
  break;
}
case kind_typename: break;
case kind_type_variable: break;
case kind_typeof_expr: {
  typeof_expr x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_typeof_expr && (tEmPcast)->kind <= postkind_typeof_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_typeof_expr && (tEmPcast)->kind <= postkind_typeof_expr)", "AST_parent.c", 81, __PRETTY_FUNCTION__), 0))); (typeof_expr)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  break;
}
case kind_typeof_type: {
  typeof_type x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_typeof_type && (tEmPcast)->kind <= postkind_typeof_type)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_typeof_type && (tEmPcast)->kind <= postkind_typeof_type)", "AST_parent.c", 87, __PRETTY_FUNCTION__), 0))); (typeof_type)(tEmPcast); });
  AST_set_parent_list(&x->asttype, n);
  break;
}
case kind_attribute: {
  attribute x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_attribute && (tEmPcast)->kind <= postkind_attribute)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_attribute && (tEmPcast)->kind <= postkind_attribute)", "AST_parent.c", 93, __PRETTY_FUNCTION__), 0))); (attribute)(tEmPcast); });
  AST_set_parent_list(&x->word1, n);
  AST_set_parent_list(&x->word2, n);
  AST_set_parent_list(&x->args, n);
  break;
}
case kind_rid: break;
case kind_user_qual: break;
case kind_qualifier: break;
case kind_tag_ref: case kind_enum_ref: case kind_union_ref: case kind_struct_ref: {
  tag_ref x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_tag_ref && (tEmPcast)->kind <= postkind_tag_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_tag_ref && (tEmPcast)->kind <= postkind_tag_ref)", "AST_parent.c", 104, __PRETTY_FUNCTION__), 0))); (tag_ref)(tEmPcast); });
  AST_set_parent_list(&x->word1, n);
  AST_set_parent_list(&x->attributes, n);
  AST_set_parent_list(&x->fields, n);
  break;
}
case kind_function_declarator: {
  function_declarator x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_function_declarator && (tEmPcast)->kind <= postkind_function_declarator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_function_declarator && (tEmPcast)->kind <= postkind_function_declarator)", "AST_parent.c", 112, __PRETTY_FUNCTION__), 0))); (function_declarator)(tEmPcast); });
  AST_set_parent_list(&x->declarator, n);
  AST_set_parent_list(&x->parms, n);
  AST_set_parent_list(&x->qualifiers, n);
  break;
}
case kind_pointer_declarator: {
  pointer_declarator x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_pointer_declarator && (tEmPcast)->kind <= postkind_pointer_declarator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_pointer_declarator && (tEmPcast)->kind <= postkind_pointer_declarator)", "AST_parent.c", 120, __PRETTY_FUNCTION__), 0))); (pointer_declarator)(tEmPcast); });
  AST_set_parent_list(&x->declarator, n);
  AST_set_parent_list(&x->qualifiers, n);
  break;
}
case kind_array_declarator: {
  array_declarator x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_array_declarator && (tEmPcast)->kind <= postkind_array_declarator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_array_declarator && (tEmPcast)->kind <= postkind_array_declarator)", "AST_parent.c", 127, __PRETTY_FUNCTION__), 0))); (array_declarator)(tEmPcast); });
  AST_set_parent_list(&x->declarator, n);
  AST_set_parent_list(&x->arg1, n);
  break;
}
case kind_identifier_declarator: break;
case kind_asm_stmt: {
  asm_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_asm_stmt && (tEmPcast)->kind <= postkind_asm_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_asm_stmt && (tEmPcast)->kind <= postkind_asm_stmt)", "AST_parent.c", 135, __PRETTY_FUNCTION__), 0))); (asm_stmt)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->asm_operands1, n);
  AST_set_parent_list(&x->asm_operands2, n);
  AST_set_parent_list(&x->asm_clobbers, n);
  AST_set_parent_list(&x->qualifiers, n);
  break;
}
case kind_compound_stmt: {
  compound_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_compound_stmt && (tEmPcast)->kind <= postkind_compound_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_compound_stmt && (tEmPcast)->kind <= postkind_compound_stmt)", "AST_parent.c", 145, __PRETTY_FUNCTION__), 0))); (compound_stmt)(tEmPcast); });
  AST_set_parent_list(&x->id_labels, n);
  AST_set_parent_list(&x->decls, n);
  AST_set_parent_list(&x->stmts, n);
  break;
}
case kind_if_stmt: {
  if_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_if_stmt && (tEmPcast)->kind <= postkind_if_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_if_stmt && (tEmPcast)->kind <= postkind_if_stmt)", "AST_parent.c", 153, __PRETTY_FUNCTION__), 0))); (if_stmt)(tEmPcast); });
  AST_set_parent_list(&x->condition, n);
  AST_set_parent_list(&x->stmt1, n);
  AST_set_parent_list(&x->stmt2, n);
  break;
}
case kind_labeled_stmt: {
  labeled_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_labeled_stmt && (tEmPcast)->kind <= postkind_labeled_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_labeled_stmt && (tEmPcast)->kind <= postkind_labeled_stmt)", "AST_parent.c", 161, __PRETTY_FUNCTION__), 0))); (labeled_stmt)(tEmPcast); });
  AST_set_parent_list(&x->label, n);
  AST_set_parent_list(&x->stmt, n);
  break;
}
case kind_expression_stmt: {
  expression_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_expression_stmt && (tEmPcast)->kind <= postkind_expression_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_expression_stmt && (tEmPcast)->kind <= postkind_expression_stmt)", "AST_parent.c", 168, __PRETTY_FUNCTION__), 0))); (expression_stmt)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  break;
}
case kind_breakable_stmt: break;
case kind_conditional_stmt: case kind_dowhile_stmt: case kind_while_stmt: {
  conditional_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_conditional_stmt && (tEmPcast)->kind <= postkind_conditional_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_conditional_stmt && (tEmPcast)->kind <= postkind_conditional_stmt)", "AST_parent.c", 175, __PRETTY_FUNCTION__), 0))); (conditional_stmt)(tEmPcast); });
  AST_set_parent_list(&x->condition, n);
  AST_set_parent_list(&x->stmt, n);
  break;
}
case kind_switch_stmt: {
  switch_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_switch_stmt && (tEmPcast)->kind <= postkind_switch_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_switch_stmt && (tEmPcast)->kind <= postkind_switch_stmt)", "AST_parent.c", 182, __PRETTY_FUNCTION__), 0))); (switch_stmt)(tEmPcast); });
  AST_set_parent_list(&x->condition, n);
  AST_set_parent_list(&x->stmt, n);
  break;
}
case kind_for_stmt: {
  for_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_for_stmt && (tEmPcast)->kind <= postkind_for_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_for_stmt && (tEmPcast)->kind <= postkind_for_stmt)", "AST_parent.c", 189, __PRETTY_FUNCTION__), 0))); (for_stmt)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->arg2, n);
  AST_set_parent_list(&x->arg3, n);
  AST_set_parent_list(&x->stmt, n);
  break;
}
case kind_break_stmt: break;
case kind_continue_stmt: break;
case kind_return_stmt: {
  return_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_return_stmt && (tEmPcast)->kind <= postkind_return_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_return_stmt && (tEmPcast)->kind <= postkind_return_stmt)", "AST_parent.c", 200, __PRETTY_FUNCTION__), 0))); (return_stmt)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  break;
}
case kind_goto_stmt: {
  goto_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_goto_stmt && (tEmPcast)->kind <= postkind_goto_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_goto_stmt && (tEmPcast)->kind <= postkind_goto_stmt)", "AST_parent.c", 206, __PRETTY_FUNCTION__), 0))); (goto_stmt)(tEmPcast); });
  AST_set_parent_list(&x->id_label, n);
  break;
}
case kind_computed_goto_stmt: {
  computed_goto_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_computed_goto_stmt && (tEmPcast)->kind <= postkind_computed_goto_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_computed_goto_stmt && (tEmPcast)->kind <= postkind_computed_goto_stmt)", "AST_parent.c", 212, __PRETTY_FUNCTION__), 0))); (computed_goto_stmt)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  break;
}
case kind_empty_stmt: break;
case kind_assert_type_stmt: {
  assert_type_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_assert_type_stmt && (tEmPcast)->kind <= postkind_assert_type_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_assert_type_stmt && (tEmPcast)->kind <= postkind_assert_type_stmt)", "AST_parent.c", 219, __PRETTY_FUNCTION__), 0))); (assert_type_stmt)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->asttype, n);
  break;
}
case kind_change_type_stmt: {
  change_type_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_change_type_stmt && (tEmPcast)->kind <= postkind_change_type_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_change_type_stmt && (tEmPcast)->kind <= postkind_change_type_stmt)", "AST_parent.c", 226, __PRETTY_FUNCTION__), 0))); (change_type_stmt)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->asttype, n);
  break;
}
case kind_deep_restrict_stmt: {
  deep_restrict_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_deep_restrict_stmt && (tEmPcast)->kind <= postkind_deep_restrict_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_deep_restrict_stmt && (tEmPcast)->kind <= postkind_deep_restrict_stmt)", "AST_parent.c", 233, __PRETTY_FUNCTION__), 0))); (deep_restrict_stmt)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->stmt, n);
  break;
}
case kind_unary: case kind_not: case kind_bitnot: case kind_postdecrement: case kind_postincrement: case kind_predecrement: case kind_preincrement: case kind_conjugate: case kind_unary_plus: case kind_unary_minus: case kind_address_of: case kind_imagpart: case kind_realpart: case kind_alignof_expr: case kind_sizeof_expr: case kind_extension_expr: case kind_dereference: {
  unary x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_unary && (tEmPcast)->kind <= postkind_unary)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_unary && (tEmPcast)->kind <= postkind_unary)", "AST_parent.c", 240, __PRETTY_FUNCTION__), 0))); (unary)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  break;
}
case kind_binary: case kind_bitxor_assign: case kind_bitor_assign: case kind_bitand_assign: case kind_rshift_assign: case kind_lshift_assign: case kind_modulo_assign: case kind_divide_assign: case kind_times_assign: case kind_minus_assign: case kind_plus_assign: case kind_assign: case kind_oror: case kind_andand: case kind_bitxor: case kind_bitor: case kind_bitand: case kind_ne: case kind_eq: case kind_gt: case kind_lt: case kind_geq: case kind_leq: case kind_rshift: case kind_lshift: case kind_modulo: case kind_divide: case kind_times: case kind_minus: case kind_plus: {
  binary x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_binary && (tEmPcast)->kind <= postkind_binary)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_binary && (tEmPcast)->kind <= postkind_binary)", "AST_parent.c", 246, __PRETTY_FUNCTION__), 0))); (binary)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->arg2, n);
  break;
}
case kind_comma: {
  comma x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_comma && (tEmPcast)->kind <= postkind_comma)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_comma && (tEmPcast)->kind <= postkind_comma)", "AST_parent.c", 253, __PRETTY_FUNCTION__), 0))); (comma)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  break;
}
case kind_sizeof_type: {
  sizeof_type x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_sizeof_type && (tEmPcast)->kind <= postkind_sizeof_type)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_sizeof_type && (tEmPcast)->kind <= postkind_sizeof_type)", "AST_parent.c", 259, __PRETTY_FUNCTION__), 0))); (sizeof_type)(tEmPcast); });
  AST_set_parent_list(&x->asttype, n);
  break;
}
case kind_alignof_type: {
  alignof_type x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_alignof_type && (tEmPcast)->kind <= postkind_alignof_type)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_alignof_type && (tEmPcast)->kind <= postkind_alignof_type)", "AST_parent.c", 265, __PRETTY_FUNCTION__), 0))); (alignof_type)(tEmPcast); });
  AST_set_parent_list(&x->asttype, n);
  break;
}
case kind_label_address: {
  label_address x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_label_address && (tEmPcast)->kind <= postkind_label_address)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_label_address && (tEmPcast)->kind <= postkind_label_address)", "AST_parent.c", 271, __PRETTY_FUNCTION__), 0))); (label_address)(tEmPcast); });
  AST_set_parent_list(&x->id_label, n);
  break;
}
case kind_cast: {
  cast x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_cast && (tEmPcast)->kind <= postkind_cast)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_cast && (tEmPcast)->kind <= postkind_cast)", "AST_parent.c", 277, __PRETTY_FUNCTION__), 0))); (cast)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->asttype, n);
  break;
}
case kind_cast_list: {
  cast_list x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_cast_list && (tEmPcast)->kind <= postkind_cast_list)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_cast_list && (tEmPcast)->kind <= postkind_cast_list)", "AST_parent.c", 284, __PRETTY_FUNCTION__), 0))); (cast_list)(tEmPcast); });
  AST_set_parent_list(&x->asttype, n);
  AST_set_parent_list(&x->init_expr, n);
  break;
}
case kind_conditional: {
  conditional x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_conditional && (tEmPcast)->kind <= postkind_conditional)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_conditional && (tEmPcast)->kind <= postkind_conditional)", "AST_parent.c", 291, __PRETTY_FUNCTION__), 0))); (conditional)(tEmPcast); });
  AST_set_parent_list(&x->condition, n);
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->arg2, n);
  break;
}
case kind_identifier: break;
case kind_compound_expr: {
  compound_expr x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_compound_expr && (tEmPcast)->kind <= postkind_compound_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_compound_expr && (tEmPcast)->kind <= postkind_compound_expr)", "AST_parent.c", 300, __PRETTY_FUNCTION__), 0))); (compound_expr)(tEmPcast); });
  AST_set_parent_list(&x->stmt, n);
  break;
}
case kind_function_call: {
  function_call x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_function_call && (tEmPcast)->kind <= postkind_function_call)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_function_call && (tEmPcast)->kind <= postkind_function_call)", "AST_parent.c", 306, __PRETTY_FUNCTION__), 0))); (function_call)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->args, n);
  break;
}
case kind_array_ref: {
  array_ref x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_array_ref && (tEmPcast)->kind <= postkind_array_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_array_ref && (tEmPcast)->kind <= postkind_array_ref)", "AST_parent.c", 313, __PRETTY_FUNCTION__), 0))); (array_ref)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->arg2, n);
  break;
}
case kind_field_ref: {
  field_ref x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_field_ref && (tEmPcast)->kind <= postkind_field_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_field_ref && (tEmPcast)->kind <= postkind_field_ref)", "AST_parent.c", 320, __PRETTY_FUNCTION__), 0))); (field_ref)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  break;
}
case kind_init_list: {
  init_list x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_init_list && (tEmPcast)->kind <= postkind_init_list)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_init_list && (tEmPcast)->kind <= postkind_init_list)", "AST_parent.c", 326, __PRETTY_FUNCTION__), 0))); (init_list)(tEmPcast); });
  AST_set_parent_list(&x->args, n);
  break;
}
case kind_init_index: {
  init_index x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_init_index && (tEmPcast)->kind <= postkind_init_index)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_init_index && (tEmPcast)->kind <= postkind_init_index)", "AST_parent.c", 332, __PRETTY_FUNCTION__), 0))); (init_index)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->arg2, n);
  AST_set_parent_list(&x->init_expr, n);
  break;
}
case kind_init_field: {
  init_field x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_init_field && (tEmPcast)->kind <= postkind_init_field)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_init_field && (tEmPcast)->kind <= postkind_init_field)", "AST_parent.c", 340, __PRETTY_FUNCTION__), 0))); (init_field)(tEmPcast); });
  AST_set_parent_list(&x->word1, n);
  AST_set_parent_list(&x->init_expr, n);
  break;
}
case kind_lexical_cst: break;
case kind_string_cst: break;
case kind_string: {
  string x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_string && (tEmPcast)->kind <= postkind_string)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_string && (tEmPcast)->kind <= postkind_string)", "AST_parent.c", 349, __PRETTY_FUNCTION__), 0))); (string)(tEmPcast); });
  AST_set_parent_list(&x->strings, n);
  break;
}
case kind_id_label: break;
case kind_case_label: {
  case_label x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_case_label && (tEmPcast)->kind <= postkind_case_label)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_case_label && (tEmPcast)->kind <= postkind_case_label)", "AST_parent.c", 356, __PRETTY_FUNCTION__), 0))); (case_label)(tEmPcast); });
  AST_set_parent_list(&x->arg1, n);
  AST_set_parent_list(&x->arg2, n);
  break;
}
case kind_default_label: break;
case kind_word: break;
case kind_asm_operand: {
  asm_operand x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_asm_operand && (tEmPcast)->kind <= postkind_asm_operand)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_asm_operand && (tEmPcast)->kind <= postkind_asm_operand)", "AST_parent.c", 365, __PRETTY_FUNCTION__), 0))); (asm_operand)(tEmPcast); });
  AST_set_parent_list(&x->string, n);
  AST_set_parent_list(&x->arg1, n);
  break;
}
    default:
      ((void) ((0) ? 0 : (__assert_fail ("0", "AST.c", 152, __PRETTY_FUNCTION__), 0)));
    }
}
static void AST_set_parent_list(void *vnptr, node parent)
{
  node *nptr = ({ast_generic *tEmPcast = (ast_generic *)(vnptr); if (tEmPcast && *tEmPcast) ((void) ((((*tEmPcast)->kind >= kind_node && (*tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((*tEmPcast)->kind >= kind_node && (*tEmPcast)->kind <= postkind_node)", "AST.c", 158, __PRETTY_FUNCTION__), 0))); (node *)(tEmPcast); });
  while (*nptr)
    {
      AST_set_parent1(nptr, parent);
      nptr = &(*nptr)->next;
    }
}
void AST_set_parents(node n)
{
  AST_set_parent_list(&n, ((void *)0));
}
static void AST_print_list(int indent, void *vn);
static void pindent(int by)
{
  int i;
  for (i = 0; i < by; i++)
    putchar(' ');
}
static void AST_print1(int indent, node n)
{
  pindent(indent);
  indent += 1;
  switch (n->kind)
    {
    case kind_identifier: {
      identifier x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_identifier && (tEmPcast)->kind <= postkind_identifier)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_identifier && (tEmPcast)->kind <= postkind_identifier)", "AST.c", 192, __PRETTY_FUNCTION__), 0))); (identifier)(tEmPcast); });
      printf("identifier %s\n", x->ddecl->name);
      return;
    }
    case kind_lexical_cst: {
      lexical_cst x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_lexical_cst && (tEmPcast)->kind <= postkind_lexical_cst)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_lexical_cst && (tEmPcast)->kind <= postkind_lexical_cst)", "AST.c", 198, __PRETTY_FUNCTION__), 0))); (lexical_cst)(tEmPcast); });
      printf("lexical_cst %s\n", x->cstring.data);
      return;
    }
    case kind_string_cst: {
      string_cst x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_string_cst && (tEmPcast)->kind <= postkind_string_cst)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_string_cst && (tEmPcast)->kind <= postkind_string_cst)", "AST.c", 204, __PRETTY_FUNCTION__), 0))); (string_cst)(tEmPcast); });
      printf("string_cst %s\n", x->cstring.data);
      return;
    }
    case kind_id_label: {
      id_label x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_id_label && (tEmPcast)->kind <= postkind_id_label)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_id_label && (tEmPcast)->kind <= postkind_id_label)", "AST.c", 210, __PRETTY_FUNCTION__), 0))); (id_label)(tEmPcast); });
      printf("id_label %s\n", x->cstring.data);
      return;
    }
    case kind_identifier_declarator: {
      identifier_declarator x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_identifier_declarator && (tEmPcast)->kind <= postkind_identifier_declarator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_identifier_declarator && (tEmPcast)->kind <= postkind_identifier_declarator)", "AST.c", 216, __PRETTY_FUNCTION__), 0))); (identifier_declarator)(tEmPcast); });
      printf("identifier_declarator %s\n", x->cstring.data);
      return;
    }
    case kind_word: {
      word x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_word && (tEmPcast)->kind <= postkind_word)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_word && (tEmPcast)->kind <= postkind_word)", "AST.c", 222, __PRETTY_FUNCTION__), 0))); (word)(tEmPcast); });
      printf("word %s\n", x->cstring.data);
      return;
    }
    case kind_rid: {
      rid x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_rid && (tEmPcast)->kind <= postkind_rid)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_rid && (tEmPcast)->kind <= postkind_rid)", "AST.c", 228, __PRETTY_FUNCTION__), 0))); (rid)(tEmPcast); });
      printf("rid %s\n", rid_name(x));
      return;
    }
    default:
      break;
    }
  switch (n->kind)
    {
case kind_node: puts("node"); break;
case kind_declaration: puts("declaration"); break;
case kind_statement: puts("statement"); break;
case kind_expression: puts("expression"); break;
case kind_type_element: puts("type_element"); break;
case kind_declarator: puts("declarator"); break;
case kind_label: puts("label"); break;
case kind_asm_decl: {
  asm_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_asm_decl && (tEmPcast)->kind <= postkind_asm_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_asm_decl && (tEmPcast)->kind <= postkind_asm_decl)", "AST_print.c", 12, __PRETTY_FUNCTION__), 0))); (asm_decl)(tEmPcast); });
  puts("asm_decl");
  pindent(indent); puts("asm_stmt:"); AST_print_list(indent + 1, x->asm_stmt);
  break;
}
case kind_data_decl: {
  data_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_data_decl && (tEmPcast)->kind <= postkind_data_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_data_decl && (tEmPcast)->kind <= postkind_data_decl)", "AST_print.c", 19, __PRETTY_FUNCTION__), 0))); (data_decl)(tEmPcast); });
  puts("data_decl");
  pindent(indent); puts("modifiers:"); AST_print_list(indent + 1, x->modifiers);
  pindent(indent); puts("attributes:"); AST_print_list(indent + 1, x->attributes);
  pindent(indent); puts("decls:"); AST_print_list(indent + 1, x->decls);
  break;
}
case kind_extension_decl: {
  extension_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_extension_decl && (tEmPcast)->kind <= postkind_extension_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_extension_decl && (tEmPcast)->kind <= postkind_extension_decl)", "AST_print.c", 28, __PRETTY_FUNCTION__), 0))); (extension_decl)(tEmPcast); });
  puts("extension_decl");
  pindent(indent); puts("decl:"); AST_print_list(indent + 1, x->decl);
  break;
}
case kind_ellipsis_decl: {
  ellipsis_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_ellipsis_decl && (tEmPcast)->kind <= postkind_ellipsis_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_ellipsis_decl && (tEmPcast)->kind <= postkind_ellipsis_decl)", "AST_print.c", 35, __PRETTY_FUNCTION__), 0))); (ellipsis_decl)(tEmPcast); });
  puts("ellipsis_decl");
  pindent(indent); puts("qualifiers:"); AST_print_list(indent + 1, x->qualifiers);
  break;
}
case kind_enumerator: {
  enumerator x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_enumerator && (tEmPcast)->kind <= postkind_enumerator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_enumerator && (tEmPcast)->kind <= postkind_enumerator)", "AST_print.c", 42, __PRETTY_FUNCTION__), 0))); (enumerator)(tEmPcast); });
  puts("enumerator");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_oldidentifier_decl: puts("oldidentifier_decl"); break;
case kind_function_decl: {
  function_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_function_decl && (tEmPcast)->kind <= postkind_function_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_function_decl && (tEmPcast)->kind <= postkind_function_decl)", "AST_print.c", 50, __PRETTY_FUNCTION__), 0))); (function_decl)(tEmPcast); });
  puts("function_decl");
  pindent(indent); puts("declarator:"); AST_print_list(indent + 1, x->declarator);
  pindent(indent); puts("qualifiers:"); AST_print_list(indent + 1, x->qualifiers);
  pindent(indent); puts("attributes:"); AST_print_list(indent + 1, x->attributes);
  pindent(indent); puts("stmt:"); AST_print_list(indent + 1, x->stmt);
  break;
}
case kind_implicit_decl: puts("implicit_decl"); break;
case kind_variable_decl: {
  variable_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_variable_decl && (tEmPcast)->kind <= postkind_variable_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_variable_decl && (tEmPcast)->kind <= postkind_variable_decl)", "AST_print.c", 61, __PRETTY_FUNCTION__), 0))); (variable_decl)(tEmPcast); });
  puts("variable_decl");
  pindent(indent); puts("declarator:"); AST_print_list(indent + 1, x->declarator);
  pindent(indent); puts("attributes:"); AST_print_list(indent + 1, x->attributes);
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("asm_stmt:"); AST_print_list(indent + 1, x->asm_stmt);
  break;
}
case kind_field_decl: {
  field_decl x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_field_decl && (tEmPcast)->kind <= postkind_field_decl)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_field_decl && (tEmPcast)->kind <= postkind_field_decl)", "AST_print.c", 71, __PRETTY_FUNCTION__), 0))); (field_decl)(tEmPcast); });
  puts("field_decl");
  pindent(indent); puts("declarator:"); AST_print_list(indent + 1, x->declarator);
  pindent(indent); puts("attributes:"); AST_print_list(indent + 1, x->attributes);
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_asttype: {
  asttype x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_asttype && (tEmPcast)->kind <= postkind_asttype)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_asttype && (tEmPcast)->kind <= postkind_asttype)", "AST_print.c", 80, __PRETTY_FUNCTION__), 0))); (asttype)(tEmPcast); });
  puts("asttype");
  pindent(indent); puts("declarator:"); AST_print_list(indent + 1, x->declarator);
  pindent(indent); puts("qualifiers:"); AST_print_list(indent + 1, x->qualifiers);
  break;
}
case kind_typename: puts("typename"); break;
case kind_type_variable: puts("type_variable"); break;
case kind_typeof_expr: {
  typeof_expr x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_typeof_expr && (tEmPcast)->kind <= postkind_typeof_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_typeof_expr && (tEmPcast)->kind <= postkind_typeof_expr)", "AST_print.c", 90, __PRETTY_FUNCTION__), 0))); (typeof_expr)(tEmPcast); });
  puts("typeof_expr");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_typeof_type: {
  typeof_type x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_typeof_type && (tEmPcast)->kind <= postkind_typeof_type)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_typeof_type && (tEmPcast)->kind <= postkind_typeof_type)", "AST_print.c", 97, __PRETTY_FUNCTION__), 0))); (typeof_type)(tEmPcast); });
  puts("typeof_type");
  pindent(indent); puts("asttype:"); AST_print_list(indent + 1, x->asttype);
  break;
}
case kind_attribute: {
  attribute x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_attribute && (tEmPcast)->kind <= postkind_attribute)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_attribute && (tEmPcast)->kind <= postkind_attribute)", "AST_print.c", 104, __PRETTY_FUNCTION__), 0))); (attribute)(tEmPcast); });
  puts("attribute");
  pindent(indent); puts("word1:"); AST_print_list(indent + 1, x->word1);
  pindent(indent); puts("word2:"); AST_print_list(indent + 1, x->word2);
  pindent(indent); puts("args:"); AST_print_list(indent + 1, x->args);
  break;
}
case kind_rid: puts("rid"); break;
case kind_user_qual: puts("user_qual"); break;
case kind_qualifier: puts("qualifier"); break;
case kind_tag_ref: {
  tag_ref x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_tag_ref && (tEmPcast)->kind <= postkind_tag_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_tag_ref && (tEmPcast)->kind <= postkind_tag_ref)", "AST_print.c", 116, __PRETTY_FUNCTION__), 0))); (tag_ref)(tEmPcast); });
  puts("tag_ref");
  pindent(indent); puts("word1:"); AST_print_list(indent + 1, x->word1);
  pindent(indent); puts("attributes:"); AST_print_list(indent + 1, x->attributes);
  pindent(indent); puts("fields:"); AST_print_list(indent + 1, x->fields);
  break;
}
case kind_function_declarator: {
  function_declarator x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_function_declarator && (tEmPcast)->kind <= postkind_function_declarator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_function_declarator && (tEmPcast)->kind <= postkind_function_declarator)", "AST_print.c", 125, __PRETTY_FUNCTION__), 0))); (function_declarator)(tEmPcast); });
  puts("function_declarator");
  pindent(indent); puts("declarator:"); AST_print_list(indent + 1, x->declarator);
  pindent(indent); puts("parms:"); AST_print_list(indent + 1, x->parms);
  pindent(indent); puts("qualifiers:"); AST_print_list(indent + 1, x->qualifiers);
  break;
}
case kind_pointer_declarator: {
  pointer_declarator x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_pointer_declarator && (tEmPcast)->kind <= postkind_pointer_declarator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_pointer_declarator && (tEmPcast)->kind <= postkind_pointer_declarator)", "AST_print.c", 134, __PRETTY_FUNCTION__), 0))); (pointer_declarator)(tEmPcast); });
  puts("pointer_declarator");
  pindent(indent); puts("declarator:"); AST_print_list(indent + 1, x->declarator);
  pindent(indent); puts("qualifiers:"); AST_print_list(indent + 1, x->qualifiers);
  break;
}
case kind_array_declarator: {
  array_declarator x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_array_declarator && (tEmPcast)->kind <= postkind_array_declarator)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_array_declarator && (tEmPcast)->kind <= postkind_array_declarator)", "AST_print.c", 142, __PRETTY_FUNCTION__), 0))); (array_declarator)(tEmPcast); });
  puts("array_declarator");
  pindent(indent); puts("declarator:"); AST_print_list(indent + 1, x->declarator);
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_identifier_declarator: puts("identifier_declarator"); break;
case kind_asm_stmt: {
  asm_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_asm_stmt && (tEmPcast)->kind <= postkind_asm_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_asm_stmt && (tEmPcast)->kind <= postkind_asm_stmt)", "AST_print.c", 151, __PRETTY_FUNCTION__), 0))); (asm_stmt)(tEmPcast); });
  puts("asm_stmt");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("asm_operands1:"); AST_print_list(indent + 1, x->asm_operands1);
  pindent(indent); puts("asm_operands2:"); AST_print_list(indent + 1, x->asm_operands2);
  pindent(indent); puts("asm_clobbers:"); AST_print_list(indent + 1, x->asm_clobbers);
  pindent(indent); puts("qualifiers:"); AST_print_list(indent + 1, x->qualifiers);
  break;
}
case kind_compound_stmt: {
  compound_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_compound_stmt && (tEmPcast)->kind <= postkind_compound_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_compound_stmt && (tEmPcast)->kind <= postkind_compound_stmt)", "AST_print.c", 162, __PRETTY_FUNCTION__), 0))); (compound_stmt)(tEmPcast); });
  puts("compound_stmt");
  pindent(indent); puts("id_labels:"); AST_print_list(indent + 1, x->id_labels);
  pindent(indent); puts("decls:"); AST_print_list(indent + 1, x->decls);
  pindent(indent); puts("stmts:"); AST_print_list(indent + 1, x->stmts);
  break;
}
case kind_if_stmt: {
  if_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_if_stmt && (tEmPcast)->kind <= postkind_if_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_if_stmt && (tEmPcast)->kind <= postkind_if_stmt)", "AST_print.c", 171, __PRETTY_FUNCTION__), 0))); (if_stmt)(tEmPcast); });
  puts("if_stmt");
  pindent(indent); puts("condition:"); AST_print_list(indent + 1, x->condition);
  pindent(indent); puts("stmt1:"); AST_print_list(indent + 1, x->stmt1);
  pindent(indent); puts("stmt2:"); AST_print_list(indent + 1, x->stmt2);
  break;
}
case kind_labeled_stmt: {
  labeled_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_labeled_stmt && (tEmPcast)->kind <= postkind_labeled_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_labeled_stmt && (tEmPcast)->kind <= postkind_labeled_stmt)", "AST_print.c", 180, __PRETTY_FUNCTION__), 0))); (labeled_stmt)(tEmPcast); });
  puts("labeled_stmt");
  pindent(indent); puts("label:"); AST_print_list(indent + 1, x->label);
  pindent(indent); puts("stmt:"); AST_print_list(indent + 1, x->stmt);
  break;
}
case kind_expression_stmt: {
  expression_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_expression_stmt && (tEmPcast)->kind <= postkind_expression_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_expression_stmt && (tEmPcast)->kind <= postkind_expression_stmt)", "AST_print.c", 188, __PRETTY_FUNCTION__), 0))); (expression_stmt)(tEmPcast); });
  puts("expression_stmt");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_breakable_stmt: puts("breakable_stmt"); break;
case kind_conditional_stmt: {
  conditional_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_conditional_stmt && (tEmPcast)->kind <= postkind_conditional_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_conditional_stmt && (tEmPcast)->kind <= postkind_conditional_stmt)", "AST_print.c", 196, __PRETTY_FUNCTION__), 0))); (conditional_stmt)(tEmPcast); });
  puts("conditional_stmt");
  pindent(indent); puts("condition:"); AST_print_list(indent + 1, x->condition);
  pindent(indent); puts("stmt:"); AST_print_list(indent + 1, x->stmt);
  break;
}
case kind_switch_stmt: {
  switch_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_switch_stmt && (tEmPcast)->kind <= postkind_switch_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_switch_stmt && (tEmPcast)->kind <= postkind_switch_stmt)", "AST_print.c", 204, __PRETTY_FUNCTION__), 0))); (switch_stmt)(tEmPcast); });
  puts("switch_stmt");
  pindent(indent); puts("condition:"); AST_print_list(indent + 1, x->condition);
  pindent(indent); puts("stmt:"); AST_print_list(indent + 1, x->stmt);
  break;
}
case kind_for_stmt: {
  for_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_for_stmt && (tEmPcast)->kind <= postkind_for_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_for_stmt && (tEmPcast)->kind <= postkind_for_stmt)", "AST_print.c", 212, __PRETTY_FUNCTION__), 0))); (for_stmt)(tEmPcast); });
  puts("for_stmt");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  pindent(indent); puts("arg3:"); AST_print_list(indent + 1, x->arg3);
  pindent(indent); puts("stmt:"); AST_print_list(indent + 1, x->stmt);
  break;
}
case kind_break_stmt: puts("break_stmt"); break;
case kind_continue_stmt: puts("continue_stmt"); break;
case kind_return_stmt: {
  return_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_return_stmt && (tEmPcast)->kind <= postkind_return_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_return_stmt && (tEmPcast)->kind <= postkind_return_stmt)", "AST_print.c", 224, __PRETTY_FUNCTION__), 0))); (return_stmt)(tEmPcast); });
  puts("return_stmt");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_goto_stmt: {
  goto_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_goto_stmt && (tEmPcast)->kind <= postkind_goto_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_goto_stmt && (tEmPcast)->kind <= postkind_goto_stmt)", "AST_print.c", 231, __PRETTY_FUNCTION__), 0))); (goto_stmt)(tEmPcast); });
  puts("goto_stmt");
  pindent(indent); puts("id_label:"); AST_print_list(indent + 1, x->id_label);
  break;
}
case kind_computed_goto_stmt: {
  computed_goto_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_computed_goto_stmt && (tEmPcast)->kind <= postkind_computed_goto_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_computed_goto_stmt && (tEmPcast)->kind <= postkind_computed_goto_stmt)", "AST_print.c", 238, __PRETTY_FUNCTION__), 0))); (computed_goto_stmt)(tEmPcast); });
  puts("computed_goto_stmt");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_empty_stmt: puts("empty_stmt"); break;
case kind_assert_type_stmt: {
  assert_type_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_assert_type_stmt && (tEmPcast)->kind <= postkind_assert_type_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_assert_type_stmt && (tEmPcast)->kind <= postkind_assert_type_stmt)", "AST_print.c", 246, __PRETTY_FUNCTION__), 0))); (assert_type_stmt)(tEmPcast); });
  puts("assert_type_stmt");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("asttype:"); AST_print_list(indent + 1, x->asttype);
  break;
}
case kind_change_type_stmt: {
  change_type_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_change_type_stmt && (tEmPcast)->kind <= postkind_change_type_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_change_type_stmt && (tEmPcast)->kind <= postkind_change_type_stmt)", "AST_print.c", 254, __PRETTY_FUNCTION__), 0))); (change_type_stmt)(tEmPcast); });
  puts("change_type_stmt");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("asttype:"); AST_print_list(indent + 1, x->asttype);
  break;
}
case kind_deep_restrict_stmt: {
  deep_restrict_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_deep_restrict_stmt && (tEmPcast)->kind <= postkind_deep_restrict_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_deep_restrict_stmt && (tEmPcast)->kind <= postkind_deep_restrict_stmt)", "AST_print.c", 262, __PRETTY_FUNCTION__), 0))); (deep_restrict_stmt)(tEmPcast); });
  puts("deep_restrict_stmt");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("stmt:"); AST_print_list(indent + 1, x->stmt);
  break;
}
case kind_unary: {
  unary x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_unary && (tEmPcast)->kind <= postkind_unary)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_unary && (tEmPcast)->kind <= postkind_unary)", "AST_print.c", 270, __PRETTY_FUNCTION__), 0))); (unary)(tEmPcast); });
  puts("unary");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_binary: {
  binary x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_binary && (tEmPcast)->kind <= postkind_binary)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_binary && (tEmPcast)->kind <= postkind_binary)", "AST_print.c", 277, __PRETTY_FUNCTION__), 0))); (binary)(tEmPcast); });
  puts("binary");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_comma: {
  comma x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_comma && (tEmPcast)->kind <= postkind_comma)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_comma && (tEmPcast)->kind <= postkind_comma)", "AST_print.c", 285, __PRETTY_FUNCTION__), 0))); (comma)(tEmPcast); });
  puts("comma");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_sizeof_type: {
  sizeof_type x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_sizeof_type && (tEmPcast)->kind <= postkind_sizeof_type)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_sizeof_type && (tEmPcast)->kind <= postkind_sizeof_type)", "AST_print.c", 292, __PRETTY_FUNCTION__), 0))); (sizeof_type)(tEmPcast); });
  puts("sizeof_type");
  pindent(indent); puts("asttype:"); AST_print_list(indent + 1, x->asttype);
  break;
}
case kind_alignof_type: {
  alignof_type x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_alignof_type && (tEmPcast)->kind <= postkind_alignof_type)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_alignof_type && (tEmPcast)->kind <= postkind_alignof_type)", "AST_print.c", 299, __PRETTY_FUNCTION__), 0))); (alignof_type)(tEmPcast); });
  puts("alignof_type");
  pindent(indent); puts("asttype:"); AST_print_list(indent + 1, x->asttype);
  break;
}
case kind_label_address: {
  label_address x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_label_address && (tEmPcast)->kind <= postkind_label_address)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_label_address && (tEmPcast)->kind <= postkind_label_address)", "AST_print.c", 306, __PRETTY_FUNCTION__), 0))); (label_address)(tEmPcast); });
  puts("label_address");
  pindent(indent); puts("id_label:"); AST_print_list(indent + 1, x->id_label);
  break;
}
case kind_cast: {
  cast x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_cast && (tEmPcast)->kind <= postkind_cast)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_cast && (tEmPcast)->kind <= postkind_cast)", "AST_print.c", 313, __PRETTY_FUNCTION__), 0))); (cast)(tEmPcast); });
  puts("cast");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("asttype:"); AST_print_list(indent + 1, x->asttype);
  break;
}
case kind_cast_list: {
  cast_list x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_cast_list && (tEmPcast)->kind <= postkind_cast_list)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_cast_list && (tEmPcast)->kind <= postkind_cast_list)", "AST_print.c", 321, __PRETTY_FUNCTION__), 0))); (cast_list)(tEmPcast); });
  puts("cast_list");
  pindent(indent); puts("asttype:"); AST_print_list(indent + 1, x->asttype);
  pindent(indent); puts("init_expr:"); AST_print_list(indent + 1, x->init_expr);
  break;
}
case kind_conditional: {
  conditional x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_conditional && (tEmPcast)->kind <= postkind_conditional)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_conditional && (tEmPcast)->kind <= postkind_conditional)", "AST_print.c", 329, __PRETTY_FUNCTION__), 0))); (conditional)(tEmPcast); });
  puts("conditional");
  pindent(indent); puts("condition:"); AST_print_list(indent + 1, x->condition);
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_identifier: puts("identifier"); break;
case kind_compound_expr: {
  compound_expr x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_compound_expr && (tEmPcast)->kind <= postkind_compound_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_compound_expr && (tEmPcast)->kind <= postkind_compound_expr)", "AST_print.c", 339, __PRETTY_FUNCTION__), 0))); (compound_expr)(tEmPcast); });
  puts("compound_expr");
  pindent(indent); puts("stmt:"); AST_print_list(indent + 1, x->stmt);
  break;
}
case kind_function_call: {
  function_call x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_function_call && (tEmPcast)->kind <= postkind_function_call)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_function_call && (tEmPcast)->kind <= postkind_function_call)", "AST_print.c", 346, __PRETTY_FUNCTION__), 0))); (function_call)(tEmPcast); });
  puts("function_call");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("args:"); AST_print_list(indent + 1, x->args);
  break;
}
case kind_array_ref: {
  array_ref x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_array_ref && (tEmPcast)->kind <= postkind_array_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_array_ref && (tEmPcast)->kind <= postkind_array_ref)", "AST_print.c", 354, __PRETTY_FUNCTION__), 0))); (array_ref)(tEmPcast); });
  puts("array_ref");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_field_ref: {
  field_ref x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_field_ref && (tEmPcast)->kind <= postkind_field_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_field_ref && (tEmPcast)->kind <= postkind_field_ref)", "AST_print.c", 362, __PRETTY_FUNCTION__), 0))); (field_ref)(tEmPcast); });
  puts("field_ref");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_init_list: {
  init_list x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_init_list && (tEmPcast)->kind <= postkind_init_list)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_init_list && (tEmPcast)->kind <= postkind_init_list)", "AST_print.c", 369, __PRETTY_FUNCTION__), 0))); (init_list)(tEmPcast); });
  puts("init_list");
  pindent(indent); puts("args:"); AST_print_list(indent + 1, x->args);
  break;
}
case kind_init_index: {
  init_index x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_init_index && (tEmPcast)->kind <= postkind_init_index)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_init_index && (tEmPcast)->kind <= postkind_init_index)", "AST_print.c", 376, __PRETTY_FUNCTION__), 0))); (init_index)(tEmPcast); });
  puts("init_index");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  pindent(indent); puts("init_expr:"); AST_print_list(indent + 1, x->init_expr);
  break;
}
case kind_init_field: {
  init_field x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_init_field && (tEmPcast)->kind <= postkind_init_field)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_init_field && (tEmPcast)->kind <= postkind_init_field)", "AST_print.c", 385, __PRETTY_FUNCTION__), 0))); (init_field)(tEmPcast); });
  puts("init_field");
  pindent(indent); puts("word1:"); AST_print_list(indent + 1, x->word1);
  pindent(indent); puts("init_expr:"); AST_print_list(indent + 1, x->init_expr);
  break;
}
case kind_lexical_cst: puts("lexical_cst"); break;
case kind_string_cst: puts("string_cst"); break;
case kind_string: {
  string x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_string && (tEmPcast)->kind <= postkind_string)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_string && (tEmPcast)->kind <= postkind_string)", "AST_print.c", 395, __PRETTY_FUNCTION__), 0))); (string)(tEmPcast); });
  puts("string");
  pindent(indent); puts("strings:"); AST_print_list(indent + 1, x->strings);
  break;
}
case kind_id_label: puts("id_label"); break;
case kind_case_label: {
  case_label x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_case_label && (tEmPcast)->kind <= postkind_case_label)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_case_label && (tEmPcast)->kind <= postkind_case_label)", "AST_print.c", 403, __PRETTY_FUNCTION__), 0))); (case_label)(tEmPcast); });
  puts("case_label");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_default_label: puts("default_label"); break;
case kind_word: puts("word"); break;
case kind_asm_operand: {
  asm_operand x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_asm_operand && (tEmPcast)->kind <= postkind_asm_operand)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_asm_operand && (tEmPcast)->kind <= postkind_asm_operand)", "AST_print.c", 413, __PRETTY_FUNCTION__), 0))); (asm_operand)(tEmPcast); });
  puts("asm_operand");
  pindent(indent); puts("string:"); AST_print_list(indent + 1, x->string);
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_error_decl: puts("error_decl"); break;
case kind_struct_ref: {
  struct_ref x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_struct_ref && (tEmPcast)->kind <= postkind_struct_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_struct_ref && (tEmPcast)->kind <= postkind_struct_ref)", "AST_print.c", 422, __PRETTY_FUNCTION__), 0))); (struct_ref)(tEmPcast); });
  puts("struct_ref");
  pindent(indent); puts("word1:"); AST_print_list(indent + 1, x->word1);
  pindent(indent); puts("attributes:"); AST_print_list(indent + 1, x->attributes);
  pindent(indent); puts("fields:"); AST_print_list(indent + 1, x->fields);
  break;
}
case kind_union_ref: {
  union_ref x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_union_ref && (tEmPcast)->kind <= postkind_union_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_union_ref && (tEmPcast)->kind <= postkind_union_ref)", "AST_print.c", 431, __PRETTY_FUNCTION__), 0))); (union_ref)(tEmPcast); });
  puts("union_ref");
  pindent(indent); puts("word1:"); AST_print_list(indent + 1, x->word1);
  pindent(indent); puts("attributes:"); AST_print_list(indent + 1, x->attributes);
  pindent(indent); puts("fields:"); AST_print_list(indent + 1, x->fields);
  break;
}
case kind_enum_ref: {
  enum_ref x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_enum_ref && (tEmPcast)->kind <= postkind_enum_ref)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_enum_ref && (tEmPcast)->kind <= postkind_enum_ref)", "AST_print.c", 440, __PRETTY_FUNCTION__), 0))); (enum_ref)(tEmPcast); });
  puts("enum_ref");
  pindent(indent); puts("word1:"); AST_print_list(indent + 1, x->word1);
  pindent(indent); puts("attributes:"); AST_print_list(indent + 1, x->attributes);
  pindent(indent); puts("fields:"); AST_print_list(indent + 1, x->fields);
  break;
}
case kind_error_stmt: puts("error_stmt"); break;
case kind_while_stmt: {
  while_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_while_stmt && (tEmPcast)->kind <= postkind_while_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_while_stmt && (tEmPcast)->kind <= postkind_while_stmt)", "AST_print.c", 450, __PRETTY_FUNCTION__), 0))); (while_stmt)(tEmPcast); });
  puts("while_stmt");
  pindent(indent); puts("condition:"); AST_print_list(indent + 1, x->condition);
  pindent(indent); puts("stmt:"); AST_print_list(indent + 1, x->stmt);
  break;
}
case kind_dowhile_stmt: {
  dowhile_stmt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_dowhile_stmt && (tEmPcast)->kind <= postkind_dowhile_stmt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_dowhile_stmt && (tEmPcast)->kind <= postkind_dowhile_stmt)", "AST_print.c", 458, __PRETTY_FUNCTION__), 0))); (dowhile_stmt)(tEmPcast); });
  puts("dowhile_stmt");
  pindent(indent); puts("condition:"); AST_print_list(indent + 1, x->condition);
  pindent(indent); puts("stmt:"); AST_print_list(indent + 1, x->stmt);
  break;
}
case kind_error_expr: puts("error_expr"); break;
case kind_dereference: {
  dereference x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_dereference && (tEmPcast)->kind <= postkind_dereference)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_dereference && (tEmPcast)->kind <= postkind_dereference)", "AST_print.c", 467, __PRETTY_FUNCTION__), 0))); (dereference)(tEmPcast); });
  puts("dereference");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_extension_expr: {
  extension_expr x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_extension_expr && (tEmPcast)->kind <= postkind_extension_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_extension_expr && (tEmPcast)->kind <= postkind_extension_expr)", "AST_print.c", 474, __PRETTY_FUNCTION__), 0))); (extension_expr)(tEmPcast); });
  puts("extension_expr");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_sizeof_expr: {
  sizeof_expr x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_sizeof_expr && (tEmPcast)->kind <= postkind_sizeof_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_sizeof_expr && (tEmPcast)->kind <= postkind_sizeof_expr)", "AST_print.c", 481, __PRETTY_FUNCTION__), 0))); (sizeof_expr)(tEmPcast); });
  puts("sizeof_expr");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_alignof_expr: {
  alignof_expr x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_alignof_expr && (tEmPcast)->kind <= postkind_alignof_expr)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_alignof_expr && (tEmPcast)->kind <= postkind_alignof_expr)", "AST_print.c", 488, __PRETTY_FUNCTION__), 0))); (alignof_expr)(tEmPcast); });
  puts("alignof_expr");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_realpart: {
  realpart x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_realpart && (tEmPcast)->kind <= postkind_realpart)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_realpart && (tEmPcast)->kind <= postkind_realpart)", "AST_print.c", 495, __PRETTY_FUNCTION__), 0))); (realpart)(tEmPcast); });
  puts("realpart");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_imagpart: {
  imagpart x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_imagpart && (tEmPcast)->kind <= postkind_imagpart)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_imagpart && (tEmPcast)->kind <= postkind_imagpart)", "AST_print.c", 502, __PRETTY_FUNCTION__), 0))); (imagpart)(tEmPcast); });
  puts("imagpart");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_address_of: {
  address_of x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_address_of && (tEmPcast)->kind <= postkind_address_of)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_address_of && (tEmPcast)->kind <= postkind_address_of)", "AST_print.c", 509, __PRETTY_FUNCTION__), 0))); (address_of)(tEmPcast); });
  puts("address_of");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_unary_minus: {
  unary_minus x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_unary_minus && (tEmPcast)->kind <= postkind_unary_minus)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_unary_minus && (tEmPcast)->kind <= postkind_unary_minus)", "AST_print.c", 516, __PRETTY_FUNCTION__), 0))); (unary_minus)(tEmPcast); });
  puts("unary_minus");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_unary_plus: {
  unary_plus x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_unary_plus && (tEmPcast)->kind <= postkind_unary_plus)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_unary_plus && (tEmPcast)->kind <= postkind_unary_plus)", "AST_print.c", 523, __PRETTY_FUNCTION__), 0))); (unary_plus)(tEmPcast); });
  puts("unary_plus");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_conjugate: {
  conjugate x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_conjugate && (tEmPcast)->kind <= postkind_conjugate)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_conjugate && (tEmPcast)->kind <= postkind_conjugate)", "AST_print.c", 530, __PRETTY_FUNCTION__), 0))); (conjugate)(tEmPcast); });
  puts("conjugate");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_preincrement: {
  preincrement x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_preincrement && (tEmPcast)->kind <= postkind_preincrement)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_preincrement && (tEmPcast)->kind <= postkind_preincrement)", "AST_print.c", 537, __PRETTY_FUNCTION__), 0))); (preincrement)(tEmPcast); });
  puts("preincrement");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_predecrement: {
  predecrement x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_predecrement && (tEmPcast)->kind <= postkind_predecrement)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_predecrement && (tEmPcast)->kind <= postkind_predecrement)", "AST_print.c", 544, __PRETTY_FUNCTION__), 0))); (predecrement)(tEmPcast); });
  puts("predecrement");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_postincrement: {
  postincrement x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_postincrement && (tEmPcast)->kind <= postkind_postincrement)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_postincrement && (tEmPcast)->kind <= postkind_postincrement)", "AST_print.c", 551, __PRETTY_FUNCTION__), 0))); (postincrement)(tEmPcast); });
  puts("postincrement");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_postdecrement: {
  postdecrement x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_postdecrement && (tEmPcast)->kind <= postkind_postdecrement)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_postdecrement && (tEmPcast)->kind <= postkind_postdecrement)", "AST_print.c", 558, __PRETTY_FUNCTION__), 0))); (postdecrement)(tEmPcast); });
  puts("postdecrement");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_bitnot: {
  bitnot x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitnot && (tEmPcast)->kind <= postkind_bitnot)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitnot && (tEmPcast)->kind <= postkind_bitnot)", "AST_print.c", 565, __PRETTY_FUNCTION__), 0))); (bitnot)(tEmPcast); });
  puts("bitnot");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_not: {
  not x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_not && (tEmPcast)->kind <= postkind_not)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_not && (tEmPcast)->kind <= postkind_not)", "AST_print.c", 572, __PRETTY_FUNCTION__), 0))); (not)(tEmPcast); });
  puts("not");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  break;
}
case kind_plus: {
  plus x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_plus && (tEmPcast)->kind <= postkind_plus)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_plus && (tEmPcast)->kind <= postkind_plus)", "AST_print.c", 579, __PRETTY_FUNCTION__), 0))); (plus)(tEmPcast); });
  puts("plus");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_minus: {
  minus x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_minus && (tEmPcast)->kind <= postkind_minus)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_minus && (tEmPcast)->kind <= postkind_minus)", "AST_print.c", 587, __PRETTY_FUNCTION__), 0))); (minus)(tEmPcast); });
  puts("minus");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_times: {
  times x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_times && (tEmPcast)->kind <= postkind_times)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_times && (tEmPcast)->kind <= postkind_times)", "AST_print.c", 595, __PRETTY_FUNCTION__), 0))); (times)(tEmPcast); });
  puts("times");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_divide: {
  divide x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_divide && (tEmPcast)->kind <= postkind_divide)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_divide && (tEmPcast)->kind <= postkind_divide)", "AST_print.c", 603, __PRETTY_FUNCTION__), 0))); (divide)(tEmPcast); });
  puts("divide");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_modulo: {
  modulo x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_modulo && (tEmPcast)->kind <= postkind_modulo)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_modulo && (tEmPcast)->kind <= postkind_modulo)", "AST_print.c", 611, __PRETTY_FUNCTION__), 0))); (modulo)(tEmPcast); });
  puts("modulo");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_lshift: {
  lshift x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_lshift && (tEmPcast)->kind <= postkind_lshift)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_lshift && (tEmPcast)->kind <= postkind_lshift)", "AST_print.c", 619, __PRETTY_FUNCTION__), 0))); (lshift)(tEmPcast); });
  puts("lshift");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_rshift: {
  rshift x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_rshift && (tEmPcast)->kind <= postkind_rshift)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_rshift && (tEmPcast)->kind <= postkind_rshift)", "AST_print.c", 627, __PRETTY_FUNCTION__), 0))); (rshift)(tEmPcast); });
  puts("rshift");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_leq: {
  leq x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_leq && (tEmPcast)->kind <= postkind_leq)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_leq && (tEmPcast)->kind <= postkind_leq)", "AST_print.c", 635, __PRETTY_FUNCTION__), 0))); (leq)(tEmPcast); });
  puts("leq");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_geq: {
  geq x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_geq && (tEmPcast)->kind <= postkind_geq)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_geq && (tEmPcast)->kind <= postkind_geq)", "AST_print.c", 643, __PRETTY_FUNCTION__), 0))); (geq)(tEmPcast); });
  puts("geq");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_lt: {
  lt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_lt && (tEmPcast)->kind <= postkind_lt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_lt && (tEmPcast)->kind <= postkind_lt)", "AST_print.c", 651, __PRETTY_FUNCTION__), 0))); (lt)(tEmPcast); });
  puts("lt");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_gt: {
  gt x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_gt && (tEmPcast)->kind <= postkind_gt)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_gt && (tEmPcast)->kind <= postkind_gt)", "AST_print.c", 659, __PRETTY_FUNCTION__), 0))); (gt)(tEmPcast); });
  puts("gt");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_eq: {
  eq x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_eq && (tEmPcast)->kind <= postkind_eq)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_eq && (tEmPcast)->kind <= postkind_eq)", "AST_print.c", 667, __PRETTY_FUNCTION__), 0))); (eq)(tEmPcast); });
  puts("eq");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_ne: {
  ne x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_ne && (tEmPcast)->kind <= postkind_ne)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_ne && (tEmPcast)->kind <= postkind_ne)", "AST_print.c", 675, __PRETTY_FUNCTION__), 0))); (ne)(tEmPcast); });
  puts("ne");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_bitand: {
  bitand x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitand && (tEmPcast)->kind <= postkind_bitand)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitand && (tEmPcast)->kind <= postkind_bitand)", "AST_print.c", 683, __PRETTY_FUNCTION__), 0))); (bitand)(tEmPcast); });
  puts("bitand");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_bitor: {
  bitor x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitor && (tEmPcast)->kind <= postkind_bitor)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitor && (tEmPcast)->kind <= postkind_bitor)", "AST_print.c", 691, __PRETTY_FUNCTION__), 0))); (bitor)(tEmPcast); });
  puts("bitor");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_bitxor: {
  bitxor x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitxor && (tEmPcast)->kind <= postkind_bitxor)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitxor && (tEmPcast)->kind <= postkind_bitxor)", "AST_print.c", 699, __PRETTY_FUNCTION__), 0))); (bitxor)(tEmPcast); });
  puts("bitxor");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_andand: {
  andand x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_andand && (tEmPcast)->kind <= postkind_andand)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_andand && (tEmPcast)->kind <= postkind_andand)", "AST_print.c", 707, __PRETTY_FUNCTION__), 0))); (andand)(tEmPcast); });
  puts("andand");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_oror: {
  oror x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_oror && (tEmPcast)->kind <= postkind_oror)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_oror && (tEmPcast)->kind <= postkind_oror)", "AST_print.c", 715, __PRETTY_FUNCTION__), 0))); (oror)(tEmPcast); });
  puts("oror");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_assign: {
  assign x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_assign && (tEmPcast)->kind <= postkind_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_assign && (tEmPcast)->kind <= postkind_assign)", "AST_print.c", 723, __PRETTY_FUNCTION__), 0))); (assign)(tEmPcast); });
  puts("assign");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_plus_assign: {
  plus_assign x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_plus_assign && (tEmPcast)->kind <= postkind_plus_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_plus_assign && (tEmPcast)->kind <= postkind_plus_assign)", "AST_print.c", 731, __PRETTY_FUNCTION__), 0))); (plus_assign)(tEmPcast); });
  puts("plus_assign");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_minus_assign: {
  minus_assign x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_minus_assign && (tEmPcast)->kind <= postkind_minus_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_minus_assign && (tEmPcast)->kind <= postkind_minus_assign)", "AST_print.c", 739, __PRETTY_FUNCTION__), 0))); (minus_assign)(tEmPcast); });
  puts("minus_assign");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_times_assign: {
  times_assign x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_times_assign && (tEmPcast)->kind <= postkind_times_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_times_assign && (tEmPcast)->kind <= postkind_times_assign)", "AST_print.c", 747, __PRETTY_FUNCTION__), 0))); (times_assign)(tEmPcast); });
  puts("times_assign");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_divide_assign: {
  divide_assign x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_divide_assign && (tEmPcast)->kind <= postkind_divide_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_divide_assign && (tEmPcast)->kind <= postkind_divide_assign)", "AST_print.c", 755, __PRETTY_FUNCTION__), 0))); (divide_assign)(tEmPcast); });
  puts("divide_assign");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_modulo_assign: {
  modulo_assign x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_modulo_assign && (tEmPcast)->kind <= postkind_modulo_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_modulo_assign && (tEmPcast)->kind <= postkind_modulo_assign)", "AST_print.c", 763, __PRETTY_FUNCTION__), 0))); (modulo_assign)(tEmPcast); });
  puts("modulo_assign");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_lshift_assign: {
  lshift_assign x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_lshift_assign && (tEmPcast)->kind <= postkind_lshift_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_lshift_assign && (tEmPcast)->kind <= postkind_lshift_assign)", "AST_print.c", 771, __PRETTY_FUNCTION__), 0))); (lshift_assign)(tEmPcast); });
  puts("lshift_assign");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_rshift_assign: {
  rshift_assign x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_rshift_assign && (tEmPcast)->kind <= postkind_rshift_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_rshift_assign && (tEmPcast)->kind <= postkind_rshift_assign)", "AST_print.c", 779, __PRETTY_FUNCTION__), 0))); (rshift_assign)(tEmPcast); });
  puts("rshift_assign");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_bitand_assign: {
  bitand_assign x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitand_assign && (tEmPcast)->kind <= postkind_bitand_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitand_assign && (tEmPcast)->kind <= postkind_bitand_assign)", "AST_print.c", 787, __PRETTY_FUNCTION__), 0))); (bitand_assign)(tEmPcast); });
  puts("bitand_assign");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_bitor_assign: {
  bitor_assign x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitor_assign && (tEmPcast)->kind <= postkind_bitor_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitor_assign && (tEmPcast)->kind <= postkind_bitor_assign)", "AST_print.c", 795, __PRETTY_FUNCTION__), 0))); (bitor_assign)(tEmPcast); });
  puts("bitor_assign");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
case kind_bitxor_assign: {
  bitxor_assign x = ({ast_generic tEmPcast = (ast_generic)(n); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_bitxor_assign && (tEmPcast)->kind <= postkind_bitxor_assign)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_bitxor_assign && (tEmPcast)->kind <= postkind_bitxor_assign)", "AST_print.c", 803, __PRETTY_FUNCTION__), 0))); (bitxor_assign)(tEmPcast); });
  puts("bitxor_assign");
  pindent(indent); puts("arg1:"); AST_print_list(indent + 1, x->arg1);
  pindent(indent); puts("arg2:"); AST_print_list(indent + 1, x->arg2);
  break;
}
    default:
      ((void) ((0) ? 0 : (__assert_fail ("0", "AST.c", 251, __PRETTY_FUNCTION__), 0)));
    }
}
static void AST_print_list(int indent, void *vn)
{
  node n = ({ast_generic tEmPcast = (ast_generic)(vn); if (tEmPcast) ((void) ((((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)) ? 0 : (__assert_fail ("((tEmPcast)->kind >= kind_node && (tEmPcast)->kind <= postkind_node)", "AST.c", 257, __PRETTY_FUNCTION__), 0))); (node)(tEmPcast); });
  while (n)
    {
      AST_print1(indent, n);
      n = n->next;
    }
}
void AST_print(node n)
{
  fflush(stdout);
  AST_print_list(0, n);
  fflush(stdout);
}
const char CANON_IDENT_c444f2c24496921f2ab71b8d60f1e0fc[] = "CANON_IDENT_/moa/sc1/jkodumal/work/banshee/experiments/cqual/src/AST.c";
