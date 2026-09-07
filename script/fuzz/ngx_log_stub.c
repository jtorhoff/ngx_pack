/*
   Copyright (C) 2026 Juri Torhoff
 */

/* A real ngx_log_error_core would pull in ngx_conf_file.c and
   ngx_syslog.c too - ngx_log.c's own ngx_log_set_log/
   ngx_log_open_default reach both, and the linker cannot take one
   function from an object file without the rest. Every harness that
   links this gives every log it hands out log_level 0, which is
   below every real level nginx defines, so ngx_log_error's own
   "log_level >= level" guard (see ngx_log.h) means this is never
   actually called - only ever linked against, to satisfy the
   reference ngx_alloc.c and the encoders' own ngx_log_error calls
   still compile in.
 */

#include <ngx_config.h>
#include <ngx_core.h>

/* ngx_string.c's ngx_sort() reaches ngx_cycle->log on its allocation
   failure path - unreachable here (nothing in either encoder calls
   ngx_sort; it is only linked in because ngx_buf.c's file-buffer
   coalescing does, which this harness's in-memory-only buffers never
   drive), but the symbol still has to resolve. NULL rather than a
   real cycle, on the same "never actually called" footing. */
ngx_cycle_t volatile *ngx_cycle;

void
ngx_log_error_core(
    ngx_uint_t  level,
    ngx_log_t  *log,
    ngx_err_t   err,
    char const *fmt,
    ...)
{
    (void) level;
    (void) log;
    (void) err;
    (void) fmt;
}
