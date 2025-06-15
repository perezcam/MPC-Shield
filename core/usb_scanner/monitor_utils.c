// -----------------------------------------------------------------------------
// monitor_utils.c
// -----------------------------------------------------------------------------
#define _GNU_SOURCE
#include <linux/fanotify.h>
#include <sys/syscall.h>   // for SYS_open_by_handle_at
#include <sys/mount.h>     // for struct file_handle
#include <fcntl.h>         // for O_RDONLY|O_DIRECTORY
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "shared.h"


/**
 * Given a FAN_REPORT_DFID_NAME event in 'md', extract its full path.
 *   out[] = buffer of size outlen
 * Returns 0 on success (out is NUL-terminated), or -1 on error.
 */
int get_event_fullpath(struct fanotify_event_metadata *md,
                       char *out, size_t outlen)
{
    // 1) Skip the fixed‐size metadata header
    char *p = (char*)md + sizeof(*md);

    // 2) Grab the info header and check its type
    struct fanotify_event_info_header *hdr = (void*)p;
    if (hdr->info_type != FAN_EVENT_INFO_TYPE_DFID_NAME)
        return -1;

    // 3) Cast up to our DFID_NAME record
    struct fanotify_event_info_fid *fid = (void*)p;

    // 4) The basename of the child is located immediately
    //    after 'len' bytes of this info record.
    char *name = p + hdr->len;

    // 5) 'fid->handle' is the struct file_handle of the parent dir
    struct file_handle *fh = &fid->handle;

    // 6) Open the parent directory by handle
    int dirfd = open_by_handle_at(AT_FDCWD, fh,
                                  O_RDONLY | O_DIRECTORY);
    if (dirfd < 0) return -1;

    // 7) Read its real path via /proc/self/fd
    char linkpath[64], dirpath[PATH_MAX];
    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", dirfd);
    ssize_t len = readlink(linkpath, dirpath, sizeof(dirpath)-1);
    close(dirfd);
    if (len <= 0) return -1;
    dirpath[len] = '\0';

    // 8) Concatenate parent + "/" + basename
    snprintf(out, outlen, "%s/%s", dirpath, name);
    return 0;
}
