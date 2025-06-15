// -----------------------------------------------------------------------------
// monitor_utils.c
// -----------------------------------------------------------------------------
#define _GNU_SOURCE
#include <linux/fanotify.h>
#include <sys/syscall.h>   // for SYS_open_by_handle_at
#include <fcntl.h>         // for O_RDONLY|O_DIRECTORY
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h> 
#include <linux/mount.h>
#include "shared.h"


/**
 * Given a FAN_REPORT_DFID_NAME event in 'md', extract its full path.
 *   out[] = buffer of size outlen
 * Returns 0 on success (out is NUL-terminated), or -1 on error.
 */
int get_event_fullpath(struct fanotify_event_metadata *md,
                       char *out, size_t outlen)
{
    // 1) Grab the FID payload & optional entry‐name
    struct fanotify_event_info_fid *fid =
        (struct fanotify_event_info_fid *)(md + 1);
    struct file_handle *file_handle = &fid->handle;
    const char *name = NULL;
    if (fid->hdr.info_type == FAN_EVENT_INFO_TYPE_DFID_NAME) {
        // when you get DFID_NAME, the basename follows the handle bytes
        name = (char*)file_handle->f_handle + file_handle->handle_bytes;
    } else if (fid->hdr.info_type != FAN_EVENT_INFO_TYPE_FID &&
               fid->hdr.info_type != FAN_EVENT_INFO_TYPE_DFID) {
        fprintf(stderr, "Unexpected event info_type %u\n",
                fid->hdr.info_type);
        return -1;
    }

        // 2) Lookup which mount this event came from (by comparing FSID)
        __kernel_fsid_t event_fsid = fid->fsid;
        char mnt_dir[PATH_MAX];
        int mi = find_mount_by_fsid(event_fsid, mnt_dir);
        if (mi < 0) {
            fprintf(stderr, "No mount found for fsid\n");
            return -1;
        }

        printf("MNT_DIR %s\n", mnt_dir);

        // 3) Open any FD on that filesystem (the mount-root you recorded)
        int mount_fd = open(mnt_dir, O_PATH | O_DIRECTORY);
        if (mount_fd < 0) {
            perror("open(mnt_dir)");
            return -1;
        }

        printf("mount fd: %d\n", mount_fd);

        /*DEBUG ONLY*/
        struct stat st;
        if (fstat(mount_fd, &st) < 0) {
            perror("mount_fd is invalid");
        } else {
            printf("mount_fd ok: dev=%lu, ino=%lu\n",
                (unsigned long)st.st_dev,
                (unsigned long)st.st_ino);
        }


        // 4) Turn the handle into a real FD
        int event_fd = open_by_handle_at(mount_fd, file_handle, O_PATH);
        close(mount_fd);  // we only needed mount_fd for the syscall
        if (event_fd < 0) {
            if (errno == ESTALE) {
                fprintf(stderr, "Stale handle (file deleted)\n");
            } else {
            printf("ERROR\n");
                perror("open_by_handle_at");
            }
            return -1;
        }

    // 5) Read the symlink /proc/self/fd/<event_fd> → absolute path in out[]
    char linkpath[64];
    snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", event_fd);
    ssize_t len = readlink(linkpath, out, outlen - 1);
    close(event_fd);
    if (len < 0) {
        perror("readlink");
        return -1;
    }
    out[len] = '\0';  // NUL-terminate

    // 6) If we had a basename (DFID_NAME), append “/basename”
    if (name) {
        size_t base = strlen(out);
        if (base + 1 + strlen(name) < outlen) {
            out[base] = '/';
            strcpy(out + base + 1, name);
        }
    }

    return 0;  // success!
}