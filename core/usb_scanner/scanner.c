// scanner.c
#define _GNU_SOURCE
#include "shared.h"

#include <libudev.h>
#include <mntent.h>
#include <sys/fanotify.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>  

#define MAX_USBS 64

/**
 * Enumerate all block‐device partitions whose parent is on the USB bus,
 * and return the list of their current mount points.
 *
 * @param mounts  array of length MAX_USBS to fill with malloc'd strings
 * @return        number of mounts found, or -1 on error
 */
static int get_usb_mounts(char *mounts[]) {
    struct udev *udev = udev_new();
    if (!udev) {
        fprintf(stderr, "udev_new() failed\n");
        return -1;
    }

    // 1) Enumerate all block devices
    struct udev_enumerate *en = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(en, "block");
    udev_enumerate_scan_devices(en);

    // Collect devnodes whose parent is a USB device
    const char *devnodes[MAX_USBS];
    int devcount = 0;

    struct udev_list_entry *head = udev_enumerate_get_list_entry(en);
    struct udev_list_entry *entry;
    udev_list_entry_foreach(entry, head) {
        if (devcount >= MAX_USBS) break;

        const char *syspath = udev_list_entry_get_name(entry);
        struct udev_device *dev =
            udev_device_new_from_syspath(udev, syspath);
        const char *devnode = udev_device_get_devnode(dev);
        if (devnode) {
            // If any parent device in the chain is USB, record it
            struct udev_device *usb_parent =
                udev_device_get_parent_with_subsystem_devtype(
                    dev, "usb", "usb_device");
            if (usb_parent) {
                devnodes[devcount++] = strdup(devnode);
            }
        }
        udev_device_unref(dev);
    }
    udev_enumerate_unref(en);

    // 2) Match against /proc/self/mounts
    FILE *mtab = setmntent("/proc/self/mounts", "r");
    if (!mtab) {
        perror("setmntent");
        goto cleanup_udev;
    }

    int count = 0;
    struct mntent *mnt;
    while ((mnt = getmntent(mtab)) && count < MAX_USBS) {
        for (int i = 0; i < devcount; i++) {
            if (strcmp(mnt->mnt_fsname, devnodes[i]) == 0) {
                mounts[count++] = strdup(mnt->mnt_dir);
                break;
            }
        }
    }
    endmntent(mtab);

    // Cleanup devnode strings
    for (int i = 0; i < devcount; i++) {
        free((void*)devnodes[i]);
    }
    udev_unref(udev);
    return count;

cleanup_udev:
    for (int i = 0; i < devcount; i++) {
        free((void*)devnodes[i]);
    }
    udev_unref(udev);
    return -1;
}

/** Mark a directory with fanotify for recursive watch */
static int mark_dir(const char *path) {
    int err = fanotify_mark(
        g_fan_fd,
        FAN_MARK_ADD,
        FAN_CREATE | FAN_DELETE | FAN_MODIFY | FAN_MOVE | FAN_ONDIR,
        AT_FDCWD,
        path
    );
    if (err < 0) {
        fprintf(stderr, "fanotify_mark(%s): %s\n", path, strerror(errno));
    }
    return err;
}

/** scanner thread entrypoint */
void *scanner_thread(void *arg) {
    (void)arg;

    // 1) Initial USB mount detection
    char *mounts[MAX_USBS];
    int n = get_usb_mounts(mounts);
    if (n < 0) {
        fprintf(stderr, "Failed to enumerate USB mounts\n");
        return NULL;
    }

    // Mark each for fanotify and report them
    for (int i = 0; i < n; i++) {
        mark_dir(mounts[i]);
    }
    report_connected_devices((const char**)mounts, n);
    // Free our copies
    for (int i = 0; i < n; i++) {
        free(mounts[i]);
    }

    // 2) Now watch for new USB block devices via libudev
    struct udev *udev = udev_new();
    if (!udev) {
        fprintf(stderr, "udev_new() failed in watch loop\n");
        return NULL;
    }

    struct udev_monitor *mon =
        udev_monitor_new_from_netlink(udev, "udev");
    udev_monitor_filter_add_match_subsystem_devtype(mon, "block", NULL);
    udev_monitor_enable_receiving(mon);

    int mon_fd = udev_monitor_get_fd(mon);
    struct pollfd pfd = { .fd = mon_fd, .events = POLLIN };

    while (1) {
        int ret = poll(&pfd, 1, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("scanner poll");
            break;
        }
        if ((pfd.revents & POLLIN) == 0)
            continue;

        struct udev_device *dev = udev_monitor_receive_device(mon);
        if (!dev) continue;

        const char *action  = udev_device_get_action(dev);
        const char *devnode = udev_device_get_devnode(dev);

        if (action && strcmp(action, "add") == 0 && devnode) {
            // Re-scan mounts to see if it's mounted
            FILE *mtab2 = setmntent("/proc/self/mounts", "r");
            if (mtab2) {
                struct mntent *m;
                while ((m = getmntent(mtab2))) {
                    if (strcmp(m->mnt_fsname, devnode) == 0) {
                        // New USB mount found!
                        mark_dir(m->mnt_dir);
                        report_connected_devices((const char**)&m->mnt_dir, 1);
                        break;
                    }
                }
                endmntent(mtab2);
            }
        }

        udev_device_unref(dev);
    }

    udev_unref(udev);
    return NULL;
}
