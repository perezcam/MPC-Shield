// scanner.c
#define _GNU_SOURCE
#include "shared.h"

#include <libudev.h>
#include <mntent.h>
#include <sys/fanotify.h>
#include <ftw.h>
#include <poll.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>  


/* same maximum as shared.h */
#define MAX_USBS 64

/* Which fanotify events we care about on each directory */
static const uint64_t USB_EVENT_MASK =
    FAN_CREATE     | FAN_DELETE   | FAN_MODIFY    |
    FAN_MOVED_FROM | FAN_MOVED_TO | FAN_CLOSE_WRITE|
    FAN_CLOSE_NOWRITE| FAN_ATTRIB;

/* Helper: mark just this one directory for the events above */
static int mark_dir(const char *path) {
    int ret = fanotify_mark(
        g_fan_fd,
        FAN_MARK_ADD  | FAN_MARK_ONLYDIR,
        USB_EVENT_MASK,
        AT_FDCWD,
        path
    );
    if (ret < 0) {
        fprintf(stderr,
                "fanotify_mark(%s): %s\n",
                path, strerror(errno));
    }
    return ret;
}

/* function called in directory tree traversal to mark directories for fanotify*/
static int _mark_dirs_for_fanotify(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftw) {
    if (typeflag == FTW_D) {
        mark_dir(fpath);
    }
    return 0;  // continue
}

/* Tree walk using ntfw from POSIX, calling previous function*/
void mark_all_dirs(const char *root) {
    nftw(root, _mark_dirs_for_fanotify, 20, FTW_PHYS);
}

/**
    * Enumerate USB partitions whose parent is on the USB bus,
    * Match them against /proc/self/mounts, and return those mount points.
*/
static int get_usb_mounts(char *mounts[]) {

    // libudev library easily allows to scan and iterate over system devices (perfect for USB detection)
    struct udev *udev = udev_new();
    if (!udev) {
        fprintf(stderr, "udev_new() failed\n");
        return -1;
    }

    struct udev_enumerate *en = udev_enumerate_new(udev);
    
    //filter devices of "block" type such as hard drives and external disks 
    udev_enumerate_add_match_subsystem(en, "block");
    // scan all devices to create an enumerable
    udev_enumerate_scan_devices(en);

    const char *devnodes[MAX_USBS];
    int devcount = 0;

    //creates the enumerable object
    struct udev_list_entry *head = udev_enumerate_get_list_entry(en);
    // pointer to current device in the iteration
    struct udev_list_entry *entry;
    udev_list_entry_foreach(entry, head) {
        if (devcount >= MAX_USBS) break;

        // Creates an struct with represent an specific device, allowing acces to its properties
        struct udev_device *dev =
            udev_device_new_from_syspath(udev, udev_list_entry_get_name(entry));
        const char *devnode = udev_device_get_devnode(dev);
        if (devnode) {
            /* if any parent is a USB device, record this partition */
            if (udev_device_get_parent_with_subsystem_devtype(
                    dev, "usb", "usb_device")) {
                devnodes[devcount++] = strdup(devnode);
            }
        }
        udev_device_unref(dev);
    }
    udev_enumerate_unref(en);

    //extracts the mount table (here is the info about what is mounted and where)
    FILE *mtab = setmntent("/proc/self/mounts", "r");
    if (!mtab) {
        perror("setmntent");
        goto cleanup;
    }

    int count = 0;
    struct mntent *m;
    while ((m = getmntent(mtab)) && count < MAX_USBS) {
        for (int i = 0; i < devcount; i++) {
            if (strcmp(m->mnt_fsname, devnodes[i]) == 0) {
                mounts[count++] = strdup(m->mnt_dir);
                break;
            }
        }
    }
    endmntent(mtab);

cleanup:
    for (int i = 0; i < devcount; i++)
        free((void*)devnodes[i]);
    udev_unref(udev);
    return count;
}

void *scanner_thread(void *arg) {
    (void)arg;
    char *mounts[MAX_USBS];

    /* 1) Initial pass: discover, mark & report all existing USB mounts */
    int n = get_usb_mounts(mounts);
    if (n < 0) {
        fprintf(stderr, "Error enumerating USB mounts\n");
        return NULL;
    }
    for (int i = 0; i < n; i++) {
        mark_all_dirs(mounts[i]);
    }
    report_connected_devices((const char**)mounts, n);
    for (int i = 0; i < n; i++) {
        free(mounts[i]);
    }

    /* 2) Now watch for new USB block devices appearing */
    struct udev *udev = udev_new();
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
        if (!(pfd.revents & POLLIN)) continue;

        struct udev_device *dev = udev_monitor_receive_device(mon);
        if (!dev) continue;

        const char *action  = udev_device_get_action(dev);
        const char *devnode = udev_device_get_devnode(dev);

        if (action && strcmp(action, "add") == 0 && devnode) {
            /* re-scan /proc/self/mounts for this devnode */
            FILE *mtab2 = setmntent("/proc/self/mounts", "r");
            struct mntent *m2;
            while ((m2 = getmntent(mtab2))) {
                if (strcmp(m2->mnt_fsname, devnode) == 0) {
                    /* new USB mount: mark entire tree & report */
                    mark_all_dirs(m2->mnt_dir);
                    report_connected_devices((const char**)&m2->mnt_dir, 1);
                    break;
                }
            }
            endmntent(mtab2);
        }

        udev_device_unref(dev);
    }

    udev_unref(udev);
    return NULL;
}
