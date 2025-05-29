#define _GNU_SOURCE
#include "shared.h"

#include <libudev.h>
#include <mntent.h>
#include <sys/fanotify.h>
#include <ftw.h>  // for nftw
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>  // for AT_FDCWD

// Global mount-list state (protected by mount_mutex)
static struct {
    char *devnode;
    char *mnt_dir;
} mount_list[MAX_USBS];

static int             mount_count = 0;
static pthread_mutex_t mount_mutex = PTHREAD_MUTEX_INITIALIZER;

int get_current_mounts(char *mounts[], int max) {
    pthread_mutex_lock(&mount_mutex);
    int cnt = (mount_count < max ? mount_count : max);
    for (int i = 0; i < cnt; i++) {
        mounts[i] = strdup(mount_list[i].mnt_dir);
    }
    pthread_mutex_unlock(&mount_mutex);
    return cnt;
}

/* Add a new (devnode, mnt_dir) pair if not already present */
static void add_mount_entry(const char *devnode, const char *mnt_dir) {
    pthread_mutex_lock(&mount_mutex);
    for (int i = 0; i < mount_count; i++) {
        if (strcmp(mount_list[i].devnode, devnode) == 0) {
            pthread_mutex_unlock(&mount_mutex);
            return;
        }
    }
    if (mount_count < MAX_USBS) {
        mount_list[mount_count].devnode = strdup(devnode);
        mount_list[mount_count].mnt_dir  = strdup(mnt_dir);
        mount_count++;
    }
    pthread_mutex_unlock(&mount_mutex);
}

/* Remove an entry by devnode */
static void remove_mount_entry(const char *devnode) {
    pthread_mutex_lock(&mount_mutex);
    for (int i = 0; i < mount_count; i++) {
        if (strcmp(mount_list[i].devnode, devnode) == 0) {
            free(mount_list[i].devnode);
            free(mount_list[i].mnt_dir);
            /* shift the rest down */
            for (int j = i; j < mount_count - 1; j++) {
                mount_list[j] = mount_list[j+1];
            }
            mount_count--;
            break;
        }
    }
    pthread_mutex_unlock(&mount_mutex);
}

void mark_mount(const char *path) {
    printf("Marking %s",path);
    unsigned long events_content = FAN_CLOSE_WRITE | FAN_MODIFY| FAN_ACCESS;
    unsigned long events_notify  = FAN_CREATE | FAN_DELETE | FAN_MOVED_FROM | FAN_MOVED_TO;

    // mark for content events
    if (fanotify_mark(
            g_fan_content_fd,
            FAN_MARK_ADD | FAN_MARK_MOUNT,
            events_content,
            AT_FDCWD,
            path) < 0
    ){
        fprintf(stderr, "mark_mount(content) failed for %s: %s\n", path, strerror(errno));
    }

    // mark for notify events
    if (fanotify_mark(
            g_fan_notify_fd,
            FAN_MARK_ADD,
            events_notify,
            AT_FDCWD,
            path) < 0
    ) {
        fprintf(stderr, "mark_mount(notify) failed for %s: %s\n", path, strerror(errno));
    }
}

static char *find_mount(const char *devnode) {
    FILE *fp = setmntent("/proc/mounts", "r");
    if (!fp) return NULL;
    struct mntent *ent;
    char *mnt = NULL;
    while ((ent = getmntent(fp))) {
        if (strcmp(ent->mnt_fsname, devnode) == 0) {
            mnt = strdup(ent->mnt_dir);
            break;
        }
    }
    endmntent(fp);
    return mnt;
}

/**
 * Enumerate USB partitions whose parent is on the USB bus,
 * match them against /proc/self/mounts, and return those mount points.
 */
static int get_usb_mounts(char *devnodes[], char *mntpoints[]) {
    struct udev *udev = udev_new();
    if (!udev) return -1;
    struct udev_enumerate *en = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(en, "block");
    udev_enumerate_scan_devices(en);

    int devcount = 0;
    struct udev_list_entry *head = udev_enumerate_get_list_entry(en);
    struct udev_list_entry *entry;
    udev_list_entry_foreach(entry, head) {
        if (devcount >= MAX_USBS) break;
        struct udev_device *dev = udev_device_new_from_syspath(
            udev, udev_list_entry_get_name(entry));
        const char *node = udev_device_get_devnode(dev);
        if (node && udev_device_get_parent_with_subsystem_devtype(
                         dev, "usb", "usb_device")) {
            devnodes[devcount++] = strdup(node);
        }
        udev_device_unref(dev);
    }
    udev_enumerate_unref(en);

    int count = 0;
    for (int i = 0; i < devcount; i++) {
        char *mnt = find_mount(devnodes[i]);
        if (mnt) {
            mntpoints[count++] = mnt;  // strdup done in find_mount
        }
    }
    udev_unref(udev);
    return count;
}


void *scanner_thread(void *arg) {
    (void)arg;
    /* 1) Initial enumeration of existing USB mounts */
    char *devnodes[MAX_USBS], *mntpoints[MAX_USBS];
    int n = get_usb_mounts(devnodes, mntpoints);
    if (n < 0) {
        fprintf(stderr, "Error enumerating mounts");
        return NULL;
    }
    for (int i = 0; i < n; i++) {
        mark_mount(mntpoints[i]);
        add_mount_entry(devnodes[i], mntpoints[i]);
        free(mntpoints[i]);
        free(devnodes[i]);
    }

    /* 2) Udev monitor loop for hotplug using poll() */
    struct udev *udev = udev_new();
    if (!udev) {
        fprintf(stderr, "udev_new() failed");
        return NULL;
    }
    struct udev_monitor *mon =
        udev_monitor_new_from_netlink(udev, "udev");
    udev_monitor_filter_add_match_subsystem_devtype(
        mon, "block", "partition");
    udev_monitor_enable_receiving(mon);
    int mon_fd = udev_monitor_get_fd(mon);
    struct pollfd pfd = { .fd = mon_fd, .events = POLLIN };

    while (1) {
        int ret = poll(&pfd, 1, -1);
        if (ret < 0) {
            if (errno == EINTR) continue;
            perror("poll udev");
            break;
        }
        if (pfd.revents & POLLIN) {
            struct udev_device *dev =
                udev_monitor_receive_device(mon);
            if (!dev) continue;
            const char *action =
                udev_device_get_action(dev);
            const char *devnode =
                udev_device_get_devnode(dev);
            if (action && devnode) {
                if (strcmp(action, "add") == 0) {
                    sleep(1);  // wait for mount
                    char *mnt = find_mount(devnode);
                    if (mnt) {
                        mark_mount(mnt);
                        add_mount_entry(devnode, mnt);
                        free(mnt);

                    }
                } else if (strcmp(action, "remove") == 0) {
                    remove_mount_entry(devnode);
                }
            }
            udev_device_unref(dev);
        }
    }
    udev_unref(udev);
    return NULL;
}
