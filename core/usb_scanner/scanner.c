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
#include <fcntl.h>  //for AT_FDCWD

//Global mount‐list state (protected by mount_mutex)
 
static struct {
    char *devnode;
    char *mnt_dir;
} mount_list[MAX_USBS];

static int             mount_count = 0;
static pthread_mutex_t mount_mutex = PTHREAD_MUTEX_INITIALIZER;

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

/**
 * Returns the current list of mount-point strings.
 * Caller must free each returned string.
 */
int get_current_mounts(char *mounts[], int max) {
    pthread_mutex_lock(&mount_mutex);
    int cnt = (mount_count < max ? mount_count : max);
    for (int i = 0; i < cnt; i++) {
        mounts[i] = strdup(mount_list[i].mnt_dir);
    }
    pthread_mutex_unlock(&mount_mutex);
    return cnt;
}

static const uint64_t USB_EVENT_MASK =
    FAN_CREATE     | FAN_DELETE    | FAN_MODIFY    |
    FAN_MOVED_FROM | FAN_MOVED_TO  |
    FAN_CLOSE_WRITE| FAN_CLOSE_NOWRITE | FAN_ATTRIB;

/* mark *one* directory (ONLYDIR) */
static int mark_dir(const char *path) {
    int ret = fanotify_mark(
        g_fan_fd,
        FAN_MARK_ADD  | FAN_MARK_ONLYDIR,
        USB_EVENT_MASK,
        AT_FDCWD,
        path
    );
    if (ret < 0) {
        fprintf(stderr, "fanotify_mark(%s): %s\n", path, strerror(errno));
    }
    return ret;
}

/* function called in directory tree traversal to mark directories for fanotify*/
static int _nftw_cb(const char *fpath,
                    const struct stat *sb,
                    int typeflag,
                    struct FTW *ftw) {
    if (typeflag == FTW_D) {
        mark_dir(fpath);
    }
    return 0;
}

/* Tree walk using ntfw from POSIX, calling previous function*/
void mark_all_dirs(const char *root) {
    nftw(root, _nftw_cb, 20, FTW_PHYS);
}

/**
    * Enumerate USB partitions whose parent is on the USB bus,
    * Match them against /proc/self/mounts, and return those mount points.
*/
static int get_usb_mounts(char *devnodes[], char *mntpoints[]) {
    
    // libudev library easily allows to scan and iterate over system devices (perfect for USB detection)
    struct udev *udev = udev_new();
    if (!udev) return -1;

    /*find all block devices whose parent is a USB device */
    struct udev_enumerate *en = udev_enumerate_new(udev);
    
    //filter devices of "block" type such as hard drives and external disks 
    udev_enumerate_add_match_subsystem(en, "block");
    // scan all devices to create an enumerable
    udev_enumerate_scan_devices(en);

    int devcount = 0;

    //creates the enumerable object
    struct udev_list_entry *head = udev_enumerate_get_list_entry(en);
    // pointer to current device in the iteration
    struct udev_list_entry *entry;
    udev_list_entry_foreach(entry, head) {
        if (devcount >= MAX_USBS) break;

        // Creates an struct with represent an specific device, allowing acces to its properties
        struct udev_device *dev = udev_device_new_from_syspath(udev,udev_list_entry_get_name(entry));
        const char *node = udev_device_get_devnode(dev);
        
        if (node && udev_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_device")) {
            devnodes[devcount++] = strdup(node);
        }
        udev_device_unref(dev);
    }
    udev_enumerate_unref(en);

    //opens the mount table (it contains info about where are mounted the devices)
    FILE *mtab = setmntent("/proc/self/mounts", "r");
    if (!mtab) {
        udev_unref(udev);
        return -1;
    }

    int count = 0;
    struct mntent *m;
    while ((m = getmntent(mtab)) && count < devcount) {
        for (int i = 0; i < devcount; i++) {
            if (strcmp(m->mnt_fsname, devnodes[i]) == 0) {
                mntpoints[count++] = strdup(m->mnt_dir);
                break;
            }
        }
    }
    endmntent(mtab);
    udev_unref(udev);

    //We mix the udev approach with the mount table approach to discard mounts that are not USB devices (such as internal disk partitions)

    /* cleanup devnodes */
    for (int i = 0; i < devcount; i++)
        free(devnodes[i]);
    return count;
}

void *scanner_thread(void *arg) {
    (void)arg; // to avoid warning

    char *devnodes[MAX_USBS], *mntpoints[MAX_USBS];
    int n = get_usb_mounts(devnodes, mntpoints);
    if (n < 0) {
        fprintf(stderr, "Error enumerating USB mounts\n");
        return NULL;
    }
    for (int i = 0; i < n; i++) {
        mark_all_dirs(mntpoints[i]);
        add_mount_entry(devnodes[i], mntpoints[i]);
        free(devnodes[i]);
        free(mntpoints[i]);
    }    

    struct udev *udev = udev_new();
    //returns a monitor object that listens to uevent from udev library (triggered when some new mount is added or removed)
    struct udev_monitor *mon = udev_monitor_new_from_netlink(udev, "udev");
    //filter devices of "block" type
    udev_monitor_filter_add_match_subsystem_devtype(mon, "block", NULL);
    //starts listening to uevents
    udev_monitor_enable_receiving(mon);

    int mon_fd = udev_monitor_get_fd(mon);

    //File descriptor to watch events
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

        //gets the name of the event 
        const char *action  = udev_device_get_action(dev);
        //gets the filesystem path of the device node
        const char *devnode = udev_device_get_devnode(dev);

        if (action && strcmp(action,"add")==0 && devnode) {
            // new device → find its mount 
            FILE *mt2 = setmntent("/proc/self/mounts","r");
            struct mntent *m2;
            while ((m2 = getmntent(mt2))) {
                if (strcmp(m2->mnt_fsname, devnode)==0) {
                    mark_all_dirs(m2->mnt_dir);
                    add_mount_entry(devnode, m2->mnt_dir);
                    break;
                }
            }
            endmntent(mt2);
            
        }
        else if (action && strcmp(action,"remove")==0 && devnode) {
            remove_mount_entry(devnode);
            
        }

        udev_device_unref(dev);
    }

    udev_unref(udev);
    return NULL;
}
