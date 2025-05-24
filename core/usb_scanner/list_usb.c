// list_usb_fixed.c
#define _GNU_SOURCE
#include <libudev.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_USBS 64

/**
 * Fill `mounts[]` with up to `max` mount‐point paths for
 * partitions on USB disks, returning how many were found.
 * Returns –1 on error.
 */
int get_usb_mounts(char *mounts[], int max) {
    struct udev *udev = udev_new();
    if (!udev) {
        fprintf(stderr, "udev_new(): out of memory\n");
        return -1;
    }

    // 1) Enumerate all block devices
    struct udev_enumerate *en = udev_enumerate_new(udev);
    udev_enumerate_add_match_subsystem(en, "block");
    udev_enumerate_scan_devices(en);

    // Collect devnodes whose ancestry includes a USB device
    const char *devnodes[MAX_USBS];
    int devcount = 0;

    struct udev_list_entry *head = udev_enumerate_get_list_entry(en);
    udev_list_entry_foreach(head, head) {
        if (devcount >= MAX_USBS) break;

        const char *syspath = udev_list_entry_get_name(head);
        struct udev_device *dev =
            udev_device_new_from_syspath(udev, syspath);
        const char *devnode = udev_device_get_devnode(dev);
        if (devnode) {
            // Check parent chain for a USB device
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

    // 2) Walk /proc/self/mounts to find matching fs sources
    FILE *mtab = setmntent("/proc/self/mounts", "r");
    if (!mtab) {
        perror("setmntent");
        for (int i = 0; i < devcount; i++) free((void*)devnodes[i]);
        udev_unref(udev);
        return -1;
    }

    int count = 0;
    struct mntent *mnt;
    while ((mnt = getmntent(mtab)) != NULL && count < max) {
        for (int i = 0; i < devcount; i++) {
            if (strcmp(mnt->mnt_fsname, devnodes[i]) == 0) {
                mounts[count++] = strdup(mnt->mnt_dir);
                break;
            }
        }
    }
    endmntent(mtab);

    // Clean up
    for (int i = 0; i < devcount; i++)
        free((void*)devnodes[i]);
    udev_unref(udev);

    return count;
}

int main(void) {
    char *mounts[MAX_USBS];
    int n = get_usb_mounts(mounts, MAX_USBS);
    if (n < 0) return 1;

    printf("Found %d USB mount(s):\n", n);
    for (int i = 0; i < n; i++) {
        printf("  %s\n", mounts[i]);
        free(mounts[i]);
    }
    return 0;
}
