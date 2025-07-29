/*
 * SentinalOS Virtual File System Implementation
 * Pentagon-Level Secure File System Framework
 */

#include "../include/system.h"
#include <string.h>

/* VFS constants */
#define MAX_FILESYSTEMS 32
#define MAX_MOUNTPOINTS 64
#define MAX_PATH_LENGTH 4096
#define INODE_CACHE_SIZE 1024

/* File system types */
typedef enum {
    FS_TYPE_SENTINALFS = 0,
    FS_TYPE_EXT4,
    FS_TYPE_TMPFS,
    FS_TYPE_PROCFS,
    FS_TYPE_SYSFS,
    FS_TYPE_DEVFS
} fs_type_t;

/* File system operations */
struct filesystem_ops {
    const char *name;
    fs_type_t type;
    
    /* Super block operations */
    int (*mount)(const char *device, const char *mountpoint, uint32_t flags);
    int (*unmount)(const char *mountpoint);
    struct super_block *(*get_super)(const char *device);
    
    /* Inode operations */
    struct inode *(*alloc_inode)(struct super_block *sb);
    void (*destroy_inode)(struct inode *inode);
    int (*read_inode)(struct inode *inode);
    int (*write_inode)(struct inode *inode);
    
    /* File operations */
    int (*open)(struct inode *inode, struct file *file);
    int (*release)(struct inode *inode, struct file *file);
    ssize_t (*read)(struct file *file, char *buffer, size_t count, loff_t *offset);
    ssize_t (*write)(struct file *file, const char *buffer, size_t count, loff_t *offset);
    
    /* Directory operations */
    int (*readdir)(struct file *file, struct directory_entry *entries, size_t count);
    int (*mkdir)(struct inode *dir, const char *name, uint32_t mode);
    int (*rmdir)(struct inode *dir, const char *name);
    
    /* Security operations */
    int (*check_permission)(struct inode *inode, uint32_t mask);
    int (*set_security_context)(struct inode *inode, const char *context);
    int (*get_security_context)(struct inode *inode, char *context, size_t size);
};

/* Super block structure */
struct super_block {
    uint32_t magic;
    fs_type_t fs_type;
    uint32_t block_size;
    uint64_t total_blocks;
    uint64_t free_blocks;
    uint32_t total_inodes;
    uint32_t free_inodes;
    uint32_t mount_flags;
    char device_name[256];
    char mount_point[256];
    struct filesystem_ops *ops;
    void *private_data;
    uint32_t security_level;
};

/* File structure */
struct file {
    struct inode *inode;
    loff_t offset;
    uint32_t flags;
    uint32_t mode;
    uint32_t ref_count;
    struct super_block *sb;
    void *private_data;
};

/* Mount point structure */
struct mount_point {
    char path[256];
    struct super_block *sb;
    uint32_t flags;
    uint32_t security_level;
    struct mount_point *next;
};

/* Inode cache entry */
struct inode_cache_entry {
    uint32_t inode_num;
    struct super_block *sb;
    struct inode *inode;
    uint64_t last_access;
    int ref_count;
    struct inode_cache_entry *next;
    struct inode_cache_entry *prev;
};

/* Global VFS state */
static struct filesystem_ops *registered_filesystems[MAX_FILESYSTEMS];
static struct mount_point *mount_points = NULL;
static struct super_block *root_sb = NULL;
static struct inode_cache_entry *inode_cache[INODE_CACHE_SIZE];
static uint32_t next_inode_num = 1;
static volatile int vfs_lock = 0;

/* Forward declarations */
static struct inode *inode_cache_get(struct super_block *sb, uint32_t inode_num);
static void inode_cache_put(struct inode *inode);
static struct mount_point *find_mount_point(const char *path);
static int resolve_path(const char *path, struct inode **parent, char *name);
static int check_path_security(const char *path, uint32_t operation);

/* Initialize VFS */
int vfs_init(void) {
    debug_print("Initializing Virtual File System\n");
    
    /* Clear filesystem registry */
    for (int i = 0; i < MAX_FILESYSTEMS; i++) {
        registered_filesystems[i] = NULL;
    }
    
    /* Clear mount points */
    mount_points = NULL;
    
    /* Clear inode cache */
    for (int i = 0; i < INODE_CACHE_SIZE; i++) {
        inode_cache[i] = NULL;
    }
    
    debug_print("VFS initialized\n");
    return 0;
}

/* Register a file system */
int vfs_register_filesystem(struct filesystem_ops *fs_ops) {
    if (!fs_ops || !fs_ops->name) {
        return -1;
    }
    
    /* Find free slot */
    for (int i = 0; i < MAX_FILESYSTEMS; i++) {
        if (registered_filesystems[i] == NULL) {
            registered_filesystems[i] = fs_ops;
            debug_print("Registered filesystem: %s\n", fs_ops->name);
            return 0;
        }
    }
    
    return -1; /* No free slots */
}

/* Mount a file system */
int vfs_mount(const char *device, const char *mountpoint, const char *fstype, uint32_t flags) {
    if (!device || !mountpoint || !fstype) {
        return -1;
    }
    
    debug_print("Mounting %s on %s (type: %s)\n", device, mountpoint, fstype);
    
    /* Find filesystem */
    struct filesystem_ops *fs_ops = NULL;
    for (int i = 0; i < MAX_FILESYSTEMS; i++) {
        if (registered_filesystems[i] && 
            strcmp(registered_filesystems[i]->name, fstype) == 0) {
            fs_ops = registered_filesystems[i];
            break;
        }
    }
    
    if (!fs_ops) {
        debug_print("Unknown filesystem type: %s\n", fstype);
        return -1;
    }
    
    /* Check security */
    if (check_path_security(mountpoint, 0x02) != 0) { /* Write permission */
        security_audit_log("MOUNT_DENIED", 0, mountpoint);
        return -1;
    }
    
    /* Create mount point */
    struct mount_point *mp = (struct mount_point *)kmalloc(sizeof(struct mount_point));
    if (!mp) {
        return -1;
    }
    
    strncpy(mp->path, mountpoint, sizeof(mp->path) - 1);
    mp->path[sizeof(mp->path) - 1] = '\0';
    mp->flags = flags;
    mp->security_level = current_process ? current_process->security_level : 0;
    
    /* Mount filesystem */
    if (fs_ops->mount && fs_ops->mount(device, mountpoint, flags) != 0) {
        kfree(mp);
        return -1;
    }
    
    /* Get super block */
    mp->sb = fs_ops->get_super ? fs_ops->get_super(device) : NULL;
    if (!mp->sb) {
        kfree(mp);
        return -1;
    }
    
    /* Add to mount list */
    mp->next = mount_points;
    mount_points = mp;
    
    /* Set as root if mounting at / */
    if (strcmp(mountpoint, "/") == 0) {
        root_sb = mp->sb;
    }
    
    security_audit_log("FILESYSTEM_MOUNTED", 0, mountpoint);
    debug_print("Successfully mounted %s\n", mountpoint);
    
    return 0;
}

/* Unmount a file system */
int vfs_unmount(const char *mountpoint) {
    if (!mountpoint) {
        return -1;
    }
    
    debug_print("Unmounting %s\n", mountpoint);
    
    /* Find mount point */
    struct mount_point *mp = mount_points;
    struct mount_point *prev = NULL;
    
    while (mp) {
        if (strcmp(mp->path, mountpoint) == 0) {
            break;
        }
        prev = mp;
        mp = mp->next;
    }
    
    if (!mp) {
        return -1; /* Mount point not found */
    }
    
    /* Check security */
    if (check_path_security(mountpoint, 0x02) != 0) {
        security_audit_log("UNMOUNT_DENIED", 0, mountpoint);
        return -1;
    }
    
    /* Unmount filesystem */
    if (mp->sb->ops->unmount && mp->sb->ops->unmount(mountpoint) != 0) {
        return -1;
    }
    
    /* Remove from mount list */
    if (prev) {
        prev->next = mp->next;
    } else {
        mount_points = mp->next;
    }
    
    /* Clear root if unmounting / */
    if (mp->sb == root_sb) {
        root_sb = NULL;
    }
    
    kfree(mp);
    
    security_audit_log("FILESYSTEM_UNMOUNTED", 0, mountpoint);
    debug_print("Successfully unmounted %s\n", mountpoint);
    
    return 0;
}

/* Open a file */
struct file *vfs_open(const char *path, uint32_t flags, uint32_t mode) {
    if (!path) {
        return NULL;
    }
    
    debug_print("Opening file: %s\n", path);
    
    /* Check security */
    if (check_path_security(path, flags & 0x03) != 0) {
        security_audit_log("FILE_OPEN_DENIED", 0, path);
        return NULL;
    }
    
    /* Find mount point */
    struct mount_point *mp = find_mount_point(path);
    if (!mp) {
        debug_print("No mount point for path: %s\n", path);
        return NULL;
    }
    
    /* Resolve path to inode */
    struct inode *parent_inode;
    char filename[256];
    
    if (resolve_path(path, &parent_inode, filename) != 0) {
        debug_print("Failed to resolve path: %s\n", path);
        return NULL;
    }
    
    /* Find inode in directory */
    struct inode *inode = NULL;
    /* This would typically search the directory for the filename */
    /* For simplicity, we'll create a dummy inode */
    inode = (struct inode *)kmalloc(sizeof(struct inode));
    if (!inode) {
        return NULL;
    }
    
    /* Initialize inode */
    inode->inode_num = next_inode_num++;
    inode->mode = mode;
    inode->uid = current_process ? current_process->uid : 0;
    inode->gid = current_process ? current_process->gid : 0;
    inode->size = 0;
    inode->blocks = 0;
    inode->atime = inode->mtime = inode->ctime = get_timestamp();
    inode->links_count = 1;
    inode->flags = 0;
    inode->security_level = current_process ? current_process->security_level : 0;
    
    /* Create file structure */
    struct file *file = (struct file *)kmalloc(sizeof(struct file));
    if (!file) {
        kfree(inode);
        return NULL;
    }
    
    file->inode = inode;
    file->offset = 0;
    file->flags = flags;
    file->mode = mode;
    file->ref_count = 1;
    file->sb = mp->sb;
    file->private_data = NULL;
    
    /* Call filesystem open operation */
    if (mp->sb->ops->open && mp->sb->ops->open(inode, file) != 0) {
        kfree(file);
        kfree(inode);
        return NULL;
    }
    
    security_audit_log("FILE_OPENED", 0, path);
    debug_print("Successfully opened file: %s\n", path);
    
    return file;
}

/* Close a file */
int vfs_close(struct file *file) {
    if (!file) {
        return -1;
    }
    
    debug_print("Closing file (inode %d)\n", file->inode->inode_num);
    
    /* Decrement reference count */
    file->ref_count--;
    
    if (file->ref_count == 0) {
        /* Call filesystem release operation */
        if (file->sb->ops->release) {
            file->sb->ops->release(file->inode, file);
        }
        
        /* Free inode and file structures */
        kfree(file->inode);
        kfree(file);
    }
    
    return 0;
}

/* Read from a file */
ssize_t vfs_read(struct file *file, char *buffer, size_t count) {
    if (!file || !buffer || count == 0) {
        return -1;
    }
    
    /* Check permissions */
    if (!(file->flags & 0x01)) { /* O_RDONLY or O_RDWR */
        return -1; /* Permission denied */
    }
    
    /* Call filesystem read operation */
    if (file->sb->ops->read) {
        return file->sb->ops->read(file, buffer, count, &file->offset);
    }
    
    return -1; /* Not supported */
}

/* Write to a file */
ssize_t vfs_write(struct file *file, const char *buffer, size_t count) {
    if (!file || !buffer || count == 0) {
        return -1;
    }
    
    /* Check permissions */
    if (!(file->flags & 0x02)) { /* O_WRONLY or O_RDWR */
        return -1; /* Permission denied */
    }
    
    /* Call filesystem write operation */
    if (file->sb->ops->write) {
        return file->sb->ops->write(file, buffer, count, &file->offset);
    }
    
    return -1; /* Not supported */
}

/* Create a directory */
int vfs_mkdir(const char *path, uint32_t mode) {
    if (!path) {
        return -1;
    }
    
    debug_print("Creating directory: %s\n", path);
    
    /* Check security */
    if (check_path_security(path, 0x02) != 0) {
        security_audit_log("MKDIR_DENIED", 0, path);
        return -1;
    }
    
    /* Find mount point */
    struct mount_point *mp = find_mount_point(path);
    if (!mp) {
        return -1;
    }
    
    /* Resolve parent directory */
    struct inode *parent_inode;
    char dirname[256];
    
    if (resolve_path(path, &parent_inode, dirname) != 0) {
        return -1;
    }
    
    /* Call filesystem mkdir operation */
    if (mp->sb->ops->mkdir) {
        int result = mp->sb->ops->mkdir(parent_inode, dirname, mode);
        if (result == 0) {
            security_audit_log("DIRECTORY_CREATED", 0, path);
        }
        return result;
    }
    
    return -1; /* Not supported */
}

/* Remove a directory */
int vfs_rmdir(const char *path) {
    if (!path) {
        return -1;
    }
    
    debug_print("Removing directory: %s\n", path);
    
    /* Check security */
    if (check_path_security(path, 0x02) != 0) {
        security_audit_log("RMDIR_DENIED", 0, path);
        return -1;
    }
    
    /* Find mount point */
    struct mount_point *mp = find_mount_point(path);
    if (!mp) {
        return -1;
    }
    
    /* Resolve parent directory */
    struct inode *parent_inode;
    char dirname[256];
    
    if (resolve_path(path, &parent_inode, dirname) != 0) {
        return -1;
    }
    
    /* Call filesystem rmdir operation */
    if (mp->sb->ops->rmdir) {
        int result = mp->sb->ops->rmdir(parent_inode, dirname);
        if (result == 0) {
            security_audit_log("DIRECTORY_REMOVED", 0, path);
        }
        return result;
    }
    
    return -1; /* Not supported */
}

/* Find mount point for a path */
static struct mount_point *find_mount_point(const char *path) {
    struct mount_point *best_match = NULL;
    size_t best_match_len = 0;
    
    struct mount_point *mp = mount_points;
    while (mp) {
        size_t mp_len = strlen(mp->path);
        if (strncmp(path, mp->path, mp_len) == 0 && mp_len > best_match_len) {
            best_match = mp;
            best_match_len = mp_len;
        }
        mp = mp->next;
    }
    
    return best_match ? best_match : (root_sb ? mount_points : NULL);
}

/* Resolve path to parent inode and filename */
static int resolve_path(const char *path, struct inode **parent, char *name) {
    if (!path || !parent || !name) {
        return -1;
    }
    
    /* Find last '/' */
    const char *last_slash = strrchr(path, '/');
    if (!last_slash) {
        /* No slash, use current directory as parent */
        *parent = NULL; /* Would be current working directory */
        strncpy(name, path, 255);
        name[255] = '\0';
        return 0;
    }
    
    /* Extract filename */
    strncpy(name, last_slash + 1, 255);
    name[255] = '\0';
    
    /* For simplicity, return a dummy parent inode */
    *parent = (struct inode *)kmalloc(sizeof(struct inode));
    if (!*parent) {
        return -1;
    }
    
    /* Initialize parent inode as directory */
    (*parent)->inode_num = 1; /* Root directory */
    (*parent)->mode = 0755 | S_IFDIR;
    (*parent)->uid = 0;
    (*parent)->gid = 0;
    (*parent)->size = 4096;
    
    return 0;
}

/* Check path security */
static int check_path_security(const char *path, uint32_t operation) {
    if (!current_process) {
        return 0; /* Kernel operations allowed */
    }
    
    /* Pentagon-level path security checks */
    if (current_process->security_level < 2) {
        /* Restricted access for low clearance */
        if (strstr(path, "/classified/") || 
            strstr(path, "/secret/") ||
            strstr(path, "/pentagon/")) {
            return -1; /* Access denied */
        }
    }
    
    /* Additional security checks based on operation */
    if (operation & 0x02) { /* Write access */
        if (strstr(path, "/system/") && current_process->uid != 0) {
            return -1; /* Only root can write to system */
        }
    }
    
    return 0; /* Access allowed */
}

/* Get file system statistics */
int vfs_statfs(const char *path, struct statfs *buf) {
    if (!path || !buf) {
        return -1;
    }
    
    struct mount_point *mp = find_mount_point(path);
    if (!mp || !mp->sb) {
        return -1;
    }
    
    /* Fill statistics */
    buf->f_type = mp->sb->magic;
    buf->f_bsize = mp->sb->block_size;
    buf->f_blocks = mp->sb->total_blocks;
    buf->f_bfree = mp->sb->free_blocks;
    buf->f_bavail = mp->sb->free_blocks;
    buf->f_files = mp->sb->total_inodes;
    buf->f_ffree = mp->sb->free_inodes;
    
    return 0;
}

/* List all mounted file systems */
void vfs_list_mounts(void) {
    debug_print("\n=== Mounted File Systems ===\n");
    debug_print("Device\t\tMount Point\tType\tSecurity Level\n");
    debug_print("------\t\t-----------\t----\t--------------\n");
    
    struct mount_point *mp = mount_points;
    while (mp) {
        debug_print("%s\t\t%s\t\t%d\t%d\n",
                   mp->sb->device_name,
                   mp->path,
                   mp->sb->fs_type,
                   mp->security_level);
        mp = mp->next;
    }
    
    debug_print("============================\n\n");
}