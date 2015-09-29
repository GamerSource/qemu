#include "qemu-common.h"
#include "qapi/qmp/qerror.h"
#include "qemu/error-report.h"
#include "sysemu/sysemu.h"
#include "qmp-commands.h"
#include "qemu-options.h"
#include "migration/qemu-file.h"
#include "qom/qom-qobject.h"
#include "migration/migration.h"
#include "block/snapshot.h"
#include "block/qapi.h"
#include "block/block.h"
#include "qemu/timer.h"
#include "sysemu/block-backend.h"
#include "qapi/qmp/qstring.h"

/* #define DEBUG_SAVEVM_STATE */

#ifdef DEBUG_SAVEVM_STATE
#define DPRINTF(fmt, ...) \
    do { printf("savevm-async: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

enum {
    SAVE_STATE_DONE,
    SAVE_STATE_ERROR,
    SAVE_STATE_ACTIVE,
    SAVE_STATE_COMPLETED,
    SAVE_STATE_CANCELLED
};


static struct SnapshotState {
    BlockDriverState *bs;
    size_t bs_pos;
    int state;
    Error *error;
    Error *blocker;
    int saved_vm_running;
    QEMUFile *file;
    int64_t total_time;
} snap_state;

SaveVMInfo *qmp_query_savevm(Error **errp)
{
    SaveVMInfo *info = g_malloc0(sizeof(*info));
    struct SnapshotState *s = &snap_state;

    if (s->state != SAVE_STATE_DONE) {
        info->has_bytes = true;
        info->bytes = s->bs_pos;
        switch (s->state) {
        case SAVE_STATE_ERROR:
            info->has_status = true;
            info->status = g_strdup("failed");
            info->has_total_time = true;
            info->total_time = s->total_time;
            if (s->error) {
                info->has_error = true;
                info->error = g_strdup(error_get_pretty(s->error));
            }
            break;
        case SAVE_STATE_ACTIVE:
            info->has_status = true;
            info->status = g_strdup("active");
            info->has_total_time = true;
            info->total_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME)
                - s->total_time;
            break;
        case SAVE_STATE_COMPLETED:
            info->has_status = true;
            info->status = g_strdup("completed");
            info->has_total_time = true;
            info->total_time = s->total_time;
            break;
        }
    }

    return info;
}

static int save_snapshot_cleanup(void)
{
    int ret = 0;

    DPRINTF("save_snapshot_cleanup\n");

    snap_state.total_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME) -
        snap_state.total_time;

    if (snap_state.file) {
        ret = qemu_fclose(snap_state.file);
    }

    if (snap_state.bs) {
        /* try to truncate, but ignore errors (will fail on block devices).
         * note: bdrv_read() need whole blocks, so we round up
         */
        size_t size = (snap_state.bs_pos + BDRV_SECTOR_SIZE) & BDRV_SECTOR_MASK;
        bdrv_truncate(snap_state.bs, size);
        bdrv_op_unblock_all(snap_state.bs, snap_state.blocker);
        error_free(snap_state.blocker);
        snap_state.blocker = NULL;
        bdrv_unref(snap_state.bs);
        snap_state.bs = NULL;
    }

    return ret;
}

static void save_snapshot_error(const char *fmt, ...)
{
    va_list ap;
    char *msg;

    va_start(ap, fmt);
    msg = g_strdup_vprintf(fmt, ap);
    va_end(ap);

    DPRINTF("save_snapshot_error: %s\n", msg);

    if (!snap_state.error) {
        error_set(&snap_state.error, ERROR_CLASS_GENERIC_ERROR, "%s", msg);
    }

    g_free (msg);

    snap_state.state = SAVE_STATE_ERROR;

    save_snapshot_cleanup();
}

static void save_snapshot_completed(void)
{
    DPRINTF("save_snapshot_completed\n");

    if (save_snapshot_cleanup() < 0) {
        snap_state.state = SAVE_STATE_ERROR;
    } else {
        snap_state.state = SAVE_STATE_COMPLETED;
    }
}

static int block_state_close(void *opaque)
{
    snap_state.file = NULL;
    return bdrv_flush(snap_state.bs);
}

static int block_state_put_buffer(void *opaque, const uint8_t *buf,
                                  int64_t pos, int size)
{
    int ret;

    assert(pos == snap_state.bs_pos);

    if ((ret = bdrv_pwrite(snap_state.bs, snap_state.bs_pos, buf, size)) > 0) {
        snap_state.bs_pos += ret;
    }

    return ret;
}

static int store_and_stop(void) {
    if (global_state_store()) {
        save_snapshot_error("Error saving global state");
        return 1;
    }
    if (runstate_is_running()) {
        vm_stop(RUN_STATE_SAVE_VM);
    }
    return 0;
}

static void process_savevm_co(void *opaque)
{
    int ret;
    int64_t maxlen;
    MigrationParams params = {
        .blk = 0,
        .shared = 0
    };

    snap_state.state = SAVE_STATE_ACTIVE;

    qemu_mutex_unlock_iothread();
    qemu_savevm_state_header(snap_state.file);
    ret = qemu_savevm_state_begin(snap_state.file, &params);
    qemu_mutex_lock_iothread();

    if (ret < 0) {
        save_snapshot_error("qemu_savevm_state_begin failed");
        return;
    }

    while (snap_state.state == SAVE_STATE_ACTIVE) {
        uint64_t pending_size;

        pending_size = qemu_savevm_state_pending(snap_state.file, 0);

        if (pending_size) {
                ret = qemu_savevm_state_iterate(snap_state.file);
                if (ret < 0) {
                    save_snapshot_error("qemu_savevm_state_iterate error %d", ret);
                    break;
                }
                DPRINTF("savevm inerate pending size %lu ret %d\n", pending_size, ret);
        } else {
            DPRINTF("done iterating\n");
            if (store_and_stop())
                break;
            DPRINTF("savevm inerate finished\n");
            qemu_savevm_state_complete_precopy(snap_state.file);
            DPRINTF("save complete\n");
            save_snapshot_completed();
            break;
        }

        /* stop the VM if we get to the end of available space,
         * or if pending_size is just a few MB
         */
        maxlen = bdrv_getlength(snap_state.bs) - 30*1024*1024;
        if ((pending_size < 100000) ||
            ((snap_state.bs_pos + pending_size) >= maxlen)) {
            if (store_and_stop())
                break;
        }
    }

    if(snap_state.state == SAVE_STATE_CANCELLED) {
        save_snapshot_completed();
        Error *errp = NULL;
        qmp_savevm_end(&errp);
    }

}

static const QEMUFileOps block_file_ops = {
    .put_buffer =     block_state_put_buffer,
    .close =          block_state_close,
};


void qmp_savevm_start(bool has_statefile, const char *statefile, Error **errp)
{
    BlockDriver *drv = NULL;
    Error *local_err = NULL;

    int bdrv_oflags = BDRV_O_CACHE_WB | BDRV_O_RDWR;
    int ret;

    if (snap_state.state != SAVE_STATE_DONE) {
        error_set(errp, ERROR_CLASS_GENERIC_ERROR,
                  "VM snapshot already started\n");
        return;
    }

    /* initialize snapshot info */
    snap_state.saved_vm_running = runstate_is_running();
    snap_state.bs_pos = 0;
    snap_state.total_time = qemu_clock_get_ms(QEMU_CLOCK_REALTIME);
    snap_state.blocker = NULL;

    if (snap_state.error) {
        error_free(snap_state.error);
        snap_state.error = NULL;
    }

    if (!has_statefile) {
        vm_stop(RUN_STATE_SAVE_VM);
        snap_state.state = SAVE_STATE_COMPLETED;
        return;
    }

    if (qemu_savevm_state_blocked(errp)) {
        return;
    }

    /* Open the image */
    snap_state.bs = bdrv_new();
 
    QDict *options = NULL;
    options = qdict_new();
    qdict_put(options, "driver", qstring_from_str("raw"));
    ret = bdrv_open(&snap_state.bs, statefile, NULL, options, bdrv_oflags, drv, &local_err);
    if (ret < 0) {
        error_set(errp, ERROR_CLASS_GENERIC_ERROR, "failed to open '%s'", statefile);
        goto restart;
    }

    snap_state.file = qemu_fopen_ops(&snap_state, &block_file_ops);

    if (!snap_state.file) {
        error_set(errp, ERROR_CLASS_GENERIC_ERROR, "failed to open '%s'", statefile);
        goto restart;
    }


    error_setg(&snap_state.blocker, "block device is in use by savevm");
    bdrv_op_block_all(snap_state.bs, snap_state.blocker);

    Coroutine *co = qemu_coroutine_create(process_savevm_co);
    qemu_coroutine_enter(co, NULL);

    return;

restart:

    save_snapshot_error("setup failed");

    if (snap_state.saved_vm_running) {
        vm_start();
    }
}

void qmp_savevm_end(Error **errp)
{
    if (snap_state.state == SAVE_STATE_DONE) {
        error_set(errp, ERROR_CLASS_GENERIC_ERROR,
                  "VM snapshot not started\n");
        return;
    }

    if (snap_state.state == SAVE_STATE_ACTIVE) {
        snap_state.state = SAVE_STATE_CANCELLED;
        return;
    }

    if (snap_state.saved_vm_running) {
        vm_start();
    }

    snap_state.state = SAVE_STATE_DONE;
}

void qmp_snapshot_drive(const char *device, const char *name, Error **errp)
{
    BlockBackend *blk;
    BlockDriverState *bs;
    QEMUSnapshotInfo sn1, *sn = &sn1;
    int ret;
#ifdef _WIN32
    struct _timeb tb;
#else
    struct timeval tv;
#endif

    if (snap_state.state != SAVE_STATE_COMPLETED) {
        error_set(errp, ERROR_CLASS_GENERIC_ERROR,
                  "VM snapshot not ready/started\n");
        return;
    }

    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                  "Device '%s' not found", device);
        return;
    }

    bs = blk_bs(blk);
    if (!bdrv_is_inserted(bs)) {
        error_setg(errp, QERR_DEVICE_HAS_NO_MEDIUM, device);
        return;
    }

    if (bdrv_is_read_only(bs)) {
        error_setg(errp, "Node '%s' is read only", device);
        return;
    }

    if (!bdrv_can_snapshot(bs)) {
        error_setg(errp, QERR_UNSUPPORTED);
        return;
    }

    if (bdrv_snapshot_find(bs, sn, name) >= 0) {
        error_set(errp, ERROR_CLASS_GENERIC_ERROR,
                  "snapshot '%s' already exists", name);
        return;
    }

    sn = &sn1;
    memset(sn, 0, sizeof(*sn));

#ifdef _WIN32
    _ftime(&tb);
    sn->date_sec = tb.time;
    sn->date_nsec = tb.millitm * 1000000;
#else
    gettimeofday(&tv, NULL);
    sn->date_sec = tv.tv_sec;
    sn->date_nsec = tv.tv_usec * 1000;
#endif
    sn->vm_clock_nsec = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    pstrcpy(sn->name, sizeof(sn->name), name);

    sn->vm_state_size = 0; /* do not save state */

    ret = bdrv_snapshot_create(bs, sn);
    if (ret < 0) {
        error_set(errp, ERROR_CLASS_GENERIC_ERROR,
                  "Error while creating snapshot on '%s'\n", device);
        return;
    }
}

void qmp_delete_drive_snapshot(const char *device, const char *name,
                               Error **errp)
{
    BlockBackend *blk;
    BlockDriverState *bs;
    QEMUSnapshotInfo sn1, *sn = &sn1;
    Error *local_err = NULL;

    int ret;

    blk = blk_by_name(device);
    if (!blk) {
        error_set(errp, ERROR_CLASS_DEVICE_NOT_FOUND,
                  "Device '%s' not found", device);
        return;
    }

    bs = blk_bs(blk);
    if (bdrv_is_read_only(bs)) {
        error_setg(errp, "Node '%s' is read only", device);
        return;
    }

    if (!bdrv_can_snapshot(bs)) {
        error_setg(errp, QERR_UNSUPPORTED);
        return;
    }

    if (bdrv_snapshot_find(bs, sn, name) < 0) {
        /* return success if snapshot does not exists */
        return;
    }

    ret = bdrv_snapshot_delete(bs, NULL, name, &local_err);
    if (ret < 0) {
        error_set(errp, ERROR_CLASS_GENERIC_ERROR,
                  "Error while deleting snapshot on '%s'\n", device);
        return;
    }
}

static int loadstate_get_buffer(void *opaque, uint8_t *buf, int64_t pos,
                                int size)
{
    BlockDriverState *bs = (BlockDriverState *)opaque;
    int64_t maxlen = bdrv_getlength(bs);
    if (pos > maxlen) {
        return -EIO;
    }
    if ((pos + size) > maxlen) {
        size = maxlen - pos - 1;
    }
    if (size == 0) {
        return 0;
    }
    return bdrv_pread(bs, pos, buf, size);
}

static const QEMUFileOps loadstate_file_ops = {
    .get_buffer = loadstate_get_buffer,
};

int load_state_from_blockdev(const char *filename)
{
    BlockDriverState *bs = NULL;
    BlockDriver *drv = NULL;
    Error *local_err = NULL;
    Error *blocker = NULL;

    QEMUFile *f;
    int ret;

    bs = bdrv_new();
    ret = bdrv_open(&bs, filename, NULL, NULL, BDRV_O_CACHE_WB, drv, &local_err);
    error_setg(&blocker, "block device is in use by load state");
    bdrv_op_block_all(bs, blocker);

    if (ret < 0) {
        error_report("Could not open VM state file");
        goto the_end;
    }

    /* restore the VM state */
    f = qemu_fopen_ops(bs, &loadstate_file_ops);
    if (!f) {
        error_report("Could not open VM state file");
        ret = -EINVAL;
        goto the_end;
    }

    qemu_system_reset(VMRESET_SILENT);
    migration_incoming_state_new(f);
    ret = qemu_loadvm_state(f);

    qemu_fclose(f);
    migration_incoming_state_destroy();
    if (ret < 0) {
        error_report("Error %d while loading VM state", ret);
        goto the_end;
    }

    ret = 0;

 the_end:
    if (bs) {
        bdrv_op_unblock_all(bs, blocker);
        error_free(blocker);
        bdrv_unref(bs);
    }
    return ret;
}