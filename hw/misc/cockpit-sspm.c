/* SPDX-License-Identifier: GPL-2.0-or-later */
/* MTK SSPM v1 mailbox transport experiment; no SSPM command execution.
 * Addresses and optional software-peer boot layout come from the caller.
 * ctrl+0 sends a doorbell; ctrl+4 is receive pending / write-one-to-clear.
 * No peer is connected: sends remain pending and NEVER manufacture replies.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "qemu/module.h"
#include "hw/qdev-properties.h"
#include "sysemu/reset.h"
#include "exec/address-spaces.h"
#include "exec/memory.h"

#define TYPE_SSPM "cockpit-sspm-mailbox"
#define BANK_SIZE 256

typedef struct SSPMState {
    DeviceState parent_obj;
    MemoryRegion data, control;
    uint64_t addr, ctrl_addr, ram_size;
    char *boot_layout;
    bool analysis;
    uint8_t initial[BANK_SIZE];
    uint8_t *bytes;
    uint32_t tx_pending, rx_pending;
} SSPMState;

static uint64_t sspm_ctrl_read(void *opaque, hwaddr offset, unsigned size)
{
    SSPMState *s = opaque;
    return offset == 0 ? s->tx_pending : s->rx_pending;
}

static void sspm_ctrl_write(void *opaque, hwaddr offset, uint64_t value,
                            unsigned size)
{
    SSPMState *s = opaque;
    if (offset == 4) {
        s->rx_pending &= ~value;
    } else {
        s->tx_pending |= value;
        /* Metadata only: do not log mailbox payloads. */
        qemu_log_mask(LOG_UNIMP, TYPE_SSPM " send addr=0x%" PRIx64
                      " mask=0x%08" PRIx64 " unsupported-peer; no reply\n",
                      s->ctrl_addr, value);
    }
}

static const MemoryRegionOps sspm_ctrl_ops = {
    .read = sspm_ctrl_read, .write = sspm_ctrl_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 4, .max_access_size = 4 },
    .impl = { .min_access_size = 4, .max_access_size = 4 },
};

static bool sspm_mapping_ok(uint64_t addr, uint64_t size, Error **errp)
{
    MemoryRegionSection section;
    uint64_t end = addr + size;
    if (addr % 4 || addr < 0x10000000 || addr > 0x3eff0000 - size) {
        error_setg(errp, TYPE_SSPM ": mapping must be aligned in virt low PCI aperture");
        return false;
    }
    while (addr < end) {
        bool valid;
        section = memory_region_find(get_system_memory(), addr, end - addr);
        if (!section.mr) {
            break;
        }
        /* Refuse RAM and all populated devices, including another mailbox. */
        valid = !memory_region_is_ram(section.mr) &&
                !memory_region_is_rom(section.mr) &&
                !strcmp(memory_region_name(section.mr), "gpex_mmio_window");
        addr = section.offset_within_address_space + int128_get64(section.size);
        memory_region_unref(section.mr);
        if (!valid) {
            error_setg(errp, TYPE_SSPM ": refusing populated mapping");
            return false;
        }
    }
    return true;
}

static void sspm_reset(DeviceState *dev)
{
    SSPMState *s = (SSPMState *)dev;
    if (s->bytes) {
        /* Page padding is explicitly owned analysis RAM, not hardware state. */
        memset(s->bytes, 0, s->ram_size);
        memcpy(s->bytes, s->initial, BANK_SIZE);
        memory_region_set_dirty(&s->data, 0, s->ram_size);
    }
    s->tx_pending = s->rx_pending = 0;
}

static void sspm_machine_reset(void *opaque)
{
    sspm_reset(DEVICE(opaque));
}

static void sspm_unrealize(DeviceState *dev)
{
    SSPMState *s = (SSPMState *)dev;
    qemu_unregister_reset(sspm_machine_reset, dev);
    memory_region_del_subregion(get_system_memory(), &s->data);
    memory_region_del_subregion(get_system_memory(), &s->control);
}

static void sspm_realize(DeviceState *dev, Error **errp)
{
    SSPMState *s = (SSPMState *)dev;
    g_autofree char *contents = NULL;
    g_autofree char *ram_name = NULL;
    g_autoptr(GError) error = NULL;
    Error *ram_error = NULL;
    gsize length;
    if (!s->analysis) {
        error_setg(errp, TYPE_SSPM ": requires explicit analysis=on; no SSPM firmware peer");
        return;
    }
    /* No implicit expansion of the firmware's 256-byte resource. The caller
     * must reserve the full backing extent, including padding, from PCI and
     * all other devices. Refuse hosts whose pages would swallow controls. */
    if (s->ram_size < qemu_real_host_page_size() ||
        s->ram_size < 4096 || s->ram_size > 65536 ||
        (s->ram_size & (s->ram_size - 1)) || s->addr % s->ram_size) {
        error_setg(errp, TYPE_SSPM ": explicit aligned ram-size (host page..64 KiB) required");
        return;
    }
    if (!sspm_mapping_ok(s->addr, s->ram_size, errp) ||
        !sspm_mapping_ok(s->ctrl_addr, 8, errp)) {
        return;
    }
    if (s->addr < s->ctrl_addr + 8 && s->ctrl_addr < s->addr + s->ram_size) {
        error_setg(errp, TYPE_SSPM ": data/control overlap");
        return;
    }
    if (s->boot_layout) {
        if (!g_file_get_contents(s->boot_layout, &contents, &length, &error)) {
            error_setg(errp, TYPE_SSPM ": cannot read boot layout: %s", error->message);
            return;
        }
        if (length != BANK_SIZE) {
            error_setg(errp, TYPE_SSPM ": boot layout must be exactly 256 bytes");
            return;
        }
        memcpy(s->initial, contents, BANK_SIZE);
    }
    warn_report(TYPE_SSPM ": software transport only; boot layout=%s; no command replies/IRQ/SSPM execution",
                s->boot_layout ? "explicit analysis seed, not silicon reset" : "zero analysis state");
    /* Plain DeviceState has no bus path for the RAMBlock identifier. */
    ram_name = g_strdup_printf(TYPE_SSPM "-data@%" PRIx64, s->addr);
    memory_region_init_ram(&s->data, OBJECT(dev), ram_name,
                           s->ram_size, &ram_error);
    if (ram_error) {
        error_propagate(errp, ram_error);
        return;
    }
    s->bytes = memory_region_get_ram_ptr(&s->data);
    sspm_reset(dev);
    memory_region_init_io(&s->control, OBJECT(dev), &sspm_ctrl_ops, s,
                         TYPE_SSPM "-control", 8);
    memory_region_add_subregion_overlap(get_system_memory(), s->addr, &s->data, 1);
    memory_region_add_subregion_overlap(get_system_memory(), s->ctrl_addr, &s->control, 1);
    /* Explicitly mapped DeviceState has no bus reset traversal. Register
     * with machine reset without coupling virt's dynamic sysbus/FDT lists. */
    qemu_register_reset(sspm_machine_reset, dev);
}

static Property sspm_props[] = {
    DEFINE_PROP_UINT64("addr", SSPMState, addr, 0),
    DEFINE_PROP_UINT64("ctrl-addr", SSPMState, ctrl_addr, 0),
    DEFINE_PROP_UINT64("ram-size", SSPMState, ram_size, 0),
    DEFINE_PROP_BOOL("analysis", SSPMState, analysis, false),
    DEFINE_PROP_STRING("boot-layout", SSPMState, boot_layout),
    DEFINE_PROP_END_OF_LIST(),
};

static void sspm_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = sspm_realize;
    dc->unrealize = sspm_unrealize;
    dc->reset = sspm_reset;
    dc->hotpluggable = false;
    dc->user_creatable = true;
    dc->desc = "Analysis-only MTK SSPM v1 mailbox storage/doorbell, no firmware peer";
    device_class_set_props(dc, sspm_props);
}

static const TypeInfo sspm_info = {
    .name = TYPE_SSPM, .parent = TYPE_DEVICE,
    .instance_size = sizeof(SSPMState), .class_init = sspm_class_init,
};

static void sspm_register(void)
{
    type_register_static(&sspm_info);
}
type_init(sspm_register)
