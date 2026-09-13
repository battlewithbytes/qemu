/* Exact experimental MMIO and shared-memory mappings for the debug cockpit.
 * SPDX-License-Identifier: GPL-2.0-or-later
 * DT construction, PCI aperture exclusion, and evidence policy are performed
 * by cockpit. These explicit devices never attach themselves automatically.
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/log.h"
#include "hw/qdev-properties.h"
#include "hw/core/cpu.h"
#include "exec/address-spaces.h"
#include "sysemu/hostmem.h"
#include "sysemu/cpus.h"
#include "sysemu/hw_accel.h"
#include "qemu/module.h"
#include "qemu/units.h"

#define TYPE_COCKPIT_MMIO "cockpit-mmio"
#define TYPE_COCKPIT_SHMEM "cockpit-shmem"

typedef struct CockpitMMIO {
    DeviceState parent_obj;
    MemoryRegion mr;
    uint64_t addr;
    uint64_t size;
    uint32_t read_value;
} CockpitMMIO;

static uint64_t cockpit_pc(void)
{
    if (!current_cpu) {
        return 0;
    }
    cpu_synchronize_state(current_cpu);
    return CPU_GET_CLASS(current_cpu)->get_pc(current_cpu);
}

static uint64_t cockpit_read(void *opaque, hwaddr offset, unsigned size)
{
    CockpitMMIO *s = opaque;
    uint64_t pattern = ((uint64_t)s->read_value << 32) | s->read_value;
    uint64_t value = pattern >> ((offset & 3) * 8);
    if (size < 8) {
        value &= (1ULL << (size * 8)) - 1;
    }
    qemu_log_mask(LOG_UNIMP, "cockpit-mmio read addr=0x%" HWADDR_PRIx
                  " size=%u value=0x%" PRIx64 " pc=0x%" PRIx64 "\n",
                  s->addr + offset, size, value,
                  cockpit_pc());
    return value;
}

static void cockpit_write(void *opaque, hwaddr offset, uint64_t value,
                          unsigned size)
{
    CockpitMMIO *s = opaque;
    qemu_log_mask(LOG_UNIMP, "cockpit-mmio write addr=0x%" HWADDR_PRIx
                  " size=%u value=0x%" PRIx64 " pc=0x%" PRIx64 " ignored\n",
                  s->addr + offset, size, value,
                  cockpit_pc());
}

static const MemoryRegionOps cockpit_ops = {
    .read = cockpit_read,
    .write = cockpit_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = { .min_access_size = 1, .max_access_size = 4 },
    .impl = { .min_access_size = 1, .max_access_size = 4 },
};

static void cockpit_mmio_realize(DeviceState *dev, Error **errp)
{
    CockpitMMIO *s = (CockpitMMIO *)dev;
    MemoryRegionSection section;
    if (!s->size || s->size > 16 * MiB || s->addr > UINT64_MAX - s->size) {
        error_setg(errp, "cockpit-mmio: invalid address/size (maximum 16 MiB)");
        return;
    }
    section = memory_region_find(get_system_memory(), s->addr, s->size);
    if (section.mr) {
        bool ram = memory_region_is_ram(section.mr) || memory_region_is_rom(section.mr);
        memory_region_unref(section.mr);
        if (ram) {
            error_setg(errp, "cockpit-mmio: refusing to overlay RAM/ROM");
            return;
        }
        /* v1 permits only virt's low PCI aperture. The accompanying DT must
         * exclude these exact bytes from PCI ranges before Linux assigns BARs.
         */
        if (s->addr < 0x10000000 || s->addr + s->size > 0x3eff0000) {
            error_setg(errp, "cockpit-mmio: refusing to overlay a platform device");
            return;
        }
    }
    memory_region_init_io(&s->mr, OBJECT(dev), &cockpit_ops, s,
                          TYPE_COCKPIT_MMIO, s->size);
    memory_region_add_subregion_overlap(get_system_memory(), s->addr, &s->mr, 1);
}

static Property cockpit_mmio_props[] = {
    DEFINE_PROP_UINT64("addr", CockpitMMIO, addr, 0),
    DEFINE_PROP_UINT64("size", CockpitMMIO, size, 0),
    DEFINE_PROP_UINT32("read-value", CockpitMMIO, read_value, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void cockpit_mmio_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = cockpit_mmio_realize;
    dc->hotpluggable = false;
    dc->desc = "Experimental exact-range constant MMIO (not a hardware model)";
    device_class_set_props(dc, cockpit_mmio_props);
}

typedef struct CockpitShmem {
    DeviceState parent_obj;
    MemoryRegion alias;
    HostMemoryBackend *memdev;
    uint64_t addr;
} CockpitShmem;

static void cockpit_shmem_realize(DeviceState *dev, Error **errp)
{
    CockpitShmem *s = (CockpitShmem *)dev;
    MemoryRegion *mr;
    MemoryRegionSection section;
    if (!s->memdev || host_memory_backend_is_mapped(s->memdev)) {
        error_setg(errp, "cockpit-shmem: an unused memdev is required");
        return;
    }
    mr = host_memory_backend_get_memory(s->memdev);
    if (s->addr > UINT64_MAX - memory_region_size(mr)) {
        error_setg(errp, "cockpit-shmem: address overflow");
        return;
    }
    /* Keep v1 outside existing RAM/device mappings. Fixed-address aliases
     * within guest RAM need a separate verified reservation/overlay policy.
     */
    section = memory_region_find(get_system_memory(), s->addr, memory_region_size(mr));
    if (section.mr) {
        memory_region_unref(section.mr);
        error_setg(errp, "cockpit-shmem: range is already mapped");
        return;
    }
    memory_region_init_alias(&s->alias, OBJECT(dev), TYPE_COCKPIT_SHMEM,
                             mr, 0, memory_region_size(mr));
    memory_region_add_subregion(get_system_memory(), s->addr, &s->alias);
    host_memory_backend_set_mapped(s->memdev, true);
}

static Property cockpit_shmem_props[] = {
    DEFINE_PROP_UINT64("addr", CockpitShmem, addr, 0),
    DEFINE_PROP_LINK("memdev", CockpitShmem, memdev, TYPE_MEMORY_BACKEND,
                     HostMemoryBackend *),
    DEFINE_PROP_END_OF_LIST(),
};

static void cockpit_shmem_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    dc->realize = cockpit_shmem_realize;
    dc->hotpluggable = false;
    dc->desc = "Fixed-address shared memory for AP/modem experiments";
    device_class_set_props(dc, cockpit_shmem_props);
}

static const TypeInfo cockpit_types[] = {
    { .name = TYPE_COCKPIT_MMIO, .parent = TYPE_DEVICE,
      .instance_size = sizeof(CockpitMMIO), .class_init = cockpit_mmio_class_init },
    { .name = TYPE_COCKPIT_SHMEM, .parent = TYPE_DEVICE,
      .instance_size = sizeof(CockpitShmem), .class_init = cockpit_shmem_class_init },
};
DEFINE_TYPES(cockpit_types)
