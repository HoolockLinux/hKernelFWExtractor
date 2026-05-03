#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "plooshfinder.h"
#include "plooshfinder32.h"
#include "shared.h"

#include "formats/macho.h"

void *pmp_fw;
size_t pmp_fw_size;

static bool pmp_cb(struct pf_patch_t *patch, uint32_t *stream)
{
    // Extract size
    pmp_fw_size = 0x10000 | ((stream[2] >> 5) & 0xffff);

    pmp_fw = pf_follow_xref(kernel_buf, stream);

    if (!memmem(pmp_fw, pmp_fw_size, "RTKSTACK", 7)) {
        printf("PMP FW sanity check failed @ 0x %" PRIx64, macho_ptr_to_va(kernel_buf, stream));
        pmp_fw = NULL;

        return false;
    }

    printf("Found PMP FW size=%zu\n", pmp_fw_size);

    return true;
}

static bool pmp_old_cb(struct pf_patch_t *patch, uint32_t *stream)
{
    uint64_t *fw_entry = pf_follow_xref(kernel_buf, &stream[1]);
    const char *fw_name = macho_va_to_ptr(kernel_buf, fw_entry[0]);
    const char *fw_role = macho_va_to_ptr(kernel_buf, fw_entry[1]);
    const char *fw_ver = macho_va_to_ptr(kernel_buf, fw_entry[2]);
    const char *fw_var = macho_va_to_ptr(kernel_buf, fw_entry[3]);
    void *fw_ptr = macho_va_to_ptr(kernel_buf, fw_entry[4]);
    uint64_t fw_size = fw_entry[5];

    if (!fw_name || !fw_role || !fw_ver || !fw_var || !fw_ptr || fw_size < 0x10000 ||
        fw_size > 0x20000) {
        printf("PMP: Could not parse firmware entry @ 0x%" PRIx64,
               macho_ptr_to_va(kernel_buf, fw_entry));
        return false;
    }

    if (strcmp(fw_role, "PMP")) {
        printf("PMP: Unxpected firmware role");
        return false;
    }

    if (!memmem(fw_ptr, fw_size, "RTKSTACK", 7)) {
        printf("PMP FW sanity check failed @ 0x %" PRIx64, macho_ptr_to_va(kernel_buf, stream));
        return false;
    }

    pmp_fw = fw_ptr;
    pmp_fw_size = fw_size;

    printf("Found PMP FW size=%zu\n", pmp_fw_size);

    return true;
}

void find_pmp_fw(void *text_buf, size_t text_len)
{
    uint32_t matches[] = {
        0x90000000, // adrp x0, ...
        0x91000000, // add x0, x0, #0
        0x52800001, // movz w1, #.... ; lower bits of size
        0x72a00021, // movk w1, #1, lsl 16 ; high bits of size
        0x94000000  // bl
    };
    uint32_t masks[] = {
        0x9f00001f, //
        0xffffffff, //
        0xffe0001f, //
        0xffffffff, //
        0xfc000000, //
    };

    struct pf_patch_t pmp_fw_patch =
        pf_construct_patch(matches, masks, sizeof(matches) / sizeof(uint32_t), (void *)pmp_cb);

    uint32_t matches_old[] = {
        0x36000000, // tbz w0, #0x0
        0x90000000, // adrp x0, ...
        0x91000000, // add x0, x0, ...
        0x14000000  // b
    };

    uint32_t masks_old[] = {
        0xfff8001f, //
        0x9f00001f, //
        0xffc003ff, //
        0xfc000000, //
    };

    struct pf_patch_t pmp_fw_old_patch = pf_construct_patch(
        matches_old, masks_old, sizeof(matches_old) / sizeof(uint32_t), (void *)pmp_old_cb);

    struct pf_patch_t patches[] = {pmp_fw_patch, pmp_fw_old_patch};

    struct pf_patchset_t patchset = pf_construct_patchset(
        patches, sizeof(patches) / sizeof(struct pf_patch_t), (void *)pf_find_maskmatch32);

    pf_patchset_emit(text_buf, text_len, patchset);
}
