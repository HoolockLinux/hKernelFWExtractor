#ifndef _PATCHES_PMP_H
#define _PATCHES_PMP_H

#include <stddef.h>

extern size_t pmp_fw_size;
extern void *pmp_fw;
void find_pmp_fw(void *text_buf, size_t text_len);

#endif
