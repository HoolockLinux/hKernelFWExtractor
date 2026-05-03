#ifdef __gnu_linux__
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>

#include "formats/macho.h"
#include "patches/pmp.h"

static char *pmp_fw_kexts[][2] = {
    {"com.apple.driver.AppleS8000PMPFirmware", "s8000"},
    {"com.apple.driver.AppleS8001PMPFirmware", "s8001"},
    {"com.apple.driver.AppleT8010PMPFirmware", "t8010"},
    {"com.apple.driver.AppleT8011PMPFirmware", "t8011"},
    /* T8012: PMP HW exists, doesn't seem used */
    {"com.apple.driver.AppleT8015PMPFirmware", "t8015"},
};

void *kernel_buf;
size_t kernel_len;

#define xnu_va_to_ptr(addr)   macho_va_to_ptr(kernel_buf, macho_xnu_untag_va(addr))
#define find(function, sect) function(xnu_va_to_ptr(sect->addr), sect->size)

static int process_kernel(const char *directory, int out_fd, int apple_fd)
{
    printf("Starting hKernelFWExtractor\n");

    for (size_t i = 0; i < sizeof(pmp_fw_kexts) / sizeof(char *[2]); i++) {
        struct mach_header_64 *pmp_kext = macho_find_kext(kernel_buf, pmp_fw_kexts[i][0]);

        if (!pmp_kext)
            continue;

        struct section_64 *pmp_text = macho_find_section(pmp_kext, "__TEXT_EXEC", "__text");
        if (!pmp_text) {
            printf("Unable to find %s text!\n", pmp_fw_kexts[i][0]);
            return -1;
        }

        find(find_pmp_fw, pmp_text);

        if (!pmp_fw) {
            printf("Unable to find PMP firmware in %s!\n", pmp_fw_kexts[i][0]);
            return -1;
        }

        char fw_name[16];
        snprintf(fw_name, 16, "pmp-%s.bin", pmp_fw_kexts[i][1]);

        int fw_fd = openat(apple_fd, fw_name, O_CREAT | O_WRONLY, 0644);
        if (fw_fd < 0) {
            printf("Could not create file %s/apple/%s: %d (%s)\n", directory, fw_name, errno,
                   strerror(errno));
            return -1;
        }

        printf("%s -> %s/apple/%s\n", pmp_fw_kexts[i][0], directory, fw_name);

        write(fw_fd, pmp_fw, pmp_fw_size);
        close(fw_fd);

        pmp_fw = NULL;
        pmp_fw_size = 0;
    }

    printf("Kernel Processed!\n");
    return 0;
}

int output_files(const char *directory, int *out_fd, int *apple_fd)
{
    if (access(directory, F_OK) != 0) {
        int ret = mkdir(directory, 0755);
        if (ret < 0) {
            printf("Could not create directory %s: %d (%s)\n", directory, errno, strerror(errno));
            return -1;
        }
    }

    *out_fd = open(directory, O_DIRECTORY | O_SEARCH);
    if (*out_fd < 0) {
        printf("Could not open destination directory %s: %d (%s)\n", directory, errno,
               strerror(errno));
        return -1;
    }

    if (faccessat(*out_fd, "apple", F_OK, 0) != 0) {
        int ret = mkdirat(*out_fd, "apple", 0755);
        if (ret < 0) {
            printf("Could not create directory %s/apple: %d (%s)\n", directory, errno,
                   strerror(errno));
            return -1;
        }
    }

    *apple_fd = openat(*out_fd, "apple", O_DIRECTORY | O_SEARCH);
    if (*apple_fd < 0) {
        printf("Could not open destination directory %s/apple: %d (%s)\n", directory, errno,
               strerror(errno));
        close(*out_fd);
        return -1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int ret, in_fd, out_fd, apple_fd;

    if (argc < 3) {
        printf("Usage: %s <input kernel> <output directory>\n", argv[0]);
        return 0;
    }

    in_fd = open(argv[1], O_RDONLY);
    if (in_fd < 0) {
        printf("Failed to open kernel!\n");
        return -1;
    }

    kernel_len = lseek(in_fd, 0, SEEK_END);
    if (kernel_len < 0) {
        printf("Failed to seek kernel!\n");
        return -1;
    }

    kernel_buf = mmap(NULL, kernel_len, PROT_READ, MAP_FILE | MAP_PRIVATE, in_fd, 0);

    if (kernel_buf == MAP_FAILED) {
        printf("Failed to map kernel!\n");
        close(in_fd);
        return -1;
    }

    uint32_t magic = macho_get_magic(kernel_buf);

    if (!magic) {
        munmap(kernel_buf, kernel_len);
        close(in_fd);
        return 1;
    }

    void *orig_kernel_buf = kernel_buf;
    if (magic == 0xbebafeca) {
        kernel_buf = macho_find_arch(kernel_buf, CPU_TYPE_ARM64);
        if (!kernel_buf) {
            munmap(orig_kernel_buf, kernel_len);
            close(in_fd);
            return 1;
        }
    }

    ret = output_files(argv[2], &out_fd, &apple_fd);
    if (ret < 0)
        return -1;

    int retval = process_kernel(argv[2], out_fd, apple_fd);

    munmap(orig_kernel_buf, kernel_len);
    close(in_fd);
    close(apple_fd);
    close(out_fd);

    return retval;
}
