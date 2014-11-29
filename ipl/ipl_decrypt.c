/*
 * IPL-DECRYPTER SAMPLE
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <aio.h>
#include "kirk_engine.h"
#include "ipl.h"

static struct aiocb in = {
	.aio_offset = 0,
	.aio_nbytes = sizeof(iplEncBlk),
	.aio_reqprio = 0,
	.aio_sigevent.sigev_notify = SIGEV_NONE,
	.aio_lio_opcode = LIO_NOP
};

static struct aiocb out = {
	.aio_offset = 0,
	.aio_reqprio = 0,
	.aio_sigevent.sigev_notify = SIGEV_NONE,
	.aio_lio_opcode = LIO_NOP
};

static void errExit(const char *s)
{
	perror(s);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	int i;
	int ret;
	u32 hash = 0;
	const struct aiocb * const inp = &in;
	const struct aiocb * const outp = &out;
	iplEncBlk encblk;
	iplBlk blk;

	if (argc != 3) {
		printf("Usage: %s <input> <output>\n", argv[0]);
		return EXIT_FAILURE;
	}

	in.aio_fildes = open(argv[1], O_RDONLY);
	if (in.aio_fildes == -1)
		errExit("input");

	in.aio_buf = &encblk;

	if (aio_read(&in) == -1)
		errExit("input");

	out.aio_fildes = open(argv[2], O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (out.aio_fildes == -1)
		errExit("output");

	out.aio_buf = blk.data;

	kirk_init();

	while (1) {
		if (aio_suspend(&inp, 1, NULL))
			errExit("input");

		ret = kirk_CMD1(&blk, &encblk, sizeof(encblk));
		if (ret) {
			printf("Decryption failed: %d\n", ret);
			return EXIT_FAILURE;
		}

		out.aio_offset += out.aio_nbytes;
		out.aio_nbytes = blk.size;
		if (aio_write(&out) == -1)
			errExit("output");

		if (blk.entry)
			break;

		in.aio_offset += in.aio_nbytes;
		if (aio_read(&in) == -1)
			errExit("input");

		if (blk.hash != hash) {
			printf("hash check failed: expected: 0x%08X, result: 0x%08X\n",
				hash, blk.hash);
			return EXIT_FAILURE;
		}

		hash = 0;
		for (i = 0; i < blk.size / sizeof(u32); i++)
			hash += blk.data[i];

		if (aio_suspend(&outp, 1, NULL))
			errExit("output");
	}

	if (blk.hash != hash) {
		printf("hash check failed: expected: 0x%08X, result: 0x%08X\n",
			hash, blk.hash);
		return EXIT_FAILURE;
	}

	printf("entry: 0x%08X\n", blk.entry);

	if (close(in.aio_fildes))
		perror("input");

	if (aio_suspend(&outp, 1, NULL))
		errExit("output");

	if (close(out.aio_fildes))
		errExit("output");

	return EXIT_SUCCESS;
}
