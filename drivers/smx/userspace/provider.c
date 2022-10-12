#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/mman.h>

#include <smx.h>
#include "memparse.h"

struct provider_config {
	uint64_t size;
	char *device;
};

void print_help(char *bin_name)
{
	printf("usage: %s -s <size>\n", bin_name);
}

int parse_args(int argc, char **argv, struct provider_config *config)
{
	uint64_t size;
	int c;
	char *endp;

	opterr = 0;
	config->size = 0;
	config->device = NULL;

	while ((c = getopt(argc, argv, "hs:d:")) != -1) {
		switch (c) {
		case 'h':
			print_help(argv[0]);
			break;
		case 's':
			size = memparse(optarg, &endp);
			if (size == 0) {
				fprintf(stderr, "Parsing memory size failed.\n");
				print_help(argv[0]);
				return -EINVAL;
			}
			config->size = size;
			break;
		case 'd':
			config->device = optarg;
			break;
		case '?':
			if (optopt == 's')
				fprintf(stderr, "option -%c requires an argument.\n", optopt);
			else if (isprint(optopt))
				fprintf(stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf(stderr, "Unknown option character `\\x%x'.\n", optopt);
			print_help(argv[0]);
			return -EINVAL;
		default:
			abort();
		}
	}

	return 0;
}

int main (int argc, char **argv)
{
	struct provider_config config;
	struct smx_provider_map_info info;
	int devfd, rc;
	uint64_t version;
	void *mem;

	rc = parse_args(argc, argv, &config);
	if (rc)
		return rc;

	devfd = open(config.device, O_RDWR);
	if (devfd < 0) {
		fprintf(stderr, "Cannot open %s.\n", config.device);
		return -EPERM;
	}

	mem = mmap(NULL, config.size, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB | MAP_HUGE_2MB, -1, 0);
	if (mem == NULL) {
		fprintf(stderr, "Unable to map %lu huge pages.\n", config.size / (1 << 20));
		return -ENOMEM;
	}
	info.base = (uint64_t) mem;
	info.size = config.size;

	rc = ioctl(devfd, SMX_PROVIDER_GET_VERSION, &version);
	if (rc) {
		fprintf(stderr, "Unable to get version.\n");
		return -EINVAL;
	}
	printf("smx version: %lx\n", version);

	rc = ioctl(devfd, SMX_PROVIDER_MAP_REGION, &info);
	if (rc) {
		fprintf(stderr, "Unable to pin memory.\n");
		return -EINVAL;
	}
	printf("region id: %lx\ndevice virtual address: %lx\n", info.id, info.dva);

	for (;;)
		pause();

	return 0;
}
