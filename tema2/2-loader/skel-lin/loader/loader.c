/*
 * Loader Implementation
 *
 * 2022, Operating Systems
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#include "exec_parser.h"

static so_exec_t *exec;
int fd = 0;
int rc = 0;

static void segv_handler(int signum, siginfo_t *info, void *context)
{
	/* TODO - actual loader implementation */
	int flag = 0;
	struct sigaction sa;
	if (signum != SIGSEGV)
	{
		sa.sa_sigaction(signum, info, context);
		return;
	}
	int page_size = getpagesize();
	uintptr_t psi_addr = (uintptr_t)info->si_addr;
	for (int i = 0; i < exec->segments_no; i++)
	{
		if ((psi_addr >= exec->segments[i].vaddr) && (psi_addr < exec->segments[i].vaddr + exec->segments[i].mem_size))
		{
			flag = 1;
			if (info->si_code == SEGV_MAPERR)
			{
				int page_nr = (int)(psi_addr - exec->segments[i].vaddr) / page_size;
				int page_distance = page_nr * page_size;
				if (page_nr < 0)
				{
					printf("bad page_nr ...weird\n");
					return;
				}
				void *addr_to_map = (void *)(exec->segments[i].vaddr + page_distance);
				void *p = mmap(addr_to_map, page_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
				if (p == MAP_FAILED)
				{
					printf("mmap failed segv_handler\n");
				}
				lseek(fd, 0, SEEK_SET);
				lseek(fd, exec->segments[i].offset + page_distance, SEEK_SET);
				if (page_distance > exec->segments[i].file_size && page_distance < exec->segments[i].mem_size){
					memset(p, 0, page_size);
				}
				else if (exec->segments[i].file_size - page_distance < page_size)
				{
					rc = read(fd, p, exec->segments[i].file_size - page_distance);
					if (rc < 0)
					{
						printf("bad read 1\n");
						return;
					}
				}
				else
				{
					rc = read(fd, p, page_size);
					if (rc < 0)
					{
						printf("bad read 2\n");
						return;
					}
				}
				rc = mprotect(p, page_size, exec->segments[i].perm);
				if (rc == -1)
				{
					printf("mprotect error\n");
					return;
				}
				return;
			}else if(info->si_code == SEGV_ACCERR){
				sa.sa_sigaction(signum, info, context);
				return;
			}
		}
	}
	if (flag == 0){
		sa.sa_sigaction(signum, info, context);return;
	}
}

int so_init_loader(void)
{
	int rc;
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	rc = sigaction(SIGSEGV, &sa, NULL);
	if (rc < 0)
	{
		perror("sigaction");
		return -1;
	}
	return 0;
}

int so_execute(char *path, char *argv[])
{
	fd = open(path, O_RDONLY);
	if (fd < 0)
	{
		printf("error open file so_execute\n");
		return -1;
	}
	exec = so_parse_exec(path);
	if (!exec)
		return -1;

	so_start_exec(exec, argv);
	rc = close(fd);
	if (rc == -1)
	{
		printf("error close in so_execute\n");
		return -1;
	}
	return -1;
}
