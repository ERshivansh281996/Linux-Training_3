#Write a sophisticated signal handler to handle the Segmentation Violation case;it must display all relevant information that the kernel makes available; 
#bonus points for using an alternate signal stack for handling the signal 
----------------------------------------------------------------------------------------------------
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

typedef unsigned int u32;
typedef long unsigned int u64;
#if __x86_64__			
#define ADDR_TYPE u64
#define ADDR_FMT "%016lx"
static u64 rubbish_uaddr = 0x500f60L;
static u64 rubbish_kaddr = 0xffff0a8700100000L;
#else
#define ADDR_TYPE u32
#define ADDR_FMT "%08lx"
static u32 rubbish_uaddr = 0x500ffeL;
static u32 rubbish_kaddr = 0xd0c00000L;
#endif

static void myfault(int signum, siginfo_t * siginfo, void *rest)
{
	static int c = 0;

	printf("*** %s: [%d] received signal %d. errno=%d\n"
	       " Cause/Origin: (si_code=%d): ",
	       __func__, ++c, signum, siginfo->si_errno, siginfo->si_code);

	switch (siginfo->si_code) {
	case SI_USER:
		printf("user\n");
		break;
	case SI_KERNEL:
		printf("kernel\n");
		break;
	case SI_QUEUE:
		printf("queue\n");
		break;
	case SI_TIMER:
		printf("timer\n");
		break;
	case SI_MESGQ:
		printf("mesgq\n");
		break;
	case SI_ASYNCIO:
		printf("async io\n");
		break;
	case SI_SIGIO:
		printf("sigio\n");
		break;
	case SI_TKILL:
		printf("t[g]kill\n");
		break;
	case SEGV_MAPERR:
		printf("SEGV_MAPERR: address not mapped to object\n");
		break;
	case SEGV_ACCERR:
		printf("SEGV_ACCERR: invalid permissions for mapped object\n");
		break;
	default:
		printf("-none-\n");
	}
	printf(" Faulting addr=0x" ADDR_FMT "\n", (ADDR_TYPE) siginfo->si_addr);

#if 1
	exit(1);
#else
	abort();
#endif
}


int setup_altsigstack(size_t stack_sz)
{
	stack_t ss;

	printf("Alt signal stack size = %zu bytes\n", stack_sz);
	ss.ss_sp = malloc(stack_sz);
	if (!ss.ss_sp){
		printf("malloc(%zu) for alt sig stack failed\n", stack_sz);
		return -ENOMEM;
	}

	ss.ss_size = stack_sz;
	ss.ss_flags = 0;
	if (sigaltstack(&ss, NULL) == -1){
		printf("sigaltstack for size %zu failed!\n", stack_sz);
		return -errno;
	}
	printf("Alt signal stack uva (user virt addr) = %p\n", ss.ss_sp);

	return 0;
}

static void usage(char *nm)
{
	fprintf(stderr, "Usage: %s u|k r|w\n"
		"u => user mode\n"
		"k => kernel mode\n"
		" r => read attempt\n" " w => write attempt\n", nm);
}

int main(int argc, char **argv)
{
	struct sigaction act;

	if (argc != 3) {
		usage(argv[0]);
		exit(1);
	}

	printf("Regular stack uva eg (user virt addr) = %p\n", &act);

	
	if (setup_altsigstack(10*1024*1024) < 0) {
		fprintf(stderr, "%s: setting up alt sig stack failed\n", argv[0]);
		exit(1);
	}

	memset(&act, 0, sizeof(act));
	act.sa_sigaction = myfault;
	act.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
	sigemptyset(&act.sa_mask);

	if (sigaction(SIGSEGV, &act, 0) == -1) {
		perror("sigaction");
		exit(1);
	}

	if ((tolower(argv[1][0]) == 'u') && tolower(argv[2][0] == 'r')) {
		ADDR_TYPE *uptr = (ADDR_TYPE *) rubbish_uaddr;	
		printf
		    ("Attempting to read contents of arbitrary usermode va uptr = 0x"
		     ADDR_FMT ":\n", (ADDR_TYPE) uptr);
		printf("*uptr = 0x" ADDR_FMT "\n", *uptr);	
	} else if ((tolower(argv[1][0]) == 'u') && tolower(argv[2][0] == 'w')) {
		ADDR_TYPE *uptr = (ADDR_TYPE *) & main;
		printf
		    ("Attempting to write into arbitrary usermode va uptr (&main actually) = 0x"
		     ADDR_FMT ":\n", (ADDR_TYPE) uptr);
		*uptr = 40;
	} else if ((tolower(argv[1][0]) == 'k') && tolower(argv[2][0] == 'r')) {
		ADDR_TYPE *kptr = (ADDR_TYPE *) rubbish_kaddr;	
		printf
		    ("Attempting to read contents of arbitrary kernel va kptr = 0x"
		     ADDR_FMT ":\n", (ADDR_TYPE) kptr);
		printf("*kptr = 0x" ADDR_FMT "\n", *kptr);	
	} else if ((tolower(argv[1][0]) == 'k') && tolower(argv[2][0] == 'w')) {
		ADDR_TYPE *kptr = (ADDR_TYPE *) rubbish_kaddr;	
		printf
		    ("Attempting to write into arbitrary kernel va kptr = 0x"
		     ADDR_FMT ":\n", (ADDR_TYPE) kptr);
		*kptr = 0x62;	
	} else
		usage(argv[0]);
	exit(0);
}
