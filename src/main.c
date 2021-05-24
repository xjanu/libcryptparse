#include <stdio.h>
#include <stdlib.h>

#include <libcryptparse.h>

int main()
{
	struct cryptparse_alg *algorithms;
	cryptparse_parse("/proc/crypto", &algorithms);
	cryptparse_destroy(algorithms);
	return 0;
}
