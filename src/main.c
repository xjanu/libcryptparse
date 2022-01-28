#include <stdio.h>
#include <stdlib.h>

#include <libcryptparse.h>

int main()
{
	struct cryptparse_alg *algorithms;
	cryptparse_parse("/proc/crypto", &algorithms);

	for (struct cryptparse_alg *alg = algorithms; alg != NULL; alg = alg->next)
	{
		printf("%s\n", alg->name);
	}

	cryptparse_destroy(algorithms);
	return 0;
}
