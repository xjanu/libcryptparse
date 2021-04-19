
// For getline(3)
#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcryptparse.h"

// TODO: Check all mallocs

// Used for binding strings to fields
struct field_binding {
	char *string;
	enum cryptparse_alg_fields field;
};

// Lookup table for matching a string with a field it represents
static const struct field_binding field_lookup[] = {
	{"type",        cryptparse_alg_type},
	{"name",        cryptparse_alg_name},
	{"driver",      cryptparse_alg_driver},
	{"module",      cryptparse_alg_module},
	{"priority",    cryptparse_alg_priority},
	{"refcnt",      cryptparse_alg_refcnt},
	{"async",       cryptparse_alg_async},
	{"blocksize",   cryptparse_alg_blocksize},
	{"chunksize",   cryptparse_alg_chunksize},
	{"digestsize",  cryptparse_alg_digestsize},
	{"geniv",       cryptparse_alg_geniv},
	{"internal",    cryptparse_alg_internal},
	{"ivsize",      cryptparse_alg_ivsize},
	{"maxauthsize", cryptparse_alg_maxauthsize},
	{"max_keysize", cryptparse_alg_max_keysize},
	{"min_keysize", cryptparse_alg_min_keysize},
	{"seedsize",    cryptparse_alg_seedsize},
	{"selftest",    cryptparse_alg_selftest},
	{"walksize",    cryptparse_alg_walksize}
};

static bool value_parser_string(char **res, char *value) {
	*res = calloc(strlen(value) + 1, sizeof(char));
	if (*res == NULL)
		return false;
	strcpy(*res, value);
	return true;
}

static bool value_parser_bool(bool *res, char *value,
                              const char *trueval, const char *falseval)
{
	if (strcmp(value, trueval) == 0) {
		*res = true;
	} else if (strcmp(value, falseval) == 0) {
		*res = false;
	} else {
		errno = EINVAL;
		return false;
	}
	return true;
}

static bool value_parser_unsigned(unsigned *res, char *value)
{
	errno = 0;
	unsigned long big = strtoul(value, NULL, 10);
	if (big > UINT_MAX)
		errno = ERANGE;
	*res = big;
	return errno == 0 ? true : false;
}

static void _alg_destroy(struct cryptparse_alg *algorithm) {
	free(algorithm->type);
	free(algorithm->name);
	free(algorithm->driver);
	free(algorithm->module);
	if (algorithm->used_fields & cryptparse_alg_geniv)
		free(algorithm->geniv);
	algorithm->used_fields = 0;
	// Don't leave garbage in memory
	memset(algorithm, 0, sizeof(struct cryptparse_alg));
}

static int cryptparse_alg_parse(FILE *fp, struct cryptparse_alg *algorithm)
{
	// TODO: Better decomposition
	// TODO: Better error checking and reporting
	int ret = 0;

	algorithm->used_fields = 0;

	char *line = NULL;
	size_t line_buf_len = 0;
	ssize_t nread;

	while ((nread = getline(&line, &line_buf_len, fp)) != -1) {
		if (nread == 1)
			break;
		assert(line[nread - 1] == '\n');
		line[nread-1] = '\0';

		char *colon = strchr(line, ':');
		assert(colon != NULL);

		char *field = line;
		for (char* i = colon - 1; i >= field && *i == ' '; --i)
			*i = '\0';

		assert(*colon == ':');
		assert(*(colon + 1) == ' ');
		assert(line[nread - 1] == '\0');
		line[nread] = '\0';
		char *value = colon + 2;

		int alg_field = 0;
		for (size_t i = 0;
		     i < sizeof(field_lookup)/ sizeof(struct field_binding);
		     ++i) {
			if (strcmp(field, field_lookup[i].string) == 0) {
				alg_field = field_lookup[i].field;
				break;
			}
		}
		assert(alg_field != 0);
		assert((algorithm->used_fields & alg_field) == 0);

		algorithm->used_fields |= alg_field;

		bool parser_ret;
		switch(alg_field) {
		// String members
		case cryptparse_alg_type:
			parser_ret = value_parser_string(&algorithm->type, value);
			break;
		case cryptparse_alg_name:
			parser_ret = value_parser_string(&algorithm->name, value);
			break;
		case cryptparse_alg_driver:
			parser_ret = value_parser_string(&algorithm->driver, value);
			break;
		case cryptparse_alg_module:
			parser_ret = value_parser_string(&algorithm->module, value);
			break;
		case cryptparse_alg_geniv:
			parser_ret = value_parser_string(&algorithm->geniv, value);
			break;
		// Bool members
		case cryptparse_alg_async:
			parser_ret = value_parser_bool(&algorithm->async, value, "yes", "no");
			break;
		case cryptparse_alg_internal:
			parser_ret = value_parser_bool(&algorithm->internal, value, "yes", "no");
			break;
		case cryptparse_alg_selftest:
			parser_ret = value_parser_bool(&algorithm->selftest, value, "passed", "failed");
			break;
		// Unsigned members
		case cryptparse_alg_priority:
			parser_ret = value_parser_unsigned(&algorithm->priority, value);
			break;
		case cryptparse_alg_refcnt:
			parser_ret = value_parser_unsigned(&algorithm->refcnt, value);
			break;
		case cryptparse_alg_blocksize:
			parser_ret = value_parser_unsigned(&algorithm->blocksize, value);
			break;
		case cryptparse_alg_chunksize:
			parser_ret = value_parser_unsigned(&algorithm->chunksize, value);
			break;
		case cryptparse_alg_digestsize:
			parser_ret = value_parser_unsigned(&algorithm->digestsize, value);
			break;
		case cryptparse_alg_ivsize:
			parser_ret = value_parser_unsigned(&algorithm->ivsize, value);
			break;
		case cryptparse_alg_maxauthsize:
			parser_ret = value_parser_unsigned(&algorithm->maxauthsize, value);
			break;
		case cryptparse_alg_max_keysize:
			parser_ret = value_parser_unsigned(&algorithm->max_keysize, value);
			break;
		case cryptparse_alg_min_keysize:
			parser_ret = value_parser_unsigned(&algorithm->min_keysize, value);
			break;
		case cryptparse_alg_seedsize:
			parser_ret = value_parser_unsigned(&algorithm->seedsize, value);
			break;
		case cryptparse_alg_walksize:
			parser_ret = value_parser_unsigned(&algorithm->walksize, value);
			break;
		default:
			assert(false);
		}
		if (!parser_ret) {
			fprintf(stderr, "%s ", field);
			perror("value_parser");
			ret = 1;
			goto out;
		}
	}

out:
	free(line);
	return ret;
}

int cryptparse_parse(char *path, struct cryptparse_alg **algorithms)
{
	FILE *fp = fopen(path, "r");

	// TODO: Parse more than one algo ^_~
	*algorithms = malloc(sizeof(struct cryptparse_alg));
	cryptparse_alg_parse(fp, *algorithms);

	_alg_destroy(*algorithms);
	fclose(fp);

	return 1;
}
