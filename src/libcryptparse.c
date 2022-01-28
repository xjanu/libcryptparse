
// For getline(3)
#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcryptparse.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

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
	{"max keysize", cryptparse_alg_max_keysize},
	{"min keysize", cryptparse_alg_min_keysize},
	{"seedsize",    cryptparse_alg_seedsize},
	{"selftest",    cryptparse_alg_selftest},
	{"walksize",    cryptparse_alg_walksize}
};

uint32_t field_lookup_from_str(char *from)
{
	for (size_t i = 0; i < ARRAY_SIZE(field_lookup); ++i) {
		if (strcmp(from, field_lookup[i].string) == 0) {
			return field_lookup[i].field;
		}
	}
	return 0;
}

static int value_parser_string(char **res, char *value)
{
	*res = calloc(strlen(value) + 1, sizeof(char));
	if (*res == NULL) {
		return ENOMEM;
	}
	strcpy(*res, value);
	return 0;
}

static int value_parser_bool(bool *res, char *value,
                             const char *trueval, const char *falseval)
{
	if (strcmp(value, trueval) == 0) {
		*res = true;
	} else if (strcmp(value, falseval) == 0) {
		*res = false;
	} else {
		return EINVAL;
	}
	return 0;
}

static int value_parser_unsigned(unsigned *res, char *value)
{
	errno = 0;
	unsigned long big = strtoul(value, NULL, 10);
	*res = big;
	if (big > UINT_MAX) {
		return ERANGE;
	}
	return errno;
}

static void _alg_destroy(struct cryptparse_alg *algorithm)
{
	if (algorithm->used_fields & cryptparse_alg_type)
		free(algorithm->type);
	if (algorithm->used_fields & cryptparse_alg_name)
		free(algorithm->name);
	if (algorithm->used_fields & cryptparse_alg_driver)
		free(algorithm->driver);
	if (algorithm->used_fields & cryptparse_alg_module)
		free(algorithm->module);
	if (algorithm->used_fields & cryptparse_alg_geniv)
		free(algorithm->geniv);
	algorithm->used_fields = 0;
	// Don't leave garbage in memory
	memset(algorithm, 0, sizeof(struct cryptparse_alg));
	free(algorithm);
}

static int line_parser(char* line, char **field, char **value)
{
	// Find the separating colon
	char *colon = strchr(line, ':');
	if (colon == NULL) {
		return 1; // No field-value separator.
	}

	// Get rid of trailing whitespace after field.
	*field = line;
	char *end = colon - 1;
	while (end > line && *end == ' ')
		--end;
	end[1] = '\0';

	if (colon[1] != ' ') {
		return 1; // Value not found.
	}
	*value = colon + 2;

	return 0;
}

static int cryptparse_alg_parse(FILE *fp, struct cryptparse_alg *algorithm)
{
	// TODO: Better error checking and reporting
	int ret = 0;

	algorithm->used_fields = 0;
	algorithm->next = NULL;

	char *line = NULL;
	size_t line_buf_len = 0;
	ssize_t nread;

	char *field, *value;

	while ((nread = getline(&line, &line_buf_len, fp)) != -1) {
		if (nread == 1)
			break;

		if (line[nread - 1] != '\n') {
			// Missing newline at EOF.
			ret = 1;
			goto out;
		}
		line[nread - 1] = '\0';

		if (line_parser(line, &field, &value) != 0) {
			// Failed to parse line
			ret = 1;
			goto out;
		}

		uint32_t alg_field = field_lookup_from_str(field);
		if (alg_field == 0) {
			// Invalid field name
			continue;
		}
		if ((algorithm->used_fields & alg_field) != 0) {
			// Field appeared twice
			continue;
		}

		algorithm->used_fields |= alg_field;

		int parser_ret;
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
		if (parser_ret != 0) {
			errno = parser_ret;
			fprintf(stderr, "%s ", field);
			perror("value_parser");
			ret = 1;
			goto out;
		}
	}
	if (nread == -1)
		ret = 2;
out:
	free(line);
	return ret;
}

int cryptparse_parse(char *path, struct cryptparse_alg **algorithms)
{
	FILE *fp = fopen(path, "r");
	if (fp == NULL) {
		*algorithms = NULL;
		return 1;
	}

	struct cryptparse_alg *prev, *curr;
	*algorithms = malloc(sizeof(struct cryptparse_alg));
	if (algorithms == NULL) {
		return 1;
	}

	if (cryptparse_alg_parse(fp, *algorithms) != 0)
	{
		return 1;
	}

	prev = *algorithms;
	while (true) {
		curr = malloc(sizeof(struct cryptparse_alg));
		if (cryptparse_alg_parse(fp, curr) != 0) {
			free(curr);
			break;
		}
		prev->next = curr;
		prev = curr;
	}
	fclose(fp);
	return 0;
}

void cryptparse_destroy(struct cryptparse_alg *algorithms)
{
	struct cryptparse_alg *next;
	while (algorithms != NULL) {
		next = algorithms->next;
		_alg_destroy(algorithms);
		algorithms = next;
	}
}
