
// For getline(3)
#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libcryptparse.h"

// Check cryptparse_alg_parse format when changing these macro values.
#define MAX_FIELD_LENGTH 16  // 12 should be enough
#define MAX_VALUE_LENGTH 128

// TODO: Check all mallocs

static char *_alg_string_thing(char *value) {
	char *ret = calloc(strlen(value) + 1, sizeof(char));
	if (ret != NULL)
		strcpy(ret, value);
	return ret;
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
	algorithm->used_fields = 0;

	char *field, *value, *line = NULL;
	size_t line_buf_len = 0;
	ssize_t nread;

	while ((nread = getline(&line, &line_buf_len, fp)) != -1) {
		if (nread == 1)
			break;
		line[nread-1] = '\0';

		char* colon = strchr(line, ':');
		assert(colon != NULL);

		field = line;
		for (char* i = colon - 1; i >= field && *i == ' '; --i)
			*i = '\0';

		assert(*colon == ':');
		assert(*(colon + 1) == ' ');
		value = colon + 2;

		// TODO: Fix vvv (Perhaps use a lookup table?)
		//       Also use helper functions for unsigned/bool conversions
		// This is horrid and i know it :(
		if (strcmp(field, "type") == 0) {
			// TODO: Fix the string copying
			algorithm->type = _alg_string_thing(value);
			algorithm->used_fields |= cryptparse_alg_type;

		} else if (strcmp(field, "name") == 0) {
			algorithm->name = _alg_string_thing(value);
			algorithm->used_fields |= cryptparse_alg_name;

		} else if (strcmp(field, "driver") == 0) {
			algorithm->driver = _alg_string_thing(value);
			algorithm->used_fields |= cryptparse_alg_driver;

		} else if (strcmp(field, "module") == 0) {
			algorithm->module = _alg_string_thing(value);
			algorithm->used_fields |= cryptparse_alg_module;

		} else if (strcmp(field, "priority") == 0) {
			algorithm->priority = strtoul(value, NULL, 10);
			algorithm->used_fields |= cryptparse_alg_priority;

		} else if (strcmp(field, "refcnt") == 0) {
			algorithm->refcnt = strtoul(value, NULL, 10);
			algorithm->used_fields |= cryptparse_alg_refcnt;

		} else if (strcmp(field, "async") == 0) {
			if (strcmp(value, "yes") == 0)
				algorithm->async = true;
			else if (strcmp(value, "no") == 0)
				algorithm->async = false;
			else
				assert(false);
			algorithm->used_fields |= cryptparse_alg_async;

		} else if (strcmp(field, "blocksize") == 0) {
			algorithm->blocksize = strtoul(value, NULL, 10);
			algorithm->used_fields |= cryptparse_alg_blocksize;

		} else if (strcmp(field, "chunksize") == 0) {
			algorithm->chunksize = strtoul(value, NULL, 10);
			algorithm->used_fields |= cryptparse_alg_chunksize;

		} else if (strcmp(field, "digestsize") == 0) {
			algorithm->digestsize = strtoul(value, NULL, 10);
			algorithm->used_fields |= cryptparse_alg_digestsize;

		} else if (strcmp(field, "geniv") == 0) {
			algorithm->geniv = _alg_string_thing(value);
			algorithm->used_fields |= cryptparse_alg_geniv;

		} else if (strcmp(field, "internal") == 0) {
			if (strcmp(value, "yes") == 0)
				algorithm->internal = true;
			else if (strcmp(value, "no") == 0)
				algorithm->internal = false;
			else
				assert(false);
			algorithm->used_fields |= cryptparse_alg_internal;

		} else if (strcmp(field, "ivsize") == 0) {
			algorithm->ivsize = strtoul(value, NULL, 10);
			algorithm->used_fields |= cryptparse_alg_ivsize;

		} else if (strcmp(field, "maxauthsize") == 0) {
			algorithm->maxauthsize = strtoul(value, NULL, 10);
			algorithm->used_fields |= cryptparse_alg_maxauthsize;

		} else if (strcmp(field, "max_keysize") == 0) {
			algorithm->max_keysize = strtoul(value, NULL, 10);
			algorithm->used_fields |= cryptparse_alg_max_keysize;

		} else if (strcmp(field, "min_keysize") == 0) {
			algorithm->min_keysize = strtoul(value, NULL, 10);
			algorithm->used_fields |= cryptparse_alg_min_keysize;

		} else if (strcmp(field, "seedsize") == 0) {
			algorithm->seedsize = strtoul(value, NULL, 10);
			algorithm->used_fields |= cryptparse_alg_seedsize;

		} else if (strcmp(field, "selftest") == 0) {
			if (strcmp(value, "passed") == 0)
				algorithm->selftest = true;
			// TODO: Find out the real printed value if test fails
			else if (strcmp(value, "failed") == 0)
				algorithm->selftest = false;
			else
				assert(false);
			algorithm->used_fields |= cryptparse_alg_selftest;

		} else if (strcmp(field, "walksize") == 0) {
			algorithm->walksize = strtoul(value, NULL, 10);
			algorithm->used_fields |= cryptparse_alg_walksize;

		} else {
			// Unknown field
			assert(false);
		}
	}

	free(line);

	return 0;
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
