#include "util.h"
#include <stdlib.h>
#include <string.h>
char **split_string(char *str, int len, char *sep, int sep_len, int *count) {
    if(!str || len <= 0 || sep_len < 1) return NULL;

    int i = 0, start, step, slots = 5;
    char **tokens;
    *count = 0;
    tokens = malloc(slots * sizeof(char *));

    if(!tokens) {
        tokens = NULL;
    }

    start = i;
    while(i <= len - sep_len) {
        step = 1;
        if(str[i] == sep[0] && memcmp(str + i, sep, sep_len) == 0) {
            if(i > start) {
                if(*count + 1 == slots) {
                    slots *= 2;
                    tokens = realloc(tokens, slots * sizeof(char *));
                    if (!tokens) goto cleanup;
                }

                tokens[*count]  = strndup(str + start, i - start);
                if(!tokens[*count]) goto cleanup;

                step = sep_len;
                *count += 1;
            }
            start = i + sep_len;
        }
        i += step;
    }

    if(len > start) {
        tokens[*count]  = strndup(str + start, len - start);
        if(!tokens[*count]) goto cleanup;
        *count += 1;
    }
    return tokens;

cleanup:
    for(i = 0; i < *count; i++) {
        if(tokens[*count]) free(tokens[*count]);
    }
    free(tokens);
    return NULL;
}

void split_string_free(char **tokens, int count) {
    int i;
    for(i = 0; i < count; i++) {
        if(tokens[i]) free(tokens[i]);
    }
    free(tokens);
}

#ifdef _UTIL_TEST_
#include <stdio.h>
int main() {
    char *str = "..b..cc....ddd..", ** tokens;
    int count;
    tokens = split_string(str, strlen(str), "..", 1, &count);
    printf("Count: %d\n", count);
    int i;
    for( i = 0; i < count; i++) {
        printf("token:%s\n", tokens[i]);
    }
    split_string_free(tokens, count);
    return 0;
}
#endif
