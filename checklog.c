#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include "base64.h"

#define MAX_LINE_LENGTH 1024

static char* compute_hash(const char* line);
static int validate_log_line(const char* line, const char* expected_hash, int line_number);
static char* extract_hash(const char* line);

int main(int argc, char *argv[]) {
    // Check for unexpected command line arguments
    if (argc > 1) {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        return 1;
    }

    FILE *log_file = fopen("log.txt", "r");
    FILE *head_file = fopen("loghead.txt", "r");
    
    // Validate file existence
    if (!log_file) {
        printf("failed: log.txt is missing\n");
        return 1;
    }
    if (!head_file) {
        printf("failed: loghead.txt is missing\n");
        fclose(log_file);
        return 1;
    }

    char line[MAX_LINE_LENGTH];
    char head_hash[MAX_LINE_LENGTH];
    char *current_hash = NULL;
    int line_number = 1;
    int valid = 1;

    // Read the head hash
    if (!fgets(head_hash, sizeof(head_hash), head_file)) {
        printf("failed: empty head file\n");
        fclose(log_file);
        fclose(head_file);
        return 1;
    }
    // Remove newline if present
    char *newline = strchr(head_hash, '\n');
    if (newline) *newline = '\0';

    // Read first line
    if (!fgets(line, sizeof(line), log_file)) {
        printf("failed: empty log file\n");
        fclose(log_file);
        fclose(head_file);
        return 1;
    }
    
    // Remove newline if present
    newline = strchr(line, '\n');
    if (newline) *newline = '\0';

    // Validate first line contains "start"
    char *first_hash = extract_hash(line);
    if (!first_hash) {
        printf("failed: invalid log format at line %d\n", line_number);
        fclose(log_file);
        fclose(head_file);
        return 1;
    }

    if (strcmp(first_hash, "start") != 0) {
        printf("failed: first line does not contain 'start' hash\n");
        free(first_hash);
        fclose(log_file);
        fclose(head_file);
        return 1;
    }
    free(first_hash);

    // Compute hash of first line for next iteration
    current_hash = compute_hash(line);
    line_number++;
    
    // Process remaining lines
    while (fgets(line, sizeof(line), log_file)) {
        // Remove newline if present
        newline = strchr(line, '\n');
        if (newline) *newline = '\0';

        // Validate the current line
        if (!validate_log_line(line, current_hash, line_number)) {
            valid = 0;
            break;
        }

        // Compute hash for next iteration
        free(current_hash);
        current_hash = compute_hash(line);
        line_number++;
    }

    // Verify final hash matches head hash
    if (valid && strcmp(current_hash, head_hash) != 0) {
        printf("failed: head hash mismatch at end of file\n");
        valid = 0;
    }

    // Cleanup
    free(current_hash);
    fclose(log_file);
    fclose(head_file);

    if (valid) {
        printf("valid\n");
        return 0;
    }
    return 1;
}

static char* compute_hash(const char* line) {
    BYTE hash[SHA256_BLOCK_SIZE];
    BYTE b64_hash[44];
    SHA256_CTX ctx;
    
    sha256_init(&ctx);
    sha256_update(&ctx, (BYTE*)line, strlen(line));
    sha256_final(&ctx, hash);
    
    size_t b64_len = base64_encode(hash, b64_hash, SHA256_BLOCK_SIZE, 0);
    char *result = malloc(25);
    if (!result) return NULL;
    
    strncpy(result, (char*)b64_hash + b64_len - 24, 24);
    result[24] = '\0';
    
    return result;
}

static int validate_log_line(const char* line, const char* expected_hash, int line_number) {
    char *line_hash = extract_hash(line);
    if (!line_hash) {
        printf("failed: invalid log format at line %d\n", line_number);
        return 0;
    }

    if (strcmp(line_hash, expected_hash) != 0) {
        printf("failed: hash mismatch at line %d\n", line_number - 1);
        free(line_hash);
        return 0;
    }

    free(line_hash);
    return 1;
}

static char* extract_hash(const char* line) {
    // Find the first hyphen with a space after it
    char *hyphen = strstr(line, " - ");
    if (!hyphen) {
        return NULL;
    }

    // Skip past " - "
    char *hash_start = hyphen + 3;
    char *space = strchr(hash_start, ' ');
    if (!space) {
        return NULL;
    }

    size_t hash_len = space - hash_start;
    char *hash = malloc(hash_len + 1);
    if (!hash) {
        return NULL;
    }

    strncpy(hash, hash_start, hash_len);
    hash[hash_len] = '\0';
    return hash;
} 
