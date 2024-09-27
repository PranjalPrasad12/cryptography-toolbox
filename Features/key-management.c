#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Features/key-management.h"

// Helper function to write key details to a file in the specified format
void write_key_to_file(const char *key_type, const char *key_file, const char *format) {
    FILE *file = fopen(key_file, "w");
    if (file == NULL) {
        perror("Error opening key file");
        return;
    }

    // Write based on the format
    if (strcmp(format, "txt") == 0) {
        fprintf(file, "Key Type: %s\n", key_type);
    } else if (strcmp(format, "odf") == 0) {
        // Basic ODF format (not a full-featured ODF implementation)
        fprintf(file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        fprintf(file, "<office:document>\n");
        fprintf(file, "<office:body>\n");
        fprintf(file, "<text:p>Key Type: %s</text:p>\n", key_type);
        fprintf(file, "</office:body>\n");
        fprintf(file, "</office:document>\n");
    } else {
        fprintf(file, "Unsupported format: %s\n", format);
    }

    fclose(file);
}

// Generate key and save it in the specified format (txt or odf)
void generate_key(const char *key_type, const char *key_file, const char *format) {
    printf("Generating %s key...\n", key_type);

    char command[512];
    snprintf(command, sizeof(command), "python3 cli.py generate-key %s > %s", key_type, key_file);
    system(command);

    // Append key info to key store
    FILE *store = fopen(KEY_STORE, "a");
    if (store != NULL) {
        fprintf(store, "Key Type: %s, Key File: %s, Format: %s\n", key_type, key_file, format);
        fclose(store);
        printf("Key stored in %s and registered.\n", KEY_STORE);
    } else {
        perror("Error writing to key store");
    }

    // Write the key details to the specified file format
    write_key_to_file(key_type, key_file, format);
}

// View all keys in the key store
void view_keys() {
    FILE *store = fopen(KEY_STORE, "r");
    if (store == NULL) {
        printf("No keys stored yet.\n");
        return;
    }

    char line[BUFFER_SIZE];
    printf("Keys stored in %s:\n", KEY_STORE);
    while (fgets(line, sizeof(line), store)) {
        printf("%s", line);
    }
    fclose(store);
}

// Delete key and remove it from the key store
void delete_key(const char *key_file) {
    printf("Deleting key: %s\n", key_file);

    // Delete the key from the file system
    if (remove(key_file) == 0) {
        printf("Key file %s deleted successfully.\n", key_file);
    } else {
        perror("Error deleting key file");
    }

    // Remove key from the key store
    FILE *store = fopen(KEY_STORE, "r");
    FILE *temp_store = fopen("temp_key_store.txt", "w");
    if (store == NULL || temp_store == NULL) {
        perror("Error opening key store");
        return;
    }

    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), store)) {
        if (strstr(line, key_file) == NULL) {
            fputs(line, temp_store);
        }
    }

    fclose(store);
    fclose(temp_store);
    remove(KEY_STORE);
    rename("temp_key_store.txt", KEY_STORE);

    printf("Key entry removed from %s.\n", KEY_STORE);
}
