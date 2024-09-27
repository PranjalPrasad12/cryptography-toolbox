#ifndef KEY_MANAGEMENT_H
#define KEY_MANAGEMENT_H

#define KEY_STORE "key_store.txt"
#define BUFFER_SIZE 1024

// Function declarations for key management
void generate_key(const char *key_type, const char *key_file, const char *format);
void view_keys();
void delete_key(const char *key_file);

#endif // KEY_MANAGEMENT_H
