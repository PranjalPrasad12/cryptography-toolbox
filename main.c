/*
    Cryptography Toolbox- A simple toolbox for managing various encryptions and key management
    Copyright (C) Pranjal Prasad 2023-2024

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
// Function prototypes
void display_warranty();
void display_license();
void display_help();
void about();
void encrypt_data(const char *encryption_type, const char *input, const char *key, const char *output_file);
void decrypt_data(const char *encryption_type, const char *input_file, const char *key_file, const char *output_file);
void hash_data(const char *input, char *output_buffer);
void generate_rsa_keypair(const char *public_key_file, const char *private_key_file);
char *get_path_from_mc();

// Constants
#define BUFFER_SIZE 256
#define DEFAULT_OUTPUT_FILE "./output_encrypted.txt"
#define KEY_STORE "key_store.txt"

// Main function
int main(int argc, char *argv[]) {
    if (argc == 1) {
        printf("Cryptography Toolbox- A simple toolbox for managing various encryptions and key management\n");
        printf("Copyright (C) 2023-2024 Pranjal Prasad\n");
        printf("This program comes with ABSOLUTELY NO WARRANTY; for details type '-w'.\n");
        printf("This is free software; you are welcome to redistribute it under certain conditions; type '-c' for details.\n");
        printf("For options, type '-help'.\n");
        return 0;
    }

    // Handle command line options
    if (strcmp(argv[1], "hash") == 0 && argc == 3) {
        char output_buffer[SHA256_DIGEST_LENGTH * 2 + 1];  // +1 for null terminator
        hash_data(argv[2], output_buffer);
        printf("SHA-256 Hash: %s\n", output_buffer);
    } 
    else if (strcmp(argv[1], "generate-key") == 0 && argc == 4) {
        generate_rsa_keypair(argv[2], argv[3]);
    } 
    else if (strcmp(argv[1], "encrypt") == 0 && argc >= 5) {
        char *output_file = (argc == 6) ? argv[5] : DEFAULT_OUTPUT_FILE;
        char *key_file = strstr(argv[4], "@m-commander") ? get_path_from_mc() : argv[4];
        encrypt_data(argv[2], argv[3], key_file, output_file);
        if (strstr(argv[4], "@m-commander")) free(key_file);
    } 
    else if (strcmp(argv[1], "decrypt") == 0 && argc == 6) {
        decrypt_data(argv[2], argv[3], argv[4], argv[5]);
    } 
    else {
        printf("Invalid option. Type '-help' for usage.\n");
    }

    return 0;
}

// Hash data using SHA-256
void hash_data(const char *input, char *output_buffer) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)input, strlen(input), hash);

    // Convert hash to a hex string
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output_buffer + (i * 2), "%02x", hash[i]);
    }
    output_buffer[SHA256_DIGEST_LENGTH * 2] = '\0';  // Null-terminate the string
}

// Generate RSA keys
void generate_rsa_keypair(const char *public_key_file, const char *private_key_file) {
    RSA *rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);

    // Save private key
    FILE *private_key_fp = fopen(private_key_file, "wb");
    if (private_key_fp) {
        PEM_write_RSAPrivateKey(private_key_fp, rsa, NULL, NULL, 0, NULL, NULL);
        fclose(private_key_fp);
    } else {
        perror("Unable to open private key file");
    }

    // Save public key
    FILE *public_key_fp = fopen(public_key_file, "wb");
    if (public_key_fp) {
        PEM_write_RSAPublicKey(public_key_fp, rsa);
        fclose(public_key_fp);
    } else {
        perror("Unable to open public key file");
    }

    RSA_free(rsa); // Free the RSA key
    printf("RSA key pair generated: %s (public), %s (private)\n", public_key_file, private_key_file);
}

// Display warranty information
void display_warranty() {
    printf("This program comes with ABSOLUTELY NO WARRANTY.\n");
}

// Display license information
void display_license() {
    FILE *license_file = fopen("LICENSE", "r");
    if (license_file == NULL) {
        perror("Error opening LICENSE file");
        return;
    }

    char line[BUFFER_SIZE];
    printf("Displaying the LICENSE file:\n\n");
    while (fgets(line, sizeof(line), license_file)) {
        printf("%s", line);
    }
    fclose(license_file);
}

// Display help information
void display_help() {
    printf("Usage: crypto-toolbox [OPTION] [ARGUMENTS...]\n");
    printf("Options:\n");
    printf("  -w                Show warranty details\n");
    printf("  -c                Show license conditions\n");
    printf("  -help             Show this help message\n");
    printf("  -about            Show information about the program\n");
    printf("  encrypt [type] [input] [key] [output_file]  Encrypt input with specified key and output file\n");
    printf("  decrypt [type] [input_file] [key_file] [output_file]  Decrypt input using key and save to output file\n");
    printf("  hash [input]      Compute the SHA-256 hash of the input\n");
    printf("  generate-key [public_key_file] [private_key_file]  Generate RSA key pair\n");
    printf("  view-keys         View all keys in the key store\n");
    printf("  delete-key [key_file]  Delete the specified key from the key store\n");
    printf("Encryption types: AES, DES, RSA, etc.\n");
}

// Display program information
void about() {
    printf("Cryptography Toolbox\n");
    printf("Version Alpha Build 1.98.1\n");
    printf("Developed by Pranjal Prasad\n");
    printf("This is free software. For more information, see the LICENSE file.\n");
}

// Get path from Midnight Commander
char *get_path_from_mc() {
    printf("Launching Midnight Commander...\n");
    system("mc");  // Launch Midnight Commander
    printf("Enter the selected path: ");
    char *path = malloc(BUFFER_SIZE);
    if (!path) {
        perror("Memory allocation error");
        exit(EXIT_FAILURE);
    }
    fgets(path, BUFFER_SIZE, stdin);
    path[strcspn(path, "\n")] = '\0';  // Remove newline character
    return path;
}

// Encrypt data (assuming this function is defined somewhere)
void encrypt_data(const char *encryption_type, const char *input, const char *key, const char *output_file) {
    printf("Encrypting data...\n");
   
}

// Decrypt data (assuming this function is defined somewhere)
void decrypt_data(const char *encryption_type, const char *input_file, const char *key_file, const char *output_file) {
    printf("Decrypting data...\n");
    
}
      
