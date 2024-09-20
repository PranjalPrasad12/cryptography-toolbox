/*
    Cryptography Toolbox- A simple toolbox for managing various encryptions
    Copyright (C) Pranjal Prasad 2023-2024

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
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

// Function prototypes
void display_warranty();
void display_license();
void display_help();
void about();
void encrypt_data(const char *encryption_type, const char *input, const char *key, const char *output_file);
void decrypt_data(const char *encryption_type, const char *input_file, const char *key_file, const char *output_file);
char *get_path_from_mc();

// Constants
#define BUFFER_SIZE 256
#define DEFAULT_OUTPUT_FILE "./output_encrypted.txt"

// Main function
int main(int argc, char *argv[]) {
    if (argc == 1) {
        printf("Cryptography Toolbox- A simple toolbox for managing various encryptions\n");
        printf("Copyright (C) 2023-2024 Pranjal Prasad\n");
        printf("This program comes with ABSOLUTELY NO WARRANTY; for details type '-w'.\n");
        printf("This is free software; you are welcome to redistribute it under certain conditions; type '-c' for details.\n");
        printf("For options, type '-help'.\n");
        return 0;
    }

    // Handle command line options
    if (strcmp(argv[1], "-w") == 0) {
        display_warranty();
    } else if (strcmp(argv[1], "-c") == 0) {
        display_license();
    } else if (strcmp(argv[1], "-help") == 0) {
        display_help();
    } else if (strcmp(argv[1], "-about") == 0) {
        about();
    } else if (strcmp(argv[1], "encrypt") == 0 && argc >= 5) {
        char *output_file = (argc == 6) ? argv[5] : DEFAULT_OUTPUT_FILE;
        char *key_file = strstr(argv[4], "@m-commander") ? get_path_from_mc() : argv[4];
        encrypt_data(argv[2], argv[3], key_file, output_file);
        if (strstr(argv[4], "@m-commander")) free(key_file);  // Free memory if allocated for MC path
    } else if (strcmp(argv[1], "decrypt") == 0 && argc == 5) {
        decrypt_data(argv[2], argv[3], argv[4], argv[5]);
    } else {
        printf("Invalid option. Type '-help' for usage.\n");
    }

    return 0;
}

// Display warranty information
void display_warranty() {
    printf("This program comes with ABSOLUTELY NO WARRANTY.\n");
    printf("For details, see the LICENSE file or visit https://www.gnu.org/licenses/gpl-3.0.en.html.\n");
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
    printf("Encryption types: AES, DES, RSA, etc.\n");
}

// Display program information
void about() {
    printf("Cryptography Toolbox\n");
    printf("Version Alpha Build 1.97\n");
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

// Encrypt data
void encrypt_data(const char *encryption_type, const char *input, const char *key, const char *output_file) {
    printf("Encrypting data...\n");

    char command[512];
    snprintf(command, sizeof(command), "python3 cli.py encrypt %s \"%s\" \"%s\" > %s", encryption_type, input, key, output_file);
    system(command);

    printf("Data encrypted and saved to %s\n", output_file);
}

// Decrypt data
void decrypt_data(const char *encryption_type, const char *input_file, const char *key_file, const char *output_file) {
    printf("Decrypting data...\n");

    char command[512];
    snprintf(command, sizeof(command), "python3 cli.py decrypt %s %s %s > %s", encryption_type, input_file, key_file, output_file);
    system(command);

    printf("Data decrypted and saved to %s\n", output_file);
}
