#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <arpa/inet.h>
#include "sha256.h"
#include "base64.h"

#define BUFFER_SIZE 1024
#define POW_BITS 20
char *generate_proof_of_work(const char *message);
void convert_whitespace(char *str);
int validate_hash(const BYTE *hash);

int main(int argc, char *argv[]) {

    if (argc != 3) {
        fprintf(stderr, "Usage: %s <port> <message>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int port = atoi(argv[1]);
    char *message = argv[2];

    int client_socket;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];

    // Create a socket
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Could not create socket");
        exit(EXIT_FAILURE);
    }

    // Set up the server address structure
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Connect to the server
    if (connect(client_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }


    // Convert whitespace to spaces
    convert_whitespace(message);

    // Generate proof of work
    char *pow = generate_proof_of_work(message);
    if (pow == NULL) {
        fprintf(stderr, "Failed to generate proof of work\n");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // Combine PoW and message
    char full_message[BUFFER_SIZE];
    snprintf(full_message, sizeof(full_message), "%s:%s", pow, message);
    free(pow);


    // Send the message with a newline at the end
    size_t msg_len = strlen(full_message);
    if (msg_len >= BUFFER_SIZE - 2) { // Check if message plus \n\0 would exceed buffer
        fprintf(stderr, "Message too long\n");
        close(client_socket);
        exit(EXIT_FAILURE);
    }
    snprintf(buffer, sizeof(buffer), "%s\n", full_message);
    if (send(client_socket, buffer, strlen(buffer), 0) < 0) {
        perror("Send failed");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // Receive the server's response
    ssize_t num_bytes = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (num_bytes < 0) {
        perror("Error receiving data from server");
        close(client_socket);
        exit(EXIT_FAILURE);
    }

    // Null-terminate and print the response
    buffer[num_bytes] = '\0';
    printf("Server response: %s", buffer);

    close(client_socket);
    return 0;
}

void convert_whitespace(char *str) {
    for (int i = 0; str[i]; i++) {
        if (isspace(str[i])) {
            str[i] = ' ';
        }
    }
}

char *generate_proof_of_work(const char *message) {
    BYTE hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    char pow[9] = {0};  // 8 characters + null terminator
    char full_message[BUFFER_SIZE];

    for (int i = 0; i < 100000000; i++) {  // Arbitrary large number of attempts
        snprintf(pow, sizeof(pow), "%08x", i);  // Use hex representation for simplicity
        snprintf(full_message, sizeof(full_message), "%s:%s", pow, message);

        sha256_init(&ctx);
        sha256_update(&ctx, (BYTE*)full_message, strlen(full_message));
        sha256_final(&ctx, hash);

        // Check if the first 20 bits are zero
        if ((hash[0] == 0) && (hash[1] == 0) && ((hash[2] & 0xF0) == 0)) { //validate hash
            return strdup(pow);
        }
    }

    return NULL;  // Failed to find a valid proof of work
}