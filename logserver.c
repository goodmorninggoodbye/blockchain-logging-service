#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <time.h>
#include "sha256.h"
#include "base64.h"

#define MAX_MSG 1024

int validate_proof_of_work(const char *message);

void handle_client(int client_socket) {
    char msg[MAX_MSG];
    FILE *log_file;
    int len;

    // Read data from the client
    ssize_t num_bytes = recv(client_socket, msg, MAX_MSG - 1, 0);
    if (num_bytes < 0) {
        perror("Error reading from socket");
        close(client_socket);
        return;
    }

    msg[num_bytes] = '\0'; // null-terminate the string and strip the newline at the end
    char *newline_pos = strchr(msg, '\n');
    if (newline_pos) {
        *newline_pos = '\0';  // remove the newline character
    }
    len = strlen(msg);
    printf("Received: %s\n", msg);

    //### Validate the the PoW in the message
    //### Stril the PoW from the message
    //### Read the last hash from loghead.txt
    //### Create the full line for the log entry
    //### Compute its hash
    //### Append the line to the log
    //### Update loghead.txt
    //### Add error checking

    // Validate proof of work
    if (!validate_proof_of_work(msg)) {
        const char *response = "Invalid proof of work\n";
        send(client_socket, response, strlen(response), 0);
        close(client_socket);
        return;
    }

    // Strip proof of work from message
    char *colon = strchr(msg, ':');
    if (colon != NULL) {
        memmove(msg, colon + 1, strlen(colon));
    }

    // Get previous hash from loghead.txt or use "start"
    char prev_hash[25];
    FILE *head_file = fopen("loghead.txt", "r");
    if (head_file == NULL) {
        if (access("log.txt", F_OK) != -1) {
            const char *response = "Error: loghead.txt is missing\n";
            send(client_socket, response, strlen(response), 0);
            close(client_socket);
            return;
        }
        strncpy(prev_hash, "start", sizeof(prev_hash));
    } else {
        if (fgets(prev_hash, sizeof(prev_hash), head_file) == NULL) {
            strncpy(prev_hash, "start", sizeof(prev_hash));
        }
        // Remove newline if present
        char *newline = strchr(prev_hash, '\n');
        if (newline) *newline = '\0';
        fclose(head_file);
    }

    // Create timestamp
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", t);

    // Create full log entry
    char log_entry[MAX_MSG];

    // Check if combined length would exceed buffer
    size_t total_len = strlen(timestamp) + 3 + strlen(prev_hash) + 1 + strlen(msg) + 1; // 3 for " - " and extra space
    if (total_len >= MAX_MSG) {
        const char *response = "Error: Message too long for log entry\n";
        send(client_socket, response, strlen(response), 0);
        close(client_socket);
        return;
    }

    snprintf(log_entry, sizeof(log_entry), "%s - %s %s", timestamp, prev_hash, msg);

    // Compute hash of the log entry
    BYTE hash[SHA256_BLOCK_SIZE];
    BYTE b64_hash[44];
    SHA256_CTX ctx;
    
    sha256_init(&ctx);
    sha256_update(&ctx, (BYTE*)log_entry, strlen(log_entry));
    sha256_final(&ctx, hash);
    
    size_t b64_len = base64_encode(hash, b64_hash, SHA256_BLOCK_SIZE, 0);
    char new_hash[25];
    strncpy(new_hash, (char*)b64_hash + b64_len - 24, 24);
    new_hash[24] = '\0';

    // Append to log.txt
    log_file = fopen("log.txt", "a");
    if (log_file == NULL) {
        const char *response = "Error: Cannot open log file\n";
        send(client_socket, response, strlen(response), 0);
        close(client_socket);
        return;
    }
    
    printf("logging: \"%s\"\n", log_entry);
    fprintf(log_file, "%s\n", log_entry);
    fclose(log_file);

    // Update loghead.txt with new hash
    head_file = fopen("loghead.txt", "w");
    if (head_file == NULL) {
        const char *response = "Error: Cannot update head file\n";
        send(client_socket, response, strlen(response), 0);
        close(client_socket);
        return;
    }
    fprintf(head_file, "%s", new_hash);
    fclose(head_file);

    // Send success response
    const char *response_msg = "ok\n";
    send(client_socket, response_msg, strlen(response_msg), 0);
    close(client_socket);
}

int validate_proof_of_work(const char *message) {
    BYTE hash[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    
    sha256_init(&ctx);
    sha256_update(&ctx, (BYTE*)message, strlen(message));
    sha256_final(&ctx, hash);
    
    // Check if the first 20 bits are zero
    return (hash[0] == 0 && hash[1] == 0 && (hash[2] & 0xF0) == 0);
}

int main() {
    int server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    // Create the server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Could not create socket");
        exit(EXIT_FAILURE);
    }

    // Bind the server to an available port
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = 0;  // System assigns any available port

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Get the assigned port number and print it
    socklen_t len = sizeof(server_addr);
    if (getsockname(server_socket, (struct sockaddr*)&server_addr, &len) == -1) {
        perror("getsockname failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    int port = ntohs(server_addr.sin_port);
    printf("Server listening on port: %d\n", port);

    // Start listening for connections
    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    // Continuously accept and handle clients
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }

        printf("Client connected\n");
        handle_client(client_socket);
    }

    close(server_socket);
    return 0;
}
