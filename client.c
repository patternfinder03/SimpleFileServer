/**
 * @file client.c
 * @brief Implementation of client communication functions.
 *
 * This file contains the main function and various utility functions to handle
 * client-server communication. It supports various commands such as GET, PUT,
 * LIST, and DELETE, and provides necessary error handling and data processing.
 */

#include "format.h"
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include "common.h"


// Function Declarations
char **parse_args(int argc, char **argv);
verb check_args(char **args);
void handle_get(char **args);
void handle_put(char **args);
void handle_list(char **args);
void handle_delete(char **args);
int connect_to_server(const char *host, const char *port);
ssize_t write_all_to_socket(const char *buffer, size_t count);
ssize_t read_all_from_socket(char *buffer, size_t count);
ssize_t fetch_message_size();
void close_client();
bool has_content(char* filename);
size_t get_file_size(char* filename);
char* get_data_file(char* filename);

// Global Variables
static int server_socket;
static char** args;
static char* remote;
static char* local;


/**
 * @brief Main function to run the client program.
 *
 * This function initializes the client program, parses the command-line arguments,
 * establishes a connection to the server, and handles various commands such as
 * GET, PUT, LIST, and DELETE.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line arguments.
 * @return int Exit status.
 */
int main(int argc, char **argv) {
    args = parse_args(argc, argv);


    if (args == NULL) {
        print_client_usage();
        exit(1);
    }

    verb command = check_args(args);

    remote = args[3];
    local = args[4];

    server_socket = connect_to_server(args[0], args[1]);
    if (server_socket == -1) {
        exit(1);
    }

    switch (command) {
        case GET:
            handle_get(args);
            break;
        case PUT:
            handle_put(args);
            break;
        case LIST:
            handle_list(args);
            break;
        case DELETE:
            handle_delete(args);
            break;
        default:
            print_client_help();
            exit(1);
    }

    close_client(1);
    return 0;
}


/**
 * @brief Handles the GET command.
 *
 * This function sends a GET request to the server to retrieve a file. It processes
 * the server's response and writes the received file data to the local file system.
 *
 * @param args Array of command-line arguments.
 */
void handle_get(char **args) {
    if (!remote || !local) {
        print_client_usage();
        close_client(0);
        return;
    }

    char getRequest[1024];
    snprintf(getRequest, sizeof(getRequest), "GET %s\n", remote);
    if (write_all_to_socket(getRequest, strlen(getRequest)) == -1) {
        close_client(0);
        return;
    }

    if (shutdown(server_socket, SHUT_WR) == -1) {
        close_client(0);
        return;
    }

    char response[1024] = {0};
    if (read_all_from_socket(response, 3) <= 0) {
        print_invalid_response();
        close_client(0);
        return;
    }

    if (strncmp(response, "OK\n", 3) == 0) {
    } else {
        read_all_from_socket(response + 3, 3);
        if (!strcmp(response, "ERROR\n")) {
            read_all_from_socket(response, strlen(err_bad_request));
            print_error_message(response);
            close_client(0);
            return;
        } else {
            print_invalid_response();
            close_client(0);
            return;
        }
    }

    ssize_t responseSize = fetch_message_size();
    if (responseSize <= 0) {
        fprintf(stderr, "Invalid response size: %zd\n", responseSize);
        close_client(0);
        return;
    }

    char *fileBuffer = calloc(responseSize + 1, sizeof(char));
    if (!fileBuffer) {
        close_client(0);
        return;
    }

    ssize_t actualSize = read_all_from_socket(fileBuffer, responseSize);
    if (actualSize < responseSize) {
        print_too_little_data();
        free(fileBuffer);
        close_client(0);
        return;
    }

    char extraByte;
    if (read_all_from_socket(&extraByte, 1) != 0) {
        print_received_too_much_data();
        free(fileBuffer);
        close_client(0);
        return;
    }

    FILE *file = fopen(local, "w+");
    if (!file) {
        free(fileBuffer);
        close_client(0);
        return;
    }
    fwrite(fileBuffer, sizeof(char), actualSize, file);
    fclose(file);
    
    free(fileBuffer);
    close_client(1);
}


/**
 * @brief Handles the PUT command.
 *
 * This function sends a PUT request to the server to upload a file. It reads the
 * local file data and transmits it to the server, handling any errors that occur.
 *
 * @param args Array of command-line arguments.
 */
void handle_put(char **args) {
    if (!local || !remote) {
        print_client_usage();
        close_client(0);
        return;
    }

    if (has_content(local)) {
        char putRequest[1024];
        snprintf(putRequest, sizeof(putRequest), "PUT %s\n", remote);
        char* data = get_data_file(local);
        size_t file_size = get_file_size(local);

        ssize_t status;

        status = write_all_to_socket(putRequest, strlen(putRequest));
        if (status == -1) {
            print_error_message("Failed to send PUT command.");
            free(data);
            close_client(1);
            return;
        } else if (status != (ssize_t)strlen(putRequest)) {
            print_error_message("Incomplete PUT command sent.");
            free(data);
            close_client(1);
            return;
        }

        status = write_all_to_socket((char *) &file_size, sizeof(size_t));
        if (status == -1) {
            print_error_message("Failed to send file size.");
            free(data);
            close_client(1);
            return;
        } else if (status != sizeof(size_t)) {
            print_error_message("Incomplete file size sent.");
            free(data);
            close_client(1);
            return;
        }

        // file_size += 100;

        status = write_all_to_socket(data, file_size);
        if (status == -1) {
            print_error_message("Failed to send file data.");
            free(data);
            close_client(1);
            return;
        } else if (status != (ssize_t)file_size) {
            print_error_message("Incomplete file data sent.");
            free(data);
            close_client(1);
            return;
        }

        shutdown(server_socket, SHUT_WR);

        char response[1024] = {0};
        read_all_from_socket(response, 3);
        if (strncmp(response, "OK\n", 3) == 0) {
            print_success();
        } else {
            read_all_from_socket(response + 3, 3);
            if (!strcmp(response, "ERROR\n")) {
                read_all_from_socket(response, 4);
                //printf("%s\n", response);

                if (!strcmp(response, "Bad R\n")) {
                    read_all_from_socket(response + 4, strlen(err_bad_request) - 4);
                } else {
                    read_all_from_socket(response + 4, strlen(err_bad_file_size));
                }
                // read_all_from_socket(response, strlen(err_bad_request));
                print_error_message(response);
            }
        }


        free(data);
    } else {
        close_client(0);
    }
}




/**
 * @brief Handles the LIST command.
 *
 * This function sends a LIST request to the server to retrieve a list of files.
 * It processes the server's response and displays the list of files.
 *
 * @param args Array of command-line arguments.
 */
void handle_list(char **args) {
    char listRequest[] = "LIST\n";
    if (write_all_to_socket(listRequest, strlen(listRequest)) == -1) {
        close_client(0);
        return;
    }

    shutdown(server_socket, SHUT_WR);

    char response[1024] = {0};
    if (read_all_from_socket(response, 3) <= 0 || strcmp(response, "OK\n") != 0) {
        read_all_from_socket(response + 3, 3);
        if (!strcmp(response, "ERROR\n")) {
            read_all_from_socket(response, strlen(err_bad_request));
            print_error_message(response);
        }
        close_client(0);
        return;
    }

    ssize_t size = fetch_message_size();
    if (size <= 0) {
        close_client(0);
        return;
    }

    char* fileList = calloc(1, size + 1);
    if (!fileList) {
        close_client(0);
        return;
    }

    if (read_all_from_socket(fileList, size) != size) {
        free(fileList);
        close_client(0);
        return;
    }

    fileList[size] = '\0';
    printf("%s\n", fileList);

    free(fileList);
    close_client(1);
}



/**
 * @brief Handles the DELETE command.
 *
 * This function sends a DELETE request to the server to remove a file. It processes
 * the server's response to ensure the file is deleted.
 *
 * @param args Array of command-line arguments.
 */
void handle_delete(char **args) {
    if (!remote) {
        print_client_usage();
        close_client(0);
        return;
    }

    char deleteRequest[1024];
    snprintf(deleteRequest, sizeof(deleteRequest), "DELETE %s\n", remote);
    if (write_all_to_socket(deleteRequest, strlen(deleteRequest)) == -1) {
        close_client(0);
        return;
    }

    shutdown(server_socket, SHUT_WR);

    char response[1024] = {0};
    if (read_all_from_socket(response, 3) <= 0) {
        print_connection_closed();
        close_client(0);
        return;
    }

    // if (!strcmp(response, "OK\n")) {
    //     print_success();
    // } else {
    //     print_error_message(response);
    // }

    if (strncmp(response, "OK\n", 3) == 0) {
    } else {
        read_all_from_socket(response + 3, 3);
        if (!strcmp(response, "ERROR\n")) {
            read_all_from_socket(response, strlen(err_bad_request));
            print_error_message(response);
            close_client(0);
            return;
        } else {
            print_invalid_response();
            close_client(0);
            return;
        }
    }

    close_client(1);
}


/**
 * @brief Parses command-line arguments.
 *
 * This function parses the command-line arguments provided to the client program
 * and returns them in a format suitable for further processing.
 *
 * @param argc Number of command-line arguments.
 * @param argv Array of command-line arguments.
 * @return char** Parsed arguments.
 */
char **parse_args(int argc, char **argv) {
    if (argc < 3) {
        return NULL;
    }

    char *host = strtok(argv[1], ":");
    char *port = strtok(NULL, ":");
    if (port == NULL) {
        return NULL;
    }

    char **args = calloc(1, 6 * sizeof(char *));
    args[0] = host;
    args[1] = port;
    args[2] = argv[2];
    char *temp = args[2];
    while (*temp) {
        *temp = toupper((unsigned char)*temp);
        temp++;
    }
    if (argc > 3) {
        args[3] = argv[3];
    }
    if (argc > 4) {
        args[4] = argv[4];
    }

    return args;
}



/**
 * @brief Checks the parsed command-line arguments.
 *
 * This function checks the validity of the parsed command-line arguments and
 * determines the command to be executed (GET, PUT, LIST, DELETE).
 *
 * @param args Array of parsed command-line arguments.
 * @return verb Command to be executed.
 */
verb check_args(char **args) {
    if (args == NULL) {
        print_client_usage();
        exit(1);
    }

    char *command = args[2];

    if (strcmp(command, "LIST") == 0) {
        return LIST;
    }

    if (strcmp(command, "GET") == 0) {
        if (args[3] != NULL && args[4] != NULL) {
            return GET;
        }
        print_client_help();
        exit(1);
    }

    if (strcmp(command, "DELETE") == 0) {
        if (args[3] != NULL) {
            return DELETE;
        }
        print_client_help();
        exit(1);
    }

    if (strcmp(command, "PUT") == 0) {
        if (args[3] == NULL || args[4] == NULL) {
            print_client_help();
            exit(1);
        }
        return PUT;
    }

    print_client_help();
    exit(1);
}


/**
 * @brief Connects to the server.
 *
 * This function establishes a connection to the server using the provided host
 * and port.
 *
 * @param host The server host.
 * @param port The server port.
 * @return int Server socket descriptor.
 */
int connect_to_server(const char *host, const char *port) {
    int sockfd;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(host, port, &hints, &servinfo)) != 0) {
        return 1;
    }

    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }

        break;
    }

    if (p == NULL) {
        return 2;
    }

    freeaddrinfo(servinfo);
    return sockfd;
}


/**
 * @brief Reads all data from the socket.
 *
 * This function reads data from the server socket into the specified buffer, ensuring
 * all requested data is received.
 *
 * @param buffer The buffer to store received data.
 * @param count The number of bytes to read.
 * @return ssize_t Number of bytes read, or -1 on error.
 */
ssize_t read_all_from_socket(char *buffer, size_t count) {
    size_t total = 0;
    ssize_t bytes_read = 0;

    while (total < count) {
        bytes_read = read(server_socket, buffer + total, count - total);
        if (bytes_read == -1) {
            if (errno == EINTR) continue;
            return -1;
        } else if (bytes_read == 0) {
            break;
        } else {
            total += bytes_read;
        }
    }

    return total;
}


/**
 * @brief Writes all data to the socket.
 *
 * This function writes the specified buffer data to the server socket, ensuring
 * all data is sent.
 *
 * @param buffer The data buffer to send.
 * @param count The number of bytes to send.
 * @return ssize_t Number of bytes written, or -1 on error.
 */
ssize_t write_all_to_socket(const char *buffer, size_t count) {
    size_t total = 0;
    ssize_t bytes_written;

    while (total < count) {
        bytes_written = write(server_socket, buffer + total, count - total);
        if (bytes_written == -1) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += bytes_written;
    }

    return total;
}


/**
 * @brief Fetches the size of the incoming message.
 *
 * This function reads the size of the incoming message from the server socket.
 *
 * @return ssize_t Size of the incoming message, or -1 on error.
 */
ssize_t fetch_message_size() {
    size_t message_size;
    ssize_t status = read_all_from_socket((char *)&message_size, sizeof(size_t));

    if (status <= 0)
        return status;

    return message_size;
}



/**
 * @brief Closes the client connection.
 *
 * This function closes the connection to the server and performs any necessary
 * cleanup.
 *
 * @param success Indicator of whether the client operation was successful.
 */
void close_client(int* success) {
    if (args) free(args);
    
    if (success) {
        exit(0);
    } else {
        exit(1);
    }
}


/**
 * @brief Gets the data from a file.
 *
 * This function reads the data from the specified file into a buffer.
 *
 * @param filename The name of the file to read.
 * @return char* Buffer containing the file data.
 */
char* get_data_file(char* filename) {
    if (!filename) {
        return NULL;
    }

    FILE* f = fopen(filename, "rb");
    if (!f) {
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len == -1) {
        fclose(f);
        return NULL;
    }

    fseek(f, 0, SEEK_SET);
    char* buffer = calloc(len, 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }

    if (fread(buffer, 1, len, f) != (size_t)len) {
        free(buffer);
        fclose(f);
        return NULL;
    }

    fclose(f);
    return buffer;
}



/**
 * @brief Gets the size of a file.
 *
 * This function retrieves the size of the specified file.
 *
 * @param filename The name of the file.
 * @return size_t Size of the file.
 */
size_t get_file_size(char* filename) {
    if (!filename) {
        return 0;
    }

    FILE* f = fopen(filename, "rb");
    if (!f) {
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    if (len == -1) {
        fclose(f);
        return 0;
    }

    fclose(f);
    return (size_t)len;
}



/**
 * @brief Checks if a file has content.
 *
 * This function checks if the specified file contains any data.
 *
 * @param filename The name of the file to check.
 * @return bool True if the file has content, false otherwise.
 */
bool has_content(char* filename) {
    if (!filename) {
        return false;
    }

    size_t size = get_file_size(filename);
    if (size == 0) {
        return false;
    }

    char* content = get_data_file(filename);
    if (!content) {
        return false;
    }

    free(content);
    return true;
}