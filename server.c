/**
 * nonstop_networking
 * CS 341 - Spring 2024
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "dictionary.h"
#include "vector.h"
#include "common.h"
#include <ctype.h> 
#include <netdb.h>
#include "format.h"
#include <errno.h>

#define MAX_CLIENTS 1000

static int epollfd;
static char* dir;
static vector* file_vector;
static dictionary* clientfd_to_cinfo;
int handle_put(int client_file_descriptor);
int handle_get(int client_file_descriptor);
int handle_delete(int client_file_descriptor);
int handle_list(int client_file_descriptor);
int handle_client(int client_file_descriptor);

typedef struct cinfo_t {
    int fd;
    verb command_sent;
    size_t file_size;
    char filename[256];
    char header[1024];
} cinfo_t;


void signal_handler(int signal);
int init_server_socket(char* port);
void quit_server();
void create_server(char* port);
ssize_t read_all_from_socket(int socket, char *buffer, size_t count, int is_header);
ssize_t write_all_to_socket(int socket, const char *buffer, size_t count);

ssize_t get_message_size(int client_file_descriptor) {
    size_t message_size;
    char *buffer = (char *)&message_size;
    memset(buffer, 0, sizeof(size_t));
    ssize_t status = read_all_from_socket(client_file_descriptor, (char *)&message_size, sizeof(size_t), 0);

    if (status <= 0)
        return status;

    return message_size;
}


size_t read_all_from_socket_put(int socket, char *buffer, size_t count) {
    size_t total_bytes_read = 0;
    while (total_bytes_read < count) {
        ssize_t result = read(socket, buffer + total_bytes_read, count - total_bytes_read);
        if (result == 0) {  // No more data, normal termination
            break;
        }
        if (result < 0) {  // Handle possible errors
            if (errno == EINTR) continue;  // Interrupted, retry read
            return -1;  // An error occurred, return -1
        }
        total_bytes_read += result;  // Increment the count of bytes read
    }
    return total_bytes_read == 0 ? 0 : total_bytes_read;
}



ssize_t read_all_from_socket(int socket, char *buffer, size_t count, int is_header) {
    size_t bytes_read = 0;
    while (bytes_read < count) {
        int read_retval = read(socket, (void*) (buffer + bytes_read), 1);

        if (is_header) {
            if (read_retval == 0 || buffer[strlen(buffer) - 1] == '\n') {
                return 0;
            } else if (read_retval == -1 && errno == EINTR) {
                continue;
            } else if (read_retval > 0) {
                bytes_read += read_retval;
            } else {
                return -1;
            }
        } else {
            if (read_retval == 0) {
                return 0;
            } else if (read_retval == -1 && errno == EINTR) {
                continue;
            } else if (read_retval > 0) {
                bytes_read += read_retval;
            } else {
                return -1;
            }
        }
    }
    return bytes_read;
}


ssize_t write_all_to_socket(int socket, const char *buffer, size_t count) {
    size_t total = 0;
    ssize_t bytes_written;

    while (total < count) {
        bytes_written = write(socket, buffer + total, count - total);
        if (bytes_written == -1) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += bytes_written;
    }

    return total;
}

void signal_handler(int signal) {
}

void quit_server() {
    printf("Quitting server\n");

    VECTOR_FOR_EACH(file_vector, file_name, {
        char* path = NULL;
        asprintf(&path, "%s/%s", dir, (char*)file_name);
        unlink(path);
        free(path);
    });

    vector_destroy(file_vector);
    rmdir(dir);
    close(epollfd);

    exit(0);
}


int main(int argc, char **argv) {

    if (argc != 2) {
        print_server_usage();
        exit(1);
    }

    signal(SIGPIPE, signal_handler);
    
    struct sigaction sigint_act;
    memset(&sigint_act, '\0', sizeof(sigint_act));
    sigint_act.sa_handler = quit_server;
    if (sigaction(SIGINT, &sigint_act, NULL) != 0) {
        perror("sigaction");
	    exit(1);
    }

    file_vector = string_vector_create();
    clientfd_to_cinfo = int_to_shallow_dictionary_create();

    char dirname[] = "XXXXXX";
    dir = mkdtemp(dirname);
    if (dir == NULL) {
        perror("mkdtemp");
        exit(1);
    }
    print_temp_directory(dir);

    create_server(argv[1]);
}


// Chat-gpt generated this function
void sanitize_filename(char *filename) {
    if (filename == NULL) return;
    char *p = filename;
    while (*p) {
        if (*p == '\n' || *p == '\r') {
            *p = '\0';  // Replace newline or carriage return with null terminator
            break;
        }
        p++;
    }
}

// I used GPT to generate a majority of this function. I told it specific things 
// I wanted to use for the function and it completed.
int handle_get(int client_file_descriptor) {
    printf("Starting GET\n");

    // Retrieve client information
    struct cinfo_t* current_client = dictionary_get(clientfd_to_cinfo, &client_file_descriptor);
    if (!current_client) {
        fprintf(stderr, "Failed to get client info.\n");
        return -1;
    }

    sanitize_filename(current_client->filename);

    // Check if the file is in the vector and construct the path
    char *path = NULL;
    int found = 0;
    VECTOR_FOR_EACH(file_vector, elem, {
        if (strcmp(elem, current_client->filename) == 0) {
            asprintf(&path, "%s/%s", dir, (char*)elem);
            found = 1;
            break;
        }
    });

    if (!found) {
        printf("File not found: %s\n", current_client->filename);
        return -1;
    }

    // Get file stats
    struct stat stats;
    if (stat(path, &stats) != 0) {
        perror("Failed to get file stats");
        free(path);
        return -1;
    }

    current_client->file_size = stats.st_size;

    // Open the file
    int file_fd = open(path, O_RDONLY);
    if (file_fd < 0) {
        perror("Failed to open file");
        free(path);
        return -1;
    }

    printf("File size: %ld bytes\n", stats.st_size);  // Output the file size

    write_all_to_socket(client_file_descriptor, "OK\n", strlen("OK\n"));
    write_all_to_socket(client_file_descriptor, (char*) &(current_client->file_size), sizeof(size_t));

    // Send the file contents
    char buf[1024];
    ssize_t bytes_read;
    while ((bytes_read = read(file_fd, buf, sizeof(buf))) > 0) {
        if (write_all_to_socket(client_file_descriptor, buf, bytes_read) != bytes_read) {
            fprintf(stderr, "Failed to send all data.\n");
            close(file_fd);
            free(path);
            return -1;
        }
    }

    if (bytes_read < 0) {
        perror("Failed to read file");
        close(file_fd);
        free(path);
        return -1;
    }

    // Cleanup and close file
    close(file_fd);
    free(path);
    printf("File sent successfully.\n");
    return 0;  // Indicate success
}

// I used GPT to generate a majority of this function. I told it specific things 
// I wanted to use for the function and it completed.
int handle_put(int client_file_descriptor) {
    printf("Starting PUT\n");

    struct cinfo_t* current_client = dictionary_get(clientfd_to_cinfo, &client_file_descriptor);
    if (!current_client) {
        fprintf(stderr, "Client info not found\n");
        return -1;
    }

    sanitize_filename(current_client->filename);

    char *path;
    if (asprintf(&path, "%s/%s", dir, current_client->filename) == -1) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    printf("Path: %s\n", path);

    int file_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (file_fd < 0) {
        perror("open");
        free(path);
        return -1;
    }

    char buf[1024] = {0};
    ssize_t bytes_read;
    size_t bytes_left = current_client->file_size;
    size_t total_bytes_received = 0;
    
    // int while_loop_count = 0;
    while (bytes_left > 0) {
        size_t to_read = sizeof(buf) < bytes_left ? sizeof(buf) : bytes_left;
        bytes_read = read_all_from_socket_put(client_file_descriptor, buf, to_read);
        // printf("While loop count: %d\n and bytes_read: %ld\n, bytes_left: %ld\n", while_loop_count++, bytes_read, bytes_left);
        
        if (bytes_read == -1) {
            printf("Total bytes received: %zu\n", total_bytes_received);
            printf("File size: %zu\n", current_client->file_size);
            fprintf(stderr, "Failed to read from socket or connection closed prematurely.\n");
            close(file_fd);
            unlink(path);
            free(path);
            return -1;
        }

        if (bytes_read == 0) {
            if (total_bytes_received < current_client->file_size) {
                print_too_little_data();
                write_all_to_socket(client_file_descriptor, "ERROR\n", 6);
                write_all_to_socket(client_file_descriptor, err_bad_file_size, strlen(err_bad_file_size));
                close(file_fd);
                unlink(path);
                free(path);
                return -1;
            }
            if (total_bytes_received > current_client->file_size) {
                print_received_too_much_data();
                write_all_to_socket(client_file_descriptor, "ERROR\n", 6);
                write_all_to_socket(client_file_descriptor, err_bad_file_size, strlen(err_bad_file_size));
                close(file_fd);
                unlink(path);
                free(path);
                return -1;
            }
        }

        total_bytes_received += bytes_read;
        if (total_bytes_received > current_client->file_size) {
            print_received_too_much_data();
            write_all_to_socket(client_file_descriptor, "ERROR\n", 6);
            write_all_to_socket(client_file_descriptor, err_bad_file_size, strlen(err_bad_file_size));
            close(file_fd);
            unlink(path);
            free(path);
            return -1;
        }

        if (write(file_fd, buf, bytes_read) != bytes_read) {
            perror("write");
            close(file_fd);
            unlink(path);
            free(path);
            return -1;
        }

        bytes_left -= bytes_read;
    }

    printf("Total bytes received: %zu\n", total_bytes_received);
    printf("File size: %zu\n", current_client->file_size);

    if (total_bytes_received < current_client->file_size) {
        print_too_little_data();
        write_all_to_socket(client_file_descriptor, "ERROR\n", 6);
        write_all_to_socket(client_file_descriptor, err_bad_file_size, strlen(err_bad_file_size));
        close(file_fd);
        unlink(path);
        free(path);
        return -1;
    }

    printf("Successfully received and wrote %zu bytes.\n", total_bytes_received);
    vector_push_back(file_vector, strdup(current_client->filename));

    close(file_fd);
    free(path);
    return 0;
}




// I used GPT to generate a majority of this function. I told it specific things 
// I wanted to use for the function and it completed.
int handle_list(int client_file_descriptor) {

    printf("Starting LIST\n");

    // Construct the list of filenames
    char *list = NULL;
    size_t total_size = 0;
    write_all_to_socket(client_file_descriptor, "OK\n", strlen("OK\n"));
    VECTOR_FOR_EACH(file_vector, filename, {
        size_t name_len = strlen(filename);
        char *new_list = realloc(list, total_size + name_len + 1); // +1 for '\n'
        if (!new_list) {
            perror("Failed to allocate memory for file list");
            free(list);
            return -1;
        }
        list = new_list;
        memcpy(list + total_size, filename, name_len);
        list[total_size + name_len] = '\n';  // Append newline after each filename
        total_size += name_len + 1;
    });

    // Ensure list is null-terminated
    if (list) {
        list[total_size] = '\0';
    } else {
        // No files to list
        list = strdup("");
        total_size = 1;
    }

    write_all_to_socket(client_file_descriptor, (char*) &total_size, sizeof(size_t));

    // Write the list to the socket
    if (write_all_to_socket(client_file_descriptor, list, total_size) != (ssize_t)(total_size - 1)) {
        fprintf(stderr, "Failed to send file list.\n");
        free(list);
        return -1;
    }

    free(list);
    printf("File list sent successfully.\n");
    return 0;
}

// I used GPT to generate a majority of this function. I told it specific things 
// I wanted to use for the function and it completed.
int handle_delete(int client_file_descriptor) {
    printf("Starting DELETE\n");

    // Retrieve client information
    struct cinfo_t* current_client = dictionary_get(clientfd_to_cinfo, &client_file_descriptor);
    if (!current_client) {
        fprintf(stderr, "Failed to get client info.\n");
        return -1;
    }

    sanitize_filename(current_client->filename);

    // Check if the file exists in the vector
    int found = 0;
    size_t index = 0;
    VECTOR_FOR_EACH(file_vector, elem, {
        if (strcmp(elem, current_client->filename) == 0) {
            found = 1;
            break;
        }
        index++;
    });

    if (!found) {
        printf("File not found: %s\n", current_client->filename);
        // Optionally send an error message to the client here
        return -1;
    }

    // Construct the file path
    char *path = NULL;
    asprintf(&path, "%s/%s", dir, current_client->filename);

    // Attempt to delete the file
    if (unlink(path) != 0) {
        perror("Failed to delete file");
        free(path);
        return -1;
    }
    free(path);

    vector_erase(file_vector, index);

    printf("File %s deleted successfully.\n", current_client->filename);
    return 0;
}

int handle_client(int client_file_descriptor) {
    printf("Handling client %d\n", client_file_descriptor);

    cinfo_t* curr_client_info = dictionary_get(clientfd_to_cinfo, &client_file_descriptor);


    read_all_from_socket(client_file_descriptor, curr_client_info->header, 1024, 1);
    printf("Header received: %s\n", curr_client_info->header);

    if (!strncmp(curr_client_info->header, "PUT", 3)) {
        curr_client_info->command_sent = PUT;
        strcpy(curr_client_info->filename, curr_client_info->header + 4);
        curr_client_info->file_size = get_message_size(client_file_descriptor);
        //free(curr_client_info->header);
    } else if (!strncmp(curr_client_info->header, "GET", 3)) {
        curr_client_info->command_sent = GET;
        strcpy(curr_client_info->filename, curr_client_info->header + 4);
        curr_client_info->file_size = -1;
        //free(curr_client_info->header);
    } else if (!strncmp(curr_client_info->header, "DELETE", 6)) {
        curr_client_info->command_sent = DELETE;
        strcpy(curr_client_info->filename, curr_client_info->header + 7);
        curr_client_info->file_size = -1;
        //free(curr_client_info->header);
    } else if (!strncmp(curr_client_info->header, "LIST", 4)) {
        curr_client_info->command_sent = LIST;
        strcpy(curr_client_info->filename, "Nothing");
        curr_client_info->file_size = -1;
        //free(curr_client_info->header);
    } else {
        print_invalid_response();
        struct epoll_event eve_temp;
        eve_temp.events = EPOLLOUT;
        eve_temp.data.fd = client_file_descriptor;
        epoll_ctl(epollfd, EPOLL_CTL_DEL, client_file_descriptor, &eve_temp);
        write_all_to_socket(client_file_descriptor, "ERROR\n", 6);
        printf("sending Bad request\n");
        write_all_to_socket(client_file_descriptor, err_bad_request, strlen(err_bad_request));
        printf("Bad request\n");

        return 1;
    }

    if (curr_client_info->command_sent == PUT) {
        if (curr_client_info->filename[0] == '\0') {
            struct epoll_event eve_temp;
            eve_temp.events = EPOLLOUT;
            eve_temp.data.fd = client_file_descriptor;
            epoll_ctl(epollfd, EPOLL_CTL_DEL, client_file_descriptor, &eve_temp);
            write_all_to_socket(client_file_descriptor, err_bad_request, strlen(err_bad_request));
        }

        handle_put(client_file_descriptor);
        close(client_file_descriptor);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, client_file_descriptor, NULL);
    } else if (curr_client_info->command_sent == GET) {
        if (curr_client_info->filename[0] == '\0') {
            struct epoll_event eve_temp;
            eve_temp.events = EPOLLOUT;
            eve_temp.data.fd = client_file_descriptor;
            epoll_ctl(epollfd, EPOLL_CTL_DEL, client_file_descriptor, &eve_temp);
            write_all_to_socket(client_file_descriptor, err_bad_request, strlen(err_bad_request));
        }
        handle_get(client_file_descriptor);
        close(client_file_descriptor);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, client_file_descriptor, NULL);
    } else if (curr_client_info->command_sent == DELETE) {
        if (curr_client_info->filename[0] == '\0') {
            struct epoll_event eve_temp;
            eve_temp.events = EPOLLOUT;
            eve_temp.data.fd = client_file_descriptor;
            epoll_ctl(epollfd, EPOLL_CTL_DEL, client_file_descriptor, &eve_temp);
            write_all_to_socket(client_file_descriptor, err_bad_request, strlen(err_bad_request));
        }
        handle_delete(client_file_descriptor);
        close(client_file_descriptor);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, client_file_descriptor, NULL);
    } else if (curr_client_info->command_sent == LIST) {
        handle_list(client_file_descriptor);
        close(client_file_descriptor);
        epoll_ctl(epollfd, EPOLL_CTL_DEL, client_file_descriptor, NULL);
    } else {
        perror("Invalid command");
    }

    return 0;
}



// Copilot generated a majority of this code
int init_server_socket(char* port) {
    int sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("socket");
        exit(1);
    }

    // Set the socket to non-blocking
    int flags = fcntl(sock_fd, F_GETFL, 0);
    if (flags < 0) {
        perror("fcntl - F_GETFL");
        exit(1);
    }
    flags |= O_NONBLOCK;
    if (fcntl(sock_fd, F_SETFL, flags) < 0) {
        perror("fcntl - F_SETFL");
        exit(1);
    }

    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    int s = getaddrinfo(NULL, port, &hints, &result);
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        // quit_server();
        exit(1);
    }

    int optval = 1;
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
        perror("setsockopt");
        // quit_server();
        exit(1);
    }

    if (bind(sock_fd, result->ai_addr, result->ai_addrlen) < 0) {
        perror("bind");
        // quit_server();
        exit(1);
    }

    if (listen(sock_fd, MAX_CLIENTS) < 0) {
        perror("listen");
        // quit_server();
        exit(1);
    }

    freeaddrinfo(result);

    return sock_fd;
}

// Copilot generated a majority of this code
void create_server(char* port) {

    int sock_fd = init_server_socket(port);

    epollfd = epoll_create1(0);
    if (epollfd < 0) {
        perror("epoll_create1");
        // quit_server();
        exit(1);
    }

    struct epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = sock_fd;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, sock_fd, &event) < 0) {
        perror("epoll_ctl");
        // quit_server();
        exit(1);
    }

    struct epoll_event events[MAX_CLIENTS];

    while (true) {
        int num_events = epoll_wait(epollfd, events, MAX_CLIENTS, -1);
        if (num_events < 0) {
            perror("epoll_wait");
            // quit_server();
            exit(1);
        } else if (num_events == 0) {
            continue;
        }

        for (int i = 0; i < num_events; i++) {
            if (events[i].data.fd == sock_fd) {
                int client_fd = accept(sock_fd, NULL, NULL);
                if (client_fd < 0) {
                    perror("accept");
                    // quit_server();
                    exit(1);
                }

                struct epoll_event client_event;
                memset(&client_event, 0, sizeof(client_event));
                client_event.events = EPOLLIN;
                client_event.data.fd = client_fd;

                if (epoll_ctl(epollfd, EPOLL_CTL_ADD, client_fd, &client_event) < 0) {
                    perror("epoll_ctl");
                    // quit_server();
                    exit(1);
                }

                cinfo_t* cinfo = calloc(1, sizeof(cinfo_t));
                memset(cinfo->filename, 0, 256);
                memset(cinfo->header, 0, 1024);
                dictionary_set(clientfd_to_cinfo, &client_fd, cinfo);
            } else {
                printf("Here");
                handle_client(events[i].data.fd);
            }
        }
    }
}