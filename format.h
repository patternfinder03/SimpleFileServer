/**
 * @file client_server_program.h
 * @brief Header file for client-server communication program.
 *
 * This file contains the declarations for functions used in the client-server
 * communication program. It provides utility functions for printing various
 * messages related to the client's usage, error handling, and server communication.
 */

#pragma once

#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Error message for bad request.
 */
extern const char *err_bad_request;

/**
 * @brief Error message for bad file size.
 */
extern const char *err_bad_file_size;

/**
 * @brief Error message for no such file.
 */
extern const char *err_no_such_file;

/**
 * @brief Prints usage information for the client.
 *
 * This function displays the correct way to use the client program.
 */
void print_client_usage(void);

/**
 * @brief Prints help information for the client.
 *
 * This function displays detailed help information about the client's options and usage.
 */
void print_client_help(void);

/**
 * @brief Prints a message indicating that the connection has been closed.
 *
 * This function notifies the user that the connection to the server has been closed.
 */
void print_connection_closed(void);

/**
 * @brief Prints a specified error message.
 *
 * @param err The error message to print.
 *
 * This function displays the provided error message to the user.
 */
void print_error_message(char *err);

/**
 * @brief Prints a message indicating an invalid response from the server.
 *
 * This function notifies the user that the response received from the server was invalid.
 */
void print_invalid_response(void);

/**
 * @brief Prints a message indicating that too little data was received.
 *
 * This function notifies the user that the amount of data received was insufficient.
 */
void print_too_little_data(void);

/**
 * @brief Prints a message indicating that too much data was received.
 *
 * This function notifies the user that more data than expected was received.
 */
void print_received_too_much_data(void);

/**
 * @brief Prints a success message.
 *
 * This function informs the user that the operation was successful.
 */
void print_success(void);

/**
 * @brief Prints the temporary directory path.
 *
 * @param temp_directory The path to the temporary directory.
 *
 * This function displays the path to the temporary directory used by the program.
 */
void print_temp_directory(char *temp_directory);

/**
 * @brief Prints usage information for the server.
 *
 * This function displays the correct way to use the server program.
 */
void print_server_usage(void);

#endif // CLIENT_SERVER_PROGRAM_H