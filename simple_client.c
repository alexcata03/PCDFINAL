#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <sys/stat.h>
#include <libgen.h>
#include <pthread.h>
#include <stdint.h>
#include <dirent.h>

#define BUFFER_SIZE 1035
#define SERVER_PORT 12345
#define SERVER_IP "127.0.0.1"
#define MAX_FILE_PATH 512

int is_logged_in = 0;

void trim_whitespace(char *str);
void trim_trailing_slash(char *str);
int is_xml_file(const char *filename);
void show_action_menu();
int connect_to_server();
void login(int socket_fd);
void register_user();
void upload_xml(int socket_fd);
void download_json(int socket_fd, const char *download_dir);
void listen_for_messages(int socket_fd);
void search_in_file(int socket_fd);

void trim_whitespace(char *str) {
    char *end;
    while (isspace((unsigned char)*str)) str++;
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;
    *(end + 1) = '\0';
}

void trim_trailing_slash(char *str) {
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '/') {
        str[len - 1] = '\0';
    }
}

int is_xml_file(const char *filename) {
    const char *dot = strrchr(filename, '.');
    return dot && strcmp(dot, ".xml") == 0;
}

void show_action_menu() {
    if (!is_logged_in) {
        printf("1. Login\n");
        printf("2. Register\n");
        printf("3. Exit\n");
    } else {
        printf("1. Upload XML file\n");
        printf("2. Download converted JSON file\n");
        printf("3. Search in file\n");
        printf("4. Exit\n");
    }
    fflush(stdout);
}

int connect_to_server() {
    int socket_fd;
    struct sockaddr_in server_addr;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        perror("Socket error");
        return -1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    if (connect(socket_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Connect error");
        close(socket_fd);
        return -1;
    }

    return socket_fd;
}

void login(int socket_fd) {
    char username[BUFFER_SIZE / 2], password[BUFFER_SIZE / 2], buffer[BUFFER_SIZE], response[BUFFER_SIZE];

    printf("Username: ");
    fgets(username, sizeof(username), stdin);
    trim_whitespace(username);

    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    trim_whitespace(password);

    snprintf(buffer, BUFFER_SIZE, "LOGIN %.100s %.100s", username, password);
    write(socket_fd, buffer, strlen(buffer));

    memset(response, 0, sizeof(response));
    read(socket_fd, response, BUFFER_SIZE);
    printf("%s\n", response);

    if (strcmp(response, "Login successful") == 0) {
        is_logged_in = 1;
    } else {
        printf("Login failed. Try again.\n");
        close(socket_fd);
    }
}

void register_user() {
    int socket_fd = connect_to_server();
    if (socket_fd == -1) return;

    char username[BUFFER_SIZE / 2], password[BUFFER_SIZE / 2], buffer[BUFFER_SIZE], response[BUFFER_SIZE];

    printf("Register with your username: ");
    fgets(username, sizeof(username), stdin);
    trim_whitespace(username);

    printf("Password: ");
    fgets(password, sizeof(password), stdin);
    trim_whitespace(password);

    snprintf(buffer, BUFFER_SIZE, "REGISTER %.100s %.100s", username, password);
    write(socket_fd, buffer, strlen(buffer));
    memset(response, 0, sizeof(response));

    read(socket_fd, response, BUFFER_SIZE);
    printf("%s\n", response);

    if (strcmp(response, "User registered successfully") == 0) {
        printf("Please log in with your new credentials.\n");
        close(socket_fd);
        socket_fd = connect_to_server();
        if (socket_fd != -1) {
            login(socket_fd);
        }
    } else {
        close(socket_fd);
    }
}

int is_directory(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
        return 1;
    }
    return 0;
}

void upload_xml(int socket_fd) {
    char buffer[BUFFER_SIZE];
    char file_path[MAX_FILE_PATH];
    FILE *file;
    ssize_t bytes_read;

    printf("Enter the path of the XML file to upload: ");
    fgets(file_path, sizeof(file_path), stdin);
    trim_whitespace(file_path);

    if (!is_xml_file(file_path)) {
        printf("The file is not an XML file. Please try again.\n");
        return;
    }

    file = fopen(file_path, "rb");
    if (!file) {
        perror("Failed to open file");
        return;
    }

    snprintf(buffer, BUFFER_SIZE, "UPLOAD_XML %.1023s", file_path);
    write(socket_fd, buffer, strlen(buffer));
    printf("Debug: Path sent to server: %s\n", buffer);

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        printf("Debug: Read %zd bytes from file\n", bytes_read);
        if (write(socket_fd, buffer, bytes_read) != bytes_read) {
            perror("Failed to send file to server");
            fclose(file);
            return;
        }
        memset(buffer, 0, BUFFER_SIZE);
    }

    fclose(file);

    snprintf(buffer, BUFFER_SIZE, "END_OF_FILE");
    write(socket_fd, buffer, strlen(buffer));
    printf("Debug: Finished sending file. Waiting for server response...\n");

    ssize_t bytes_received = read(socket_fd, buffer, BUFFER_SIZE);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Debug: Response from server after upload: %s\n", buffer);
        printf("%s\n", buffer);
    } else {
        perror("Debug: No response from server or error reading response");
    }
}

void download_json(int socket_fd, const char *download_dir) {
    char buffer[BUFFER_SIZE];
    FILE *file;
    ssize_t bytes_received;
    char download_path[MAX_FILE_PATH * 2];
    char directory[MAX_FILE_PATH];

    strncpy(directory, download_dir, MAX_FILE_PATH);
    trim_trailing_slash(directory);

    snprintf(buffer, BUFFER_SIZE, "DOWNLOAD_JSON %s", directory);
    write(socket_fd, buffer, strlen(buffer));
    printf("Debug: Path sent to server: %s\n", buffer);

    bytes_received = read(socket_fd, buffer, BUFFER_SIZE);
    if (bytes_received <= 0) {
        perror("Failed to receive filename from server");
        return;
    }
    buffer[bytes_received] = '\0';
    printf("Debug: Filename received from server: %s\n", buffer);

    int len = snprintf(download_path, sizeof(download_path), "%s/%s", directory, buffer);
    if (len >= sizeof(download_path) - 1) {
        perror("Failed to create download path: buffer too small");
        return;
    }

    file = fopen(download_path, "wb");
    if (!file) {
        perror("Failed to open file for writing");
        return;
    }

    while ((bytes_received = read(socket_fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_received] = '\0';
        printf("Debug: Received data chunk: %s\n", buffer);

        char *eof_pos = strstr(buffer, "END_OF_FILE");
        if (eof_pos != NULL) {
            fwrite(buffer, 1, eof_pos - buffer, file);
            printf("Debug: Detected end of file marker\n");
            break;
        } else {
            fwrite(buffer, 1, bytes_received, file);
        }
    }

    fclose(file);
    printf("Debug: Finished receiving file. File saved to %s.\n", download_path);

    if (bytes_received == 0) {
        printf("Debug: Server closed connection.\n");
    } else if (bytes_received < 0) {
        perror("Error reading from server");
    } else {
        printf("Debug: End of file received.\n");
    }
}

void list_json_files(char **files, int *num_files) {
    DIR *dir;
    struct dirent *ent;
    int count = 0;

    if ((dir = opendir(".")) != NULL) {
        while ((ent = readdir(dir)) != NULL) {
            if (strstr(ent->d_name, ".json") != NULL) {
                files[count] = strdup(ent->d_name);
                count++;
            }
        }
        closedir(dir);
    } else {
        perror("Could not open directory");
    }

    *num_files = count;
}

void search_in_file(int socket_fd) {
    char buffer[BUFFER_SIZE];
    char file_path[MAX_FILE_PATH];
    char search_path[BUFFER_SIZE];
    char *files[100];
    int num_files = 0;

    // List JSON files in the current directory
    list_json_files(files, &num_files);

    if (num_files == 0) {
        printf("No JSON files found in the current directory.\n");
        return;
    }

    printf("Select a JSON file to search in:\n");
    for (int i = 0; i < num_files; i++) {
        printf("%d. %s\n", i + 1, files[i]);
    }

    printf("Enter the number corresponding to your choice: ");
    fgets(buffer, sizeof(buffer), stdin);
    int file_choice = atoi(buffer) - 1;

    if (file_choice < 0 || file_choice >= num_files) {
        printf("Invalid choice.\n");
        return;
    }

    strncpy(file_path, files[file_choice], MAX_FILE_PATH - 1);
    file_path[MAX_FILE_PATH - 1] = '\0'; // Ensure null-termination

    printf("Enter the search path (e.g., root.element): ");
    fgets(search_path, sizeof(search_path), stdin);
    trim_whitespace(search_path);

    // Clear the buffer and safely build the command string in parts
    memset(buffer, 0, BUFFER_SIZE);
    strncpy(buffer, "SEARCH_JSON ", BUFFER_SIZE - 1);
    strncat(buffer, file_path, BUFFER_SIZE - strlen(buffer) - 1);
    strncat(buffer, " ", BUFFER_SIZE - strlen(buffer) - 1);
    strncat(buffer, search_path, BUFFER_SIZE - strlen(buffer) - 1);

    write(socket_fd, buffer, strlen(buffer));

    ssize_t bytes_received = read(socket_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("Search results:\n%s\n", buffer);
    } else {
        perror("Error reading from server");
    }

    for (int i = 0; i < num_files; i++) {
        free(files[i]);
    }
}

void listen_for_messages(int socket_fd) {
    char buffer[BUFFER_SIZE];
    while (1) {
        memset(buffer, 0, BUFFER_SIZE);
        ssize_t bytes_read = read(socket_fd, buffer, BUFFER_SIZE - 1);
        if (bytes_read <= 0) {
            printf("Connection closed by server.\n");
            close(socket_fd);
            exit(0);
        }
        buffer[bytes_read] = '\0';

        if (strcmp(buffer, "DISCONNECT") == 0) {
            printf("You have been disconnected by the server.\n");
            close(socket_fd);
            exit(0);
        }
    }
}

int main() {
    char choice[BUFFER_SIZE];
    int socket_fd = -1;
    pthread_t listener_thread;

    while (1) {
        show_action_menu();
        printf("Enter choice: ");
        fgets(choice, BUFFER_SIZE, stdin);
        choice[strcspn(choice, "\n")] = 0;

        if (!is_logged_in) {
            if (strcmp(choice, "1") == 0) {
                if (socket_fd != -1) close(socket_fd);
                socket_fd = connect_to_server();
                if (socket_fd != -1) {
                    login(socket_fd);
                    if (is_logged_in) {
                        pthread_create(&listener_thread, NULL, (void *(*)(void *))listen_for_messages, (void *)(intptr_t)socket_fd);
                        pthread_detach(listener_thread);
                    }
                }
            } else if (strcmp(choice, "2") == 0) {
                register_user();
            } else if (strcmp(choice, "3") == 0) {
                if (socket_fd != -1) close(socket_fd);
                exit(0);
            } else {
                printf("Invalid choice. Please try again.\n");
            }
        } else {
            if (strcmp(choice, "1") == 0) {
                if (socket_fd != -1) upload_xml(socket_fd);
            } else if (strcmp(choice, "2") == 0) {
                if (socket_fd != -1) {
                    printf("Enter the directory path where you want to save the downloaded JSON file: ");
                    char download_dir[MAX_FILE_PATH];
                    fgets(download_dir, sizeof(download_dir), stdin);
                    trim_whitespace(download_dir);
                    download_json(socket_fd, download_dir);
                }
            } else if (strcmp(choice, "3") == 0) {
                if (socket_fd != -1) {
                    search_in_file(socket_fd);
                }
            } else if (strcmp(choice, "4") == 0) {
                if (socket_fd != -1) close(socket_fd);
                exit(0);
            } else {
                printf("Invalid choice. Please try again.\n");
            }
        }
    }
    return 0;
}
