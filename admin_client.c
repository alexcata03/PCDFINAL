#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <ctype.h>
#include <errno.h>

#define SOCKET_PATH "/tmp/admin_socket"
#define BUFFER_SIZE 256

void display_menu() {
    printf("Admin Menu:\n");
    printf("1. View connected users\n");
    printf("2. View and save logs\n");
    printf("3. Block user\n");
    printf("4. Unblock user\n");
    printf("5. Delete file (XML/JSON)\n");
    printf("6. Logout\n");
    printf("7. View all users\n");
    printf("Enter your choice: ");
}

void handle_menu(int sockfd) {
    char choice[BUFFER_SIZE];
    char buffer[BUFFER_SIZE];
    char username[BUFFER_SIZE / 2];
    char filename[BUFFER_SIZE];

    while (1) {
        display_menu();
        fgets(choice, sizeof(choice), stdin);
        choice[strcspn(choice, "\n")] = 0;

        if (strcmp(choice, "1") == 0) {
            snprintf(buffer, sizeof(buffer), "VIEW_USERS");
            send(sockfd, buffer, strlen(buffer), 0);
            recv(sockfd, buffer, sizeof(buffer), 0);
            printf("%s\n", buffer);
        } else if (strcmp(choice, "2") == 0) {
            char log_dir[BUFFER_SIZE];
            printf("Enter directory to save the logs: ");
            fgets(log_dir, sizeof(log_dir), stdin);
            log_dir[strcspn(log_dir, "\n")] = 0;

            snprintf(buffer, sizeof(buffer), "VIEW_LOGS %.245s", log_dir);
            send(sockfd, buffer, strlen(buffer), 0);
            recv(sockfd, buffer, sizeof(buffer), 0);
            printf("%s\n", buffer);
        } else if (strcmp(choice, "3") == 0) {
            printf("Enter username to block: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = 0;
            snprintf(buffer, sizeof(buffer), "BLOCK_USER %.100s", username);
            send(sockfd, buffer, strlen(buffer), 0);
            memset(buffer, 0, sizeof(buffer));
            recv(sockfd, buffer, sizeof(buffer), 0);
            printf("%s\n", buffer);
        } else if (strcmp(choice, "4") == 0) {
            printf("Enter username to unblock: ");
            fgets(username, sizeof(username), stdin);
            username[strcspn(username, "\n")] = 0;
            snprintf(buffer, sizeof(buffer), "UNBLOCK_USER %.100s", username);
            send(sockfd, buffer, strlen(buffer), 0);
            memset(buffer, 0, sizeof(buffer));
            recv(sockfd, buffer, sizeof(buffer), 0);
            printf("%s\n", buffer);
        } else if (strcmp(choice, "5") == 0) {
            printf("Enter filename to delete: ");
            fgets(filename, sizeof(filename), stdin);
            filename[strcspn(filename, "\n")] = 0;
            snprintf(buffer, sizeof(buffer), "DELETE_FILE %.100s", filename);
            send(sockfd, buffer, strlen(buffer), 0);
            memset(buffer, 0, sizeof(buffer));
            recv(sockfd, buffer, sizeof(buffer), 0);
            printf("%s\n", buffer);
        } else if (strcmp(choice, "6") == 0) {
            snprintf(buffer, sizeof(buffer), "LOGOUT");
            send(sockfd, buffer, strlen(buffer), 0);
            break;
        } else if (strcmp(choice, "7") == 0) {
            snprintf(buffer, sizeof(buffer), "VIEW_ALL_USERS");
            send(sockfd, buffer, strlen(buffer), 0);
            recv(sockfd, buffer, sizeof(buffer), 0);
            printf("Users:\n%s\n", buffer);
        } else {
            printf("Invalid choice. Please try again.\n");
            continue;
        }
    }
}

int main() {
    int sockfd;
    struct sockaddr_un addr;
    char buffer[BUFFER_SIZE];
    char username[BUFFER_SIZE / 2], password[BUFFER_SIZE / 2];

    while (1) {
        if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
            perror("socket error");
            exit(EXIT_FAILURE);
        }

        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);

        if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
            perror("connect error");
            exit(EXIT_FAILURE);
        }

        printf("Username: ");
        fgets(username, sizeof(username), stdin);
        username[strcspn(username, "\n")] = 0;

        printf("Password: ");
        fgets(password, sizeof(password), stdin);
        password[strcspn(password, "\n")] = 0;

        snprintf(buffer, sizeof(buffer), "LOGIN %.100s %.100s", username, password);
        send(sockfd, buffer, strlen(buffer), 0);

        memset(buffer, 0, sizeof(buffer));
        recv(sockfd, buffer, sizeof(buffer), 0);
        printf("%s\n", buffer);

        if (strcmp(buffer, "Login successful") == 0) {
            handle_menu(sockfd);
            break;
        } else if (strcmp(buffer, "Admin already connected. Connection rejected.") == 0) {
            close(sockfd);
            exit(EXIT_FAILURE);
        } else {
            printf("Login failed. Try again.\n");
            close(sockfd);
        }
    }

    return 0;
}