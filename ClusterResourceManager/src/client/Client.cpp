#include "Client.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <random>

Client::Client(const std::string& manager_ip, int manager_port)
    : manager_ip(manager_ip), manager_port(manager_port) {}

// Socket Programming:
int Client::connect_to_manager() {
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cerr << "Client: Socket creation error." << std::endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(manager_port);

    if (inet_pton(AF_INET, manager_ip.c_str(), &serv_addr.sin_addr) <= 0) {
        std::cerr << "Client: Invalid address/ Address not supported." << std::endl;
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cerr << "Client: Connection to manager failed." << std::endl;
        close(sock);
        return -1;
    }
    return sock;
}

void Client::send_message(int socket_fd, const Message& msg) {
    std::string serialized_msg = msg.serialize();
    uint32_t msg_len = serialized_msg.length();
    uint32_t net_msg_len = htonl(msg_len);

    if (send(socket_fd, &net_msg_len, sizeof(net_msg_len), 0) < 0) {
        std::cerr << "Client: Failed to send message length." << std::endl;
        return;
    }
    if (send(socket_fd, serialized_msg.c_str(), serialized_msg.length(), 0) < 0) {
        std::cerr << "Client: Failed to send message payload." << std::endl;
    }
}

Message Client::receive_message(int socket_fd) {
    uint32_t net_msg_len;
    if (recv(socket_fd, &net_msg_len, sizeof(net_msg_len), 0) <= 0) {
        return {MessageType::SHUTDOWN, "", "ERROR_READING_LENGTH"};
    }
    uint32_t msg_len = ntohl(net_msg_len);

    std::vector<char> buffer(msg_len);
    int bytes_received = 0;
    while (static_cast<uint32_t>(bytes_received) < msg_len) { 
        int res = recv(socket_fd, buffer.data() + bytes_received, msg_len - bytes_received, 0);
        if (res <= 0) {
            return {MessageType::SHUTDOWN, "", "ERROR_READING_PAYLOAD"};
        }
        bytes_received += res;
    }
    return Message::deserialize(std::string(buffer.begin(), buffer.end()));
}

void Client::submit_task(const TaskSubmitPayload& payload) {
    int manager_sock_fd = connect_to_manager();
    if (manager_sock_fd != -1) {
        Message msg;
        msg.type = MessageType::TASK_SUBMIT;
        msg.sender_id = "client";
        msg.payload = payload.serialize();
        send_message(manager_sock_fd, msg);
        std::cout << "Client: Submitted task: " << payload.task_name << " (ID: " << payload.task_id << ")" << std::endl;
        close(manager_sock_fd);
    } else {
        std::cerr << "Client: Failed to connect to manager to submit task." << std::endl;
    }
}

void Client::request_node_status() {
    std::cout << "Client: Node status request not implemented for this basic client." << std::endl;
}