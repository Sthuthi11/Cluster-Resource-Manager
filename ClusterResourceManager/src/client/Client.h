#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <vector>
#include "../common/Constants.h"
#include "../common/MessageTypes.h"
#include "../common/Utils.h"

//Socket Programming:

class Client {
private:
    std::string manager_ip;
    int manager_port;

    int connect_to_manager();
    void send_message(int socket_fd, const Message& msg);
    Message receive_message(int socket_fd);

public:
    Client(const std::string& manager_ip, int manager_port);
    void submit_task(const TaskSubmitPayload& payload);
    void request_node_status(); 
};

#endif // CLIENT_H