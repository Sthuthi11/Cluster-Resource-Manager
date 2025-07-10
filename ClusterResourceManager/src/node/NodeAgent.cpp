#include "NodeAgent.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <random>

NodeAgent::NodeAgent(const std::string& id, const std::string& manager_ip, int manager_port, int node_port)
    : node_id(id), manager_ip(manager_ip), manager_port(manager_port), node_port(node_port),
      current_status(NodeStatus::UP), current_cpu_usage(0), current_memory_usage(0), running(true),
      node_logger("logs/node_" + id + ".log", LogLevel::INFO) {
    listen_socket_fd = -1;
    node_logger.log(LogLevel::INFO, "NodeAgent " + node_id + " initialized.");
}

NodeAgent::~NodeAgent() {
    stop();
    node_logger.log(LogLevel::INFO, "NodeAgent " + node_id + " shut down.");
}

//Socket Programming:
int NodeAgent::connect_to_manager() {
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        node_logger.log(LogLevel::ERROR, "Node " + node_id + ": Socket creation error.");
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(manager_port);

    if (inet_pton(AF_INET, manager_ip.c_str(), &serv_addr.sin_addr) <= 0) {
        node_logger.log(LogLevel::ERROR, "Node " + node_id + ": Invalid address/ Address not supported.");
        close(sock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        node_logger.log(LogLevel::ERROR, "Node " + node_id + ": Connection to manager failed.");
        close(sock);
        return -1;
    }
    node_logger.log(LogLevel::INFO, "Node " + node_id + ": Connected to manager at " + manager_ip + ":" + std::to_string(manager_port));
    return sock;
}

void NodeAgent::send_message(int socket_fd, const Message& msg) {
    std::string serialized_msg = msg.serialize();
    // Prepend message length
    uint32_t msg_len = serialized_msg.length();
    uint32_t net_msg_len = htonl(msg_len); // Convert to network byte order

    if (send(socket_fd, &net_msg_len, sizeof(net_msg_len), 0) < 0) {
        node_logger.log(LogLevel::ERROR, "Node " + node_id + ": Failed to send message length.");
        return;
    }
    if (send(socket_fd, serialized_msg.c_str(), serialized_msg.length(), 0) < 0) {
        node_logger.log(LogLevel::ERROR, "Node " + node_id + ": Failed to send message payload.");
    }
}

Message NodeAgent::receive_message(int socket_fd) {
    uint32_t net_msg_len;
    if (recv(socket_fd, &net_msg_len, sizeof(net_msg_len), 0) <= 0) {
        // Connection closed or error
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

//Multi-threading, Health Monitoring:
void NodeAgent::send_heartbeats() {
    int manager_sock_fd = -1;
    while (running) {
        // Reconnect if necessary
        if (manager_sock_fd == -1) {
            manager_sock_fd = connect_to_manager();
            if (manager_sock_fd == -1) {
                node_logger.log(LogLevel::WARNING, "Node " + node_id + ": Retrying manager connection in 5 seconds...");
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }
            // Register with manager on reconnect
            Message register_msg;
            register_msg.type = MessageType::NODE_REGISTER;
            register_msg.sender_id = node_id;
            register_msg.payload = std::to_string(node_port) + "," +
                                   std::to_string(MAX_CPU_USAGE) + "," +
                                   std::to_string(MAX_MEMORY_USAGE_MB);
            send_message(manager_sock_fd, register_msg);
            node_logger.log(LogLevel::INFO, "Node " + node_id + ": Sent registration message to manager.");
        }

        // Simulate current resource usage
        current_cpu_usage = Utils::get_current_cpu_usage_simulated();
        current_memory_usage = Utils::get_current_memory_usage_simulated();

        // Count running tasks
        int num_tasks;
        {
            std::lock_guard<std::mutex> lock(tasks_mutex);
            num_tasks = running_tasks.size();
        }

        NodeHeartbeatPayload hb_payload = {node_id, current_cpu_usage, current_memory_usage, num_tasks};
        Message heartbeat_msg;
        heartbeat_msg.type = MessageType::NODE_HEARTBEAT;
        heartbeat_msg.sender_id = node_id;
        heartbeat_msg.payload = hb_payload.serialize();

        send_message(manager_sock_fd, heartbeat_msg);
        node_logger.log(LogLevel::DEBUG, "Node " + node_id + ": Sent heartbeat: CPU=" + std::to_string(current_cpu_usage) +
                                         "%, Mem=" + std::to_string(current_memory_usage) + "MB, Tasks=" + std::to_string(num_tasks));

        std::this_thread::sleep_for(std::chrono::seconds(2)); // Send heartbeat every 2 seconds
    }
    if (manager_sock_fd != -1) {
        close(manager_sock_fd);
    }
}

//Socket Programming, Multi-threading:
void NodeAgent::start_listener() {
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((listen_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        node_logger.log(LogLevel::CRITICAL, "Node " + node_id + ": Listener socket creation failed.");
        running = false;
        return;
    }

    if (setsockopt(listen_socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        node_logger.log(LogLevel::CRITICAL, "Node " + node_id + ": Listener setsockopt failed.");
        running = false;
        close(listen_socket_fd);
        return;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all available interfaces
    address.sin_port = htons(node_port);

    if (bind(listen_socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        node_logger.log(LogLevel::CRITICAL, "Node " + node_id + ": Listener bind failed on port " + std::to_string(node_port) + ".");
        running = false;
        close(listen_socket_fd);
        return;
    }

    if (listen(listen_socket_fd, 5) < 0) { // 5 pending connections queue size
        node_logger.log(LogLevel::CRITICAL, "Node " + node_id + ": Listener listen failed.");
        running = false;
        close(listen_socket_fd);
        return;
    }
    node_logger.log(LogLevel::INFO, "Node " + node_id + ": Listening for tasks on port " + std::to_string(node_port) + "...");

    while (running) {
        int client_socket_fd = accept(listen_socket_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_socket_fd < 0) {
            if (!running) break; // If we are stopping, ignore accept error
            node_logger.log(LogLevel::ERROR, "Node " + node_id + ": Listener accept error.");
            continue;
        }
        node_logger.log(LogLevel::INFO, "Node " + node_id + ": New connection accepted from client.");
        std::thread(&NodeAgent::handle_client_connection, this, client_socket_fd).detach(); // Detach thread to handle concurrently
    }
    if (listen_socket_fd != -1) {
        close(listen_socket_fd);
    }
}

void NodeAgent::handle_client_connection(int client_socket_fd) {
    Message received_msg = receive_message(client_socket_fd);
    if (received_msg.type == MessageType::TASK_ASSIGN) {
        TaskAssignmentPayload task_payload = TaskAssignmentPayload::deserialize(received_msg.payload);
        node_logger.log(LogLevel::INFO, "Node " + node_id + ": Received task assignment for " + task_payload.task_id);

        std::lock_guard<std::mutex> lock(tasks_mutex);
        if (running_tasks.count(task_payload.task_id)) {
            node_logger.log(LogLevel::WARNING, "Node " + node_id + ": Task " + task_payload.task_id + " already exists. Ignoring.");
            close(client_socket_fd);
            return;
        }
        running_tasks.emplace(task_payload.task_id, Task(task_payload));
        // Start task execution in a separate thread
        running_tasks.at(task_payload.task_id).execution_thread = std::thread(&NodeAgent::execute_task, this, task_payload);
        node_logger.log(LogLevel::INFO, "Node " + node_id + ": Started execution thread for task " + task_payload.task_id);

    } else if (received_msg.type == MessageType::SHUTDOWN) {
        node_logger.log(LogLevel::INFO, "Node " + node_id + ": Received shutdown signal from manager.");
        running = false;
    } else {
        node_logger.log(LogLevel::WARNING, "Node " + node_id + ": Received unknown message type: " + std::to_string(static_cast<int>(received_msg.type)));
    }
    close(client_socket_fd);
}


//Scheduling, Memory Management:
void NodeAgent::execute_task(TaskAssignmentPayload task_payload) {
    std::string task_id = task_payload.task_id;
    node_logger.log(LogLevel::INFO, "Node " + node_id + ": Task " + task_id + " (" + task_payload.task_name + ") starting.");

    // Update status to RUNNING
    update_task_status(task_id, TaskStatus::RUNNING, node_id);

    // Simulate resource usage during task execution
    simulate_resource_usage(task_payload.required_cpu, task_payload.required_memory, task_payload.duration_seconds);

    node_logger.log(LogLevel::INFO, "Node " + node_id + ": Task " + task_id + " (" + task_payload.task_name + ") completed in " + std::to_string(task_payload.duration_seconds) + " seconds.");

    // Update status to COMPLETED
    update_task_status(task_id, TaskStatus::COMPLETED, node_id);

    // Remove task from running_tasks map
    {
        std::lock_guard<std::mutex> lock(tasks_mutex);
        running_tasks.erase(task_id);
    }
}

void NodeAgent::update_task_status(const std::string& task_id, TaskStatus status, const std::string& node_id) {
    int manager_sock_fd = connect_to_manager();
    if (manager_sock_fd != -1) {
        TaskStatusUpdatePayload status_payload = {task_id, status, node_id};
        Message msg;
        msg.type = MessageType::TASK_STATUS_UPDATE;
        msg.sender_id = this->node_id;
        msg.payload = status_payload.serialize();
        send_message(manager_sock_fd, msg);
        close(manager_sock_fd);
        node_logger.log(LogLevel::INFO, "Node " + this->node_id + ": Sent task " + task_id + " status: " + std::to_string(static_cast<int>(status)));
    } else {
        node_logger.log(LogLevel::ERROR, "Node " + this->node_id + ": Could not connect to manager to send task status update for " + task_id);
    }
}

void NodeAgent::simulate_resource_usage(int cpu_increase, int memory_increase, int duration_seconds) {
    // Simulate CPU usage by busy-waiting
    auto start_time = std::chrono::high_resolution_clock::now();
    long long cpu_work_iterations = 1000000000LL * cpu_increase / 100; // Scale iterations by CPU requirement

    // Simulate memory usage by allocating memory
    std::vector<char> large_memory_block;
    if (memory_increase > 0) {
        size_t block_size = memory_increase * 1024 * 1024; // Convert MB to bytes
        try {
            large_memory_block.resize(block_size);
            // Touch memory to ensure it's actually allocated and not just virtually
            for (size_t i = 0; i < block_size; i += 4096) { // Page size usually 4KB
                large_memory_block[i] = static_cast<char>(rand() % 256);
            }
            node_logger.log(LogLevel::DEBUG, "Node " + node_id + ": Allocated " + std::to_string(memory_increase) + "MB for task simulation.");
        } catch (const std::bad_alloc& e) {
            node_logger.log(LogLevel::ERROR, "Node " + node_id + ": Failed to allocate " + std::to_string(memory_increase) + "MB: " + e.what());
        }
    }

    // Busy-wait for the duration
    auto current_time = std::chrono::high_resolution_clock::now();
    while (std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count() < duration_seconds) {
        // Perform some dummy calculations to simulate CPU work
        for (long long i = 0; i < cpu_work_iterations; ++i) {
            //volatile double temp = std::sqrt(static_cast<double>(i)); // Simple CPU-bound operation
            (void)std::sqrt(static_cast<double>(i));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Yield to other threads/processes
        current_time = std::chrono::high_resolution_clock::now();
    }
    
    // Memory block will be deallocated when `large_memory_block` goes out of scope.
}


void NodeAgent::start() {
    //Multi-threading:
    // Start heartbeat thread to communicate with the manager
    heartbeat_thread = std::thread(&NodeAgent::send_heartbeats, this);
    // Start listener thread to receive tasks from the manager
    listener_thread = std::thread(&NodeAgent::start_listener, this);

    // Initial registration with manager
    // This is handled by the heartbeat thread on initial connection
}

void NodeAgent::stop() {
    running = false;
    node_logger.log(LogLevel::INFO, "Node " + node_id + ": Shutting down...");

    // Send shutdown message to manager (optional, manager will detect absence)
    int manager_sock_fd = connect_to_manager();
    if (manager_sock_fd != -1) {
        Message shutdown_msg;
        shutdown_msg.type = MessageType::SHUTDOWN;
        shutdown_msg.sender_id = node_id;
        shutdown_msg.payload = "Node " + node_id + " is shutting down.";
        send_message(manager_sock_fd, shutdown_msg);
        close(manager_sock_fd);
    }

    // Join threads to ensure they finish cleanly
    if (heartbeat_thread.joinable()) {
        heartbeat_thread.join();
    }
    if (listener_thread.joinable()) {
        // To unblock accept() call in listener_thread, connect to its own port
        int dummy_sock = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(node_port);
        inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
        connect(dummy_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
        close(dummy_sock);

        listener_thread.join();
    }

    // Join all running task threads
    std::lock_guard<std::mutex> lock(tasks_mutex);
    for (auto& pair : running_tasks) {
        if (pair.second.execution_thread.joinable()) {
            pair.second.execution_thread.join();
        }
    }
    running_tasks.clear();

    if (listen_socket_fd != -1) {
        close(listen_socket_fd);
        listen_socket_fd = -1;
    }
}