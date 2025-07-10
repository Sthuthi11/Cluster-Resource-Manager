#include "ClusterManager.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <algorithm>
#include <chrono>

ClusterManager::ClusterManager(int port)
    : manager_port(port), running(true),
      manager_logger("logs/manager.log", LogLevel::INFO) {
    listen_socket_fd = -1;
    manager_logger.log(LogLevel::INFO, "ClusterManager initialized on port " + std::to_string(manager_port) + ".");
}

ClusterManager::~ClusterManager() {
    stop();
    manager_logger.log(LogLevel::INFO, "ClusterManager shut down.");
}

//Socket Programming:
void ClusterManager::send_message(int socket_fd, const Message& msg) {
    std::string serialized_msg = msg.serialize();
    uint32_t msg_len = serialized_msg.length();
    uint32_t net_msg_len = htonl(msg_len); // Convert to network byte order

    if (send(socket_fd, &net_msg_len, sizeof(net_msg_len), 0) < 0) {
        manager_logger.log(LogLevel::ERROR, "Manager: Failed to send message length to socket " + std::to_string(socket_fd) + ". Error: " + strerror(errno));
        return;
    }
    if (send(socket_fd, serialized_msg.c_str(), serialized_msg.length(), 0) < 0) {
        manager_logger.log(LogLevel::ERROR, "Manager: Failed to send message payload to socket " + std::to_string(socket_fd) + ". Error: " + strerror(errno));
    }
}

Message ClusterManager::receive_message(int socket_fd) {
    uint32_t net_msg_len;
    // MSG_WAITALL ensures all bytes are read or an error occurs
    int bytes_read_len = recv(socket_fd, &net_msg_len, sizeof(net_msg_len), MSG_WAITALL);
    if (bytes_read_len <= 0) {
        if (bytes_read_len == 0) {
            // Connection gracefully closed
            return {MessageType::SHUTDOWN, "", "PEER_CLOSED"};
        } else {
            // Error
            // Only log if not due to graceful shutdown or expected during manager shutdown
            if (running) { // Only log errors if manager is still supposed to be running
                 manager_logger.log(LogLevel::ERROR, "Manager: Failed to receive message length from socket " + std::to_string(socket_fd) + ". Error: " + strerror(errno));
            }
            return {MessageType::SHUTDOWN, "", "ERROR_READING_LENGTH"};
        }
    }
    uint32_t msg_len = ntohl(net_msg_len); // Convert from network byte order

    if (msg_len == 0) {
        // Handle empty message or keep-alive if protocol allows
        return {MessageType::UNKNOWN, "", ""};
    }

    std::vector<char> buffer(msg_len);
    int bytes_read_payload = recv(socket_fd, buffer.data(), msg_len, MSG_WAITALL); // Ensure all payload bytes are read
    if (bytes_read_payload <= 0) {
         if (bytes_read_payload == 0) {
            return {MessageType::SHUTDOWN, "", "PEER_CLOSED"};
        } else {
            if (running) { // Only log errors if manager is still supposed to be running
                manager_logger.log(LogLevel::ERROR, "Manager: Failed to receive message payload from socket " + std::to_string(socket_fd) + ". Error: " + strerror(errno));
            }
            return {MessageType::SHUTDOWN, "", "ERROR_READING_PAYLOAD"};
        }
    }
    return Message::deserialize(std::string(buffer.begin(), buffer.end()));
}

//Multi-threading, IPC:
void ClusterManager::start_listener() {
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((listen_socket_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        manager_logger.log(LogLevel::CRITICAL, "Manager: Listener socket creation failed.");
        running = false;
        return;
    }

    // Allow reuse of address and port
    if (setsockopt(listen_socket_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        manager_logger.log(LogLevel::CRITICAL, "Manager: Listener setsockopt failed.");
        running = false;
        close(listen_socket_fd);
        return;
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; // Listen on all available network interfaces
    address.sin_port = htons(manager_port);

    if (bind(listen_socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        manager_logger.log(LogLevel::CRITICAL, "Manager: Listener bind failed on port " + std::to_string(manager_port) + ". Error: " + strerror(errno));
        running = false;
        close(listen_socket_fd);
        return;
    }

    if (listen(listen_socket_fd, 10) < 0) { // 10 pending connections queue size
        manager_logger.log(LogLevel::CRITICAL, "Manager: Listener listen failed. Error: " + std::string(strerror(errno)));
        running = false;
        close(listen_socket_fd);
        return;
    }
    manager_logger.log(LogLevel::INFO, "Manager: Listening for connections on port " + std::to_string(manager_port) + "...");

    while (running) {
        int client_socket_fd = accept(listen_socket_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_socket_fd < 0) {
            if (!running) { // If manager is stopping, accept can fail. This is expected.
                break;
            }
            manager_logger.log(LogLevel::ERROR, "Manager: Listener accept error. Error: " + std::string(strerror(errno)));
            continue;
        }
        // Spawn a new thread to handle each client connection
        // The thread detaches, meaning it runs independently.
        std::thread(&ClusterManager::handle_client_connection, this, client_socket_fd).detach();
    }
    // Clean up listener socket when loop exits (manager is stopping)
    if (listen_socket_fd != -1) {
        close(listen_socket_fd);
        listen_socket_fd = -1; // Mark as closed
    }
}

// NEW: Handles persistent connections for nodes
void ClusterManager::handle_node_connection_loop(int node_socket_fd, const std::string& node_id) {
    manager_logger.log(LogLevel::INFO, "Manager: Handling persistent connection for node " + node_id + " (socket: " + std::to_string(node_socket_fd) + ")");

    // Add this socket to active_node_sockets
    {
        std::lock_guard<std::mutex> lock(active_node_sockets_mutex);
        active_node_sockets[node_id] = node_socket_fd;
    }

    // Continuously receive messages from this node
    while (running) {
        Message received_msg = receive_message(node_socket_fd);

        if (received_msg.payload == "PEER_CLOSED" ||
            (received_msg.type == MessageType::SHUTDOWN && (received_msg.payload == "ERROR_READING_LENGTH" || received_msg.payload == "ERROR_READING_PAYLOAD")))
        {
            // Connection closed by peer or error on socket
            manager_logger.log(LogLevel::WARNING, "Manager: Node " + node_id + " disconnected (socket error/peer closed). Marking as DOWN.");
            handle_node_failure(node_id); // Treat as a node failure
            break; // Exit the loop for this connection
        }
        // If the manager is shutting down, stop processing
        if (!running) {
            manager_logger.log(LogLevel::INFO, "Manager: Shutting down, closing node " + node_id + " persistent connection.");
            break;
        }

        process_message(received_msg, node_socket_fd); // Process the message (e.g., heartbeat)

        // Add a small sleep to avoid busy-waiting and reduce CPU usage if messages are infrequent
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Clean up when loop exits
    {
        std::lock_guard<std::mutex> lock(active_node_sockets_mutex);
        // Only erase if this specific socket_fd is still associated with the node_id
        // This avoids issues if a node reconnects and gets a new socket before the old handler closes.
        if (active_node_sockets.count(node_id) && active_node_sockets.at(node_id) == node_socket_fd) {
            active_node_sockets.erase(node_id);
        }
    }
    close(node_socket_fd); // Close the socket associated with this connection
    manager_logger.log(LogLevel::INFO, "Manager: Closed persistent connection for node " + node_id);
}


// MODIFIED: Differentiates between client and node connections
void ClusterManager::handle_client_connection(int client_socket_fd) {
    Message received_msg = receive_message(client_socket_fd);

    if (received_msg.payload == "PEER_CLOSED" || received_msg.type == MessageType::SHUTDOWN) {
        manager_logger.log(LogLevel::DEBUG, "Manager: Received shutdown/closed connection from socket " + std::to_string(client_socket_fd) + ". Payload: " + received_msg.payload);
        close(client_socket_fd);
        return;
    }

    // Differentiate between node registration and other client messages
    if (received_msg.type == MessageType::NODE_REGISTER) {
        std::string node_id = received_msg.sender_id;
        // Process the registration. We explicitly pass the socket_fd
        process_message(received_msg, client_socket_fd); // This updates registered_nodes map

        // This client_socket_fd is now a persistent connection for a node.
        // Hand it off to a long-lived thread that will continuously listen.
        // The node_id is crucial for associating the socket with the correct node later.
        std::thread(&ClusterManager::handle_node_connection_loop, this, client_socket_fd, node_id).detach();
        manager_logger.log(LogLevel::INFO, "Manager: Handed off node " + node_id + " connection (socket: " + std::to_string(client_socket_fd) + ") to persistent handler.");
        // DO NOT close client_socket_fd here; it's now managed by handle_node_connection_loop
    } else {
        // For other message types (e.g., TASK_SUBMIT from a simple client),
        // process them and then close the socket.
        process_message(received_msg, client_socket_fd);
        close(client_socket_fd); // Close socket for one-off client requests
        manager_logger.log(LogLevel::DEBUG, "Manager: Closed one-off client connection (socket: " + std::to_string(client_socket_fd) + ")");
    }
}


void ClusterManager::process_message(const Message& msg, int sender_socket_fd) {
    switch (msg.type) {
        case MessageType::NODE_REGISTER: {
            // Payload: "port,max_cpu,max_memory"
            std::vector<std::string> parts = Utils::split_string(msg.payload, ',');
            if (parts.size() == 3) {
                std::lock_guard<std::mutex> lock(nodes_mutex);
                NodeInfo node;
                node.id = msg.sender_id;
                node.ip_address = "127.0.0.1"; // Assuming localhost for demo, can be improved
                node.port = std::stoi(parts[0]);
                node.max_cpu_capacity = std::stoi(parts[1]);
                node.max_memory_capacity_mb = std::stoi(parts[2]);
                node.status = NodeStatus::UP;
                node.last_heartbeat = std::chrono::system_clock::now();
                registered_nodes[node.id] = node;
                manager_logger.log(LogLevel::INFO, "Node " + node.id + " registered (Port: " + std::to_string(node.port) + ").");
            } else {
                manager_logger.log(LogLevel::WARNING, "Manager: Malformed NODE_REGISTER payload from " + msg.sender_id);
            }
            break;
        }
        case MessageType::NODE_HEARTBEAT: {
            NodeHeartbeatPayload hb_payload = NodeHeartbeatPayload::deserialize(msg.payload);
            std::lock_guard<std::mutex> lock(nodes_mutex);
            if (registered_nodes.count(hb_payload.node_id)) {
                registered_nodes[hb_payload.node_id].current_cpu_usage = hb_payload.cpu_usage_percent;
                registered_nodes[hb_payload.node_id].current_memory_usage = hb_payload.memory_usage_mb;
                registered_nodes[hb_payload.node_id].last_heartbeat = std::chrono::system_clock::now();
                registered_nodes[hb_payload.node_id].status = NodeStatus::UP; // Mark as UP if heartbeat received
                // Update assigned tasks count for the node
                registered_nodes[hb_payload.node_id].assigned_tasks.clear(); // Rebuild from actual running tasks
                std::lock_guard<std::mutex> tasks_lock(tasks_mutex); // Lock tasks_mutex to read all_tasks
                for (const auto& pair : all_tasks) {
                    if (pair.second.status == TaskStatus::RUNNING && pair.second.assigned_node_id == hb_payload.node_id) {
                        registered_nodes[hb_payload.node_id].assigned_tasks.insert(pair.first);
                    }
                }

                manager_logger.log(LogLevel::DEBUG, "Heartbeat from " + hb_payload.node_id +
                                                    " CPU: " + std::to_string(hb_payload.cpu_usage_percent) + "%" +
                                                    ", Mem: " + std::to_string(hb_payload.memory_usage_mb) + "MB");
            } else {
                manager_logger.log(LogLevel::WARNING, "Manager: Heartbeat from unknown node: " + hb_payload.node_id);
                // A disconnected node might send heartbeats upon restart before re-registering.
                // Or, if a persistent connection failed and the node re-established, but manager hasn't updated.
                // No action needed here, `handle_node_failure` will eventually mark it DOWN.
            }
            break;
        }
        case MessageType::TASK_SUBMIT: {
            TaskSubmitPayload submit_payload = TaskSubmitPayload::deserialize(msg.payload);
            std::lock_guard<std::mutex> lock(tasks_mutex);
            if (all_tasks.count(submit_payload.task_id)) {
                manager_logger.log(LogLevel::WARNING, "Manager: Task " + submit_payload.task_id + " already submitted.");
                return;
            }
            TaskInfo new_task;
            new_task.id = submit_payload.task_id;
            new_task.name = submit_payload.task_name;
            new_task.required_cpu = submit_payload.required_cpu;
            new_task.required_memory = submit_payload.required_memory;
            new_task.duration_seconds = submit_payload.duration_seconds;
            new_task.status = TaskStatus::PENDING;
            new_task.submission_time = std::chrono::system_clock::now();
            all_tasks[new_task.id] = new_task;
            pending_tasks.push(new_task.id);
            manager_logger.log(LogLevel::INFO, "Task " + new_task.id + " (" + new_task.name + ") submitted. Pending for scheduling.");
            break;
        }
        case MessageType::TASK_STATUS_UPDATE: {
            TaskStatusUpdatePayload status_payload = TaskStatusUpdatePayload::deserialize(msg.payload);
            std::lock_guard<std::mutex> lock(tasks_mutex);
            if (all_tasks.count(status_payload.task_id)) {
                all_tasks[status_payload.task_id].status = status_payload.status;
                manager_logger.log(LogLevel::INFO, "Task " + status_payload.task_id + " on " + status_payload.node_id +
                                                    " updated status to " + std::to_string(static_cast<int>(status_payload.status)));

                // Update node's assigned tasks if task completed/failed
                if (status_payload.status == TaskStatus::COMPLETED || status_payload.status == TaskStatus::FAILED) {
                    std::lock_guard<std::mutex> nodes_lock(nodes_mutex);
                    if (registered_nodes.count(status_payload.node_id)) {
                        registered_nodes.at(status_payload.node_id).assigned_tasks.erase(status_payload.task_id);
                    }
                    manager_logger.log(LogLevel::INFO, "Task " + status_payload.task_id + " removed from node " + status_payload.node_id + "'s active tasks.");
                }

            } else {
                manager_logger.log(LogLevel::WARNING, "Manager: Status update for unknown task: " + status_payload.task_id);
            }
            break;
        }
        case MessageType::SHUTDOWN: {
            manager_logger.log(LogLevel::INFO, "Manager: Received shutdown signal from " + msg.sender_id + ". Payload: " + msg.payload);
            // If a node explicitly sends shutdown, mark it as DOWN
            std::lock_guard<std::mutex> lock(nodes_mutex);
            if (registered_nodes.count(msg.sender_id)) {
                manager_logger.log(LogLevel::WARNING, "Node " + msg.sender_id + " explicitly shut down. Marking as DOWN.");
                registered_nodes[msg.sender_id].status = NodeStatus::DOWN;
                // Trigger failover for tasks on this node
                handle_node_failure(msg.sender_id);
            }
            break;
        }
        default:
            manager_logger.log(LogLevel::WARNING, "Manager: Received unhandled message type: " + std::to_string(static_cast<int>(msg.type)));
            break;
    }
}

// Scheduling, Load Balancing:
// MODIFIED: Uses persistent connections (active_node_sockets)
void ClusterManager::run_scheduler() {
    while (running) {
        std::string task_id_to_assign;
        {
            std::lock_guard<std::mutex> lock(tasks_mutex);
            if (!pending_tasks.empty()) {
                task_id_to_assign = pending_tasks.front();
                pending_tasks.pop();
            }
        }

        if (!task_id_to_assign.empty()) {
            std::lock_guard<std::mutex> tasks_lock(tasks_mutex); // Lock again to access all_tasks
            if (all_tasks.count(task_id_to_assign)) {
                TaskInfo& task = all_tasks.at(task_id_to_assign);
                if (task.status == TaskStatus::PENDING) {
                    std::string best_node_id = find_best_node(task);
                    if (!best_node_id.empty()) {
                        int node_sock_fd = -1;
                        {
                            std::lock_guard<std::mutex> nodes_lock(active_node_sockets_mutex); // Lock active sockets map
                            if (active_node_sockets.count(best_node_id)) {
                                node_sock_fd = active_node_sockets.at(best_node_id); // Get the persistent socket
                            }
                        }

                        if (node_sock_fd != -1) {
                            TaskAssignmentPayload assign_payload = {
                                task.id, task.name, task.required_cpu, task.required_memory,
                                task.duration_seconds, best_node_id
                            };
                            Message assign_msg;
                            assign_msg.type = MessageType::TASK_ASSIGN;
                            assign_msg.sender_id = "manager";
                            assign_msg.payload = assign_payload.serialize();

                            // Use the persistent socket
                            send_message(node_sock_fd, assign_msg);

                            // Assuming success for now. Node will send status update.
                            task.status = TaskStatus::RUNNING;
                            task.assigned_node_id = best_node_id;
                            {
                                std::lock_guard<std::mutex> nodes_lock(nodes_mutex);
                                if (registered_nodes.count(best_node_id)) {
                                    registered_nodes.at(best_node_id).assigned_tasks.insert(task.id);
                                }
                            }
                            manager_logger.log(LogLevel::INFO, "Task " + task.id + " assigned to node " + best_node_id);
                        } else {
                            manager_logger.log(LogLevel::WARNING, "Manager: Persistent socket for node " + best_node_id + " not found or not active. Re-queuing task " + task.id + ".");
                            pending_tasks.push(task.id); // Re-queue if persistent socket is not available
                        }
                    } else {
                        manager_logger.log(LogLevel::WARNING, "Manager: No suitable node found for task " + task.id + ". Re-queuing.");
                        pending_tasks.push(task.id); // Re-queue if no node found
                    }
                }
            } else {
                manager_logger.log(LogLevel::WARNING, "Manager: Task " + task_id_to_assign + " not found in all_tasks map (should not happen for pending tasks).");
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1)); // Run scheduler every second
    }
}

std::string ClusterManager::find_best_node(const TaskInfo& task) {
    std::string best_node_id = "";
    double min_load_score = -1.0;

    std::lock_guard<std::mutex> lock(nodes_mutex);
    for (const auto& pair : registered_nodes) {
        const NodeInfo& node = pair.second;
        if (node.status != NodeStatus::UP) {
            continue; // Only consider active nodes
        }

        // Check if node has enough resources for the task
        if ((node.current_cpu_usage + task.required_cpu) > node.max_cpu_capacity ||
            (node.current_memory_usage + task.required_memory) > node.max_memory_capacity_mb) {
            manager_logger.log(LogLevel::DEBUG, "Node " + node.id + " cannot handle task " + task.id + ": Insufficient resources.");
            continue;
        }

        // Simple load balancing heuristic: prioritize nodes with lower current resource usage
        double current_cpu_load = static_cast<double>(node.current_cpu_usage) / node.max_cpu_capacity;
        double current_memory_load = static_cast<double>(node.current_memory_usage) / node.max_memory_capacity_mb;
        double load_score = (current_cpu_load + current_memory_load) / 2.0; // Average load

        if (best_node_id.empty() || load_score < min_load_score) {
            min_load_score = load_score;
            best_node_id = node.id;
        }
    }
    return best_node_id;
}

//Health Monitoring, Failover and Recovery:
void ClusterManager::run_health_monitor() {
    while (running) {
        std::vector<std::string> nodes_to_mark_down;
        {
            std::lock_guard<std::mutex> lock(nodes_mutex);
            for (auto& pair : registered_nodes) {
                NodeInfo& node = pair.second;
                auto now = std::chrono::system_clock::now();
                auto elapsed_seconds = std::chrono::duration_cast<std::chrono::seconds>(now - node.last_heartbeat).count();

                // If no heartbeat for 5 seconds, mark node as DOWN
                if (elapsed_seconds > NODE_HEARTBEAT_TIMEOUT_SEC && node.status == NodeStatus::UP) {
                    manager_logger.log(LogLevel::ERROR, "Node " + node.id + " unresponsive for " + std::to_string(elapsed_seconds) + " seconds. Marking as DOWN.");
                    node.status = NodeStatus::DOWN;
                    nodes_to_mark_down.push_back(node.id);
                }
            }
        }

        // Handle failed nodes outside the mutex to avoid deadlock with task mutex
        for (const std::string& node_id : nodes_to_mark_down) {
            handle_node_failure(node_id);
        }

        std::this_thread::sleep_for(std::chrono::seconds(1)); // Check health every second
    }
}

void ClusterManager::handle_node_failure(const std::string& node_id) {
    manager_logger.log(LogLevel::WARNING, "Initiating failover for tasks on failed node: " + node_id);
    std::vector<std::string> tasks_to_requeue;
    {
        std::lock_guard<std::mutex> tasks_lock(tasks_mutex);
        for (auto& pair : all_tasks) {
            TaskInfo& task = pair.second;
            if (task.assigned_node_id == node_id && task.status == TaskStatus::RUNNING) {
                manager_logger.log(LogLevel::INFO, "Re-queuing task " + task.id + " from failed node " + node_id);
                task.status = TaskStatus::PENDING; // Mark as pending
                task.assigned_node_id = ""; // Clear assigned node
                pending_tasks.push(task.id); // Add back to pending queue
                tasks_to_requeue.push_back(task.id);
            }
        }
    }

    // NEW: Remove socket from active connections upon failure
    {
        std::lock_guard<std::mutex> lock(active_node_sockets_mutex);
        if (active_node_sockets.count(node_id)) {
            close(active_node_sockets.at(node_id)); // Close the socket
            active_node_sockets.erase(node_id);
            manager_logger.log(LogLevel::INFO, "Closed and removed active socket for failed node " + node_id + ".");
        }
    }


    if (tasks_to_requeue.empty()) {
        manager_logger.log(LogLevel::INFO, "No running tasks to re-queue from failed node " + node_id);
    }
}

void ClusterManager::start() {
    //Multi-threading:
    listener_thread = std::thread(&ClusterManager::start_listener, this);
    scheduler_thread = std::thread(&ClusterManager::run_scheduler, this);
    health_monitor_thread = std::thread(&ClusterManager::run_health_monitor, this);

    manager_logger.log(LogLevel::INFO, "Cluster Manager running. Press Ctrl+C to stop.");
}

void ClusterManager::stop() {
    running = false;
    manager_logger.log(LogLevel::INFO, "Manager: Shutting down...");

    // To unblock accept() call in listener_thread, connect to its own port
    // This allows the listener_thread's accept() call to return, then it checks 'running' and exits.
    int dummy_sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(manager_port);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);
    connect(dummy_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    close(dummy_sock);

    // Join all primary threads to ensure they finish cleanly
    if (listener_thread.joinable()) {
        listener_thread.join();
    }
    if (scheduler_thread.joinable()) {
        scheduler_thread.join();
    }
    if (health_monitor_thread.joinable()) {
        health_monitor_thread.join();
    }

    // NEW: Close all active node sockets gracefully
    {
        std::lock_guard<std::mutex> lock(active_node_sockets_mutex);
        for (auto const& [node_id, socket_fd] : active_node_sockets) {
            manager_logger.log(LogLevel::INFO, "Closing active socket for node " + node_id + " (socket: " + std::to_string(socket_fd) + ").");
            close(socket_fd);
        }
        active_node_sockets.clear();
    }

    // listener_socket_fd is closed in start_listener upon exit
    if (listen_socket_fd != -1) {
        close(listen_socket_fd); // Double check just in case, though it should be handled
        listen_socket_fd = -1;
    }
}

void ClusterManager::submit_task(const TaskSubmitPayload& payload) {
    Message msg;
    msg.type = MessageType::TASK_SUBMIT;
    msg.sender_id = "client"; // For internal use or if a local client uses this directly
    msg.payload = payload.serialize();
    process_message(msg, -1); // Process directly as if received from client, -1 indicates no specific sender socket
}