#ifndef NODEAGENT_H
#define NODEAGENT_H

#include <string>
#include <thread>
#include <vector>
#include <atomic>
#include <map>
#include <mutex>
#include <condition_variable>
#include <functional>

#include "../common/Constants.h"
#include "../common/MessageTypes.h"
#include "../common/Utils.h"
#include "../manager/Logger.h" // Using the shared logger

//Processes, Multi-threading, IPC:

class Task {
public:
    std::string id;
    std::string name;
    int required_cpu;
    int required_memory;
    int duration_seconds;
    TaskStatus status;
    std::thread execution_thread; // For simulating task execution

    Task(const TaskAssignmentPayload& payload)
        : id(payload.task_id), name(payload.task_name),
          required_cpu(payload.required_cpu), required_memory(payload.required_memory),
          duration_seconds(payload.duration_seconds), status(TaskStatus::PENDING) {}

    // No copy constructor/assignment for Task due to std::thread member
    Task(Task&& other) noexcept
        : id(std::move(other.id)),
          name(std::move(other.name)),
          required_cpu(other.required_cpu),
          required_memory(other.required_memory),
          duration_seconds(other.duration_seconds),
          status(other.status),
          execution_thread(std::move(other.execution_thread)) {}

    Task& operator=(Task&& other) noexcept {
        if (this != &other) {
            id = std::move(other.id);
            name = std::move(other.name);
            required_cpu = other.required_cpu;
            required_memory = other.required_memory;
            duration_seconds = other.duration_seconds;
            status = other.status;
            if (execution_thread.joinable()) {
                execution_thread.join(); // Ensure existing thread finishes if moving over
            }
            execution_thread = std::move(other.execution_thread);
        }
        return *this;
    }
};

class NodeAgent {
private:
    std::string node_id;
    std::string manager_ip;
    int manager_port;
    int node_port;
    int listen_socket_fd;
    std::atomic<NodeStatus> current_status;
    std::atomic<int> current_cpu_usage; // Simulated
    std::atomic<int> current_memory_usage; // Simulated
    std::atomic<bool> running;

    std::map<std::string, Task> running_tasks; // Map of task_id to Task object
    std::mutex tasks_mutex; // Protects running_tasks

    std::thread heartbeat_thread;
    std::thread listener_thread;

    Logger node_logger;

    //Socket Programming:
    int connect_to_manager();
    void send_message(int socket_fd, const Message& msg);
    Message receive_message(int socket_fd);

    //Multi-threading, Health Monitoring:
    void send_heartbeats();

    //Socket Programming, Multi-threading:
    void start_listener();
    void handle_client_connection(int client_socket_fd);

    //Processes, Scheduling, Memory Management:
    void execute_task(TaskAssignmentPayload task_payload);
    void update_task_status(const std::string& task_id, TaskStatus status, const std::string& node_id);
    void simulate_resource_usage(int cpu_increase, int memory_increase, int duration_seconds);


public:
    NodeAgent(const std::string& id, const std::string& manager_ip, int manager_port, int node_port);
    ~NodeAgent();

    void start();
    void stop();
};

#endif // NODEAGENT_H