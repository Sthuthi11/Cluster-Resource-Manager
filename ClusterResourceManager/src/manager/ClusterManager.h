#ifndef CLUSTER_MANAGER_H
#define CLUSTER_MANAGER_H

#include "../common/Constants.h"
#include "../common/MessageTypes.h"
#include "../common/Utils.h"
#include "Logger.h"

#include <string>
#include <vector>
#include <map>
#include <queue>
#include <mutex>
#include <thread>
#include <chrono>
#include <set> // For assigned_tasks in NodeInfo

// Forward declarations to avoid circular includes if Message.h had NodeInfo
// (though it typically wouldn't, it's good practice for complex dependencies)
struct NodeHeartbeatPayload; // Defined in MessageTypes.h (included via Constants.h)
struct TaskSubmitPayload;     // Defined in MessageTypes.h (included via Constants.h)
struct TaskStatusUpdatePayload; // Defined in MessageTypes.h (included via Constants.h)


struct NodeInfo {
    std::string id;
    std::string ip_address;
    int port; // Port where the node agent listens for tasks
    int max_cpu_capacity;
    int max_memory_capacity_mb;
    int current_cpu_usage;
    int current_memory_usage;
    NodeStatus status;
    std::chrono::time_point<std::chrono::system_clock> last_heartbeat;
    std::set<std::string> assigned_tasks; // Tasks currently assigned to this node

    NodeInfo() : id(""), ip_address(""), port(0), max_cpu_capacity(0), max_memory_capacity_mb(0),
                 current_cpu_usage(0), current_memory_usage(0), status(NodeStatus::DOWN) {}
};

struct TaskInfo {
    std::string id;
    std::string name;
    int required_cpu;
    int required_memory;
    int duration_seconds;
    TaskStatus status;
    std::string assigned_node_id;
    std::chrono::time_point<std::chrono::system_clock> submission_time;

    TaskInfo() : id(""), name(""), required_cpu(0), required_memory(0),
                 duration_seconds(0), status(TaskStatus::PENDING), assigned_node_id("") {}
};

class ClusterManager {
public:
    ClusterManager(int port);
    ~ClusterManager();

    void start();
    void stop();

    // For clients to submit tasks directly if integrated (e.g., via REST API later)
    void submit_task(const TaskSubmitPayload& payload);

private:
    int manager_port;
    bool running;
    Logger manager_logger;

    int listen_socket_fd; // Socket for listening for incoming connections (clients, nodes)

    // Threads for concurrent operations
    std::thread listener_thread;
    std::thread scheduler_thread;
    std::thread health_monitor_thread;

    // Data structures for cluster state
    std::map<std::string, NodeInfo> registered_nodes;
    std::queue<std::string> pending_tasks; // Queue of task IDs
    std::map<std::string, TaskInfo> all_tasks; // Map from task ID to TaskInfo

    // Mutexes for thread-safe access to shared data
    std::mutex nodes_mutex;
    std::mutex tasks_mutex;

    // NEW: Map to hold active sockets for persistent node connections
    std::map<std::string, int> active_node_sockets;
    std::mutex active_node_sockets_mutex; // Mutex for active_node_sockets

    // Core functionality methods
    void start_listener();
    void handle_client_connection(int client_socket_fd);
    void handle_node_connection_loop(int node_socket_fd, const std::string& node_id); // NEW: For persistent node connections
    void process_message(const Message& msg, int sender_socket_fd);
    void run_scheduler();
    void run_health_monitor();
    void handle_node_failure(const std::string& node_id);

    // Helper methods for communication
    void send_message(int socket_fd, const Message& msg);
    Message receive_message(int socket_fd);

    // Scheduling heuristic
    std::string find_best_node(const TaskInfo& task);
};

#endif // CLUSTER_MANAGER_H