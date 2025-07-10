#ifndef CONSTANTS_H
#define CONSTANTS_H
#define NODE_HEARTBEAT_TIMEOUT_SEC 5

#include <string>

// Communication ports
const int MANAGER_PORT = 8080;
const int NODE_AGENT_PORT_BASE = 9000; // Each node will use a unique port from here

// Message types
enum class MessageType {
    NODE_REGISTER,
    NODE_HEARTBEAT,
    TASK_SUBMIT,
    TASK_ASSIGN,
    TASK_STATUS_UPDATE,
    NODE_STATUS_REQUEST,
    NODE_STATUS_RESPONSE,
    SHUTDOWN,
    UNKNOWN
};

// Node and Task Status
enum class NodeStatus {
    UP,
    DOWN,
    OVERLOADED
};

enum class TaskStatus {
    PENDING,
    RUNNING,
    COMPLETED,
    FAILED
};

// Simulated resource limits
const int MAX_CPU_USAGE = 100; // Percentage
const int MAX_MEMORY_USAGE_MB = 1024; // MB

#endif // CONSTANTS_H