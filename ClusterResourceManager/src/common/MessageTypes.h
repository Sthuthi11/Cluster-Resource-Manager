#ifndef MESSAGETYPES_H
#define MESSAGETYPES_H

#include <string>
#include <vector>
#include <map>
#include "Constants.h"

// Basic message structure
struct Message {
    MessageType type;
    std::string sender_id;
    std::string payload; // JSON string or custom delimited string for complex data

    // Serialization (to string for sending over socket)
    std::string serialize() const {
        return std::to_string(static_cast<int>(type)) + "|" + sender_id + "|" + payload;
    }

    // Deserialization (from string received from socket)
    static Message deserialize(const std::string& data) {
        Message msg;
        size_t first_pipe = data.find('|');
        size_t second_pipe = data.find('|', first_pipe + 1);

        if (first_pipe == std::string::npos || second_pipe == std::string::npos) {
            // Handle error: Malformed message
            msg.type = MessageType::SHUTDOWN; // Or some error type
            msg.sender_id = "UNKNOWN";
            msg.payload = "MALFORMED_MESSAGE";
            return msg;
        }

        msg.type = static_cast<MessageType>(std::stoi(data.substr(0, first_pipe)));
        msg.sender_id = data.substr(first_pipe + 1, second_pipe - (first_pipe + 1));
        msg.payload = data.substr(second_pipe + 1);
        return msg;
    }
};

// Specific message payloads (structs to be serialized to JSON or similar)
// Used string payloads and parsed them

// Example: Node Heartbeat Payload
// Format: "node_id,cpu_usage,memory_usage,num_tasks"
struct NodeHeartbeatPayload {
    std::string node_id;
    int cpu_usage_percent;
    int memory_usage_mb;
    int num_running_tasks;

    std::string serialize() const {
        return node_id + "," + std::to_string(cpu_usage_percent) + "," +
               std::to_string(memory_usage_mb) + "," + std::to_string(num_running_tasks);
    }

    static NodeHeartbeatPayload deserialize(const std::string& s) {
        NodeHeartbeatPayload payload;
        size_t pos1 = s.find(',');
        size_t pos2 = s.find(',', pos1 + 1);
        size_t pos3 = s.find(',', pos2 + 1);

        if (pos1 == std::string::npos || pos2 == std::string::npos || pos3 == std::string::npos) {
             // Handle error
            payload.node_id = "ERROR";
            return payload;
        }

        payload.node_id = s.substr(0, pos1);
        payload.cpu_usage_percent = std::stoi(s.substr(pos1 + 1, pos2 - (pos1 + 1)));
        payload.memory_usage_mb = std::stoi(s.substr(pos2 + 1, pos3 - (pos2 + 1)));
        payload.num_running_tasks = std::stoi(s.substr(pos3 + 1));
        return payload;
    }
};

// Example: Task Submission Payload
// Format: "task_id,task_name,required_cpu,required_memory,duration_seconds"
struct TaskSubmitPayload {
    std::string task_id;
    std::string task_name;
    int required_cpu; // Percentage
    int required_memory; // MB
    int duration_seconds; // Simulated duration

    std::string serialize() const {
        return task_id + "," + task_name + "," + std::to_string(required_cpu) + "," +
               std::to_string(required_memory) + "," + std::to_string(duration_seconds);
    }

    static TaskSubmitPayload deserialize(const std::string& s) {
        TaskSubmitPayload payload;
        size_t p1 = s.find(',');
        size_t p2 = s.find(',', p1 + 1);
        size_t p3 = s.find(',', p2 + 1);
        size_t p4 = s.find(',', p3 + 1);

        if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos || p4 == std::string::npos) {
            payload.task_id = "ERROR";
            return payload;
        }

        payload.task_id = s.substr(0, p1);
        payload.task_name = s.substr(p1 + 1, p2 - (p1 + 1));
        payload.required_cpu = std::stoi(s.substr(p2 + 1, p3 - (p2 + 1)));
        payload.required_memory = std::stoi(s.substr(p3 + 1, p4 - (p3 + 1)));
        payload.duration_seconds = std::stoi(s.substr(p4 + 1));
        return payload;
    }
};

// Example: Task Assignment Payload
// Format: "task_id,task_name,required_cpu,required_memory,duration_seconds,node_id"
struct TaskAssignmentPayload {
    std::string task_id;
    std::string task_name;
    int required_cpu;
    int required_memory;
    int duration_seconds;
    std::string node_id;

    std::string serialize() const {
        return task_id + "," + task_name + "," + std::to_string(required_cpu) + "," +
               std::to_string(required_memory) + "," + std::to_string(duration_seconds) + "," +
               node_id;
    }

    static TaskAssignmentPayload deserialize(const std::string& s) {
        TaskAssignmentPayload payload;
        size_t p1 = s.find(',');
        size_t p2 = s.find(',', p1 + 1);
        size_t p3 = s.find(',', p2 + 1);
        size_t p4 = s.find(',', p3 + 1);
        size_t p5 = s.find(',', p4 + 1);

        if (p1 == std::string::npos || p2 == std::string::npos || p3 == std::string::npos ||
            p4 == std::string::npos || p5 == std::string::npos) {
            payload.task_id = "ERROR";
            return payload;
        }

        payload.task_id = s.substr(0, p1);
        payload.task_name = s.substr(p1 + 1, p2 - (p1 + 1));
        payload.required_cpu = std::stoi(s.substr(p2 + 1, p3 - (p2 + 1)));
        payload.required_memory = std::stoi(s.substr(p3 + 1, p4 - (p3 + 1)));
        payload.duration_seconds = std::stoi(s.substr(p4 + 1, p5 - (p4 + 1)));
        payload.node_id = s.substr(p5 + 1);
        return payload;
    }
};


// Example: Task Status Update Payload
// Format: "task_id,status,node_id"
struct TaskStatusUpdatePayload {
    std::string task_id;
    TaskStatus status;
    std::string node_id;

    std::string serialize() const {
        return task_id + "," + std::to_string(static_cast<int>(status)) + "," + node_id;
    }

    static TaskStatusUpdatePayload deserialize(const std::string& s) {
        TaskStatusUpdatePayload payload;
        size_t pos1 = s.find(',');
        size_t pos2 = s.find(',', pos1 + 1);

        if (pos1 == std::string::npos || pos2 == std::string::npos) {
            payload.task_id = "ERROR";
            return payload;
        }

        payload.task_id = s.substr(0, pos1);
        payload.status = static_cast<TaskStatus>(std::stoi(s.substr(pos1 + 1, pos2 - (pos1 + 1))));
        payload.node_id = s.substr(pos2 + 1);
        return payload;
    }
};

#endif // MESSAGETYPES_H