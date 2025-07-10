#include "NodeAgent.h"
#include <iostream>
#include <string>
#include <signal.h> // For signal handling

NodeAgent* global_node_agent = nullptr;

void signal_handler(int signum) {
    std::cout << "Caught signal " << signum << ". Shutting down node..." << std::endl;
    if (global_node_agent) {
        global_node_agent->stop();
    }
    exit(signum);
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <node_id> <manager_ip> <manager_port> [node_port]" << std::endl;
        std::cerr << "  node_port is optional, will use a default based on node_id if not provided." << std::endl;
        return 1;
    }

    std::string node_id = argv[1];
    std::string manager_ip = argv[2];
    int manager_port = std::stoi(argv[3]);
    int node_port = NODE_AGENT_PORT_BASE; // Default base port

    if (argc >= 5) {
        node_port = std::stoi(argv[4]);
    } else {
        // Derive node_port from node_id if not provided, for demo purposes
        // Simple hash-like: sum char values and add to base
        int id_sum = 0;
        for (char c : node_id) {
            id_sum += static_cast<int>(c);
        }
        node_port += (id_sum % 100); // Simple way to get different ports
        // Ensure port is not too high and is unique
        // In a real system, you'd use a discovery service or static assignment
    }


    global_node_agent = new NodeAgent(node_id, manager_ip, manager_port, node_port);

    // Register signal handler for graceful shutdown (Ctrl+C)
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    global_node_agent->start();

    // Keep main thread alive until shutdown
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    delete global_node_agent; // Will be called by signal handler in practice
    return 0;
}