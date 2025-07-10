#include "ClusterManager.h"
#include <iostream>
#include <signal.h> // For signal handling

ClusterManager* global_manager = nullptr;

void signal_handler(int signum) {
    std::cout << "Caught signal " << signum << ". Shutting down manager..." << std::endl;
    if (global_manager) {
        global_manager->stop();
    }
    exit(signum);
}

int main() {
    global_manager = new ClusterManager(MANAGER_PORT);

    // Register signal handler for graceful shutdown (Ctrl+C)
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    global_manager->start();

    std::cout << "Cluster Manager running. Press Ctrl+C to stop." << std::endl;

    // Keep main thread alive until shutdown
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    delete global_manager; // Will be called by signal handler in practice
    return 0;
}