#include "Client.h"
#include <iostream>
#include <random>
#include <chrono>
#include <thread>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <manager_ip> <manager_port> [num_tasks_to_submit]" << std::endl;
        return 1;
    }

    std::string manager_ip = argv[1];
    int manager_port = std::stoi(argv[2]);
    int num_tasks_to_submit = 5; // Default

    if (argc >= 4) {
        num_tasks_to_submit = std::stoi(argv[3]);
    }

    Client client(manager_ip, manager_port);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> cpu_dist(10, 50); // 10-50% CPU
    std::uniform_int_distribution<> mem_dist(50, 500); // 50-500 MB
    std::uniform_int_distribution<> duration_dist(5, 20); // 5-20 seconds

    std::cout << "Client: Submitting " << num_tasks_to_submit << " tasks..." << std::endl;

    for (int i = 0; i < num_tasks_to_submit; ++i) {
        TaskSubmitPayload task_payload;
        task_payload.task_id = "task-" + Utils::generate_uuid().substr(0, 8);
        task_payload.task_name = "Workload_" + std::to_string(i + 1);
        task_payload.required_cpu = cpu_dist(gen);
        task_payload.required_memory = mem_dist(gen);
        task_payload.duration_seconds = duration_dist(gen);

        client.submit_task(task_payload);
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Small delay between submissions
    }

    std::cout << "Client: All tasks submitted. Exiting." << std::endl;

    return 0;
}