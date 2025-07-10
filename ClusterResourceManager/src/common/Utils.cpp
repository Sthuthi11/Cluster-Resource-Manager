#include "Utils.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <random>
#include <chrono>
#include <fstream>
#include <thread> // For std::this_thread::sleep_for

namespace Utils {

    std::string generate_uuid() {
        static std::random_device rd;
        static std::mt19937 gen(rd());
        static std::uniform_int_distribution<> distrib(0, 15);
        static std::uniform_int_distribution<> distrib8(8, 11);

        std::stringstream ss;
        for (int i = 0; i < 8; ++i) ss << std::hex << distrib(gen);
        ss << "-";
        for (int i = 0; i < 4; ++i) ss << std::hex << distrib(gen);
        ss << "-4";
        for (int i = 0; i < 3; ++i) ss << std::hex << distrib(gen);
        ss << "-";
        ss << std::hex << distrib8(gen);
        for (int i = 0; i < 3; ++i) ss << std::hex << distrib(gen);
        ss << "-";
        for (int i = 0; i < 12; ++i) ss << std::hex << distrib(gen);
        return ss.str();
    }

    std::string get_current_timestamp() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }

    std::vector<std::string> split_string(const std::string& s, char delimiter) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream(s);
        while (std::getline(tokenStream, token, delimiter)) {
            tokens.push_back(token);
        }
        return tokens;
    }

    // Memory Management, Virtual Memory:

    int get_current_cpu_usage_simulated() {
        // For simulation:
        static int last_cpu_usage = 10;
        last_cpu_usage += (rand() % 20 - 10); // Fluctuate by +/- 10
        if (last_cpu_usage < 5) last_cpu_usage = 5;
        if (last_cpu_usage > 95) last_cpu_usage = 95;
        return last_cpu_usage;
    }

    int get_current_memory_usage_simulated() {
        // For simulation:
        static int last_mem_usage = 100; // MB
        last_mem_usage += (rand() % 100 - 50); // Fluctuate by +/- 50MB
        if (last_mem_usage < 50) last_mem_usage = 50;
        if (last_mem_usage > (MAX_MEMORY_USAGE_MB - 50)) last_mem_usage = MAX_MEMORY_USAGE_MB - 50;
        return last_mem_usage;
    }

}