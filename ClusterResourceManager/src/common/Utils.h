#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <random>
#include <algorithm>
#include <chrono>
#include "Constants.h"

namespace Utils {

    // Generate a unique ID (For demo)
    std::string generate_uuid();

    // Get current timestamp as string
    std::string get_current_timestamp();

    // Basic string splitting utility
    std::vector<std::string> split_string(const std::string& s, char delimiter);

    // Get current CPU usage (simplified, for demo)
    // In a real system, you'd parse /proc/stat
    int get_current_cpu_usage_simulated();

    // Get current memory usage (simplified, for demo)
    int get_current_memory_usage_simulated();
}

#endif // UTILS_H