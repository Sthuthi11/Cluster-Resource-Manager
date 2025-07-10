#include "Logger.h"

Logger::Logger(const std::string& filename, LogLevel level)
    : currentLogLevel(level) {
    logFile.open(filename, std::ios::app);
    if (!logFile.is_open()) {
        std::cerr << "Error: Could not open log file: " << filename << std::endl;
    }
}

Logger::~Logger() {
    if (logFile.is_open()) {
        logFile.close();
    }
}

void Logger::log(LogLevel level, const std::string& message) {
    if (level < currentLogLevel) {
        return; // Filter messages below current log level
    }

    std::lock_guard<std::mutex> lock(logMutex);
    std::string timestamp = Utils::get_current_timestamp();
    std::string levelStr = logLevelToString(level);

    std::string logEntry = "[" + timestamp + "] [" + levelStr + "] " + message + "\n";

    if (logFile.is_open()) {
        logFile << logEntry;
        logFile.flush(); // Ensure immediate write
    } else {
        std::cerr << "Logger Error: Log file not open. Message: " << logEntry;
    }

    // Also print to console for immediate feedback (optional)
    std::cout << logEntry;
}

void Logger::setLogLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(logMutex);
    currentLogLevel = level;
    log(LogLevel::INFO, "Log level set to " + logLevelToString(level));
}