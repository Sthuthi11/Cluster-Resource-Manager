#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <mutex>
#include <iostream>
#include "../common/Utils.h" // For get_current_timestamp

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

class Logger {
private:
    std::ofstream logFile;
    std::mutex logMutex;
    LogLevel currentLogLevel;

    std::string logLevelToString(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG:    return "DEBUG";
            case LogLevel::INFO:     return "INFO";
            case LogLevel::WARNING:  return "WARNING";
            case LogLevel::ERROR:    return "ERROR";
            case LogLevel::CRITICAL: return "CRITICAL";
            default:                 return "UNKNOWN";
        }
    }

public:
    Logger(const std::string& filename, LogLevel level = LogLevel::INFO);
    ~Logger();

    void log(LogLevel level, const std::string& message);
    void setLogLevel(LogLevel level);
};

#endif // LOGGER_H