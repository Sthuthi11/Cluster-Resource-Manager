CXX = g++
CXXFLAGS = -Wall -std=c++17 -pthread
LDFLAGS = -pthread

BUILD_DIR = build
SRC_DIR = src
LOG_DIR = logs

# Source files for each component
COMMON_SRCS = $(SRC_DIR)/common/Utils.cpp
MANAGER_SRCS = $(SRC_DIR)/manager/main_manager.cpp $(SRC_DIR)/manager/ClusterManager.cpp $(SRC_DIR)/manager/Logger.cpp $(COMMON_SRCS)
NODE_SRCS = $(SRC_DIR)/node/main_node.cpp $(SRC_DIR)/node/NodeAgent.cpp $(COMMON_SRCS) $(SRC_DIR)/manager/Logger.cpp # Node also uses the Logger
CLIENT_SRCS = $(SRC_DIR)/client/main_client.cpp $(SRC_DIR)/client/Client.cpp $(COMMON_SRCS)

# Object files for each component
MANAGER_OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(MANAGER_SRCS))
NODE_OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(NODE_SRCS))
CLIENT_OBJS = $(patsubst $(SRC_DIR)/%.cpp, $(BUILD_DIR)/%.o, $(CLIENT_SRCS))

# Executables
MANAGER_BIN = $(BUILD_DIR)/cluster_manager
NODE_BIN = $(BUILD_DIR)/node_agent
CLIENT_BIN = $(BUILD_DIR)/task_client

all: directories $(MANAGER_BIN) $(NODE_BIN) $(CLIENT_BIN)

directories:
	@mkdir -p $(BUILD_DIR)/common
	@mkdir -p $(BUILD_DIR)/manager
	@mkdir -p $(BUILD_DIR)/node
	@mkdir -p $(BUILD_DIR)/client
	@mkdir -p $(LOG_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) -I$(SRC_DIR) -c $< -o $@

$(MANAGER_BIN): $(MANAGER_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(NODE_BIN): $(NODE_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(CLIENT_BIN): $(CLIENT_OBJS)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	@rm -rf $(BUILD_DIR) $(LOG_DIR)
	@echo "Cleaned build and log directories."

.PHONY: all clean directories