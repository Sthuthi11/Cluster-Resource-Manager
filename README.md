A system designed to efficiently manage and distribute computational tasks across a set of nodes in a cluster

*Features:*

- __Central Manager:__
  The main controller (Manager) runs in one terminal. It keeps track of all available nodes and manages the lifecycle of tasks.

- __Node Creation:__
  Nodes are independent agents that register with the Manager. These can be created and run separately in different terminals. Each node is capable of receiving and processing tasks.

- __Task Assignment:__
  When tasks are created, the Manager dynamically assigns them to the available nodes.

- __Health Monitoring & Fault Tolerance:__
  The Manager continuously monitors the status of all nodes. If a node fails or stops responding, the Manager will automatically reassign its tasks to other healthy nodes, ensuring no task is lost.

- __Load Balancing:__
  Tasks are distributed evenly across nodes to maximize performance and avoid overloading any single node.

