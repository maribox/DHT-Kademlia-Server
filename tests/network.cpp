

/* for later

NodeID generateRandomNodeID() { 
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 1);
    NodeID nodeId;
    for (size_t i = 0; i < nodeId.size(); ++i) {
      nodeId[i] = dis(gen);
    }
    return nodeId;
}
*/