cd src/sim && g++ -std=c++17 -pthread -O2 -o escape_component_sim escape_component_sim.cpp ../protocol/Protocol.cpp ../protocol/Json.cpp && ./escape_component_sim --http-port 8080
