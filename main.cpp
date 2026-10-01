#include <iostream>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <chrono>
#include <cstdlib>
#include <thread>
#include <sstream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in>
#include <unistd.h>

class BandwidthEnforcer {
private:
    std::unordered_set<std::string> whitelist;
    std::unordered_set<std::string> blacklisted;
    std::unordered_map<std::string, unsigned long long> bandwidthUsage;
    unsigned long long maxBytesAllowed;
    std::string adminlockcode;

    void executeCommand(const std::string& cmd) {
        std::system(cmd.c_str());
    }

public:
    BandwidthEnforcer(unsigned long long limit, std::string password) 
        : maxBytesAllowed(limit), adminlockcode(password) {}

    void addWhitelist(const std::string& ip) {
        whitelist.insert(ip);
        if (blacklisted.count(ip)) {
            removeBlacklist(ip);
        }
    }

    void applyBlacklist(const std::string& ip) {
        if (whitelist.count(ip)) return;
        
        if (!blacklisted.count(ip)) {
            blacklisted.insert(ip);
            std::string cmd1 = "sudo iptables -A INPUT -s " + ip + " -j DROP";
            std::string cmd2 = "sudo iptables -A OUTPUT -d " + ip + " -j DROP";
            executeCommand(cmd1);
            executeCommand(cmd2);
        }
    }

    void removeBlacklist(const std::string& ip) {
        if (blacklisted.count(ip)) {
            blacklisted.erase(ip);
            std::string cmd1 = "sudo iptables -D INPUT -s " + ip + " -j DROP";
            std::string cmd2 = "sudo iptables -D OUTPUT -d " + ip + " -j DROP";
            executeCommand(cmd1);
            executeCommand(cmd2);
        }
    }

    void updateTraffic(const std::string& ip, unsigned long long bytesIncrement) {
        if (whitelist.count(ip) || blacklisted.count(ip)) {
            return;
        }
        
        bandwidthUsage[ip] += bytesIncrement;

        if (bandwidthUsage[ip] > maxBytesAllowed) {
            applyBlacklist(ip);
        }
    }

    bool verifyPassword(const std::string& pwd) {
        return pwd == adminlockcode;
    }

    std::string getStatusPage(bool authenticated) {
        if (!authenticated) {
            return "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                   "<html><body>"
                   "<h2>Bandwidth Manager Login</h2>"
                   "<form method='POST' action='/login'>"
                   "Password: <input type='password' name='password'>"
                   "<input type='submit' value='Login'>"
                   "</form>"
                   "</body></html>";
        }

        std::string html = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
                           "<html><body><h2>Bandwidth Control Panel</h2>"
                           "<h3>Whitelisted IPs</h3><ul>";
        for (const auto& ip : whitelist) {
            html += "<li>" + ip + "</li>";
        }
        html += "</ul><h3>Blacklisted IPs</h3><ul>";
        for (const auto& ip : blacklisted) {
            html += "<li>" + ip + " <form style='display:inline;' method='POST' action='/unblock'>"
                    "<input type='hidden' name='ip' value='" + ip + "'>"
                    "<input type='hidden' name='password' value='" + adminlockcode + "'>"
                    "<input type='submit' value='Unblock'>"
                    "</form></li>";
        }
        html += "</ul></body></html>";
        return html;
    }

    void unblockDevice(const std::string& ip) {
        removeBlacklist(ip);
    }
};

void runWebServer(BandwidthEnforcer& enforcer) {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(8080);

    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 3);

    while (true) {
        int addrlen = sizeof(address);
        int new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen);
        if (new_socket < 0) continue;

        char buffer[3072] = {0};
        read(new_socket, buffer, 3072);
        std::string request(buffer);

        std::string response;
        if (request.find("POST /login") != std::string::npos) {
            size_t pos = request.find("password=");
            if (pos != std::string::npos) {
                std::string pwd = request.substr(pos + 9);
                size_t amp = pwd.find('&');
                if (amp != std::string::npos) pwd = pwd.substr(0, amp);
                
                if (enforcer.verifyPassword(pwd)) {
                    response = enforcer.getStatusPage(true);
                } else {
                    response = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\n\r\n"
                               "<html><body><h3>Invalid Password</h3><a href='/'>Back</a></body></html>";
                }
            }
        } else if (request.find("POST /unblock") != std::string::npos) {
            size_t ipPos = request.find("ip=");
            size_t pwdPos = request.find("password=");
            if (ipPos != std::string::npos && pwdPos != std::string::npos) {
                std::string ip = request.substr(ipPos + 3);
                size_t amp1 = ip.find('&');
                if (amp1 != std::string::npos) ip = ip.substr(0, amp1);

                std::string pwd = request.substr(pwdPos + 9);
                size_t amp2 = pwd.find('&');
                if (amp2 != std::string::npos) pwd = pwd.substr(0, amp2);

                if (enforcer.verifyPassword(pwd)) {
                    enforcer.unblockDevice(ip);
                    response = enforcer.getStatusPage(true);
                } else {
                    response = "HTTP/1.1 401 Unauthorized\r\nContent-Type: text/html\r\n\r\n"
                               "<html><body><h3>Unauthorized</h3></body></html>";
                }
            }
        } else {
            response = enforcer.getStatusPage(false);
        }

        write(new_socket, response.c_str(), response.length());
        close(new_socket);
    }
}

int main() {
    unsigned long long limit = 500 * 1024 * 1024;
    BandwidthEnforcer enforcer(limit, "its_washed");

    enforcer.addWhitelist("192.168.1.1");
    enforcer.addWhitelist("192.168.1.50");

    std::thread serverThread(runWebServer, std::ref(enforcer));
    serverThread.detach();

    while (true) {
        enforcer.updateTraffic("192.168.1.105", 100 * 1024 * 1024);
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }

    return 0;
}
