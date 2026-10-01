# Bandwidth Enforcer & Local Admin Web Panel

A C++ daemon that monitors network traffic per device, dynamically blacklists IP addresses using `iptables` when they exceed a configurable bandwidth limit, maintains a secure device whitelist, and provides a built-in local web dashboard to manage blocked and whitelisted devices.

## Features

- **Dynamic Bandwidth Enforcement:** Automatically tracks data usage and applies `iptables` block rules (`INPUT` and `OUTPUT`) when an unwhitelisted device exceeds the maximum allowed bytes.
- **Whitelist Support:** Protects specified devices (such as gateways, servers, or priority computers) from being blacklisted regardless of their data usage.
- **Local Web Administration Panel:** Runs an embedded local HTTP server (accessible on port `8080`) allowing administrators to log in and manage blocked IPs.
- **Password Protection:** Uses an admin lock code (`its_washed`) to restrict access to management controls like unblocking devices.

---

## Prerequisites

- **Operating System:** Linux (required for `iptables` support).
- **Compiler:** A C++ compiler supporting C++11 or higher (e.g., `g++`).
- **Permissions:** Root/superuser privileges (`sudo`) are required to execute runtime firewall modifications.

---

## Compilation & Installation

Compile the C++ source code using `g++` with multi-threading support enabled:

```bash
g++ -std=c++11 -pthread main.cpp -o bandwidth_enforcer
```

---

## Running the Application

Because the program invokes `iptables` rules directly to block and unblock network traffic, execute it with `sudo`:

```bash
sudo ./bandwidth_enforcer
```

Once running:
1. The web server listens locally on port `8080`.
2. Open your web browser and navigate to:
   ```text
   http://localhost:8080
   ```
3. Enter the admin lock code: **`its_washed`** to log in, view whitelisted IPs, and unblock devices as needed.

---

## Configuration

You can adjust core settings directly inside the `main()` function:
- **Bandwidth Limit:** Modify the `limit` variable (default is set to `500 * 1024 * 1024` bytes / 500 MB).
- **Admin Password:** Configured via the `BandwidthEnforcer` constructor (`"its_washed"`).
- **Whitelisted Devices:** Add initial IPs using `enforcer.addWhitelist("IP_ADDRESS");`.