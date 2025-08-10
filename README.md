# Boost Web Framework (BWF)

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![C++](https://img.shields.io/badge/C++-17-orange.svg)
![Boost](https://img.shields.io/badge/Boost-1.75+-red.svg)

*A modern, header-only C++ web framework built on Boost libraries*

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [API Reference](#-api-reference) • [Examples](#-examples) • [Performance](#-performance)

---

## 📑 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
  - [System Requirements](#system-requirements)
  - [Installing Dependencies](#installing-dependencies)
  - [Compilation Methods](#compilation-methods)
- [Quick Start](#-quick-start)
- [API Reference](#-api-reference)
  - [Basic Routing](#basic-routing)
  - [Request Handling](#request-handling)
  - [Response Methods](#response-methods)
  - [Middleware](#middleware)
  - [WebSocket](#websocket)
  - [File Operations](#file-operations)
  - [Session Management](#session-management)
  - [Cookie Management](#cookie-management)
- [Client Examples](#-client-examples)
- [Advanced Examples](#-advanced-examples)
- [Performance Tips](#-performance-tips)
- [Troubleshooting](#-troubleshooting)

---

## ✨ Features

- **🚀 High Performance** - Built on Boost.Beast for asynchronous I/O
- **📦 Header-Only** - Single header file, easy to integrate
- **🔒 Secure** - Built-in SSL/TLS support, rate limiting, and session management
- **🌐 WebSocket Support** - Real-time bidirectional communication
- **📁 File Operations** - Efficient file upload/download with streaming support
- **🍪 Cookie Management** - Full cookie support with security options
- **🛡️ Middleware System** - Flexible request/response pipeline
- **📝 Comprehensive Logging** - Built-in structured logging with Boost.Log
- **🎯 RESTful Routing** - Express-style routing with parameter support
- **💾 Session Management** - Secure session handling with automatic cleanup
- **⚡ Rate Limiting** - Protect your API from abuse
- **🔧 Zero Dependencies** - Only requires Boost libraries

---

## 📦 Installation

### System Requirements

- **C++ Compiler**: C++17 or later (GCC 7+, Clang 5+, MSVC 2017+)
- **Boost Libraries**: Version 1.75.0 or later
- **OpenSSL**: Version 1.1.1 or later (for HTTPS support)
- **Operating System**: Linux, macOS, Windows

### Installing Dependencies

#### Ubuntu/Debian

```bash
# Update package list
sudo apt update

# Install C++ compiler and build tools
sudo apt install -y build-essential cmake

# Install Boost libraries
sudo apt install -y libboost-all-dev

# Install OpenSSL
sudo apt install -y libssl-dev

# Verify installations
g++ --version
cmake --version
dpkg -l | grep libboost
```

#### CentOS/RHEL/Fedora

```bash
# Install development tools
sudo yum groupinstall -y "Development Tools"
sudo yum install -y cmake3

# Install Boost libraries
sudo yum install -y boost-devel

# Install OpenSSL
sudo yum install -y openssl-devel

# For newer Fedora versions
sudo dnf install -y boost-devel openssl-devel cmake
```

#### macOS (using Homebrew)

```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install boost openssl cmake

# Link OpenSSL (macOS doesn't use system OpenSSL)
export OPENSSL_ROOT_DIR=$(brew --prefix openssl)
```

#### Windows (using vcpkg)

```powershell
# Install vcpkg
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install

# Install dependencies
.\vcpkg install boost:x64-windows openssl:x64-windows
```

### Compilation Methods

#### Method 1: Direct Compilation with g++/clang++

```bash
# Basic compilation (HTTP only)
clang++ -std=c++17 -O2 main.cpp -I. -DBOOST_LOG_DYN_LINK -o main   -lboost_log -lboost_log_setup -lboost_system -lboost_filesystem   -lboost_thread -lboost_regex -lboost_date_time -lpthread

# With SSL support
clang++ -std=c++17 -O2 main.cpp -I. -DBOOST_LOG_DYN_LINK -o main   -lboost_log -lboost_log_setup -lboost_system -lboost_filesystem   -lboost_thread -lboost_regex -lboost_date_time -lpthread -lssl -lcrypto
```

#### Method 2: Using CMake

Create a `CMakeLists.txt` file:

```cmake
cmake_minimum_required(VERSION 3.16)
project(MyWebServer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find packages
find_package(Boost 1.75 REQUIRED COMPONENTS 
    system 
    thread 
    filesystem 
    log 
    log_setup
    regex 
    date_time 
    chrono
)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# Add executable
add_executable(myserver main.cpp)

# Include directories
target_include_directories(myserver PRIVATE ${Boost_INCLUDE_DIRS})

# Link libraries
target_link_libraries(myserver 
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Add compile definitions
target_compile_definitions(myserver PRIVATE 
    BOOST_BIND_GLOBAL_PLACEHOLDERS
    BOOST_LOG_DYN_LINK
)
```

Build with CMake:

```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```



---

## 🚀 Quick Start

### Basic HTTP Server

```cpp
#include "boost_web_framework.hpp"

using namespace bwf;

int main() {
    // Server configuration
    HttpServer::Config config;
    config.port = 8080;
    config.num_threads = 4;
    
    HttpServer server(config);
    
    // Basic route
    server.router().get("/", [](Request& req, Response& res) {
        res.html("<h1>Welcome to Boost Web Framework!</h1>");
    });
    
    // Start server
    server.run();
    
    return 0;
}
```

### HTTPS Server

```cpp
#include "boost_web_framework.hpp"

using namespace bwf;

int main() {
    HttpServer::Config config;
    config.port = 443;
    config.use_ssl = true;
    config.cert_file = "server.crt";
    config.key_file = "server.key";
    
    HttpServer server(config);
    
    server.router().get("/", [](Request& req, Response& res) {
        res.html("<h1>Secure HTTPS Server!</h1>");
    });
    
    server.run();
    return 0;
}
```

---

## 📚 API Reference

### Basic Routing

#### HTTP Methods

```cpp
// GET request
server.router().get("/users", [](Request& req, Response& res) {
    res.json({{"users", {"Alice", "Bob", "Charlie"}}});
});

// POST request
server.router().post("/users", [](Request& req, Response& res) {
    auto body = req.json();
    std::string name = body.get<std::string>("name");
    res.status(201).json({{"message", "User created"}, {"name", name}});
});

// PUT request
server.router().put("/users/:id", [](Request& req, Response& res) {
    std::string id = req.param("id");
    auto body = req.json();
    res.json({{"message", "User updated"}, {"id", id}});
});

// DELETE request
server.router().del("/users/:id", [](Request& req, Response& res) {
    std::string id = req.param("id");
    res.json({{"message", "User deleted"}, {"id", id}});
});

// PATCH request
server.router().patch("/users/:id", [](Request& req, Response& res) {
    std::string id = req.param("id");
    res.json({{"message", "User patched"}, {"id", id}});
});
```

#### Route Parameters

```cpp
// Single parameter
server.router().get("/users/:id", [](Request& req, Response& res) {
    std::string user_id = req.param("id");
    res.json({{"user_id", user_id}});
});

// Multiple parameters
server.router().get("/posts/:year/:month/:day", [](Request& req, Response& res) {
    pt::ptree response;
    response.put("year", req.param("year"));
    response.put("month", req.param("month"));
    response.put("day", req.param("day"));
    res.json(response);
});
```

#### Query Parameters

```cpp
server.router().get("/search", [](Request& req, Response& res) {
    std::string query = req.query("q");
    std::string page = req.query("page");
    std::string limit = req.query("limit");
    
    pt::ptree response;
    response.put("query", query.empty() ? "none" : query);
    response.put("page", page.empty() ? "1" : page);
    response.put("limit", limit.empty() ? "10" : limit);
    
    res.json(response);
});
```

### Request Handling

#### Accessing Request Data

```cpp
server.router().post("/api/data", [](Request& req, Response& res) {
    // Get HTTP method
    std::string method = req.method_string(); // "POST"
    
    // Get path
    std::string path = req.path(); // "/api/data"
    
    // Get headers
    std::string content_type = req.header("content-type");
    std::string auth = req.header("authorization");
    
    // Get body as string
    std::string body = req.body();
    
    // Get body as JSON
    pt::ptree json = req.json();
    
    // Get remote address
    std::string ip = req.remote_addr();
    
    // Get cookies
    std::string session = req.cookie("session_id");
    
    res.json({
        {"method", method},
        {"path", path},
        {"content_type", content_type},
        {"ip", ip}
    });
});
```

### Response Methods

#### Text Response

```cpp
server.router().get("/text", [](Request& req, Response& res) {
    res.text("Hello, World!");
});
```

#### HTML Response

```cpp
server.router().get("/page", [](Request& req, Response& res) {
    res.html(R"(
        <!DOCTYPE html>
        <html>
        <head><title>My Page</title></head>
        <body><h1>Hello, HTML!</h1></body>
        </html>
    )");
});
```

#### JSON Response

```cpp
server.router().get("/api/status", [](Request& req, Response& res) {
    pt::ptree response;
    response.put("status", "ok");
    response.put("timestamp", std::time(nullptr));
    
    pt::ptree services;
    services.put("database", "connected");
    services.put("cache", "healthy");
    response.add_child("services", services);
    
    res.json(response);
});
```

#### File Response

```cpp
server.router().get("/download/:filename", [](Request& req, Response& res) {
    std::string filename = req.param("filename");
    std::string filepath = "downloads/" + filename;
    
    // Send file for viewing
    res.file(filepath);
    
    // Send file for download
    res.file(filepath, true);
});
```

#### Redirect

```cpp
server.router().get("/old-page", [](Request& req, Response& res) {
    res.redirect("/new-page", http::status::moved_permanently);
});
```

#### Custom Status

```cpp
server.router().get("/tea", [](Request& req, Response& res) {
    res.status(418).text("I'm a teapot");
});
```

### Middleware

#### Built-in Middleware

```cpp
// CORS middleware
server.router().use(middleware::cors("https://example.com"));

// Logger middleware
server.router().use(middleware::logger());

// Body parser with size limit
server.router().use(middleware::body_parser(10 * 1024 * 1024)); // 10MB

// Authentication middleware
server.router().use(middleware::auth([](Request& req) {
    std::string token = req.header("authorization");
    return token == "Bearer secret-token";
}));
```

#### Custom Middleware

```cpp
// Request timing middleware
server.router().use([](Request& req, Response& res, auto next) {
    auto start = std::chrono::steady_clock::now();
    
    // Call next middleware/handler
    next();
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    
    res.header("X-Response-Time", std::to_string(duration.count()) + "ms");
});

// Request ID middleware
server.router().use([](Request& req, Response& res, auto next) {
    std::string request_id = utils::generate_uuid();
    req.set_attribute("request_id", request_id);
    res.header("X-Request-ID", request_id);
    next();
});

// Error handling middleware
server.router().use([](Request& req, Response& res, auto next) {
    try {
        next();
    } catch (const std::exception& e) {
        Logger::instance().error("Error: %s", e.what());
        res.status(500).json({{"error", e.what()}});
    }
});
```

### WebSocket

#### Basic WebSocket Server

```cpp
server.router().ws("/ws", [](std::shared_ptr<WebSocketSession> ws) {
    Logger::instance().info("New WebSocket connection: %s", ws->get_id().c_str());
    
    // Handle incoming messages
    ws->set_handler([ws](const std::string& message) {
        Logger::instance().debug("Received: %s", message.c_str());
        
        // Echo back
        ws->send("Echo: " + message);
    });
    
    // Handle connection close
    ws->set_close_handler([]() {
        Logger::instance().info("WebSocket connection closed");
    });
    
    // Send welcome message
    ws->send("Welcome to WebSocket server!");
});
```

#### Chat Room Example

```cpp
class ChatRoom {
private:
    std::set<std::shared_ptr<WebSocketSession>> clients_;
    std::mutex mutex_;

public:
    void join(std::shared_ptr<WebSocketSession> client) {
        std::lock_guard<std::mutex> lock(mutex_);
        clients_.insert(client);
        broadcast("{\"type\":\"join\",\"id\":\"" + client->get_id() + "\"}", client);
    }
    
    void leave(std::shared_ptr<WebSocketSession> client) {
        std::lock_guard<std::mutex> lock(mutex_);
        clients_.erase(client);
        broadcast("{\"type\":\"leave\",\"id\":\"" + client->get_id() + "\"}", nullptr);
    }
    
    void broadcast(const std::string& message, std::shared_ptr<WebSocketSession> sender) {
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& client : clients_) {
            if (client != sender) {
                client->send(message);
            }
        }
    }
};

// Usage
auto chat_room = std::make_shared<ChatRoom>();

server.router().ws("/chat", [chat_room](std::shared_ptr<WebSocketSession> ws) {
    chat_room->join(ws);
    
    ws->set_handler([chat_room, ws](const std::string& message) {
        chat_room->broadcast(message, ws);
    });
    
    ws->set_close_handler([chat_room, ws]() {
        chat_room->leave(ws);
    });
});
```

### File Operations

#### File Upload

```cpp
server.router().post("/upload", [](Request& req, Response& res) {
    auto content_type = req.header("content-type");
    
    if (content_type.find("multipart/form-data") == std::string::npos) {
        res.status(400).json({{"error", "Expected multipart/form-data"}});
        return;
    }
    
    // Extract boundary
    size_t boundary_pos = content_type.find("boundary=");
    if (boundary_pos == std::string::npos) {
        res.status(400).json({{"error", "No boundary found"}});
        return;
    }
    
    std::string boundary = content_type.substr(boundary_pos + 9);
    auto files = FileUploadHandler::parse_multipart(req.body(), boundary);
    
    pt::ptree response;
    pt::ptree uploaded_files;
    
    for (const auto& [field_name, file] : files) {
        // Create upload directory if not exists
        fs::create_directories("uploads");
        
        // Generate unique filename
        std::string unique_name = utils::generate_uuid() + "_" + file.filename;
        std::string save_path = "uploads/" + unique_name;
        
        if (file.save_to(save_path)) {
            pt::ptree file_info;
            file_info.put("field", field_name);
            file_info.put("original_name", file.filename);
            file_info.put("saved_name", unique_name);
            file_info.put("size", file.size);
            file_info.put("content_type", file.content_type);
            uploaded_files.push_back(std::make_pair("", file_info));
        }
    }
    
    response.add_child("files", uploaded_files);
    response.put("count", files.size());
    res.json(response);
});
```

#### File Download

```cpp
server.router().get("/files/:id", [](Request& req, Response& res) {
    std::string file_id = req.param("id");
    std::string filepath = "storage/" + file_id;
    
    if (!fs::exists(filepath)) {
        res.status(404).json({{"error", "File not found"}});
        return;
    }
    
    // Get file info
    auto file_size = fs::file_size(filepath);
    auto last_modified = fs::last_write_time(filepath);
    
    // Set headers
    res.header("Content-Length", std::to_string(file_size));
    res.header("Last-Modified", utils::format_http_date(
        std::chrono::system_clock::from_time_t(last_modified)));
    
    // Send file
    res.file(filepath, req.query("download") == "true");
});
```

#### Static Files

```cpp
// Serve static files from directory
server.router().static_files("/static", "./public");

// This will serve:
// /static/css/style.css -> ./public/css/style.css
// /static/js/app.js -> ./public/js/app.js
// /static/images/logo.png -> ./public/images/logo.png
```

### Session Management

```cpp
server.router().post("/login", [&server](Request& req, Response& res) {
    auto json = req.json();
    std::string username = json.get<std::string>("username");
    std::string password = json.get<std::string>("password");
    
    // Validate credentials (example)
    if (username == "admin" && password == "secret") {
        // Get or create session
        auto session = req.get_attribute<std::shared_ptr<SessionManager::Session>>("session");
        
        // Store user data in session
        session->set("user_id", 1);
        session->set("username", username);
        session->set("logged_in", true);
        
        res.json({
            {"status", "success"},
            {"message", "Logged in successfully"}
        });
    } else {
        res.status(401).json({
            {"status", "error"},
            {"message", "Invalid credentials"}
        });
    }
});

server.router().get("/profile", [](Request& req, Response& res) {
    auto session = req.get_attribute<std::shared_ptr<SessionManager::Session>>("session");
    
    auto logged_in = session->get<bool>("logged_in");
    if (!logged_in || !*logged_in) {
        res.status(401).json({{"error", "Not authenticated"}});
        return;
    }
    
    pt::ptree profile;
    profile.put("user_id", *session->get<int>("user_id"));
    profile.put("username", *session->get<std::string>("username"));
    
    res.json(profile);
});

server.router().post("/logout", [&server](Request& req, Response& res) {
    auto session = req.get_attribute<std::shared_ptr<SessionManager::Session>>("session");
    server.sessions().destroy_session(session->id);
    
    res.json({{"message", "Logged out successfully"}});
});
```

### Cookie Management

```cpp
// Set cookie
server.router().get("/set-cookie", [](Request& req, Response& res) {
    res.cookie("user_pref", "dark_mode", "/", 3600); // 1 hour
    res.cookie("lang", "en", "/", -1, false, false); // Session cookie
    
    Cookie secure_cookie;
    secure_cookie.name = "auth_token";
    secure_cookie.value = "secure_value";
    secure_cookie.secure = true;
    secure_cookie.http_only = true;
    secure_cookie.same_site = "Strict";
    secure_cookie.expires = std::chrono::system_clock::now() + std::chrono::hours(24);
    
    res.cookie(secure_cookie);
    res.text("Cookies set");
});

// Read cookie
server.router().get("/read-cookie", [](Request& req, Response& res) {
    std::string user_pref = req.cookie("user_pref");
    std::string lang = req.cookie("lang");
    
    pt::ptree cookies;
    cookies.put("user_pref", user_pref);
    cookies.put("lang", lang);
    
    res.json(cookies);
});

// Remove cookie
server.router().get("/remove-cookie", [](Request& req, Response& res) {
    res.remove_cookie("user_pref");
    res.text("Cookie removed");
});
```

---

## 🌐 Client Examples

### Using cURL

#### GET Request

```bash
# Simple GET
curl http://localhost:8080/

# GET with headers
curl -H "Authorization: Bearer token123" http://localhost:8080/api/data

# GET with query parameters
curl "http://localhost:8080/search?q=boost&page=2&limit=20"
```

#### POST Request

```bash
# POST with JSON
curl -X POST http://localhost:8080/api/users \
  -H "Content-Type: application/json" \
  -d '{"name":"Alice","email":"alice@example.com"}'

# POST with form data
curl -X POST http://localhost:8080/form \
  -d "username=alice&password=secret"
```

#### File Upload

```bash
# Upload single file
curl -X POST http://localhost:8080/upload \
  -F "file=@/path/to/file.jpg"

# Upload multiple files
curl -X POST http://localhost:8080/upload \
  -F "avatar=@avatar.jpg" \
  -F "document=@document.pdf"
```

#### WebSocket

```bash
# Using wscat (npm install -g wscat)
wscat -c ws://localhost:8080/ws

# Using curl (requires curl 7.86.0+)
curl --include \
     --no-buffer \
     --header "Connection: Upgrade" \
     --header "Upgrade: websocket" \
     --header "Sec-WebSocket-Key: SGVsbG8sIHdvcmxkIQ==" \
     --header "Sec-WebSocket-Version: 13" \
     http://localhost:8080/ws
```

### Using JavaScript (Browser)

#### Fetch API

```javascript
// GET request
fetch('http://localhost:8080/api/users')
  .then(response => response.json())
  .then(data => console.log(data));

// POST request
fetch('http://localhost:8080/api/users', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    name: 'Alice',
    email: 'alice@example.com'
  })
})
.then(response => response.json())
.then(data => console.log(data));

// File upload
const formData = new FormData();
formData.append('file', fileInput.files[0]);

fetch('http://localhost:8080/upload', {
  method: 'POST',
  body: formData
})
.then(response => response.json())
.then(data => console.log(data));
```

#### WebSocket

```javascript
const ws = new WebSocket('ws://localhost:8080/ws');

ws.onopen = () => {
  console.log('Connected');
  ws.send('Hello Server!');
};

ws.onmessage = (event) => {
  console.log('Received:', event.data);
};

ws.onclose = () => {
  console.log('Disconnected');
};

ws.onerror = (error) => {
  console.error('Error:', error);
};
```

### Using Python

```python
import requests
import websocket
import json

# GET request
response = requests.get('http://localhost:8080/api/users')
print(response.json())

# POST request
data = {'name': 'Alice', 'email': 'alice@example.com'}
response = requests.post('http://localhost:8080/api/users', json=data)
print(response.json())

# File upload
files = {'file': open('image.jpg', 'rb')}
response = requests.post('http://localhost:8080/upload', files=files)
print(response.json())

# WebSocket
def on_message(ws, message):
    print(f"Received: {message}")

def on_open(ws):
    ws.send("Hello Server!")

ws = websocket.WebSocketApp("ws://localhost:8080/ws",
                          on_open=on_open,
                          on_message=on_message)
ws.run_forever()
```

---

## 🏗️ Advanced Examples

### Complete REST API

```cpp
#include "boost_web_framework.hpp"
#include <sqlite3.h>

using namespace bwf;

class TodoAPI {
private:
    sqlite3* db_;

public:
    TodoAPI() {
        sqlite3_open("todos.db", &db_);
        const char* sql = R"(
            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                completed BOOLEAN DEFAULT 0,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        )";
        sqlite3_exec(db_, sql, nullptr, nullptr, nullptr);
    }

    ~TodoAPI() {
        sqlite3_close(db_);
    }

    void setup_routes(Router& router) {
        // List all todos
        router.get("/api/todos", [this](Request& req, Response& res) {
            pt::ptree todos;
            pt::ptree items;
            
            const char* sql = "SELECT * FROM todos ORDER BY created_at DESC";
            sqlite3_stmt* stmt;
            sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
            
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                pt::ptree todo;
                todo.put("id", sqlite3_column_int(stmt, 0));
                todo.put("title", reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1)));
                todo.put("completed", sqlite3_column_int(stmt, 2) == 1);
                todo.put("created_at", reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)));
                items.push_back(std::make_pair("", todo));
            }
            
            sqlite3_finalize(stmt);
            todos.add_child("todos", items);
            res.json(todos);
        });

        // Create todo
        router.post("/api/todos", [this](Request& req, Response& res) {
            auto json = req.json();
            std::string title = json.get<std::string>("title");
            
            const char* sql = "INSERT INTO todos (title) VALUES (?)";
            sqlite3_stmt* stmt;
            sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
            sqlite3_bind_text(stmt, 1, title.c_str(), -1, SQLITE_STATIC);
            
            if (sqlite3_step(stmt) == SQLITE_DONE) {
                int id = sqlite3_last_insert_rowid(db_);
                pt::ptree response;
                response.put("id", id);
                response.put("title", title);
                response.put("completed", false);
                res.status(201).json(response);
            } else {
                res.status(500).json({{"error", "Failed to create todo"}});
            }
            
            sqlite3_finalize(stmt);
        });

        // Update todo
        router.put("/api/todos/:id", [this](Request& req, Response& res) {
            int id = std::stoi(req.param("id"));
            auto json = req.json();
            bool completed = json.get<bool>("completed");
            
            const char* sql = "UPDATE todos SET completed = ? WHERE id = ?";
            sqlite3_stmt* stmt;
            sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
            sqlite3_bind_int(stmt, 1, completed ? 1 : 0);
            sqlite3_bind_int(stmt, 2, id);
            
            if (sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db_) > 0) {
                res.json({{"message", "Todo updated"}});
            } else {
                res.status(404).json({{"error", "Todo not found"}});
            }
            
            sqlite3_finalize(stmt);
        });

        // Delete todo
        router.del("/api/todos/:id", [this](Request& req, Response& res) {
            int id = std::stoi(req.param("id"));
            
            const char* sql = "DELETE FROM todos WHERE id = ?";
            sqlite3_stmt* stmt;
            sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
            sqlite3_bind_int(stmt, 1, id);
            
            if (sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db_) > 0) {
                res.status(204).body("");
            } else {
                res.status(404).json({{"error", "Todo not found"}});
            }
            
            sqlite3_finalize(stmt);
        });
    }
};

int main() {
    HttpServer::Config config;
    config.port = 8080;
    config.log_file = "server.log";
    
    HttpServer server(config);
    TodoAPI api;
    
    // Middleware
    server.router().use(middleware::cors());
    server.router().use(middleware::logger());
    
    // API routes
    api.setup_routes(server.router());
    
    // Serve frontend
    server.router().static_files("/", "./public");
    
    server.run();
    return 0;
}
```

### Real-time Chat Application

```cpp
#include "boost_web_framework.hpp"
#include <chrono>
#include <iomanip>

using namespace bwf;

struct ChatMessage {
    std::string id;
    std::string user;
    std::string text;
    std::chrono::system_clock::time_point timestamp;
    
    pt::ptree to_json() const {
        pt::ptree msg;
        msg.put("id", id);
        msg.put("user", user);
        msg.put("text", text);
        msg.put("timestamp", std::chrono::system_clock::to_time_t(timestamp));
        return msg;
    }
};

class ChatServer {
private:
    struct Client {
        std::string id;
        std::string username;
        std::shared_ptr<WebSocketSession> session;
    };
    
    std::map<std::string, Client> clients_;
    std::vector<ChatMessage> message_history_;
    std::mutex mutex_;
    const size_t MAX_HISTORY = 100;

public:
    void add_client(std::shared_ptr<WebSocketSession> ws) {
        Client client;
        client.id = ws->get_id();
        client.session = ws;
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            clients_[client.id] = client;
        }
        
        // Send history
        send_history(ws);
        
        // Notify others
        broadcast_system_message(client.username + " joined the chat");
    }
    
    void remove_client(const std::string& id) {
        std::string username;
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = clients_.find(id);
            if (it != clients_.end()) {
                username = it->second.username;
                clients_.erase(it);
            }
        }
        
        if (!username.empty()) {
            broadcast_system_message(username + " left the chat");
        }
    }
    
    void handle_message(const std::string& client_id, const std::string& data) {
        try {
            std::istringstream ss(data);
            pt::ptree json;
            pt::read_json(ss, json);
            
            std::string type = json.get<std::string>("type");
            
            if (type == "login") {
                handle_login(client_id, json.get<std::string>("username"));
            } else if (type == "message") {
                handle_chat_message(client_id, json.get<std::string>("text"));
            }
        } catch (const std::exception& e) {
            Logger::instance().error("Failed to handle message: %s", e.what());
        }
    }

private:
    void handle_login(const std::string& client_id, const std::string& username) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = clients_.find(client_id);
            if (it != clients_.end()) {
                it->second.username = username;
            }
        }
        
        pt::ptree response;
        response.put("type", "login_success");
        response.put("username", username);
        
        send_to_client(client_id, response);
        broadcast_system_message(username + " joined the chat");
    }
    
    void handle_chat_message(const std::string& client_id, const std::string& text) {
        std::string username;
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = clients_.find(client_id);
            if (it != clients_.end()) {
                username = it->second.username;
            }
        }
        
        if (username.empty()) return;
        
        ChatMessage msg;
        msg.id = utils::generate_uuid();
        msg.user = username;
        msg.text = text;
        msg.timestamp = std::chrono::system_clock::now();
        
        {
            std::lock_guard<std::mutex> lock(mutex_);
            message_history_.push_back(msg);
            if (message_history_.size() > MAX_HISTORY) {
                message_history_.erase(message_history_.begin());
            }
        }
        
        broadcast_message(msg);
    }
    
    void send_history(std::shared_ptr<WebSocketSession> ws) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        pt::ptree history;
        pt::ptree messages;
        
        for (const auto& msg : message_history_) {
            messages.push_back(std::make_pair("", msg.to_json()));
        }
        
        history.put("type", "history");
        history.add_child("messages", messages);
        
        std::ostringstream ss;
        pt::write_json(ss, history);
        ws->send(ss.str());
    }
    
    void broadcast_message(const ChatMessage& msg) {
        pt::ptree json;
        json.put("type", "message");
        json.add_child("message", msg.to_json());
        
        broadcast(json);
    }
    
    void broadcast_system_message(const std::string& text) {
        pt::ptree json;
        json.put("type", "system");
        json.put("text", text);
        json.put("timestamp", std::time(nullptr));
        
        broadcast(json);
    }
    
    void broadcast(const pt::ptree& json) {
        std::ostringstream ss;
        pt::write_json(ss, json);
        std::string data = ss.str();
        
        std::lock_guard<std::mutex> lock(mutex_);
        for (const auto& [id, client] : clients_) {
            client.session->send(data);
        }
    }
    
    void send_to_client(const std::string& client_id, const pt::ptree& json) {
        std::ostringstream ss;
        pt::write_json(ss, json);
        
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = clients_.find(client_id);
        if (it != clients_.end()) {
            it->second.session->send(ss.str());
        }
    }
};

int main() {
    HttpServer::Config config;
    config.port = 8080;
    
    HttpServer server(config);
    auto chat_server = std::make_shared<ChatServer>();
    
    // WebSocket endpoint
    server.router().ws("/chat", [chat_server](std::shared_ptr<WebSocketSession> ws) {
        std::string client_id = ws->get_id();
        
        chat_server->add_client(ws);
        
        ws->set_handler([chat_server, client_id](const std::string& message) {
            chat_server->handle_message(client_id, message);
        });
        
        ws->set_close_handler([chat_server, client_id]() {
            chat_server->remove_client(client_id);
        });
    });
    
    // Serve chat UI
    server.router().get("/", [](Request& req, Response& res) {
        res.html(R"(
<!DOCTYPE html>
<html>
<head>
    <title>Chat Application</title>
    <style>
        #messages { height: 400px; overflow-y: scroll; border: 1px solid #ccc; padding: 10px; }
        .message { margin: 5px 0; }
        .system { color: #666; font-style: italic; }
    </style>
</head>
<body>
    <div id="messages"></div>
    <input type="text" id="username" placeholder="Enter username">
    <button onclick="login()">Login</button>
    <br>
    <input type="text" id="messageInput" placeholder="Type a message" disabled>
    <button onclick="sendMessage()" disabled id="sendBtn">Send</button>
    
    <script>
        let ws;
        let username;
        
        function connect() {
            ws = new WebSocket('ws://localhost:8080/chat');
            
            ws.onmessage = (event) => {
                const data = JSON.parse(event.data);
                
                if (data.type === 'history') {
                    data.messages.forEach(msg => displayMessage(msg));
                } else if (data.type === 'message') {
                    displayMessage(data.message);
                } else if (data.type === 'system') {
                    displaySystem(data.text);
                } else if (data.type === 'login_success') {
                    username = data.username;
                    document.getElementById('messageInput').disabled = false;
                    document.getElementById('sendBtn').disabled = false;
                    document.getElementById('username').disabled = true;
                }
            };
            
            ws.onclose = () => {
                displaySystem('Disconnected from server');
                setTimeout(connect, 3000);
            };
        }
        
        function login() {
            const usernameInput = document.getElementById('username').value;
            if (usernameInput && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({type: 'login', username: usernameInput}));
            }
        }
        
        function sendMessage() {
            const input = document.getElementById('messageInput');
            if (input.value && ws.readyState === WebSocket.OPEN) {
                ws.send(JSON.stringify({type: 'message', text: input.value}));
                input.value = '';
            }
        }
        
        function displayMessage(msg) {
            const messages = document.getElementById('messages');
            const div = document.createElement('div');
            div.className = 'message';
            div.textContent = `${msg.user}: ${msg.text}`;
            messages.appendChild(div);
            messages.scrollTop = messages.scrollHeight;
        }
        
        function displaySystem(text) {
            const messages = document.getElementById('messages');
            const div = document.createElement('div');
            div.className = 'system';
            div.textContent = text;
            messages.appendChild(div);
            messages.scrollTop = messages.scrollHeight;
        }
        
        document.getElementById('messageInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendMessage();
        });
        
        connect();
    </script>
</body>
</html>
        )");
    });
    
    server.run();
    return 0;
}
```

---

## 🎯 Performance Tips

### 1. Thread Pool Configuration

```cpp
HttpServer::Config config;
// Set threads based on CPU cores
config.num_threads = std::thread::hardware_concurrency();
// Or set manually for specific workloads
config.num_threads = 8; // For I/O heavy applications
```

### 2. Enable Keep-Alive

```cpp
server.router().use([](Request& req, Response& res, auto next) {
    res.header("Connection", "keep-alive");
    res.header("Keep-Alive", "timeout=5, max=1000");
    next();
});
```

### 3. Response Compression

```cpp
// Gzip compression middleware (pseudo-code)
server.router().use([](Request& req, Response& res, auto next) {
    std::string accept_encoding = req.header("accept-encoding");
    
    if (accept_encoding.find("gzip") != std::string::npos) {
        // Store original body method
        auto original_body = res.body;
        
        // Override body method to compress
        res.body = [&res, original_body](const std::string& content) {
            std::string compressed = gzip_compress(content);
            res.header("Content-Encoding", "gzip");
            res.header("Content-Length", std::to_string(compressed.size()));
            original_body(compressed);
            return res;
        };
    }
    
    next();
});
```

### 4. Static File Caching

```cpp
server.router().use([](Request& req, Response& res, auto next) {
    // Cache static assets
    if (req.path().find("/static/") == 0) {
        res.header("Cache-Control", "public, max-age=31536000"); // 1 year
        res.header("ETag", generate_etag(req.path()));
        
        std::string if_none_match = req.header("if-none-match");
        if (!if_none_match.empty() && if_none_match == generate_etag(req.path())) {
            res.status(304).body("");
            return;
        }
    }
    
    next();
});
```

### 5. Database Connection Pooling

```cpp
class DatabasePool {
private:
    std::queue<std::unique_ptr<DatabaseConnection>> pool_;
    std::mutex mutex_;
    std::condition_variable cv_;
    size_t max_connections_ = 10;

public:
    std::unique_ptr<DatabaseConnection> acquire() {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [this] { return !pool_.empty(); });
        
        auto conn = std::move(pool_.front());
        pool_.pop();
        return conn;
    }
    
    void release(std::unique_ptr<DatabaseConnection> conn) {
        std::lock_guard<std::mutex> lock(mutex_);
        pool_.push(std::move(conn));
        cv_.notify_one();
    }
};
```

---

## 🔧 Troubleshooting

### Common Issues

#### 1. Boost Libraries Not Found

```bash
# Ubuntu/Debian
sudo apt install libboost-all-dev

# Check installation
ldconfig -p | grep boost

# Set library path if needed
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

#### 2. SSL Certificate Issues

```bash
# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

#### 3. Port Already in Use

```bash
# Find process using port
sudo lsof -i :8080
# or
sudo netstat -tlnp | grep 8080

# Kill process
sudo kill -9 <PID>
```

#### 4. Compilation Errors

```bash
# Missing headers
sudo apt install libc++-dev

# Link errors - check library order
# Libraries should be listed after source files
g++ main.cpp -lboost_system -lboost_thread # Correct
g++ -lboost_system -lboost_thread main.cpp # Wrong
```

### Debug Mode

```cpp
// Enable debug logging
HttpServer::Config config;
config.log_level = Logger::DEBUG;
config.log_file = "debug.log";

// Add request/response logging
server.router().use([](Request& req, Response& res, auto next) {
    Logger::instance().debug("Request: %s %s", 
        req.method_string().c_str(), 
        req.path().c_str());
    
    Logger::instance().debug("Headers:");
    for (const auto& [name, value] : req.headers()) {
        Logger::instance().debug("  %s: %s", name.c_str(), value.c_str());
    }
    
    if (!req.body().empty()) {
        Logger::instance().debug("Body: %s", req.body().c_str());
    }
    
    next();
});
```

---

## 📄 License

This project is licensed under the MIT License.

---

<div align="center">
Made with ❤️ by the C++ community
</div>