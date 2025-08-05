#pragma once

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/format.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>
#include <boost/thread/thread_pool.hpp>
#include <boost/compute/detail/sha1.hpp>

#include <iostream>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <memory>
#include <functional>
#include <sstream>
#include <fstream>
#include <chrono>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <optional>
#include <variant>
#include <any>
#include <queue>
#include <deque>
#include <set>
#include <algorithm>
#include <iomanip>
#include <random>
#include <limits>
#include <type_traits>
#include <utility>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace fs = boost::filesystem;
namespace pt = boost::property_tree;
using tcp = boost::asio::ip::tcp;

namespace bwf {

// Forward declarations
class Request;
class Response;
class Router;
class WebSocketSession;
class FileUploadHandler;
class CookieManager;
class SessionManager;
class RateLimiter;
class Logger;
class Middleware;
class HttpServer;

// Type aliases
using HttpMethod = http::verb;
using Headers = std::unordered_map<std::string, std::string>;
using Params = std::unordered_map<std::string, std::string>;
using Query = std::unordered_map<std::string, std::string>;
using Cookies = std::unordered_map<std::string, std::string>;
using Handler = std::function<void(Request&, Response&)>;
using WebSocketHandler = std::function<void(std::shared_ptr<WebSocketSession>)>;
using MiddlewareFunc = std::function<void(Request&, Response&, std::function<void()>)>;
using ErrorHandler = std::function<void(Request&, Response&, const std::exception&)>;

// Utility functions
namespace utils {
    inline std::string generate_uuid() {
        boost::uuids::random_generator gen;
        return boost::uuids::to_string(gen());
    }

    inline std::string sha256(const std::string& data) {
        boost::compute::detail::sha1 hasher;
        hasher.process(data.data(), data.size());
        std::stringstream ss;
        hasher.get_digest(ss);
        return ss.str();
    }

    inline std::string url_decode(const std::string& str) {
        std::string result;
        for (size_t i = 0; i < str.length(); ++i) {
            if (str[i] == '%' && i + 2 < str.length()) {
                int hex = std::stoi(str.substr(i + 1, 2), nullptr, 16);
                result += static_cast<char>(hex);
                i += 2;
            } else if (str[i] == '+') {
                result += ' ';
            } else {
                result += str[i];
            }
        }
        return result;
    }

    inline std::string url_encode(const std::string& str) {
        std::ostringstream escaped;
        escaped.fill('0');
        escaped << std::hex;
        for (auto c : str) {
            if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                escaped << c;
            } else {
                escaped << std::uppercase;
                escaped << '%' << std::setw(2) << int((unsigned char)c);
                escaped << std::nouppercase;
            }
        }
        return escaped.str();
    }

    inline Query parse_query_string(const std::string& query) {
        Query result;
        if (query.empty()) return result;
        
        std::vector<std::string> pairs;
        boost::split(pairs, query, boost::is_any_of("&"));
        
        for (const auto& pair : pairs) {
            auto pos = pair.find('=');
            if (pos != std::string::npos) {
                std::string key = url_decode(pair.substr(0, pos));
                std::string value = url_decode(pair.substr(pos + 1));
                result[key] = value;
            }
        }
        return result;
    }

    inline std::string get_mime_type(const std::string& path) {
        static const std::unordered_map<std::string, std::string> mime_types = {
            {".html", "text/html"},
            {".htm", "text/html"},
            {".css", "text/css"},
            {".js", "application/javascript"},
            {".json", "application/json"},
            {".xml", "application/xml"},
            {".jpg", "image/jpeg"},
            {".jpeg", "image/jpeg"},
            {".png", "image/png"},
            {".gif", "image/gif"},
            {".svg", "image/svg+xml"},
            {".ico", "image/x-icon"},
            {".mp4", "video/mp4"},
            {".webm", "video/webm"},
            {".mp3", "audio/mpeg"},
            {".wav", "audio/wav"},
            {".pdf", "application/pdf"},
            {".zip", "application/zip"},
            {".txt", "text/plain"}
        };
        
        auto ext = fs::path(path).extension().string();
        boost::to_lower(ext);
        
        auto it = mime_types.find(ext);
        return (it != mime_types.end()) ? it->second : "application/octet-stream";
    }

    inline std::string format_http_date(const std::chrono::system_clock::time_point& tp) {
        std::time_t time = std::chrono::system_clock::to_time_t(tp);
        std::tm tm = *std::gmtime(&time);
        std::ostringstream ss;
        ss << std::put_time(&tm, "%a, %d %b %Y %H:%M:%S GMT");
        return ss.str();
    }
}

// Logger class
class Logger {
public:
    enum Level {
        TRACE = 0,
        DEBUG = 1,
        INFO = 2,
        WARNING = 3,
        ERROR = 4,
        FATAL = 5
    };

    static Logger& instance() {
        static Logger instance;
        return instance;
    }

    void init(const std::string& log_file = "", Level min_level = INFO) {
        namespace logging = boost::log;
        namespace keywords = boost::log::keywords;
        namespace expr = boost::log::expressions;
        
        min_level_ = min_level;
        
        logging::add_common_attributes();
        
        if (!log_file.empty()) {
            logging::add_file_log(
                keywords::file_name = log_file,
                keywords::rotation_size = 10 * 1024 * 1024,
                keywords::time_based_rotation = logging::sinks::file::rotation_at_time_point(0, 0, 0),
                keywords::format = "[%TimeStamp%] [%Severity%] %Message%",
                keywords::auto_flush = true
            );
        }
        
        logging::add_console_log(
            std::cout,
            keywords::format = "[%TimeStamp%] [%Severity%] %Message%"
        );
        
        logging::core::get()->set_filter(
            logging::trivial::severity >= static_cast<logging::trivial::severity_level>(min_level)
        );
    }

    template<typename... Args>
    void log(Level level, const std::string& format, Args&&... args) {
        if (level < min_level_) return;
        
        std::string message = (boost::format(format) % ... % std::forward<Args>(args)).str();
        
        switch (level) {
            case TRACE:
                BOOST_LOG_TRIVIAL(trace) << message;
                break;
            case DEBUG:
                BOOST_LOG_TRIVIAL(debug) << message;
                break;
            case INFO:
                BOOST_LOG_TRIVIAL(info) << message;
                break;
            case WARNING:
                BOOST_LOG_TRIVIAL(warning) << message;
                break;
            case ERROR:
                BOOST_LOG_TRIVIAL(error) << message;
                break;
            case FATAL:
                BOOST_LOG_TRIVIAL(fatal) << message;
                break;
        }
    }

    template<typename... Args>
    void trace(const std::string& format, Args&&... args) {
        log(TRACE, format, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void debug(const std::string& format, Args&&... args) {
        log(DEBUG, format, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void info(const std::string& format, Args&&... args) {
        log(INFO, format, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void warning(const std::string& format, Args&&... args) {
        log(WARNING, format, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void error(const std::string& format, Args&&... args) {
        log(ERROR, format, std::forward<Args>(args)...);
    }

    template<typename... Args>
    void fatal(const std::string& format, Args&&... args) {
        log(FATAL, format, std::forward<Args>(args)...);
    }

private:
    Logger() = default;
    Level min_level_ = INFO;
};

// Cookie class
class Cookie {
public:
    std::string name;
    std::string value;
    std::string domain;
    std::string path = "/";
    std::chrono::system_clock::time_point expires;
    bool secure = false;
    bool http_only = true;
    std::string same_site = "Lax"; // None, Lax, Strict

    std::string to_string() const {
        std::ostringstream ss;
        ss << name << "=" << value;
        
        if (!domain.empty()) {
            ss << "; Domain=" << domain;
        }
        
        ss << "; Path=" << path;
        
        if (expires != std::chrono::system_clock::time_point{}) {
            ss << "; Expires=" << utils::format_http_date(expires);
        }
        
        if (secure) {
            ss << "; Secure";
        }
        
        if (http_only) {
            ss << "; HttpOnly";
        }
        
        if (!same_site.empty()) {
            ss << "; SameSite=" << same_site;
        }
        
        return ss.str();
    }
};

// Request class
class Request {
public:
    Request(http::request<http::string_body>&& req, const std::string& remote_addr)
        : req_(std::move(req)), remote_addr_(remote_addr) {
        parse_headers();
        parse_cookies();
        parse_url();
    }

    HttpMethod method() const { return req_.method(); }
    std::string method_string() const { return std::string(http::to_string(req_.method())); }
    std::string target() const { return std::string(req_.target()); }
    std::string path() const { return path_; }
    std::string body() const { return req_.body(); }
    const Headers& headers() const { return headers_; }
    const Params& params() const { return params_; }
    const Query& query() const { return query_; }
    const Cookies& cookies() const { return cookies_; }
    const std::string& remote_addr() const { return remote_addr_; }
    
    std::string header(const std::string& name) const {
        auto it = headers_.find(boost::to_lower_copy(name));
        return (it != headers_.end()) ? it->second : "";
    }
    
    std::string param(const std::string& name) const {
        auto it = params_.find(name);
        return (it != params_.end()) ? it->second : "";
    }
    
    std::string query(const std::string& name) const {
        auto it = query_.find(name);
        return (it != query_.end()) ? it->second : "";
    }
    
    std::string cookie(const std::string& name) const {
        auto it = cookies_.find(name);
        return (it != cookies_.end()) ? it->second : "";
    }
    
    void set_param(const std::string& name, const std::string& value) {
        params_[name] = value;
    }
    
    void set_attribute(const std::string& name, const std::any& value) {
        attributes_[name] = value;
    }
    
    template<typename T>
    std::optional<T> get_attribute(const std::string& name) const {
        auto it = attributes_.find(name);
        if (it != attributes_.end()) {
            try {
                return std::any_cast<T>(it->second);
            } catch (...) {
                return std::nullopt;
            }
        }
        return std::nullopt;
    }
    
    pt::ptree json() const {
        pt::ptree tree;
        std::istringstream ss(body());
        try {
            pt::read_json(ss, tree);
        } catch (const std::exception& e) {
            Logger::instance().error("Failed to parse JSON: %s", e.what());
        }
        return tree;
    }
    
    bool is_websocket_upgrade() const {
        return websocket::is_upgrade(req_);
    }

private:
    void parse_headers() {
        for (const auto& field : req_) {
            std::string name = std::string(field.name_string());
            boost::to_lower(name);
            headers_[name] = std::string(field.value());
        }
    }
    
    void parse_cookies() {
        auto cookie_header = header("cookie");
        if (cookie_header.empty()) return;
        
        std::vector<std::string> cookie_pairs;
        boost::split(cookie_pairs, cookie_header, boost::is_any_of(";"));
        
        for (auto& pair : cookie_pairs) {
            boost::trim(pair);
            auto pos = pair.find('=');
            if (pos != std::string::npos) {
                std::string name = pair.substr(0, pos);
                std::string value = pair.substr(pos + 1);
                cookies_[name] = value;
            }
        }
    }
    
    void parse_url() {
        std::string target = std::string(req_.target());
        auto pos = target.find('?');
        
        if (pos != std::string::npos) {
            path_ = target.substr(0, pos);
            std::string query_string = target.substr(pos + 1);
            query_ = utils::parse_query_string(query_string);
        } else {
            path_ = target;
        }
    }

    http::request<http::string_body> req_;
    std::string remote_addr_;
    std::string path_;
    Headers headers_;
    Params params_;
    Query query_;
    Cookies cookies_;
    std::unordered_map<std::string, std::any> attributes_;
};

// Response class
class Response {
public:
    Response() : status_(http::status::ok) {
        set_header("Server", "BoostWebFramework/1.0");
        set_header("Date", utils::format_http_date(std::chrono::system_clock::now()));
    }
    
    Response& status(http::status code) {
        status_ = code;
        return *this;
    }
    
    Response& status(unsigned int code) {
        status_ = static_cast<http::status>(code);
        return *this;
    }
    
    Response& header(const std::string& name, const std::string& value) {
        headers_[name] = value;
        return *this;
    }
    
    Response& set_header(const std::string& name, const std::string& value) {
        return header(name, value);
    }
    
    Response& content_type(const std::string& type) {
        return header("Content-Type", type);
    }
    
    Response& body(const std::string& content) {
        body_ = content;
        return *this;
    }
    
    Response& text(const std::string& content) {
        content_type("text/plain; charset=utf-8");
        return body(content);
    }
    
    Response& html(const std::string& content) {
        content_type("text/html; charset=utf-8");
        return body(content);
    }
    
    Response& json(const pt::ptree& tree) {
        std::ostringstream ss;
        pt::write_json(ss, tree);
        content_type("application/json; charset=utf-8");
        return body(ss.str());
    }
    
    Response& json(const std::string& json_str) {
        content_type("application/json; charset=utf-8");
        return body(json_str);
    }
    
    Response& file(const std::string& path, bool download = false) {
        try {
            if (!fs::exists(path) || !fs::is_regular_file(path)) {
                status(http::status::not_found);
                return text("File not found");
            }
            
            std::ifstream file(path, std::ios::binary);
            if (!file) {
                status(http::status::internal_server_error);
                return text("Failed to read file");
            }
            
            std::ostringstream ss;
            ss << file.rdbuf();
            std::string content = ss.str();
            
            content_type(utils::get_mime_type(path));
            
            if (download) {
                std::string filename = fs::path(path).filename().string();
                header("Content-Disposition", "attachment; filename=\"" + filename + "\"");
            }
            
            header("Content-Length", std::to_string(content.size()));
            return body(content);
            
        } catch (const std::exception& e) {
            Logger::instance().error("Failed to serve file: %s", e.what());
            status(http::status::internal_server_error);
            return text("Internal server error");
        }
    }
    
    Response& redirect(const std::string& url, http::status code = http::status::found) {
        status(code);
        return header("Location", url);
    }
    
    Response& cookie(const Cookie& cookie) {
        cookies_.push_back(cookie);
        return *this;
    }
    
    Response& cookie(const std::string& name, const std::string& value,
                    const std::string& path = "/", int max_age = -1,
                    bool secure = false, bool http_only = true) {
        Cookie c;
        c.name = name;
        c.value = value;
        c.path = path;
        c.secure = secure;
        c.http_only = http_only;
        
        if (max_age > 0) {
            c.expires = std::chrono::system_clock::now() + std::chrono::seconds(max_age);
        }
        
        return cookie(c);
    }
    
    Response& remove_cookie(const std::string& name, const std::string& path = "/") {
        Cookie c;
        c.name = name;
        c.value = "";
        c.path = path;
        c.expires = std::chrono::system_clock::now() - std::chrono::hours(24);
        return cookie(c);
    }
    
    http::response<http::string_body> build() const {
        http::response<http::string_body> res{status_, 11};
        res.body() = body_;
        res.prepare_payload();
        
        for (const auto& [name, value] : headers_) {
            res.set(name, value);
        }
        
        for (const auto& c : cookies_) {
            res.insert(http::field::set_cookie, c.to_string());
        }
        
        return res;
    }

private:
    http::status status_;
    Headers headers_;
    std::string body_;
    std::vector<Cookie> cookies_;
};

// File upload handler
class FileUploadHandler {
public:
    struct UploadedFile {
        std::string filename;
        std::string content_type;
        std::vector<uint8_t> data;
        size_t size;
        
        bool save_to(const std::string& path) const {
            try {
                std::ofstream file(path, std::ios::binary);
                if (!file) return false;
                
                file.write(reinterpret_cast<const char*>(data.data()), data.size());
                return file.good();
            } catch (...) {
                return false;
            }
        }
    };
    
    static std::unordered_map<std::string, UploadedFile> parse_multipart(
        const std::string& body, const std::string& boundary) {
        
        std::unordered_map<std::string, UploadedFile> files;
        
        std::string delimiter = "--" + boundary;
        std::string end_delimiter = delimiter + "--";
        
        size_t pos = 0;
        while ((pos = body.find(delimiter, pos)) != std::string::npos) {
            size_t end_pos = body.find(delimiter, pos + delimiter.length());
            if (end_pos == std::string::npos) {
                end_pos = body.find(end_delimiter, pos + delimiter.length());
                if (end_pos == std::string::npos) break;
            }
            
            std::string part = body.substr(pos + delimiter.length(),
                                          end_pos - pos - delimiter.length());
            
            // Parse headers
            size_t header_end = part.find("\r\n\r\n");
            if (header_end == std::string::npos) continue;
            
            std::string headers = part.substr(0, header_end);
            std::string content = part.substr(header_end + 4);
            
            // Remove trailing CRLF
            if (content.size() >= 2 && content.substr(content.size() - 2) == "\r\n") {
                content.resize(content.size() - 2);
            }
            
            // Parse Content-Disposition
            boost::regex name_regex("name=\"([^\"]*)\"");
            boost::regex filename_regex("filename=\"([^\"]*)\"");
            boost::smatch matches;
            
            std::string name, filename;
            if (boost::regex_search(headers, matches, name_regex)) {
                name = matches[1];
            }
            if (boost::regex_search(headers, matches, filename_regex)) {
                filename = matches[1];
            }
            
            if (!name.empty() && !filename.empty()) {
                UploadedFile file;
                file.filename = filename;
                file.content_type = "application/octet-stream";
                
                // Parse Content-Type
                size_t ct_pos = headers.find("Content-Type: ");
                if (ct_pos != std::string::npos) {
                    size_t ct_end = headers.find("\r\n", ct_pos);
                    file.content_type = headers.substr(ct_pos + 14, ct_end - ct_pos - 14);
                }
                
                file.data.assign(content.begin(), content.end());
                file.size = file.data.size();
                
                files[name] = std::move(file);
            }
            
            pos = end_pos;
        }
        
        return files;
    }
};

// Session manager
class SessionManager {
public:
    struct Session {
        std::string id;
        std::chrono::system_clock::time_point created_at;
        std::chrono::system_clock::time_point last_accessed;
        std::unordered_map<std::string, std::any> data;
        
        template<typename T>
        void set(const std::string& key, const T& value) {
            data[key] = value;
        }
        
        template<typename T>
        std::optional<T> get(const std::string& key) const {
            auto it = data.find(key);
            if (it != data.end()) {
                try {
                    return std::any_cast<T>(it->second);
                } catch (...) {
                    return std::nullopt;
                }
            }
            return std::nullopt;
        }
        
        void remove(const std::string& key) {
            data.erase(key);
        }
    };
    
    SessionManager(std::chrono::minutes timeout = std::chrono::minutes(30))
        : timeout_(timeout) {}
    
    std::shared_ptr<Session> create_session() {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto session = std::make_shared<Session>();
        session->id = utils::generate_uuid();
        session->created_at = std::chrono::system_clock::now();
        session->last_accessed = session->created_at;
        
        sessions_[session->id] = session;
        return session;
    }
    
    std::shared_ptr<Session> get_session(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto it = sessions_.find(id);
        if (it != sessions_.end()) {
            auto now = std::chrono::system_clock::now();
            if (now - it->second->last_accessed < timeout_) {
                it->second->last_accessed = now;
                return it->second;
            } else {
                sessions_.erase(it);
            }
        }
        return nullptr;
    }
    
    void destroy_session(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex_);
        sessions_.erase(id);
    }
    
    void cleanup_expired() {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::system_clock::now();
        
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            if (now - it->second->last_accessed >= timeout_) {
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }

private:
    std::unordered_map<std::string, std::shared_ptr<Session>> sessions_;
    std::chrono::minutes timeout_;
    mutable std::mutex mutex_;
};

// Rate limiter
class RateLimiter {
public:
    RateLimiter(size_t max_requests = 100, std::chrono::seconds window = std::chrono::seconds(60))
        : max_requests_(max_requests), window_(window) {}
    
    bool allow(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        
        auto now = std::chrono::steady_clock::now();
        auto& requests = requests_[key];
        
        // Remove old requests
        while (!requests.empty() && now - requests.front() > window_) {
            requests.pop();
        }
        
        if (requests.size() >= max_requests_) {
            return false;
        }
        
        requests.push(now);
        return true;
    }
    
    void reset(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex_);
        requests_.erase(key);
    }

private:
    size_t max_requests_;
    std::chrono::seconds window_;
    std::unordered_map<std::string, std::queue<std::chrono::steady_clock::time_point>> requests_;
    mutable std::mutex mutex_;
};

// WebSocket session
class WebSocketSession : public std::enable_shared_from_this<WebSocketSession> {
public:
    WebSocketSession(tcp::socket&& socket)
        : ws_(std::move(socket)), strand_(ws_.get_executor()) {}
    
    void run(http::request<http::string_body> req) {
        req_ = std::move(req);
        
        ws_.set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
        ws_.set_option(websocket::stream_base::decorator(
            [](websocket::response_type& res) {
                res.set(http::field::server, "BoostWebFramework/1.0");
            }));
        
        ws_.async_accept(req_,
            beast::bind_front_handler(&WebSocketSession::on_accept, shared_from_this()));
    }
    
    void send(const std::string& message) {
        net::post(strand_,
            [self = shared_from_this(), message]() {
                self->messages_.push_back(message);
                if (self->messages_.size() == 1) {
                    self->do_write();
                }
            });
    }
    
    void close() {
        net::post(strand_,
            [self = shared_from_this()]() {
                self->ws_.async_close(websocket::close_code::normal,
                    beast::bind_front_handler(&WebSocketSession::on_close, self));
            });
    }
    
    std::string get_id() const { return id_; }
    
    void set_handler(std::function<void(const std::string&)> on_message) {
        on_message_ = on_message;
    }
    
    void set_close_handler(std::function<void()> on_close) {
        on_close_ = on_close;
    }

private:
    void on_accept(beast::error_code ec) {
        if (ec) {
            Logger::instance().error("WebSocket accept error: %s", ec.message().c_str());
            return;
        }
        
        id_ = utils::generate_uuid();
        do_read();
    }
    
    void do_read() {
        ws_.async_read(buffer_,
            beast::bind_front_handler(&WebSocketSession::on_read, shared_from_this()));
    }
    
    void on_read(beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);
        
        if (ec) {
            if (ec != websocket::error::closed) {
                Logger::instance().error("WebSocket read error: %s", ec.message().c_str());
            }
            if (on_close_) on_close_();
            return;
        }
        
        std::string message = beast::buffers_to_string(buffer_.data());
        buffer_.consume(buffer_.size());
        
        if (on_message_) {
            on_message_(message);
        }
        
        do_read();
    }
    
    void do_write() {
        ws_.async_write(net::buffer(messages_.front()),
            beast::bind_front_handler(&WebSocketSession::on_write, shared_from_this()));
    }
    
    void on_write(beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);
        
        if (ec) {
            Logger::instance().error("WebSocket write error: %s", ec.message().c_str());
            if (on_close_) on_close_();
            return;
        }
        
        messages_.pop_front();
        if (!messages_.empty()) {
            do_write();
        }
    }
    
    void on_close(beast::error_code ec) {
        if (ec) {
            Logger::instance().error("WebSocket close error: %s", ec.message().c_str());
        }
        if (on_close_) on_close_();
    }

    websocket::stream<tcp::socket> ws_;
    net::strand<net::any_io_executor> strand_;
    http::request<http::string_body> req_;
    beast::flat_buffer buffer_;
    std::deque<std::string> messages_;
    std::string id_;
    std::function<void(const std::string&)> on_message_;
    std::function<void()> on_close_;
};

// Router
class Router {
public:
    struct Route {
        std::string path;
        HttpMethod method;
        Handler handler;
        std::vector<MiddlewareFunc> middlewares;
    };
    
    Router& route(HttpMethod method, const std::string& path, Handler handler) {
        Route route;
        route.path = path;
        route.method = method;
        route.handler = handler;
        route.middlewares = global_middlewares_;
        routes_.push_back(route);
        return *this;
    }
    
    Router& get(const std::string& path, Handler handler) {
        return route(http::verb::get, path, handler);
    }
    
    Router& post(const std::string& path, Handler handler) {
        return route(http::verb::post, path, handler);
    }
    
    Router& put(const std::string& path, Handler handler) {
        return route(http::verb::put, path, handler);
    }
    
    Router& patch(const std::string& path, Handler handler) {
        return route(http::verb::patch, path, handler);
    }
    
    Router& del(const std::string& path, Handler handler) {
        return route(http::verb::delete_, path, handler);
    }
    
    Router& head(const std::string& path, Handler handler) {
        return route(http::verb::head, path, handler);
    }
    
    Router& options(const std::string& path, Handler handler) {
        return route(http::verb::options, path, handler);
    }
    
    Router& ws(const std::string& path, WebSocketHandler handler) {
        ws_routes_[path] = handler;
        return *this;
    }
    
    Router& use(MiddlewareFunc middleware) {
        global_middlewares_.push_back(middleware);
        return *this;
    }
    
    Router& static_files(const std::string& url_prefix, const std::string& directory) {
        static_routes_[url_prefix] = directory;
        return *this;
    }
    
    std::optional<Route> find_route(HttpMethod method, const std::string& path) const {
        for (const auto& route : routes_) {
            if (route.method != method) continue;
            
            auto params = match_path(route.path, path);
            if (params) {
                return route;
            }
        }
        return std::nullopt;
    }
    
    std::optional<WebSocketHandler> find_ws_route(const std::string& path) const {
        auto it = ws_routes_.find(path);
        if (it != ws_routes_.end()) {
            return it->second;
        }
        return std::nullopt;
    }
    
    std::optional<std::pair<std::string, std::string>> find_static_route(
        const std::string& path) const {
        
        for (const auto& [prefix, directory] : static_routes_) {
            if (path.find(prefix) == 0) {
                std::string relative_path = path.substr(prefix.length());
                if (relative_path.front() == '/') {
                    relative_path = relative_path.substr(1);
                }
                return std::make_pair(directory, relative_path);
            }
        }
        return std::nullopt;
    }
    
    static std::optional<Params> match_path(const std::string& pattern,
                                           const std::string& path) {
        Params params;
        
        std::vector<std::string> pattern_parts;
        std::vector<std::string> path_parts;
        
        boost::split(pattern_parts, pattern, boost::is_any_of("/"));
        boost::split(path_parts, path, boost::is_any_of("/"));
        
        if (pattern_parts.size() != path_parts.size()) {
            return std::nullopt;
        }
        
        for (size_t i = 0; i < pattern_parts.size(); ++i) {
            if (pattern_parts[i].empty() && path_parts[i].empty()) {
                continue;
            }
            
            if (pattern_parts[i].front() == ':') {
                std::string param_name = pattern_parts[i].substr(1);
                params[param_name] = path_parts[i];
            } else if (pattern_parts[i] != path_parts[i]) {
                return std::nullopt;
            }
        }
        
        return params;
    }

private:
    std::vector<Route> routes_;
    std::unordered_map<std::string, WebSocketHandler> ws_routes_;
    std::unordered_map<std::string, std::string> static_routes_;
    std::vector<MiddlewareFunc> global_middlewares_;
};

// HTTP connection handler
template<typename Derived>
class HttpConnection : public std::enable_shared_from_this<Derived> {
public:
    HttpConnection(tcp::socket socket, Router& router, SessionManager& session_manager,
                   RateLimiter& rate_limiter)
        : stream_(std::move(socket))
        , router_(router)
        , session_manager_(session_manager)
        , rate_limiter_(rate_limiter) {}
    
    void run() {
        net::dispatch(stream_.get_executor(),
            beast::bind_front_handler(&HttpConnection::do_read,
                                    this->shared_from_this()));
    }

protected:
    tcp::socket& socket() {
        return static_cast<Derived&>(*this).socket();
    }
    
    void do_read() {
        request_ = {};
        
        stream_.expires_after(std::chrono::seconds(30));
        
        http::async_read(stream_, buffer_, request_,
            beast::bind_front_handler(&HttpConnection::on_read,
                                    this->shared_from_this()));
    }
    
    void on_read(beast::error_code ec, std::size_t bytes_transferred) {
        boost::ignore_unused(bytes_transferred);
        
        if (ec == http::error::end_of_stream) {
            return do_close();
        }
        
        if (ec) {
            Logger::instance().error("Read error: %s", ec.message().c_str());
            return;
        }
        
        handle_request();
    }
    
    void handle_request() {
        auto remote_endpoint = socket().remote_endpoint();
        std::string remote_addr = remote_endpoint.address().to_string();
        
        // Rate limiting
        if (!rate_limiter_.allow(remote_addr)) {
            send_response(create_error_response(http::status::too_many_requests,
                                              "Too many requests"));
            return;
        }
        
        // Check for WebSocket upgrade
        if (websocket::is_upgrade(request_)) {
            std::string path = std::string(request_.target());
            auto ws_handler = router_.find_ws_route(path);
            
            if (ws_handler) {
                auto ws_session = std::make_shared<WebSocketSession>(std::move(socket()));
                (*ws_handler)(ws_session);
                ws_session->run(std::move(request_));
                return;
            }
        }
        
        Request req(std::move(request_), remote_addr);
        Response res;
        
        try {
            // Handle session
            std::string session_id = req.cookie("session_id");
            auto session = session_manager_.get_session(session_id);
            
            if (!session) {
                session = session_manager_.create_session();
                res.cookie("session_id", session->id, "/", 0, false, true);
            }
            
            req.set_attribute("session", session);
            
            // Check for static file
            auto static_route = router_.find_static_route(req.path());
            if (static_route) {
                std::string full_path = fs::path(static_route->first) / static_route->second;
                res.file(full_path);
                send_response(res.build());
                return;
            }
            
            // Find route
            auto route = router_.find_route(req.method(), req.path());
            if (!route) {
                res.status(http::status::not_found).text("Not found");
                send_response(res.build());
                return;
            }
            
            // Apply route params
            auto params = Router::match_path(route->path, req.path());
            if (params) {
                for (const auto& [key, value] : *params) {
                    req.set_param(key, value);
                }
            }
            
            // Execute middlewares
            execute_middlewares(route->middlewares, req, res, 0,
                [this, &route, &req, &res]() {
                    route->handler(req, res);
                    send_response(res.build());
                });
            
        } catch (const std::exception& e) {
            Logger::instance().error("Request handler error: %s", e.what());
            send_response(create_error_response(http::status::internal_server_error,
                                              "Internal server error"));
        }
    }
    
    void execute_middlewares(const std::vector<MiddlewareFunc>& middlewares,
                           Request& req, Response& res, size_t index,
                           std::function<void()> final_handler) {
        if (index >= middlewares.size()) {
            final_handler();
            return;
        }
        
        middlewares[index](req, res, [this, &middlewares, &req, &res, index, final_handler]() {
            execute_middlewares(middlewares, req, res, index + 1, final_handler);
        });
    }
    
    void send_response(http::response<http::string_body> res) {
        auto sp = std::make_shared<http::response<http::string_body>>(std::move(res));
        
        http::async_write(stream_, *sp,
            [self = this->shared_from_this(), sp](beast::error_code ec, std::size_t) {
                self->on_write(ec, sp->need_eof());
            });
    }
    
    void on_write(beast::error_code ec, bool close) {
        if (ec) {
            Logger::instance().error("Write error: %s", ec.message().c_str());
            return;
        }
        
        if (close) {
            return do_close();
        }
        
        do_read();
    }
    
    void do_close() {
        beast::error_code ec;
        socket().shutdown(tcp::socket::shutdown_send, ec);
    }
    
    http::response<http::string_body> create_error_response(http::status status,
                                                           const std::string& message) {
        http::response<http::string_body> res{status, 11};
        res.set(http::field::server, "BoostWebFramework/1.0");
        res.set(http::field::content_type, "text/plain");
        res.body() = message;
        res.prepare_payload();
        return res;
    }

    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> request_;
    Router& router_;
    SessionManager& session_manager_;
    RateLimiter& rate_limiter_;
};

// Plain HTTP connection
class PlainHttpConnection : public HttpConnection<PlainHttpConnection> {
public:
    PlainHttpConnection(tcp::socket socket, Router& router,
                       SessionManager& session_manager, RateLimiter& rate_limiter)
        : HttpConnection<PlainHttpConnection>(std::move(socket), router,
                                            session_manager, rate_limiter) {}
    
    tcp::socket& socket() {
        return stream_.socket();
    }
};

// HTTPS connection
class SslHttpConnection : public HttpConnection<SslHttpConnection> {
public:
    SslHttpConnection(tcp::socket socket, ssl::context& ctx, Router& router,
                     SessionManager& session_manager, RateLimiter& rate_limiter)
        : HttpConnection<SslHttpConnection>(std::move(socket), router,
                                          session_manager, rate_limiter)
        , stream_(std::move(stream_.socket()), ctx) {}
    
    void run() {
        stream_.async_handshake(ssl::stream_base::server,
            beast::bind_front_handler(&SslHttpConnection::on_handshake,
                                    shared_from_this()));
    }
    
    tcp::socket& socket() {
        return stream_.next_layer();
    }

private:
    void on_handshake(beast::error_code ec) {
        if (ec) {
            Logger::instance().error("SSL handshake error: %s", ec.message().c_str());
            return;
        }
        
        HttpConnection<SslHttpConnection>::run();
    }

    beast::ssl_stream<tcp::socket> stream_;
};

// HTTP Server
class HttpServer {
public:
    struct Config {
        std::string host = "0.0.0.0";
        uint16_t port = 8080;
        size_t num_threads = std::thread::hardware_concurrency();
        bool use_ssl = false;
        std::string cert_file;
        std::string key_file;
        size_t max_requests_per_minute = 600;
        std::chrono::minutes session_timeout{30};
        std::string log_file;
        Logger::Level log_level = Logger::INFO;
    };
    
    HttpServer(const Config& config = Config())
        : config_(config)
        , ioc_(config.num_threads)
        , acceptor_(ioc_)
        , ssl_context_(ssl::context::sslv23)
        , session_manager_(config.session_timeout)
        , rate_limiter_(config.max_requests_per_minute, std::chrono::seconds(60)) {
        
        // Initialize logger
        Logger::instance().init(config.log_file, config.log_level);
        
        // Setup SSL if enabled
        if (config.use_ssl) {
            setup_ssl();
        }
    }
    
    Router& router() { return router_; }
    SessionManager& sessions() { return session_manager_; }
    RateLimiter& rate_limiter() { return rate_limiter_; }
    
    void run() {
        auto const address = net::ip::make_address(config_.host);
        auto const port = config_.port;
        
        tcp::endpoint endpoint{address, port};
        
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(net::socket_base::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen(net::socket_base::max_listen_connections);
        
        Logger::instance().info("Server listening on %s:%d %s",
                               config_.host.c_str(), port,
                               config_.use_ssl ? "(HTTPS)" : "(HTTP)");
        
        // Start session cleanup timer
        start_session_cleanup();
        
        // Accept connections
        do_accept();
        
        // Run the I/O service on the requested number of threads
        std::vector<std::thread> threads;
        threads.reserve(config_.num_threads - 1);
        
        for (size_t i = 0; i < config_.num_threads - 1; ++i) {
            threads.emplace_back([this] { ioc_.run(); });
        }
        
        ioc_.run();
        
        // Wait for all threads to complete
        for (auto& t : threads) {
            t.join();
        }
    }
    
    void stop() {
        ioc_.stop();
        Logger::instance().info("Server stopped");
    }

private:
    void setup_ssl() {
        ssl_context_.set_options(
            ssl::context::default_workarounds |
            ssl::context::no_sslv2 |
            ssl::context::single_dh_use);
        
        ssl_context_.use_certificate_chain_file(config_.cert_file);
        ssl_context_.use_private_key_file(config_.key_file, ssl::context::pem);
        
        Logger::instance().info("SSL configured with cert: %s", config_.cert_file.c_str());
    }
    
    void do_accept() {
        acceptor_.async_accept(
            [this](beast::error_code ec, tcp::socket socket) {
                if (!ec) {
                    if (config_.use_ssl) {
                        std::make_shared<SslHttpConnection>(
                            std::move(socket), ssl_context_, router_,
                            session_manager_, rate_limiter_)->run();
                    } else {
                        std::make_shared<PlainHttpConnection>(
                            std::move(socket), router_,
                            session_manager_, rate_limiter_)->run();
                    }
                } else {
                    Logger::instance().error("Accept error: %s", ec.message().c_str());
                }
                
                do_accept();
            });
    }
    
    void start_session_cleanup() {
        auto timer = std::make_shared<net::steady_timer>(ioc_);
        timer->expires_after(std::chrono::minutes(5));
        
        timer->async_wait([this, timer](beast::error_code ec) {
            if (!ec) {
                session_manager_.cleanup_expired();
                start_session_cleanup();
            }
        });
    }

    Config config_;
    net::io_context ioc_;
    tcp::acceptor acceptor_;
    ssl::context ssl_context_;
    Router router_;
    SessionManager session_manager_;
    RateLimiter rate_limiter_;
};

// Middleware examples
namespace middleware {
    inline MiddlewareFunc cors(const std::string& origin = "*") {
        return [origin](Request& req, Response& res, std::function<void()> next) {
            res.header("Access-Control-Allow-Origin", origin);
            res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
            res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
            
            if (req.method() == http::verb::options) {
                res.status(http::status::no_content);
                return;
            }
            
            next();
        };
    }
    
    inline MiddlewareFunc logger() {
        return [](Request& req, Response& res, std::function<void()> next) {
            auto start = std::chrono::high_resolution_clock::now();
            
            next();
            
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
            
            Logger::instance().info("%s %s - %dms",
                                   req.method_string().c_str(),
                                   req.path().c_str(),
                                   duration.count());
        };
    }
    
    inline MiddlewareFunc auth(std::function<bool(Request&)> validator) {
        return [validator](Request& req, Response& res, std::function<void()> next) {
            if (!validator(req)) {
                res.status(http::status::unauthorized).text("Unauthorized");
                return;
            }
            next();
        };
    }
    
    inline MiddlewareFunc body_parser(size_t max_size = 10 * 1024 * 1024) {
        return [max_size](Request& req, Response& res, std::function<void()> next) {
            if (req.body().size() > max_size) {
                res.status(http::status::payload_too_large).text("Payload too large");
                return;
            }
            next();
        };
    }
}

} // namespace bwf
