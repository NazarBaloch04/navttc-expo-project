#define NOMINMAX
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <commdlg.h>
#include <shlobj.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <ctime>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <stdexcept>
#include <sstream>
#include <string>
#include <thread>
#include <cwctype>
#include <utility>
#include <vector>

#pragma comment(lib, "Comctl32.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "Comdlg32.lib")

namespace fs = std::filesystem;

struct sqlite3;
struct sqlite3_stmt;

namespace {

constexpr wchar_t kWindowClass[] = L"RansomwareBehaviorMonitorWindow";
constexpr wchar_t kWindowTitle[] = L"Ransomware Behavior Monitor";
constexpr int kSidebarWidth = 238;
constexpr int kHeaderHeight = 82;
constexpr UINT_PTR kUiTimer = 1;
constexpr int kSqliteRow = 100;
constexpr int kDefaultModificationThreshold = 8;
constexpr int kDefaultRenameThreshold = 5;
constexpr int kDefaultDeletionThreshold = 8;
constexpr int kDefaultOperationThreshold = 25;

struct SqliteApi {
    HMODULE library = nullptr;
    int(__cdecl* open)(const char*, sqlite3**) = nullptr;
    int(__cdecl* close)(sqlite3*) = nullptr;
    int(__cdecl* exec)(sqlite3*, const char*, int(__cdecl*)(void*, int, char**, char**), void*, char**) = nullptr;
    int(__cdecl* prepare)(sqlite3*, const char*, int, sqlite3_stmt**, const char**) = nullptr;
    int(__cdecl* step)(sqlite3_stmt*) = nullptr;
    int(__cdecl* finalize)(sqlite3_stmt*) = nullptr;
    const unsigned char*(__cdecl* columnText)(sqlite3_stmt*, int) = nullptr;
    int(__cdecl* columnInt)(sqlite3_stmt*, int) = nullptr;
    long long(__cdecl* columnInt64)(sqlite3_stmt*, int) = nullptr;
    long long(__cdecl* lastInsertId)(sqlite3*) = nullptr;
    const char*(__cdecl* errorMessage)(sqlite3*) = nullptr;
    void(__cdecl* freeMemory)(void*) = nullptr;
    int(__cdecl* busyTimeout)(sqlite3*, int) = nullptr;

    template <typename T>
    bool Load(T& target, const char* name) {
        target = reinterpret_cast<T>(GetProcAddress(library, name));
        return target != nullptr;
    }

    bool Initialize() {
        library = LoadLibraryW(L"winsqlite3.dll");
        if (!library) {
            library = LoadLibraryW(L"sqlite3.dll");
        }
        if (!library) {
            return false;
        }
        return Load(open, "sqlite3_open") &&
            Load(close, "sqlite3_close") &&
            Load(exec, "sqlite3_exec") &&
            Load(prepare, "sqlite3_prepare_v2") &&
            Load(step, "sqlite3_step") &&
            Load(finalize, "sqlite3_finalize") &&
            Load(columnText, "sqlite3_column_text") &&
            Load(columnInt, "sqlite3_column_int") &&
            Load(columnInt64, "sqlite3_column_int64") &&
            Load(lastInsertId, "sqlite3_last_insert_rowid") &&
            Load(errorMessage, "sqlite3_errmsg") &&
            Load(freeMemory, "sqlite3_free") &&
            Load(busyTimeout, "sqlite3_busy_timeout");
    }

    ~SqliteApi() {
        if (library) {
            FreeLibrary(library);
        }
    }
};

std::string ToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
    if (size <= 0) {
        return {};
    }
    std::string result(static_cast<size_t>(size), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring FromUtf8(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    const int size = MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
    if (size <= 0) {
        return {};
    }
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

std::string EscapeSql(const std::string& text) {
    std::string escaped;
    escaped.reserve(text.size());
    for (const char character : text) {
        escaped.push_back(character);
        if (character == '\'') {
            escaped.push_back('\'');
        }
    }
    return escaped;
}

std::wstring CurrentTimestamp() {
    const std::time_t now = std::time(nullptr);
    std::tm localTime{};
    localtime_s(&localTime, &now);
    std::wostringstream output;
    output << std::put_time(&localTime, L"%Y-%m-%d %H:%M:%S");
    return output.str();
}

std::wstring Lower(std::wstring text) {
    std::transform(text.begin(), text.end(), text.begin(), [](wchar_t character) {
        return static_cast<wchar_t>(std::towlower(character));
    });
    return text;
}

bool StartsWithInsensitive(const std::wstring& text, const std::wstring& prefix) {
    if (text.size() < prefix.size()) {
        return false;
    }
    return Lower(text.substr(0, prefix.size())) == Lower(prefix);
}

enum class Page {
    Dashboard,
    Monitoring,
    Detection,
    Alerts,
    Logs,
    Analytics,
    Settings,
    About
};

struct Event {
    long long id = 0;
    std::wstring timestamp;
    std::wstring filename;
    std::wstring path;
    std::wstring type;
    std::wstring rule;
    int score = 0;
    std::wstring level;
    std::wstring details;
    bool simulated = false;
    bool reviewed = false;
};

struct RawEvent {
    std::wstring path;
    std::wstring type;
    std::wstring details;
    bool simulated = false;
};

struct Metrics {
    long long events = 0;
    long long uniqueFiles = 0;
    long long suspicious = 0;
    long long highRisk = 0;
    long long lowRisk = 0;
    long long mediumRisk = 0;
    long long simulated = 0;
};

class EventDatabase {
public:
    ~EventDatabase() {
        Close();
    }

    bool Open(const fs::path& path, std::wstring& error) {
        if (!api_.Initialize()) {
            error = L"SQLite could not be loaded. Install Windows 10 or newer, or place sqlite3.dll beside the application.";
            return false;
        }
        databasePath_ = path;
        const std::string utf8Path = ToUtf8(path.wstring());
        if (api_.open(utf8Path.c_str(), &database_) != 0) {
            error = LastError();
            return false;
        }
        api_.busyTimeout(database_, 3000);
        const char* schema =
            "PRAGMA journal_mode=WAL;"
            "CREATE TABLE IF NOT EXISTS events ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "timestamp TEXT NOT NULL,"
            "filename TEXT NOT NULL,"
            "path TEXT NOT NULL,"
            "event_type TEXT NOT NULL,"
            "detection_rule TEXT NOT NULL,"
            "risk_score INTEGER NOT NULL,"
            "risk_level TEXT NOT NULL,"
            "details TEXT NOT NULL,"
            "simulated INTEGER NOT NULL DEFAULT 0,"
            "reviewed INTEGER NOT NULL DEFAULT 0);"
            "CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);";
        if (!Execute(schema, error)) {
            Close();
            return false;
        }
        return true;
    }

    bool Insert(Event& event, std::wstring& error) {
        const std::string sql =
            "INSERT INTO events(timestamp,filename,path,event_type,detection_rule,risk_score,risk_level,details,simulated,reviewed) VALUES('" +
            EscapeSql(ToUtf8(event.timestamp)) + "','" +
            EscapeSql(ToUtf8(event.filename)) + "','" +
            EscapeSql(ToUtf8(event.path)) + "','" +
            EscapeSql(ToUtf8(event.type)) + "','" +
            EscapeSql(ToUtf8(event.rule)) + "'," +
            std::to_string(event.score) + ",'" +
            EscapeSql(ToUtf8(event.level)) + "','" +
            EscapeSql(ToUtf8(event.details)) + "'," +
            (event.simulated ? "1" : "0") + ",0);";
        if (!Execute(sql, error)) {
            return false;
        }
        event.id = api_.lastInsertId(database_);
        return true;
    }

    bool SetReviewed(long long id, std::wstring& error) {
        return Execute("UPDATE events SET reviewed=1 WHERE id=" + std::to_string(id) + ";", error);
    }

    bool ClearEvents(std::wstring& error) {
        return Execute("DELETE FROM events;", error);
    }

    bool SetSetting(const std::wstring& key, const std::wstring& value, std::wstring& error) {
        const std::string sql = "INSERT OR REPLACE INTO settings(key,value) VALUES('" +
            EscapeSql(ToUtf8(key)) + "','" + EscapeSql(ToUtf8(value)) + "');";
        return Execute(sql, error);
    }

    std::wstring GetSetting(const std::wstring& key, const std::wstring& fallback) {
        sqlite3_stmt* statement = nullptr;
        const std::string sql = "SELECT value FROM settings WHERE key='" + EscapeSql(ToUtf8(key)) + "';";
        if (api_.prepare(database_, sql.c_str(), -1, &statement, nullptr) != 0) {
            return fallback;
        }
        std::wstring value = fallback;
        if (api_.step(statement) == kSqliteRow) {
            const unsigned char* text = api_.columnText(statement, 0);
            if (text) {
                value = FromUtf8(reinterpret_cast<const char*>(text));
            }
        }
        api_.finalize(statement);
        return value;
    }

    std::vector<Event> LoadEvents(const std::wstring& search, const std::wstring& level, size_t limit = 500) {
        std::vector<Event> events;
        std::string where;
        if (!search.empty()) {
            const std::string term = EscapeSql(ToUtf8(search));
            where += " AND (filename LIKE '%" + term + "%' OR path LIKE '%" + term + "%' OR event_type LIKE '%" + term + "%' OR details LIKE '%" + term + "%')";
        }
        if (level != L"All") {
            where += " AND risk_level='" + EscapeSql(ToUtf8(level)) + "'";
        }
        const std::string sql =
            "SELECT id,timestamp,filename,path,event_type,detection_rule,risk_score,risk_level,details,simulated,reviewed "
            "FROM events WHERE 1=1" + where + " ORDER BY id DESC LIMIT " + std::to_string(limit) + ";";
        sqlite3_stmt* statement = nullptr;
        if (api_.prepare(database_, sql.c_str(), -1, &statement, nullptr) != 0) {
            return events;
        }
        while (api_.step(statement) == kSqliteRow) {
            Event event;
            event.id = api_.columnInt64(statement, 0);
            event.timestamp = ColumnText(statement, 1);
            event.filename = ColumnText(statement, 2);
            event.path = ColumnText(statement, 3);
            event.type = ColumnText(statement, 4);
            event.rule = ColumnText(statement, 5);
            event.score = api_.columnInt(statement, 6);
            event.level = ColumnText(statement, 7);
            event.details = ColumnText(statement, 8);
            event.simulated = api_.columnInt(statement, 9) != 0;
            event.reviewed = api_.columnInt(statement, 10) != 0;
            events.push_back(std::move(event));
        }
        api_.finalize(statement);
        return events;
    }

    Metrics GetMetrics() {
        Metrics metrics;
        sqlite3_stmt* statement = nullptr;
        const char* sql =
            "SELECT COUNT(*),COUNT(DISTINCT path),"
            "SUM(CASE WHEN detection_rule<>'None' THEN 1 ELSE 0 END),"
            "SUM(CASE WHEN risk_level='High' THEN 1 ELSE 0 END),"
            "SUM(CASE WHEN risk_level='Low' THEN 1 ELSE 0 END),"
            "SUM(CASE WHEN risk_level='Medium' THEN 1 ELSE 0 END),"
            "SUM(simulated) FROM events;";
        if (api_.prepare(database_, sql, -1, &statement, nullptr) != 0) {
            return metrics;
        }
        if (api_.step(statement) == kSqliteRow) {
            metrics.events = api_.columnInt64(statement, 0);
            metrics.uniqueFiles = api_.columnInt64(statement, 1);
            metrics.suspicious = api_.columnInt64(statement, 2);
            metrics.highRisk = api_.columnInt64(statement, 3);
            metrics.lowRisk = api_.columnInt64(statement, 4);
            metrics.mediumRisk = api_.columnInt64(statement, 5);
            metrics.simulated = api_.columnInt64(statement, 6);
        }
        api_.finalize(statement);
        return metrics;
    }

    std::wstring DatabasePath() const {
        return databasePath_.wstring();
    }

    std::wstring LastError() const {
        if (!database_ || !api_.errorMessage) {
            return L"Unknown SQLite error.";
        }
        return FromUtf8(api_.errorMessage(database_));
    }

private:
    std::wstring ColumnText(sqlite3_stmt* statement, int column) const {
        const unsigned char* text = api_.columnText(statement, column);
        return text ? FromUtf8(reinterpret_cast<const char*>(text)) : L"";
    }

    bool Execute(const std::string& sql, std::wstring& error) {
        char* message = nullptr;
        if (api_.exec(database_, sql.c_str(), nullptr, nullptr, &message) == 0) {
            return true;
        }
        error = message ? FromUtf8(message) : LastError();
        if (message) {
            api_.freeMemory(message);
        }
        return false;
    }

    void Close() {
        if (database_ && api_.close) {
            api_.close(database_);
            database_ = nullptr;
        }
    }

    SqliteApi api_;
    sqlite3* database_ = nullptr;
    fs::path databasePath_;
};

struct Thresholds {
    int modifications = kDefaultModificationThreshold;
    int renames = kDefaultRenameThreshold;
    int deletions = kDefaultDeletionThreshold;
    int operations = kDefaultOperationThreshold;
};

class DetectionEngine {
public:
    explicit DetectionEngine(Thresholds& thresholds) : thresholds_(thresholds) {}

    Event Assess(const RawEvent& raw) {
        const auto now = std::chrono::steady_clock::now();
        window_.push_back({raw, now});
        while (!window_.empty() && now - window_.front().second > std::chrono::seconds(10)) {
            window_.pop_front();
        }

        int modifications = 0;
        int renames = 0;
        int deletions = 0;
        int operations = 0;
        int extensionChanges = 0;
        for (const auto& entry : window_) {
            if (entry.first.simulated != raw.simulated) continue;
            const std::wstring& type = entry.first.type;
            if (type == L"Modified") ++modifications;
            if (type == L"Renamed") {
                ++renames;
                if (fs::path(entry.first.path).extension() != fs::path(entry.first.details).extension()) {
                    ++extensionChanges;
                }
            }
            if (type == L"Deleted") ++deletions;
            if (type == L"Created" || type == L"Modified" || type == L"Renamed" || type == L"Deleted") ++operations;
        }

        std::vector<std::wstring> rules;
        int score = 0;
        if (modifications >= thresholds_.modifications) {
            rules.push_back(L"Rapid file modification");
            score += 35;
        }
        if (renames >= thresholds_.renames) {
            rules.push_back(L"Repeated file renaming");
            score += 35;
        }
        if (deletions >= thresholds_.deletions) {
            rules.push_back(L"High file deletion activity");
            score += 35;
        }
        if (extensionChanges >= 3) {
            rules.push_back(L"Repeated file extension changes");
            score += 20;
        }
        if (operations >= thresholds_.operations) {
            rules.push_back(L"High-frequency file operations");
            score += 20;
        }
        if (rules.size() >= 2) {
            rules.push_back(L"Combined suspicious behavior");
            score += 15;
        }
        score = (std::min)(score, 100);

        Event event;
        event.timestamp = CurrentTimestamp();
        event.path = raw.path;
        event.filename = fs::path(raw.path).filename().wstring();
        if (event.filename.empty()) {
            event.filename = raw.path;
        }
        event.type = raw.type;
        event.simulated = raw.simulated;
        event.score = score;
        event.level = score >= 60 ? L"High" : (score >= 30 ? L"Medium" : L"Low");
        if (rules.empty()) {
            event.rule = L"None";
        } else {
            for (size_t index = 0; index < rules.size(); ++index) {
                if (index != 0) event.rule += L", ";
                event.rule += rules[index];
            }
        }
        event.details = raw.details;
        if (event.details.empty()) {
            event.details = L"File " + Lower(raw.type) + L" activity observed.";
        }
        if (!rules.empty()) {
            event.details += L" Rule(s): " + event.rule + L".";
        }
        event.details += L" Risk score: " + std::to_wstring(event.score) + L"/100 (" + event.level + L").";
        if (event.level == L"High") {
            event.details += L" Recommended action: review this activity and investigate with trusted security tools.";
        } else if (event.level == L"Medium") {
            event.details += L" Recommended action: review the event and confirm the activity was expected.";
        } else {
            event.details += L" Recommended action: no immediate action; continue monitoring.";
        }
        event.details += L" Risk is heuristic and is not proof of infection.";
        return event;
    }

    void Reset() {
        window_.clear();
    }

private:
    Thresholds& thresholds_;
    std::deque<std::pair<RawEvent, std::chrono::steady_clock::time_point>> window_;
};

struct Monitor {
    std::thread worker;
    HANDLE stopEvent = nullptr;
    std::atomic<bool> running{false};
    std::atomic<bool> ready{false};
    std::wstring folder;

    ~Monitor() {
        Stop();
    }

    void Stop() {
        if (stopEvent) {
            SetEvent(stopEvent);
        }
        if (worker.joinable()) {
            worker.join();
        }
        if (stopEvent) {
            CloseHandle(stopEvent);
            stopEvent = nullptr;
        }
        running = false;
        ready = false;
    }
};

struct AppState {
    HWND window = nullptr;
    EventDatabase database;
    DetectionEngine* detector = nullptr;
    Thresholds thresholds;
    Monitor monitor;
    std::wstring selectedFolder;
    std::wstring databaseDirectory;
    std::wstring simulationDirectory;
    std::wstring lastActivity = L"No events recorded yet";
    std::wstring statusMessage;
    std::wstring searchText;
    std::wstring alertFilter = L"All";
    std::wstring logFilter = L"All";
    std::vector<Event> events;
    std::vector<std::wstring> navLabels{
        L"Dashboard", L"Live Monitoring", L"Threat Detection", L"Security Alerts",
        L"Event Logs", L"Analytics & Reports", L"Settings", L"About Project"
    };
    std::vector<Page> navPages{
        Page::Dashboard, Page::Monitoring, Page::Detection, Page::Alerts,
        Page::Logs, Page::Analytics, Page::Settings, Page::About
    };
    std::mutex incomingMutex;
    std::deque<RawEvent> incoming;
    Page page = Page::Dashboard;
    bool searchFocused = false;
    bool notificationsEnabled = true;
    int selectedEvent = -1;
};

AppState* g_app = nullptr;

constexpr COLORREF kBackground = RGB(11, 17, 32);
constexpr COLORREF kSidebar = RGB(17, 24, 39);
constexpr COLORREF kCard = RGB(23, 32, 51);
constexpr COLORREF kCardLight = RGB(30, 41, 63);
constexpr COLORREF kBlue = RGB(59, 130, 246);
constexpr COLORREF kCyan = RGB(6, 182, 212);
constexpr COLORREF kGreen = RGB(34, 197, 94);
constexpr COLORREF kOrange = RGB(245, 158, 11);
constexpr COLORREF kRed = RGB(239, 68, 68);
constexpr COLORREF kText = RGB(248, 250, 252);
constexpr COLORREF kMuted = RGB(148, 163, 184);
constexpr COLORREF kBorder = RGB(48, 61, 82);

void FillRectColor(HDC dc, const RECT& rect, COLORREF color) {
    HBRUSH brush = CreateSolidBrush(color);
    FillRect(dc, &rect, brush);
    DeleteObject(brush);
}

void RoundedRect(HDC dc, const RECT& rect, COLORREF color, int radius = 12) {
    HBRUSH brush = CreateSolidBrush(color);
    HPEN pen = CreatePen(PS_SOLID, 1, color);
    HGDIOBJ oldBrush = SelectObject(dc, brush);
    HGDIOBJ oldPen = SelectObject(dc, pen);
    RoundRect(dc, rect.left, rect.top, rect.right, rect.bottom, radius, radius);
    SelectObject(dc, oldBrush);
    SelectObject(dc, oldPen);
    DeleteObject(brush);
    DeleteObject(pen);
}

void DrawTextLine(HDC dc, const std::wstring& text, int x, int y, int width, int height,
                  COLORREF color, int size, int weight = FW_NORMAL, UINT format = DT_LEFT | DT_VCENTER | DT_SINGLELINE) {
    HFONT font = CreateFontW(-MulDiv(size, GetDeviceCaps(dc, LOGPIXELSY), 72), 0, 0, 0, weight,
                             FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                             CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
                             L"Segoe UI");
    HGDIOBJ previous = SelectObject(dc, font);
    SetBkMode(dc, TRANSPARENT);
    SetTextColor(dc, color);
    RECT rect{x, y, x + width, y + height};
    DrawTextW(dc, text.c_str(), static_cast<int>(text.size()), &rect, format);
    SelectObject(dc, previous);
    DeleteObject(font);
}

void DrawButton(HDC dc, const RECT& rect, const std::wstring& label, COLORREF color, bool enabled = true) {
    RoundedRect(dc, rect, enabled ? color : kCardLight, 8);
    DrawTextLine(dc, label, rect.left + 8, rect.top, rect.right - rect.left - 16, rect.bottom - rect.top,
                 enabled ? kText : kMuted, 10, FW_SEMIBOLD, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

COLORREF LevelColor(const std::wstring& level) {
    if (level == L"High") return kRed;
    if (level == L"Medium") return kOrange;
    return kGreen;
}

std::wstring FormatNumber(long long value) {
    return std::to_wstring(value);
}

void DrawPanel(HDC dc, int x, int y, int width, int height, const std::wstring& title,
               const std::wstring& subtitle = L"") {
    RECT rect{x, y, x + width, y + height};
    RoundedRect(dc, rect, kCard, 12);
    DrawTextLine(dc, title, x + 20, y + 15, width - 40, 26, kText, 12, FW_SEMIBOLD);
    if (!subtitle.empty()) {
        DrawTextLine(dc, subtitle, x + 20, y + 42, width - 40, 20, kMuted, 9);
    }
}

void DrawMetricCard(HDC dc, int x, int y, int width, const std::wstring& label,
                    const std::wstring& value, const std::wstring& footnote, COLORREF accent) {
    RECT rect{x, y, x + width, y + 118};
    RoundedRect(dc, rect, kCard, 12);
    RECT bar{x, y + 14, x + 4, y + 48};
    FillRectColor(dc, bar, accent);
    DrawTextLine(dc, label, x + 18, y + 14, width - 32, 24, kMuted, 9, FW_SEMIBOLD);
    DrawTextLine(dc, value, x + 18, y + 40, width - 32, 42, kText, 24, FW_BOLD);
    DrawTextLine(dc, footnote, x + 18, y + 85, width - 32, 18, kMuted, 8);
}

void DrawTag(HDC dc, int x, int y, const std::wstring& label, COLORREF color) {
    RECT rect{x, y, x + 88, y + 24};
    RoundedRect(dc, rect, color, 8);
    DrawTextLine(dc, label, x + 3, y, 82, 24, kText, 8, FW_SEMIBOLD, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

std::wstring EventDisplayName(const Event& event) {
    std::wstring name = event.filename;
    if (event.simulated) {
        name += L"  [SIMULATED]";
    }
    if (event.reviewed) {
        name += L"  [REVIEWED]";
    }
    return name;
}

void DrawEventTable(HDC dc, const std::vector<Event>& events, int x, int y, int width, int height) {
    const int rowHeight = 31;
    DrawTextLine(dc, L"TIME", x + 18, y, 110, 22, kMuted, 8, FW_SEMIBOLD);
    DrawTextLine(dc, L"FILE / ACTIVITY", x + 130, y, width / 2, 22, kMuted, 8, FW_SEMIBOLD);
    DrawTextLine(dc, L"TYPE", x + width * 2 / 3, y, 100, 22, kMuted, 8, FW_SEMIBOLD);
    DrawTextLine(dc, L"RISK", x + width - 110, y, 80, 22, kMuted, 8, FW_SEMIBOLD);
    int rowY = y + 26;
    const int maxRows = (height - 28) / rowHeight;
    for (int index = 0; index < maxRows && index < static_cast<int>(events.size()); ++index) {
        const Event& event = events[static_cast<size_t>(index)];
        if (index % 2 == 0) {
            RECT stripe{x + 10, rowY, x + width - 10, rowY + rowHeight};
            RoundedRect(dc, stripe, kCardLight, 5);
        }
        DrawTextLine(dc, event.timestamp.size() >= 16 ? event.timestamp.substr(11, 8) : event.timestamp,
                     x + 18, rowY, 105, rowHeight, kMuted, 8);
        std::wstring filename = EventDisplayName(event);
        if (filename.size() > 33) filename = filename.substr(0, 30) + L"...";
        DrawTextLine(dc, filename, x + 130, rowY, width / 2 - 15, rowHeight, kText, 8);
        DrawTextLine(dc, event.type, x + width * 2 / 3, rowY, 100, rowHeight, kMuted, 8);
        DrawTag(dc, x + width - 110, rowY + 4, event.level, LevelColor(event.level));
        rowY += rowHeight;
    }
    if (events.empty()) {
        DrawTextLine(dc, L"No events yet. Select a folder and start monitoring, or run the safe demo.",
                     x + 20, rowY + 10, width - 40, 38, kMuted, 9);
    }
}

std::vector<Event> RecentEvents(AppState& app, size_t count = 8) {
    std::vector<Event> result;
    const size_t limit = (std::min)(count, app.events.size());
    result.insert(result.end(), app.events.begin(), app.events.begin() + static_cast<std::ptrdiff_t>(limit));
    return result;
}

std::vector<Event> PageEvents(AppState& app, bool alertsOnly) {
    std::vector<Event> result;
    const std::wstring filter = alertsOnly ? app.alertFilter : app.logFilter;
    for (const auto& event : app.events) {
        if (alertsOnly && event.rule == L"None") continue;
        if (filter != L"All" && event.level != filter) continue;
        if (!app.searchText.empty()) {
            const std::wstring haystack = Lower(event.filename + L" " + event.path + L" " + event.details);
            if (haystack.find(Lower(app.searchText)) == std::wstring::npos) continue;
        }
        result.push_back(event);
    }
    return result;
}

void DrawBar(HDC dc, int x, int y, int width, int barHeight, double fraction, COLORREF color, const std::wstring& label, const std::wstring& value) {
    DrawTextLine(dc, label, x, y, 130, barHeight, kMuted, 9);
    RECT track{x + 135, y + barHeight / 2 - 5, x + width - 55, y + barHeight / 2 + 5};
    RoundedRect(dc, track, kCardLight, 6);
    if (fraction > 0) {
        RECT fill = track;
        fill.right = fill.left + static_cast<LONG>((track.right - track.left) * (std::min)(fraction, 1.0));
        RoundedRect(dc, fill, color, 6);
    }
    DrawTextLine(dc, value, x + width - 48, y, 45, barHeight, kText, 9, FW_SEMIBOLD, DT_RIGHT | DT_VCENTER | DT_SINGLELINE);
}

void DrawPageHeader(HDC dc, const std::wstring& title, const std::wstring& subtitle) {
    DrawTextLine(dc, title, kSidebarWidth + 32, 25, 690, 34, kText, 20, FW_BOLD);
    DrawTextLine(dc, subtitle, kSidebarWidth + 34, 55, 820, 22, kMuted, 9);
}

void DrawDashboard(HDC dc, AppState& app, int width, int height, const Metrics& metrics) {
    DrawPageHeader(dc, L"Security overview", L"Live protection status and activity from this device.");
    const int x = kSidebarWidth + 30;
    const int available = width - x - 30;
    const int gap = 14;
    const int cardWidth = (available - gap * 3) / 4;
    DrawMetricCard(dc, x, 111, cardWidth, L"FILES OBSERVED", FormatNumber(metrics.uniqueFiles), L"Unique monitored paths", kBlue);
    DrawMetricCard(dc, x + cardWidth + gap, 111, cardWidth, L"EVENTS RECORDED", FormatNumber(metrics.events), L"Persisted in the local database", kCyan);
    DrawMetricCard(dc, x + (cardWidth + gap) * 2, 111, cardWidth, L"SUSPICIOUS EVENTS", FormatNumber(metrics.suspicious), L"Reached a detection threshold", kOrange);
    DrawMetricCard(dc, x + (cardWidth + gap) * 3, 111, cardWidth, L"HIGH-RISK EVENTS", FormatNumber(metrics.highRisk), L"Heuristic score of 60 or above", kRed);

    const int panelY = 246;
    const int half = (available - 16) / 2;
    DrawPanel(dc, x, panelY, half, 150, L"Protection status", L"Only the explicitly selected folder is monitored.");
    DrawTag(dc, x + 20, panelY + 70, app.monitor.running ? L"MONITORING" : L"STOPPED",
            app.monitor.running ? kGreen : kCardLight);
    DrawTextLine(dc, L"Selected folder", x + 132, panelY + 68, half - 150, 21, kMuted, 8);
    std::wstring folder = app.selectedFolder.empty() ? L"No folder selected" : app.selectedFolder;
    if (folder.size() > 68) folder = L"..." + folder.substr(folder.size() - 65);
    DrawTextLine(dc, folder, x + 132, panelY + 89, half - 150, 35, kText, 9, FW_NORMAL, DT_LEFT | DT_TOP | DT_WORDBREAK);
    DrawTextLine(dc, L"Last activity: " + app.lastActivity, x + 20, panelY + 119, half - 40, 20, kMuted, 8);

    DrawPanel(dc, x + half + 16, panelY, half, 150, L"Risk distribution", L"Heuristic classification across recorded events.");
    const long long total = (std::max)(1LL, metrics.events);
    DrawBar(dc, x + half + 34, panelY + 58, half - 38, 22, static_cast<double>(metrics.lowRisk) / total, kGreen, L"Low", FormatNumber(metrics.lowRisk));
    DrawBar(dc, x + half + 34, panelY + 86, half - 38, 22, static_cast<double>(metrics.mediumRisk) / total, kOrange, L"Medium", FormatNumber(metrics.mediumRisk));
    DrawBar(dc, x + half + 34, panelY + 114, half - 38, 22, static_cast<double>(metrics.highRisk) / total, kRed, L"High", FormatNumber(metrics.highRisk));

    const int tableY = 414;
    const int tableHeight = (std::max)(225, height - tableY - 28);
    DrawPanel(dc, x, tableY, available, tableHeight, L"Recent activity", L"Newest events first. Scores are heuristic indicators, not proof of infection.");
    DrawEventTable(dc, RecentEvents(app, 9), x + 4, tableY + 64, available - 8, tableHeight - 70);
}

void DrawMonitoring(HDC dc, AppState& app, int width, const Metrics& metrics) {
    DrawPageHeader(dc, L"Live monitoring", L"Watch one folder at a time. No system-wide scan is performed.");
    const int x = kSidebarWidth + 30;
    const int available = width - x - 30;
    DrawPanel(dc, x, 111, available, 170, L"Folder protection", L"Select a directory before starting the background file watcher.");
    DrawTextLine(dc, L"MONITORED DIRECTORY", x + 22, 175, 235, 20, kMuted, 8, FW_SEMIBOLD);
    std::wstring folder = app.selectedFolder.empty() ? L"Choose a folder to monitor" : app.selectedFolder;
    DrawTextLine(dc, folder, x + 22, 198, available - 44, 26, kText, 10);
    DrawButton(dc, RECT{x + 22, 235, x + 164, 267}, L"Choose folder", kBlue);
    DrawButton(dc, RECT{x + 176, 235, x + 305, 267}, L"Start monitoring", kGreen, !app.monitor.running && !app.selectedFolder.empty());
    DrawButton(dc, RECT{x + 317, 235, x + 429, 267}, L"Stop", kRed, app.monitor.running);
    DrawTag(dc, x + available - 144, 239, app.monitor.running ? L"ACTIVE" : L"INACTIVE",
            app.monitor.running ? kGreen : kCardLight);

    DrawPanel(dc, x, 299, available, 182, L"Safe simulation lab", L"All demos use disposable files under the app's private test directory. Nothing is encrypted or changed elsewhere.");
    DrawTextLine(dc, L"These clearly labeled events exercise the detection rules without requiring destructive actions on your files.",
                 x + 22, 354, available - 44, 28, kMuted, 9);
    DrawButton(dc, RECT{x + 22, 395, x + 185, 429}, L"Modify sample files", kBlue);
    DrawButton(dc, RECT{x + 197, 395, x + 347, 429}, L"Rename samples", kCyan);
    DrawButton(dc, RECT{x + 359, 395, x + 500, 429}, L"Create samples", kGreen);
    DrawButton(dc, RECT{x + 512, 395, x + 650, 429}, L"Delete samples", kOrange);
    DrawButton(dc, RECT{x + 662, 395, x + 815, 429}, L"Clean demo files", kRed);

    DrawPanel(dc, x, 499, available, 104, L"Monitoring activity", L"Events are saved locally in SQLite as they arrive.");
    DrawTextLine(dc, L"Events in history", x + 24, 554, 145, 22, kMuted, 9);
    DrawTextLine(dc, FormatNumber(metrics.events), x + 172, 551, 100, 28, kText, 16, FW_BOLD);
    DrawTextLine(dc, L"Last event", x + 310, 554, 100, 22, kMuted, 9);
    DrawTextLine(dc, app.lastActivity, x + 402, 551, available - 425, 28, kText, 9);

    DrawPanel(dc, x, 621, available, 100, L"Safety note", L"Behavior scores are heuristic and can have false positives. Review the event details before taking action.");
}

void DrawDetection(HDC dc, AppState& app, int width) {
    DrawPageHeader(dc, L"Threat detection", L"Rule-based behavior indicators, tuned to avoid treating one ordinary operation as a threat.");
    const int x = kSidebarWidth + 30;
    const int available = width - x - 30;
    DrawPanel(dc, x, 111, available, 120, L"Risk model", L"Each event includes a risk score, classification, rule evidence, and a defensive recommendation.");
    DrawTag(dc, x + 24, 178, L"LOW  0-29", kGreen);
    DrawTag(dc, x + 132, 178, L"MEDIUM  30-59", kOrange);
    DrawTag(dc, x + 285, 178, L"HIGH  60+", kRed);
    DrawTextLine(dc, L"An elevated score is a heuristic signal, not proof that a device is infected.",
                 x + 405, 177, available - 425, 30, kMuted, 9);

    DrawPanel(dc, x, 249, available, 318, L"Detection rules", L"Events are assessed over a rolling 10-second window; thresholds are configurable in Settings.");
    const int rowX = x + 24;
    const std::vector<std::pair<std::wstring, std::wstring>> rules{
        {L"Rapid file modification", std::to_wstring(app.thresholds.modifications) + L" modifications"},
        {L"Repeated file renaming", std::to_wstring(app.thresholds.renames) + L" renames"},
        {L"High file deletion activity", std::to_wstring(app.thresholds.deletions) + L" deletions"},
        {L"Unusual extension changes", L"3 repeated extension changes"},
        {L"High-frequency file operations", std::to_wstring(app.thresholds.operations) + L" operations"},
        {L"Combined suspicious behavior", L"2 or more indicators active together"}
    };
    int rowY = 310;
    for (const auto& rule : rules) {
        DrawTextLine(dc, rule.first, rowX, rowY, available / 2, 35, kText, 10, FW_SEMIBOLD);
        DrawTextLine(dc, rule.second, x + available / 2, rowY, available / 2 - 30, 35, kMuted, 9);
        RECT line{x + 24, rowY + 34, x + available - 24, rowY + 35};
        FillRectColor(dc, line, kBorder);
        rowY += 42;
    }

    DrawPanel(dc, x, 585, available, 131, L"Recommended response", L"If activity is unexpected, stop monitoring if needed, review the events, and investigate using trusted security tools.");
    DrawTextLine(dc, L"The application does not terminate processes, quarantine files, or attempt to remove malware.",
                 x + 24, 645, available - 48, 40, kMuted, 9, FW_NORMAL, DT_LEFT | DT_TOP | DT_WORDBREAK);
}

void DrawAlerts(HDC dc, AppState& app, int width, int height) {
    DrawPageHeader(dc, L"Security alerts", L"Review activity that triggered a detection rule, including low-risk indicators.");
    const int x = kSidebarWidth + 30;
    const int available = width - x - 30;
    DrawPanel(dc, x, 111, available, 94, L"Alert inbox", L"Select an event to review. Simulation entries are labeled.");
    int filterX = x + 22;
    for (const auto& filter : {L"All", L"Low", L"Medium", L"High"}) {
        const COLORREF color = app.alertFilter == filter ? kBlue : kCardLight;
        DrawButton(dc, RECT{filterX, 158, filterX + 82, 188}, filter, color);
        filterX += 92;
    }
    RECT searchRect{x + 410, 158, x + available - 190, 188};
    RoundedRect(dc, searchRect, app.searchFocused ? kCardLight : kBackground, 8);
    DrawTextLine(dc, app.searchText.empty() ? L"Search alerts..." : app.searchText,
                 searchRect.left + 10, searchRect.top, searchRect.right - searchRect.left - 20, 30,
                 app.searchText.empty() ? kMuted : kText, 8);
    DrawButton(dc, RECT{x + available - 170, 158, x + available - 22, 188}, L"Mark reviewed", kGreen);

    const int tableY = 222;
    const int tableHeight = (std::max)(210, height - tableY - 28);
    DrawPanel(dc, x, tableY, available, tableHeight, L"Alert history", L"Events with one or more triggered rules are shown.");
    auto events = PageEvents(app, true);
    DrawEventTable(dc, events, x + 4, tableY + 64, available - 8, tableHeight - 72);
    if (events.empty()) {
        DrawTextLine(dc, L"No alerts match this filter. Normal activity is not displayed here.",
                     x + 28, tableY + 112, available - 56, 32, kMuted, 9);
    }
}

void DrawLogs(HDC dc, AppState& app, int width, int height) {
    DrawPageHeader(dc, L"Event logs", L"Search, filter, and export your locally stored monitoring history.");
    const int x = kSidebarWidth + 30;
    const int available = width - x - 30;
    DrawPanel(dc, x, 111, available, 113, L"History controls", L"Newest events first. Search matches filenames, paths, event types, and details.");
    RECT searchRect{x + 22, 170, x + 300, 203};
    RoundedRect(dc, searchRect, app.searchFocused ? kCardLight : kBackground, 8);
    std::wstring searchLabel = app.searchText.empty() ? L"Search events..." : app.searchText;
    DrawTextLine(dc, searchLabel, searchRect.left + 10, searchRect.top, 255, 33,
                 app.searchText.empty() ? kMuted : kText, 9);
    int filterX = x + 315;
    for (const auto& filter : {L"All", L"Low", L"Medium", L"High"}) {
        DrawButton(dc, RECT{filterX, 171, filterX + 68, 201}, filter,
                   app.logFilter == filter ? kBlue : kCardLight);
        filterX += 76;
    }
    DrawButton(dc, RECT{x + available - 220, 171, x + available - 120, 201}, L"Export CSV", kCyan);
    DrawButton(dc, RECT{x + available - 110, 171, x + available - 22, 201}, L"Clear logs", kRed);

    const int tableY = 241;
    const int tableHeight = (std::max)(290, height - tableY - 28);
    DrawPanel(dc, x, tableY, available, tableHeight, L"Monitoring history", L"Historical records are stored in the user's local application data folder.");
    auto events = PageEvents(app, false);
    DrawEventTable(dc, events, x + 4, tableY + 64, available - 8, tableHeight - 72);
    if (events.empty()) {
        DrawTextLine(dc, L"No matching records. Start monitoring a folder to record real events.",
                     x + 28, tableY + 112, available - 56, 32, kMuted, 9);
    }
}

void DrawAnalytics(HDC dc, AppState& app, int width, int height, const Metrics& metrics) {
    DrawPageHeader(dc, L"Analytics & reports", L"Statistics reflect persisted monitoring data, including separately labeled demo events.");
    const int x = kSidebarWidth + 30;
    const int available = width - x - 30;
    const int gap = 14;
    const int cardWidth = (available - 2 * gap) / 3;
    DrawMetricCard(dc, x, 111, cardWidth, L"ALL EVENTS", FormatNumber(metrics.events), L"All recorded file operations", kBlue);
    DrawMetricCard(dc, x + cardWidth + gap, 111, cardWidth, L"SUSPICIOUS", FormatNumber(metrics.suspicious), L"Threshold-based indicators", kOrange);
    DrawMetricCard(dc, x + (cardWidth + gap) * 2, 111, cardWidth, L"DEMO EVENTS", FormatNumber(metrics.simulated), L"Safe simulation; not live activity", kCyan);

    const int panelY = 246;
    const int half = (available - 16) / 2;
    DrawPanel(dc, x, panelY, half, 235, L"Risk-level distribution", L"Based on all locally stored events.");
    const long long total = (std::max)(1LL, metrics.events);
    DrawBar(dc, x + 22, panelY + 69, half - 42, 30, static_cast<double>(metrics.lowRisk) / total, kGreen, L"Low risk", FormatNumber(metrics.lowRisk));
    DrawBar(dc, x + 22, panelY + 111, half - 42, 30, static_cast<double>(metrics.mediumRisk) / total, kOrange, L"Medium risk", FormatNumber(metrics.mediumRisk));
    DrawBar(dc, x + 22, panelY + 153, half - 42, 30, static_cast<double>(metrics.highRisk) / total, kRed, L"High risk", FormatNumber(metrics.highRisk));
    DrawTextLine(dc, L"Event totals are read from SQLite; no sample statistics are added.",
                 x + 22, panelY + 192, half - 44, 20, kMuted, 8);

    DrawPanel(dc, x + half + 16, panelY, half, 235, L"Event type distribution", L"Counts from the latest 5,000 records.");
    std::map<std::wstring, long long> eventTypes;
    for (const auto& event : app.events) ++eventTypes[event.type];
    long long maxType = 1;
    for (const auto& item : eventTypes) maxType = (std::max)(maxType, item.second);
    const std::vector<std::pair<std::wstring, COLORREF>> ordered{
        {L"Created", kGreen}, {L"Modified", kBlue}, {L"Renamed", kCyan}, {L"Deleted", kRed}
    };
    int typeY = panelY + 65;
    for (const auto& item : ordered) {
        const long long value = eventTypes[item.first];
        DrawBar(dc, x + half + 38, typeY, half - 44, 28, static_cast<double>(value) / maxType,
                item.second, item.first, FormatNumber(value));
        typeY += 38;
    }

    DrawPanel(dc, x, 499, available, (std::max)(140, height - 529), L"Report notes", L"Use Export CSV on Event Logs to save a portable event report.");
    DrawTextLine(dc, L"Ransomware Behavior Monitor  |  NAVTTC Cybersecurity Project",
                 x + 22, 557, available - 44, 24, kText, 10, FW_SEMIBOLD);
    DrawTextLine(dc, L"PDF report generation is not included in this standalone Windows build. Exported CSV contains the event timestamps, file paths, rule evidence, heuristic score, risk level, and simulation label.",
                 x + 22, 588, available - 44, 52, kMuted, 9, FW_NORMAL, DT_LEFT | DT_TOP | DT_WORDBREAK);
}

void DrawSettings(HDC dc, AppState& app, int width) {
    DrawPageHeader(dc, L"Settings", L"Thresholds are adjustable and saved in the local application database.");
    const int x = kSidebarWidth + 30;
    const int available = width - x - 30;
    DrawPanel(dc, x, 111, available, 336, L"Detection thresholds", L"Number of events within the rolling 10-second analysis window.");
    const std::vector<std::pair<std::wstring, int*>> settings{
        {L"Rapid modifications", &app.thresholds.modifications},
        {L"Repeated renames", &app.thresholds.renames},
        {L"High deletions", &app.thresholds.deletions},
        {L"High-frequency operations", &app.thresholds.operations}
    };
    int rowY = 181;
    for (const auto& setting : settings) {
        DrawTextLine(dc, setting.first, x + 24, rowY, 270, 34, kText, 10, FW_SEMIBOLD);
        DrawButton(dc, RECT{x + 380, rowY + 2, x + 423, rowY + 32}, L"-", kCardLight);
        DrawTextLine(dc, std::to_wstring(*setting.second), x + 433, rowY + 2, 50, 30, kText, 12, FW_BOLD,
                     DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        DrawButton(dc, RECT{x + 492, rowY + 2, x + 535, rowY + 32}, L"+", kBlue);
        rowY += 56;
    }

    DrawPanel(dc, x, 463, available, 142, L"Preferences", L"Notifications are optional; they do not stop or quarantine files.");
    DrawButton(dc, RECT{x + 24, 519, x + 230, 552}, app.notificationsEnabled ? L"Desktop alerts: ON" : L"Desktop alerts: OFF",
               app.notificationsEnabled ? kGreen : kCardLight);
    DrawTextLine(dc, L"Severity alerts use a native Windows notification sound and taskbar flash when enabled.",
                 x + 250, 519, available - 275, 34, kMuted, 9);

    DrawPanel(dc, x, 621, available, 101, L"Local storage", L"SQLite database location");
    DrawTextLine(dc, app.database.DatabasePath(), x + 24, 676, available - 48, 25, kText, 8);
}

void DrawAbout(HDC dc, int width) {
    DrawPageHeader(dc, L"About this project", L"Academic defensive cybersecurity demonstration.");
    const int x = kSidebarWidth + 30;
    const int available = width - x - 30;
    DrawPanel(dc, x, 111, available, 246, L"Ransomware Behavior Monitor", L"NAVTTC Cybersecurity / Information Security");
    DrawTextLine(dc, L"A defensive, behavior-based file activity monitor for identifying suspicious patterns that may resemble ransomware activity.",
                 x + 24, 180, available - 48, 48, kText, 11, FW_NORMAL, DT_LEFT | DT_TOP | DT_WORDBREAK);
    DrawTextLine(dc, L"Group members", x + 24, 244, 200, 21, kMuted, 9, FW_SEMIBOLD);
    DrawTextLine(dc, L"Suhana Qadir  |  Nazar Ali Mazari", x + 24, 268, available - 48, 22, kText, 10);
    DrawTextLine(dc, L"Project supervisor", x + 24, 302, 200, 21, kMuted, 9, FW_SEMIBOLD);
    DrawTextLine(dc, L"Sir Ashique Ali Shaikh", x + 24, 325, available - 48, 22, kText, 10);

    const int half = (available - 16) / 2;
    DrawPanel(dc, x, 375, half, 180, L"Technology", L"Native Windows implementation in C++17.");
    DrawTextLine(dc, L"Win32 desktop UI  |  ReadDirectoryChangesW\nSQLite event history  |  Background monitoring thread\nRule-based analysis  |  Safe disposable-file simulation",
                 x + 22, 435, half - 44, 90, kMuted, 9, FW_NORMAL, DT_LEFT | DT_TOP | DT_WORDBREAK);
    DrawPanel(dc, x + half + 16, 375, half, 180, L"Responsible use", L"Designed for transparent local defensive monitoring.");
    DrawTextLine(dc, L"Monitoring is restricted to the folder selected by the user. Demo actions only touch the app's dedicated test folder. Scores are heuristic indicators, not infection verdicts.",
                 x + half + 38, 435, half - 44, 91, kMuted, 9, FW_NORMAL, DT_LEFT | DT_TOP | DT_WORDBREAK);

    DrawPanel(dc, x, 573, available, 132, L"Project disclaimer", L"This educational tool is not a replacement for endpoint protection or incident response.");
    DrawTextLine(dc, L"It does not encrypt data, execute malware, terminate processes, or claim that a file system event alone proves compromise.",
                 x + 22, 633, available - 44, 45, kMuted, 9, FW_NORMAL, DT_LEFT | DT_TOP | DT_WORDBREAK);
}

void DrawSidebar(HDC dc, AppState& app, int height) {
    RECT sidebar{0, 0, kSidebarWidth, height};
    FillRectColor(dc, sidebar, kSidebar);
    RECT logo{22, 22, 58, 58};
    RoundedRect(dc, logo, kBlue, 10);
    DrawTextLine(dc, L"R", 22, 22, 36, 36, kText, 16, FW_BOLD, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    DrawTextLine(dc, L"RANSOMWHERE", 70, 22, 150, 22, kText, 10, FW_BOLD);
    DrawTextLine(dc, L"BEHAVIOR MONITOR", 70, 43, 150, 20, kMuted, 8, FW_SEMIBOLD);

    int y = 100;
    for (size_t index = 0; index < app.navLabels.size(); ++index) {
        const bool active = app.page == app.navPages[index];
        RECT item{14, y, kSidebarWidth - 14, y + 42};
        if (active) RoundedRect(dc, item, kCardLight, 8);
        DrawTextLine(dc, app.navLabels[index], 29, y, kSidebarWidth - 52, 42,
                     active ? kText : kMuted, 9, active ? FW_SEMIBOLD : FW_NORMAL);
        y += 49;
    }

    RECT line{18, height - 80, kSidebarWidth - 18, height - 79};
    FillRectColor(dc, line, kBorder);
    DrawTextLine(dc, L"MONITOR STATUS", 22, height - 69, 190, 18, kMuted, 8, FW_SEMIBOLD);
    RECT dot{23, height - 43, 32, height - 34};
    const COLORREF statusColor = app.monitor.running ? kGreen : kMuted;
    HBRUSH brush = CreateSolidBrush(statusColor);
    HGDIOBJ previousBrush = SelectObject(dc, brush);
    Ellipse(dc, dot.left, dot.top, dot.right, dot.bottom);
    SelectObject(dc, previousBrush);
    DeleteObject(brush);
    DrawTextLine(dc, app.monitor.running ? L"Active" : L"Stopped", 40, height - 48, 150, 22, statusColor, 9, FW_SEMIBOLD);
}

void DrawApplication(HWND window, HDC target) {
    RECT client{};
    GetClientRect(window, &client);
    const int width = client.right;
    const int height = client.bottom;
    HDC buffer = CreateCompatibleDC(target);
    HBITMAP bitmap = CreateCompatibleBitmap(target, width, height);
    HGDIOBJ previous = SelectObject(buffer, bitmap);
    FillRectColor(buffer, client, kBackground);
    DrawSidebar(buffer, *g_app, height);

    RECT header{kSidebarWidth, 0, width, kHeaderHeight};
    FillRectColor(buffer, header, kBackground);
    RECT divider{kSidebarWidth, kHeaderHeight - 1, width, kHeaderHeight};
    FillRectColor(buffer, divider, kBorder);
    DrawTextLine(buffer, L"NAVTTC CYBERSECURITY  /  LOCAL DEFENSE", kSidebarWidth + 30, 10, 390, 16, kMuted, 8, FW_SEMIBOLD);
    DrawTag(buffer, width - 170, 29, L"HEURISTIC", kCardLight);
    DrawTag(buffer, width - 76, 29, g_app->monitor.running ? L"LIVE" : L"IDLE",
            g_app->monitor.running ? kGreen : kCardLight);

    const Metrics metrics = g_app->database.GetMetrics();
    switch (g_app->page) {
    case Page::Dashboard: DrawDashboard(buffer, *g_app, width, height, metrics); break;
    case Page::Monitoring: DrawMonitoring(buffer, *g_app, width, metrics); break;
    case Page::Detection: DrawDetection(buffer, *g_app, width); break;
    case Page::Alerts: DrawAlerts(buffer, *g_app, width, height); break;
    case Page::Logs: DrawLogs(buffer, *g_app, width, height); break;
    case Page::Analytics: DrawAnalytics(buffer, *g_app, width, height, metrics); break;
    case Page::Settings: DrawSettings(buffer, *g_app, width); break;
    case Page::About: DrawAbout(buffer, width); break;
    }

    if (!g_app->statusMessage.empty()) {
        DrawTextLine(buffer, g_app->statusMessage, kSidebarWidth + 32, height - 24,
                     width - kSidebarWidth - 64, 18, kCyan, 8);
    }
    BitBlt(target, 0, 0, width, height, buffer, 0, 0, SRCCOPY);
    SelectObject(buffer, previous);
    DeleteObject(bitmap);
    DeleteDC(buffer);
}

fs::path AppDataDirectory() {
    wchar_t localAppData[MAX_PATH]{};
    const DWORD size = GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH);
    if (size == 0 || size >= MAX_PATH) {
        throw std::runtime_error("LOCALAPPDATA is unavailable.");
    }
    return fs::path(localAppData) / L"RansomwareBehaviorMonitor";
}

int ReadSetting(const std::wstring& value, int fallback) {
    try {
        const int parsed = std::stoi(value);
        return (std::max)(1, (std::min)(parsed, 1000));
    } catch (...) {
        return fallback;
    }
}

void AddIncoming(AppState& app, RawEvent event) {
    std::lock_guard<std::mutex> lock(app.incomingMutex);
    app.incoming.push_back(std::move(event));
}

void EmitFileEvent(AppState& app, const std::wstring& path, const std::wstring& type,
                   const std::wstring& details, bool simulated);

bool IsDirectSimulationFile(const AppState& app, const fs::path& path) {
    const std::wstring root = Lower(fs::path(app.simulationDirectory).lexically_normal().wstring());
    const std::wstring parent = Lower(path.parent_path().lexically_normal().wstring());
    return root == parent && StartsWithInsensitive(path.filename().wstring(), L"rbm_demo_");
}

bool IsWithinFolder(const fs::path& path, const fs::path& folder) {
    std::wstring target = Lower(path.lexically_normal().wstring());
    std::wstring root = Lower(folder.lexically_normal().wstring());
    if (target == root) return true;
    if (!root.empty() && root.back() != L'\\' && root.back() != L'/') root.push_back(L'\\');
    return StartsWithInsensitive(target, root);
}

void RecordSimulationEvent(AppState& app, const std::wstring& path, const std::wstring& type,
                           const std::wstring& details) {
    if (app.monitor.running && app.monitor.ready &&
        IsWithinFolder(fs::path(app.simulationDirectory), fs::path(app.selectedFolder))) {
        return;
    }
    EmitFileEvent(app, path, type, details, true);
}

void EmitFileEvent(AppState& app, const std::wstring& path, const std::wstring& type,
                   const std::wstring& details = L"", bool simulated = false) {
    RawEvent raw{path, type, details, simulated};
    Event event = app.detector->Assess(raw);
    std::wstring error;
    if (!app.database.Insert(event, error)) {
        app.statusMessage = L"Database error: " + error;
    } else {
        app.events.insert(app.events.begin(), event);
        if (app.events.size() > 5000) app.events.pop_back();
        app.lastActivity = event.timestamp;
        if (event.score >= 60 && app.notificationsEnabled) {
            MessageBeep(MB_ICONWARNING);
            FLASHWINFO flash{sizeof(FLASHWINFO), app.window, FLASHW_TRAY, 2, 0};
            FlashWindowEx(&flash);
        }
    }
}

void StartWatcher(AppState& app) {
    if (app.monitor.running || app.selectedFolder.empty()) return;
    std::error_code fileError;
    if (!fs::is_directory(app.selectedFolder, fileError) || fileError) {
        MessageBoxW(app.window, L"The selected folder is unavailable. Choose an existing directory.",
                    kWindowTitle, MB_OK | MB_ICONWARNING);
        return;
    }
    app.monitor.Stop();
    app.monitor.folder = app.selectedFolder;
    app.monitor.ready = false;
    app.monitor.stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!app.monitor.stopEvent) {
        MessageBoxW(app.window, L"Could not create the monitoring stop event.", kWindowTitle, MB_OK | MB_ICONERROR);
        return;
    }
    app.monitor.running = true;
    app.statusMessage = L"Monitoring " + app.selectedFolder;
    const std::wstring folder = app.selectedFolder;
    HANDLE stopEvent = app.monitor.stopEvent;
    app.monitor.worker = std::thread([&app, folder, stopEvent]() {
        HANDLE directory = CreateFileW(folder.c_str(), FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
        if (directory == INVALID_HANDLE_VALUE) {
            AddIncoming(app, RawEvent{folder, L"Error", L"Could not open the selected folder for monitoring. Windows error " +
                std::to_wstring(GetLastError()) + L".", false});
            app.monitor.running = false;
            return;
        }

        HANDLE changeEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!changeEvent) {
            AddIncoming(app, RawEvent{folder, L"Error", L"Could not create a file notification event.", false});
            CloseHandle(directory);
            app.monitor.running = false;
            return;
        }
        std::vector<unsigned char> buffer(64 * 1024);
        std::wstring oldRenamePath;
        bool failed = false;
        const auto queueChange = [&app](const std::wstring& path, const std::wstring& type, const std::wstring& details) {
            AddIncoming(app, RawEvent{path, type, details, IsDirectSimulationFile(app, fs::path(path))});
        };
        while (WaitForSingleObject(stopEvent, 0) != WAIT_OBJECT_0) {
            ResetEvent(changeEvent);
            OVERLAPPED overlapped{};
            overlapped.hEvent = changeEvent;
            const BOOL requested = ReadDirectoryChangesW(directory, buffer.data(),
                static_cast<DWORD>(buffer.size()), TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME |
                    FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE,
                nullptr, &overlapped, nullptr);
            if (!requested) {
                AddIncoming(app, RawEvent{folder, L"Error", L"ReadDirectoryChangesW failed. Windows error " +
                    std::to_wstring(GetLastError()) + L".", false});
                failed = true;
                break;
            }
            app.monitor.ready = true;
            HANDLE waits[] = {stopEvent, changeEvent};
            const DWORD waitResult = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
            if (waitResult == WAIT_OBJECT_0) {
                CancelIoEx(directory, &overlapped);
                DWORD ignored = 0;
                GetOverlappedResult(directory, &overlapped, &ignored, TRUE);
                break;
            }
            if (waitResult != WAIT_OBJECT_0 + 1) {
                AddIncoming(app, RawEvent{folder, L"Error", L"File monitoring wait failed.", false});
                failed = true;
                break;
            }
            DWORD bytes = 0;
            if (!GetOverlappedResult(directory, &overlapped, &bytes, FALSE)) {
                const DWORD error = GetLastError();
                if (error == ERROR_OPERATION_ABORTED) break;
                AddIncoming(app, RawEvent{folder, L"Error", L"Could not read file system changes. Windows error " +
                    std::to_wstring(error) + L".", false});
                failed = true;
                break;
            }
            if (bytes == 0) {
                AddIncoming(app, RawEvent{folder, L"Error",
                    L"The file notification buffer overflowed. Some changes may have been missed; restart monitoring.", false});
                failed = true;
                break;
            }

            DWORD offset = 0;
            while (offset < bytes) {
                const auto* info = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(buffer.data() + offset);
                const std::wstring name(info->FileName, info->FileNameLength / sizeof(wchar_t));
                const std::wstring fullPath = (fs::path(folder) / name).wstring();
                switch (info->Action) {
                case FILE_ACTION_ADDED:
                    queueChange(fullPath, L"Created", L"File or directory created.");
                    break;
                case FILE_ACTION_REMOVED:
                    queueChange(fullPath, L"Deleted", L"File or directory deleted.");
                    break;
                case FILE_ACTION_MODIFIED:
                    queueChange(fullPath, L"Modified", L"File or directory modified.");
                    break;
                case FILE_ACTION_RENAMED_OLD_NAME:
                    oldRenamePath = fullPath;
                    break;
                case FILE_ACTION_RENAMED_NEW_NAME:
                    if (!oldRenamePath.empty()) {
                        queueChange(fullPath, L"Renamed", oldRenamePath);
                        oldRenamePath.clear();
                    } else {
                        queueChange(fullPath, L"Renamed", L"Rename destination observed.");
                    }
                    break;
                default:
                    break;
                }
                if (info->NextEntryOffset == 0) break;
                offset += info->NextEntryOffset;
            }
        }
        CloseHandle(changeEvent);
        CloseHandle(directory);
        app.monitor.ready = false;
        if (failed) app.monitor.running = false;
    });
}

void StopWatcher(AppState& app) {
    app.monitor.Stop();
    app.statusMessage = L"Monitoring stopped.";
}

void ChooseFolder(AppState& app) {
    BROWSEINFOW browse{};
    browse.hwndOwner = app.window;
    browse.lpszTitle = L"Choose one folder to monitor";
    browse.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    PIDLIST_ABSOLUTE selection = SHBrowseForFolderW(&browse);
    if (!selection) {
        return;
    }
    wchar_t path[MAX_PATH]{};
    const BOOL resolved = SHGetPathFromIDListW(selection, path);
    CoTaskMemFree(selection);
    if (!resolved) {
        MessageBoxW(app.window, L"The selected directory path could not be read.", kWindowTitle, MB_OK | MB_ICONERROR);
        return;
    }
    if (app.monitor.running) {
        StopWatcher(app);
    }
    app.selectedFolder = path;
    app.statusMessage = L"Selected folder: " + app.selectedFolder;
}

std::wstring SafeSamplePath(AppState& app, int index, const std::wstring& extension = L".txt") {
    std::wostringstream name;
    name << L"rbm_demo_" << std::setw(3) << std::setfill(L'0') << index << extension;
    return (fs::path(app.simulationDirectory) / name.str()).wstring();
}

bool EnsureSimulationDirectory(AppState& app) {
    std::error_code error;
    fs::create_directories(app.simulationDirectory, error);
    if (error) {
        app.statusMessage = L"Could not create the private simulation directory: " + FromUtf8(error.message());
        return false;
    }
    return true;
}

void SimulateCreate(AppState& app) {
    if (!EnsureSimulationDirectory(app)) return;
    int firstIndex = 10000 + static_cast<int>(GetTickCount() % 500000);
    bool available = false;
    for (int attempt = 0; attempt < 1000 && !available; ++attempt, firstIndex += 12) {
        available = true;
        for (int index = 0; index < 12; ++index) {
            if (fs::exists(SafeSamplePath(app, firstIndex + index))) {
                available = false;
                break;
            }
        }
    }
    if (!available) {
        app.statusMessage = L"Could not find unused names for the disposable demo files.";
        return;
    }
    for (int index = 0; index < 12; ++index) {
        const std::wstring path = SafeSamplePath(app, firstIndex + index);
        std::ofstream file(fs::path(path), std::ios::binary | std::ios::trunc);
        if (!file) {
            app.statusMessage = L"Could not create a disposable demo file. Check the app data folder permissions.";
            return;
        }
        file << "Harmless Ransomware Behavior Monitor demo file.\r\n";
        file.close();
        RecordSimulationEvent(app, path, L"Created", L"SIMULATED: harmless disposable test file created.");
    }
    app.statusMessage = L"Safe demo: created 12 disposable files in the private test folder.";
}

void SimulateModify(AppState& app) {
    if (!EnsureSimulationDirectory(app)) return;
    const std::wstring path = SafeSamplePath(app, 1);
    if (!fs::exists(path)) {
        std::ofstream initialFile(fs::path(path), std::ios::binary);
        if (!initialFile) {
            app.statusMessage = L"Could not create a disposable demo file.";
            return;
        }
        initialFile << "Harmless Ransomware Behavior Monitor demo file.\r\n";
        initialFile.close();
        RecordSimulationEvent(app, path, L"Created", L"SIMULATED: harmless disposable test file created.");
    }
    for (int index = 0; index < 8; ++index) {
        std::ofstream file(fs::path(path), std::ios::binary | std::ios::app);
        if (!file) {
            app.statusMessage = L"Could not write to the disposable demo file.";
            return;
        }
        file << "Harmless demo update " << index << "\r\n";
        file.close();
        RecordSimulationEvent(app, path, L"Modified", L"SIMULATED: benign write to a disposable demo file.");
    }
    app.statusMessage = L"Safe demo: generated repeated writes to one disposable file.";
}

void SimulateRename(AppState& app) {
    if (!EnsureSimulationDirectory(app)) return;
    int firstIndex = 600000 + static_cast<int>(GetTickCount() % 500000);
    bool available = false;
    for (int attempt = 0; attempt < 1000 && !available; ++attempt, firstIndex += 5) {
        available = true;
        for (int index = 0; index < 5; ++index) {
            if (fs::exists(SafeSamplePath(app, firstIndex + index, L".txt")) ||
                fs::exists(SafeSamplePath(app, firstIndex + index, L".demo"))) {
                available = false;
                break;
            }
        }
    }
    if (!available) {
        app.statusMessage = L"Could not find unused names for the rename demo files.";
        return;
    }
    for (int index = 0; index < 5; ++index) {
        const std::wstring source = SafeSamplePath(app, firstIndex + index, L".txt");
        const std::wstring destination = SafeSamplePath(app, firstIndex + index, L".demo");
        std::error_code error;
        std::ofstream file(fs::path(source), std::ios::binary);
        if (!file) {
            app.statusMessage = L"Could not create a disposable rename demo file.";
            return;
        }
        file << "Harmless rename demonstration.\r\n";
        file.close();
        fs::rename(source, destination, error);
        if (error) {
            app.statusMessage = L"Could not rename a disposable demo file: " + FromUtf8(error.message());
            return;
        }
        RecordSimulationEvent(app, destination, L"Renamed", source);
    }
    app.statusMessage = L"Safe demo: generated repeated renames to the harmless .demo extension.";
}

void SimulateDelete(AppState& app) {
    if (!EnsureSimulationDirectory(app)) return;
    const int answer = MessageBoxW(app.window,
        L"This will delete only rbm_demo_* disposable files directly inside the application's private simulation folder. Continue?",
        L"Confirm safe simulation deletion", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    if (answer != IDYES) return;
    size_t removed = 0;
    std::error_code error;
    for (const auto& entry : fs::directory_iterator(app.simulationDirectory, error)) {
        if (error) break;
        if (!entry.is_regular_file(error) || error || !IsDirectSimulationFile(app, entry.path())) {
            error.clear();
            continue;
        }
        const std::wstring path = entry.path().wstring();
        if (fs::remove(entry.path(), error) && !error) {
            ++removed;
            RecordSimulationEvent(app, path, L"Deleted", L"SIMULATED: disposable file removed after explicit confirmation.");
        }
        error.clear();
    }
    if (error) {
        app.statusMessage = L"Could not enumerate the simulation folder: " + FromUtf8(error.message());
    } else {
        app.statusMessage = L"Safe demo: removed " + std::to_wstring(removed) + L" disposable files.";
    }
}

void CleanSimulationFiles(AppState& app) {
    const int answer = MessageBoxW(app.window,
        L"Remove rbm_demo_* files directly inside the application's private simulation folder? No other files are touched.",
        L"Confirm simulation cleanup", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);
    if (answer != IDYES) return;
    if (!fs::exists(app.simulationDirectory)) {
        app.statusMessage = L"The private simulation folder is already empty.";
        return;
    }
    size_t removed = 0;
    std::error_code error;
    for (const auto& entry : fs::directory_iterator(app.simulationDirectory, error)) {
        if (error) break;
        if (!entry.is_regular_file(error) || error || !IsDirectSimulationFile(app, entry.path())) {
            error.clear();
            continue;
        }
        if (fs::remove(entry.path(), error) && !error) ++removed;
        error.clear();
    }
    if (error) {
        app.statusMessage = L"Could not clean the simulation directory: " + FromUtf8(error.message());
    } else {
        app.statusMessage = L"Cleaned " + std::to_wstring(removed) + L" disposable simulation files.";
    }
}

std::wstring CsvField(const std::wstring& value) {
    std::wstring result = L"\"";
    for (const wchar_t character : value) {
        if (character == L'"') result += L"\"\"";
        else result += character;
    }
    result += L"\"";
    return result;
}

void ExportCsv(AppState& app) {
    wchar_t path[MAX_PATH] = L"ransomwhere-events.csv";
    OPENFILENAMEW dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = app.window;
    dialog.lpstrFilter = L"CSV files (*.csv)\0*.csv\0All files (*.*)\0*.*\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = MAX_PATH;
    dialog.lpstrDefExt = L"csv";
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameW(&dialog)) return;

    std::ofstream output(fs::path(path), std::ios::binary | std::ios::trunc);
    if (!output) {
        MessageBoxW(app.window, L"Could not create the CSV file. Check the destination and permissions.",
                    kWindowTitle, MB_OK | MB_ICONERROR);
        return;
    }
    output << "\xEF\xBB\xBF";
    output << "Event ID,Timestamp,Filename,File path,Event type,Detection rule,Risk score,Risk level,Details,Simulated,Reviewed\r\n";
    const auto events = app.database.LoadEvents(app.searchText, app.logFilter, 1000000);
    for (const auto& event : events) {
        const std::wstring line =
            std::to_wstring(event.id) + L"," + CsvField(event.timestamp) + L"," +
            CsvField(event.filename) + L"," + CsvField(event.path) + L"," +
            CsvField(event.type) + L"," + CsvField(event.rule) + L"," +
            std::to_wstring(event.score) + L"," + CsvField(event.level) + L"," +
            CsvField(event.details) + L"," + (event.simulated ? L"Yes" : L"No") + L"," +
            (event.reviewed ? L"Yes" : L"No") + L"\r\n";
        output << ToUtf8(line);
    }
    if (!output) {
        MessageBoxW(app.window, L"The CSV could not be fully written.", kWindowTitle, MB_OK | MB_ICONERROR);
        return;
    }
    app.statusMessage = L"Exported event history to " + std::wstring(path);
}

void ClearHistory(AppState& app) {
    const int answer = MessageBoxW(app.window,
        L"Permanently clear all locally stored monitoring events and alerts? This cannot be undone.",
        L"Confirm clear history", MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2);
    if (answer != IDYES) return;
    std::wstring error;
    if (!app.database.ClearEvents(error)) {
        MessageBoxW(app.window, (L"Could not clear event history: " + error).c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
        return;
    }
    app.events.clear();
    app.detector->Reset();
    app.lastActivity = L"No events recorded yet";
    app.selectedEvent = -1;
    app.statusMessage = L"Event history cleared.";
}

void MarkSelectedReviewed(AppState& app) {
    if (app.selectedEvent < 1) {
        app.statusMessage = L"Select an alert row first, then choose Mark reviewed.";
        return;
    }
    std::wstring error;
    if (!app.database.SetReviewed(app.selectedEvent, error)) {
        MessageBoxW(app.window, (L"Could not update the alert: " + error).c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
        return;
    }
    for (auto& event : app.events) {
        if (event.id == app.selectedEvent) {
            event.reviewed = true;
            break;
        }
    }
    app.statusMessage = L"Alert marked as reviewed.";
}

void LoadThresholds(AppState& app) {
    app.thresholds.modifications = ReadSetting(app.database.GetSetting(L"modification_threshold", std::to_wstring(kDefaultModificationThreshold)), kDefaultModificationThreshold);
    app.thresholds.renames = ReadSetting(app.database.GetSetting(L"rename_threshold", std::to_wstring(kDefaultRenameThreshold)), kDefaultRenameThreshold);
    app.thresholds.deletions = ReadSetting(app.database.GetSetting(L"deletion_threshold", std::to_wstring(kDefaultDeletionThreshold)), kDefaultDeletionThreshold);
    app.thresholds.operations = ReadSetting(app.database.GetSetting(L"operation_threshold", std::to_wstring(kDefaultOperationThreshold)), kDefaultOperationThreshold);
    app.notificationsEnabled = app.database.GetSetting(L"notifications", L"1") != L"0";
}

void SaveThresholds(AppState& app) {
    std::wstring error;
    const bool saved =
        app.database.SetSetting(L"modification_threshold", std::to_wstring(app.thresholds.modifications), error) &&
        app.database.SetSetting(L"rename_threshold", std::to_wstring(app.thresholds.renames), error) &&
        app.database.SetSetting(L"deletion_threshold", std::to_wstring(app.thresholds.deletions), error) &&
        app.database.SetSetting(L"operation_threshold", std::to_wstring(app.thresholds.operations), error);
    if (!saved) {
        MessageBoxW(app.window, (L"Could not save detection settings: " + error).c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
    }
}

void RefreshDisplayedEvents(AppState& app) {
    app.events = app.database.LoadEvents(L"", L"All", 5000);
}

void DrainIncomingEvents(AppState& app) {
    std::deque<RawEvent> pending;
    {
        std::lock_guard<std::mutex> lock(app.incomingMutex);
        pending.swap(app.incoming);
    }
    for (const auto& event : pending) {
        if (event.type == L"Error") {
            app.statusMessage = event.details;
            app.monitor.running = false;
        } else {
            EmitFileEvent(app, event.path, event.type, event.details, event.simulated);
        }
    }
}

void AddSearchCharacter(AppState& app, wchar_t character) {
    if (!app.searchFocused) return;
    if (character == L'\b') {
        if (!app.searchText.empty()) app.searchText.pop_back();
    } else if (character >= L' ' && app.searchText.size() < 100) {
        app.searchText.push_back(character);
    }
}

bool InRect(int x, int y, int left, int top, int right, int bottom) {
    return x >= left && x <= right && y >= top && y <= bottom;
}

void HandleClick(AppState& app, int x, int y, int width, int height) {
    if (x < kSidebarWidth && y >= 100) {
        const int index = (y - 100) / 49;
        if (index >= 0 && index < static_cast<int>(app.navPages.size())) {
            app.page = app.navPages[static_cast<size_t>(index)];
            app.searchFocused = false;
            app.statusMessage.clear();
        }
        return;
    }

    const int contentX = kSidebarWidth + 30;
    const int available = width - contentX - 30;
    if (app.page == Page::Monitoring) {
        if (InRect(x, y, contentX + 22, 235, contentX + 164, 267)) {
            ChooseFolder(app);
        } else if (InRect(x, y, contentX + 176, 235, contentX + 305, 267)) {
            StartWatcher(app);
        } else if (InRect(x, y, contentX + 317, 235, contentX + 429, 267)) {
            StopWatcher(app);
        } else if (InRect(x, y, contentX + 22, 395, contentX + 185, 429)) {
            SimulateModify(app);
        } else if (InRect(x, y, contentX + 197, 395, contentX + 347, 429)) {
            SimulateRename(app);
        } else if (InRect(x, y, contentX + 359, 395, contentX + 500, 429)) {
            SimulateCreate(app);
        } else if (InRect(x, y, contentX + 512, 395, contentX + 650, 429)) {
            SimulateDelete(app);
        } else if (InRect(x, y, contentX + 662, 395, contentX + 815, 429)) {
            CleanSimulationFiles(app);
        }
    } else if (app.page == Page::Alerts) {
        const RECT alertSearch{contentX + 410, 158, contentX + available - 190, 188};
        if (InRect(x, y, alertSearch.left, alertSearch.top, alertSearch.right, alertSearch.bottom)) {
            app.searchFocused = true;
            app.statusMessage = L"Type to search alerts. Press Enter to finish.";
            return;
        }
        int filterX = contentX + 22;
        for (const auto& filter : {L"All", L"Low", L"Medium", L"High"}) {
            if (InRect(x, y, filterX, 158, filterX + 82, 188)) {
                app.alertFilter = filter;
                app.searchText.clear();
                break;
            }
            filterX += 92;
        }
        if (InRect(x, y, contentX + available - 170, 158, contentX + available - 22, 188)) {
            MarkSelectedReviewed(app);
        } else if (y >= 312) {
            const auto visible = PageEvents(app, true);
            const int row = (y - 312) / 31;
            if (row >= 0 && row < static_cast<int>(visible.size())) {
                app.selectedEvent = visible[static_cast<size_t>(row)].id;
                app.statusMessage = visible[static_cast<size_t>(row)].reviewed ? L"Selected alert is already reviewed." : L"Alert selected for review.";
            }
        }
    } else if (app.page == Page::Logs) {
        if (InRect(x, y, contentX + 22, 170, contentX + 300, 203)) {
            app.searchFocused = true;
            app.statusMessage = L"Type to search. Press Enter to finish.";
        } else {
            app.searchFocused = false;
            int filterX = contentX + 315;
            for (const auto& filter : {L"All", L"Low", L"Medium", L"High"}) {
                if (InRect(x, y, filterX, 171, filterX + 68, 201)) {
                    app.logFilter = filter;
                    break;
                }
                filterX += 76;
            }
            if (InRect(x, y, contentX + available - 220, 171, contentX + available - 120, 201)) {
                ExportCsv(app);
            } else if (InRect(x, y, contentX + available - 110, 171, contentX + available - 22, 201)) {
                ClearHistory(app);
            }
        }
    } else if (app.page == Page::Settings) {
        int* values[] = {&app.thresholds.modifications, &app.thresholds.renames,
                         &app.thresholds.deletions, &app.thresholds.operations};
        for (int index = 0; index < 4; ++index) {
            const int rowY = 181 + index * 56;
            if (InRect(x, y, contentX + 380, rowY + 2, contentX + 423, rowY + 32)) {
                *values[index] = (std::max)(1, *values[index] - 1);
                SaveThresholds(app);
                break;
            }
            if (InRect(x, y, contentX + 492, rowY + 2, contentX + 535, rowY + 32)) {
                *values[index] = (std::min)(1000, *values[index] + 1);
                SaveThresholds(app);
                break;
            }
        }
        if (InRect(x, y, contentX + 24, 519, contentX + 230, 552)) {
            app.notificationsEnabled = !app.notificationsEnabled;
            std::wstring error;
            if (!app.database.SetSetting(L"notifications", app.notificationsEnabled ? L"1" : L"0", error)) {
                MessageBoxW(app.window, (L"Could not save notification preference: " + error).c_str(),
                            kWindowTitle, MB_OK | MB_ICONERROR);
            }
        }
    }
}

LRESULT CALLBACK WindowProcedure(HWND window, UINT message, WPARAM wParam, LPARAM lParam) {
    AppState* app = g_app;
    switch (message) {
    case WM_CREATE:
        SetTimer(window, kUiTimer, 250, nullptr);
        return 0;
    case WM_TIMER:
        if (app) {
            DrainIncomingEvents(*app);
            InvalidateRect(window, nullptr, FALSE);
        }
        return 0;
    case WM_PAINT: {
        PAINTSTRUCT paint{};
        HDC dc = BeginPaint(window, &paint);
        if (app) DrawApplication(window, dc);
        EndPaint(window, &paint);
        return 0;
    }
    case WM_LBUTTONUP:
        if (app) {
            RECT client{};
            GetClientRect(window, &client);
            HandleClick(*app, GET_X_LPARAM(lParam), GET_Y_LPARAM(lParam), client.right, client.bottom);
            InvalidateRect(window, nullptr, FALSE);
        }
        return 0;
    case WM_CHAR:
        if (app && app->searchFocused) {
            if (wParam == VK_RETURN) app->searchFocused = false;
            else AddSearchCharacter(*app, static_cast<wchar_t>(wParam));
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        }
        break;
    case WM_KEYDOWN:
        if (app && app->searchFocused && wParam == VK_ESCAPE) {
            app->searchFocused = false;
            InvalidateRect(window, nullptr, FALSE);
            return 0;
        }
        break;
    case WM_SIZE:
        InvalidateRect(window, nullptr, FALSE);
        return 0;
    case WM_GETMINMAXINFO: {
        auto* limits = reinterpret_cast<MINMAXINFO*>(lParam);
        limits->ptMinTrackSize.x = 1050;
        limits->ptMinTrackSize.y = 760;
        return 0;
    }
    case WM_ERASEBKGND:
        return 1;
    case WM_DESTROY:
        if (app) {
            KillTimer(window, kUiTimer);
            app->monitor.Stop();
        }
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wParam, lParam);
}

bool InitializeDatabase(AppState& app, std::wstring& error) {
    const fs::path directory = AppDataDirectory();
    std::error_code fileError;
    fs::create_directories(directory, fileError);
    if (fileError) {
        error = L"Could not create the local application data folder: " + FromUtf8(fileError.message());
        return false;
    }
    app.databaseDirectory = directory.wstring();
    app.simulationDirectory = (directory / L"simulation").wstring();
    if (!app.database.Open(directory / L"monitoring.db", error)) {
        return false;
    }
    LoadThresholds(app);
    RefreshDisplayedEvents(app);
    if (!app.events.empty()) {
        app.lastActivity = app.events.front().timestamp;
    }
    return true;
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int showCommand) {
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&controls);

    AppState app;
    g_app = &app;
    std::wstring error;
    try {
        if (!InitializeDatabase(app, error)) {
            MessageBoxW(nullptr, error.c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
            return 1;
        }
    } catch (const std::exception& exception) {
        const std::string message = exception.what();
        const std::wstring wideMessage(message.begin(), message.end());
        MessageBoxW(nullptr, wideMessage.c_str(), kWindowTitle, MB_OK | MB_ICONERROR);
        return 1;
    }

    DetectionEngine detector(app.thresholds);
    app.detector = &detector;

    WNDCLASSEXW windowClass{};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_HREDRAW | CS_VREDRAW;
    windowClass.lpfnWndProc = WindowProcedure;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    windowClass.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    windowClass.hbrBackground = CreateSolidBrush(kBackground);
    windowClass.lpszClassName = kWindowClass;
    if (!RegisterClassExW(&windowClass)) {
        MessageBoxW(nullptr, L"Could not register the application window.", kWindowTitle, MB_OK | MB_ICONERROR);
        DeleteObject(windowClass.hbrBackground);
        return 1;
    }

    HWND window = CreateWindowExW(0, kWindowClass, kWindowTitle, WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 1360, 900, nullptr, nullptr, instance, nullptr);
    if (!window) {
        MessageBoxW(nullptr, L"Could not create the application window.", kWindowTitle, MB_OK | MB_ICONERROR);
        UnregisterClassW(kWindowClass, instance);
        DeleteObject(windowClass.hbrBackground);
        return 1;
    }
    app.window = window;
    SetWindowPos(window, nullptr, 0, 0, 1360, 900, SWP_NOMOVE | SWP_NOZORDER);
    ShowWindow(window, showCommand);
    UpdateWindow(window);

    MSG message{};
    while (GetMessageW(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    DeleteObject(windowClass.hbrBackground);
    UnregisterClassW(kWindowClass, instance);
    return static_cast<int>(message.wParam);
}
