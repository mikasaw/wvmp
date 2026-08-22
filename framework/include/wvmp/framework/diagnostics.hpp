#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace wvmp {

enum class Severity { Note, Warning, Error };

struct Diagnostic {
    Severity severity = Severity::Note;
    std::string pass;
    std::string message;
};

class Diagnostics {
public:
    void report(Severity severity, std::string_view pass, std::string msg) {
        items_.push_back(Diagnostic{severity, std::string(pass), std::move(msg)});
    }
    bool has_errors() const {
        for (const auto& d : items_)
            if (d.severity == Severity::Error) return true;
        return false;
    }
    const std::vector<Diagnostic>& items() const { return items_; }
    void clear() { items_.clear(); }

private:
    std::vector<Diagnostic> items_;
};

} // namespace wvmp
