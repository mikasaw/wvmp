// t_string.cpp - CRT string functions, formatting, UTF conversion, parsers.
#include "../testfw.h"
#include "../common.h"

#include <cwchar>
#include <locale.h>
#include <sstream>
#include <vector>
#include <map>

using namespace wv;

// ---------------------------------------------------------------------------
TEST(string, crt_basics) {
    CHECK_EQ(strlen("hello world"), (size_t)11);
    CHECK_EQ(strlen(""), (size_t)0);
    CHECK_EQ(wcslen(L"wide str"), (size_t)8);

    CHECK(strcmp("abc", "abc") == 0);
    CHECK(strcmp("abc", "abd") < 0);
    CHECK(strcmp("abd", "abc") > 0);

    CHECK(strncmp("abcdef", "abcxyz", 3) == 0);
    CHECK(strncmp("abcdef", "abcxyz", 6) < 0);

    static const char lit[] = "a.b.c";
    const char* p = strchr(lit, '.');
    CHECK(p != NULL);
    CHECK_EQ((size_t)(p - lit), (size_t)1);
    CHECK_MSG(strchr(lit, 'z') == NULL, "miss");
    CHECK_MSG(strstr("haystack", "needle") == NULL, "absent");
    CHECK(strstr("haystack needle here", "needle") != NULL);

    char buf[16];
    memset(buf, 'A', sizeof(buf));
    memcpy(buf, "xyz", 3);
    CHECK(memcmp(buf, "xyzAAAA", 7) == 0);
    memmove(buf + 1, buf, 5);                    // overlapping forward
    CHECK(memcmp(buf, "xxyzAA", 6) == 0);
}

static size_t my_strlen(const char* s) { const char* p = s; while (*p) ++p; return (size_t)(p - s); }
static long my_atoi(const char* s) {
    long r = 0;
    int neg = 0;
    while (*s == ' ' || *s == '\t') ++s;
    if (*s == '-') { neg = 1; ++s; }
    else if (*s == '+') ++s;
    while (*s >= '0' && *s <= '9') { r = r * 10 + (*s - '0'); ++s; }
    return neg ? -r : r;
}

TEST(string, custom_vs_crt) {
    const char* corpus[] = { "", "a", "longer sentence here", "\ttab\t" };
    for (const char* s : corpus)
        CHECK_EQ(my_strlen(s), strlen(s));

    CHECK_EQ(my_atoi("42"), 42);
    CHECK_EQ(my_atoi("  -17"), -17);
    CHECK_EQ(my_atoi("+7"), 7);
    CHECK_EQ(my_atoi("0"), 0);
    CHECK_EQ(my_atoi("-999"), -999);
    CHECK_EQ(my_atoi("12ab"), 12);               // stops at non-digit, like atoi
    for (const char* s : corpus) {
        char* endp = NULL;
        long v = strtol(s, &endp, 10);
        if (my_strlen(s) == 0 || (s[0] != '-' && s[0] != '+' && (s[0] < '0' || s[0] > '9')))
            continue;                            // strtol semantics differ on junk
        CHECK_EQ(v, atol(s));
    }
}

TEST(string, format_roundtrip) {
    std::setlocale(LC_NUMERIC, "C");             // stable '.' decimal point

    char buf[160];
    int n = snprintf(buf, sizeof(buf), "%d|%08d|%.3f|%llu|%X|%s",
                     42, -7, 3.14159, 18446744073709551615ull, 0xBEEFu, "ok");
    CHECK(n > 0);
    CHECK_MSG(strcmp(buf,
        "42|-0000007|3.142|18446744073709551615|BEEF|ok") == 0, buf);

    n = snprintf(buf, sizeof(buf), "[%5d][%-5d][%05d]", 123, 123, 123);
    CHECK_MSG(strcmp(buf, "[  123][123  ][00123]") == 0, buf);

    n = snprintf(buf, sizeof(buf), "%c%c%%", 'O', 'K');
    CHECK_MSG(strcmp(buf, "OK%") == 0, buf);

    wchar_t wbuf[64];
    n = (int)swprintf(wbuf, 64, L"%ls-%04x-%d", L"wv", 0xBEEFu, -3);
    CHECK(n > 0);
    CHECK_MSG(wcscmp(wbuf, L"wv-beef--3") == 0, "wide format");

    // %.17g <-> strtod must round-trip doubles bit-exactly
    Rng rng(1111);
    for (int i = 0; i < 200; ++i) {
        double d = rng.d01() * 1000000.0 - 500000.0;
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "%.17g", d);
        double back = strtod(tmp, NULL);
        CHECK_MSG(memcmp(&d, &back, sizeof(d)) == 0, "double text round trip");
    }

    int a = 0, b = 0;
    CHECK_EQ(sscanf("a=13;b=-9;", "a=%d;b=%d;", &a, &b), 2);
    CHECK_EQ(a, 13);   CHECK_EQ(b, -9);
}

TEST(string, utf8_roundtrip) {
    struct CP { unsigned cp; unsigned nbytes; };
    // BMP + astral plane samples with pinned UTF-8 lengths
    const CP cps[] = {
        { 0x0041,     1 },  // 'A'
        { 0x007A,     1 },  // 'z'
        { 0x20AC,     3 },  // euro sign
        { 0x4E2D,     3 },  // CJK
        { 0x1F600,    4 },  // emoji (surrogate pair in UTF-16)
        { 0x10FFFF,   4 },  // max codepoint
    };

    // independent minimal encoder
    auto enc_cp = [](unsigned c, char out[4]) -> unsigned {
        if (c < 0x80) { out[0] = (char)c; return 1; }
        if (c < 0x800) { out[0]=(char)(0xC0|(c>>6)); out[1]=(char)(0x80|(c&63)); return 2; }
        if (c < 0x10000) { out[0]=(char)(0xE0|(c>>12)); out[1]=(char)(0x80|((c>>6)&63));
                           out[2]=(char)(0x80|(c&63)); return 3; }
        out[0]=(char)(0xF0|(c>>18)); out[1]=(char)(0x80|((c>>12)&63));
        out[2]=(char)(0x80|((c>>6)&63)); out[3]=(char)(0x80|(c&63)); return 4;
    };

    for (const CP& c : cps) {
        char utf8[8];
        unsigned nb = enc_cp(c.cp, utf8);
        CHECK_EQ(nb, c.nbytes);

        wchar_t wc[3];
        if (c.cp < 0x10000) { wc[0] = (wchar_t)c.cp; wc[1] = 0; }
        else {
            unsigned x = c.cp - 0x10000;
            wc[0] = (wchar_t)(0xD800 | (x >> 10));
            wc[1] = (wchar_t)(0xDC00 | (x & 0x3FF));
            wc[2] = 0;
        }
        // Win32 conversion agrees byte-for-byte
        char api[8];
        int conv = WideCharToMultiByte(CP_UTF8, 0, wc, -1, api, sizeof(api), NULL, NULL);
        CHECK(conv > 0);
        CHECK_EQ((size_t)(conv - 1), (size_t)c.nbytes);   // minus terminator
        CHECK(memcmp(api, utf8, c.nbytes) == 0);

        // decode back to exactly the original surrogate pair
        wchar_t back[4] = {};
        int dn = MultiByteToWideChar(CP_UTF8, 0, api, c.nbytes, back, 4);
        CHECK_EQ(dn, (int)(c.cp < 0x10000 ? 1 : 2));
        CHECK(back[dn] == 0);
        for (int k = 0; k < dn; ++k)
            CHECK_EQ((unsigned)back[k], (unsigned)wc[k]);
    }
}

// CSV parser: handles quoted fields with "" escapes
static std::vector<std::string> parse_csv(const std::string& line) {
    std::vector<std::string> out;
    std::string cur;
    bool inq = false;
    size_t i = 0;
    while (i <= line.size()) {
        char ch = i < line.size() ? line[i] : ',';
        if (inq) {
            if (ch == '"') {
                if (i + 1 < line.size() && line[i + 1] == '"') { cur += '"'; ++i; }
                else inq = false;
            } else cur += ch;
        } else {
            if (ch == '"') inq = true;
            else if (ch == ',') { out.push_back(cur); cur.clear(); }
            else if (i < line.size()) cur += ch;
        }
        ++i;
    }
    return out;
}

TEST(string, csv_parser) {
    std::vector<std::string> f =
        parse_csv("\"a,b\",plain,\"he said \"\"hi\"\"\",\"\",tail");
    CHECK_EQ(f.size(), (size_t)5);
    if (f.size() == 5) {
        CHECK(f[0] == "a,b");
        CHECK(f[1] == "plain");
        CHECK(f[2] == "he said \"hi\"");
        CHECK(f[3].empty());
        CHECK(f[4] == "tail");
    }
    // trailing separator produces exactly one empty trailing field
    std::vector<std::string> g = parse_csv("");
    CHECK_EQ(g.size(), (size_t)1);
    CHECK(g.empty() || g[0].empty());
}

TEST(string, config_kv_trimmed) {
    const char* conf =
        "# comment line\n"
        "k1=v1\n"
        "  k2 = spaced value  \n"
        "k3=multi word here\n"
        "\n";
    std::map<std::string, std::string> kv;
    std::istringstream iss(conf);
    std::string ln;
    while (std::getline(iss, ln)) {
        size_t h = ln.find('#');
        if (h == 0) continue;
        size_t eq = ln.find('=');
        if (eq == std::string::npos) continue;
        auto trim = [](std::string s) {
            size_t a = s.find_first_not_of(" \t\r");
            if (a == std::string::npos) return std::string();
            size_t b = s.find_last_not_of(" \t\r");
            return s.substr(a, b - a + 1);
        };
        kv[trim(ln.substr(0, eq))] = trim(ln.substr(eq + 1));
    }
    CHECK_EQ(kv.size(), (size_t)3);
    CHECK(kv.count("k1") && kv.at("k1") == "v1");
    CHECK(kv.count("k2") && kv.at("k2") == "spaced value");
    CHECK(kv.count("k3") && kv.at("k3") == "multi word here");
}

static size_t lev_dp(const std::string& a, const std::string& b) {
    static size_t d[32][32];
    for (size_t i = 0; i <= a.size(); ++i) d[i][0] = i;
    for (size_t j = 0; j <= b.size(); ++j) d[0][j] = j;
    for (size_t i = 1; i <= a.size(); ++i)
        for (size_t j = 1; j <= b.size(); ++j) {
            size_t cost = a[i - 1] == b[j - 1] ? 0 : 1;
            size_t m = d[i-1][j] + 1;
            if (d[i][j-1] + 1 < m) m = d[i][j-1] + 1;
            if (d[i-1][j-1] + cost < m) m = d[i-1][j-1] + cost;
            d[i][j] = m;
        }
    return d[a.size()][b.size()];
}

TEST(string, levenshtein_goldens) {
    CHECK_EQ(lev_dp("", ""), (size_t)0);
    CHECK_EQ(lev_dp("abc", "abc"), (size_t)0);
    CHECK_EQ(lev_dp("", "kitten"), (size_t)6);
    CHECK_EQ(lev_dp("sitting", ""), (size_t)7);
    CHECK_EQ(lev_dp("kitten", "sitting"), (size_t)3);
    CHECK_EQ(lev_dp("flaw", "lawn"), (size_t)2);
    CHECK_EQ(lev_dp("gumbo", "gambol"), (size_t)2);
    CHECK_EQ(lev_dp("12345", "54321"), (size_t)4);
}

static std::string replace_all(std::string s, const std::string& from,
                               const std::string& to) {
    size_t pos = 0;
    while ((pos = s.find(from, pos)) != std::string::npos) {
        s.replace(pos, from.size(), to);
        pos += to.size();
    }
    return s;
}

TEST(string, search_count_replace) {
    const char* hay = "abcabcabc";
    size_t cnt = 0;
    for (const char* p = hay; (p = strstr(p, "bca")) != NULL; ++p) ++cnt;
    CHECK_EQ(cnt, (size_t)2);                    // idx1 and idx4; idx7 lacks room

    std::string s = "abacaba";
    CHECK(replace_all(s, "aba", "X") == "XcX");
    CHECK(replace_all("aaaa", "aa", "b") == "bb");
    CHECK(replace_all("no hit here", "zzz", "!") == "no hit here");

    // word order reversal with whitespace collapsing
    std::vector<std::string> words;
    const char* txt = "  hello   brave new\tworld ";
    const char* p = txt;
    while (*p) {
        while (*p == ' ' || *p == '\t') ++p;
        const char* st = p;
        while (*p && *p != ' ' && *p != '\t') ++p;
        if (p > st) words.push_back(std::string(st, p));
    }
    CHECK_EQ(words.size(), (size_t)4);
    std::string joined;
    for (size_t i = words.size(); i-- > 0; ) {
        if (!joined.empty()) joined += ' ';
        joined += words[i];
    }
    CHECK(joined == "world new brave hello");
}
