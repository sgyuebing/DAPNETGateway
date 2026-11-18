/*
 *   Preliminaries
 *      Copyright (C) 2018,2026 by Jonathan Naylor G4KLX & contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   ------------------------------------------------------------------
 *   2026-11-18  FIXED BRANCH  — 配置解析层
 *   ------------------------------------------------------------------
 *   相对上游 2026-11-17 版修掉的问题（逐条对应审查报告）：

 *   [C1] 去注释逻辑退步：原实现 strchr(buf,'#') 无条件截断，
 *        Password=aB#3xK9! 会被切成 "aB" → 登录必失败且只报 "Login failed"。
 *        现改为：只有 trim 后**行首**是 '#' 才当注释；行内 '#' 属于值的一部分。
 *
 *   [C2] std::transform(..., ::tolower) 直接喂 char，含 UTF-8（中文备注）
 *        时 char 为负 → 未定义行为。统一走 asciiLower() 先转 unsigned char。
 *
 *   [C3] myStrToUInt32 不看 endptr、不上界：WhiteList=12345abc 静默收 12345，
 *        99999999999 截断成垃圾 RIC。现在尾随垃圾 = 报错拒载，越界 = 报错。
 *
 *   [C4] 默认 MasterPort 写成 8070，而 DAPNET 官方是 43434。
 *        用户只写 Host 不写 Port 就会连进黑洞，然后被 recover() 的死循环焊死。
 *        默认改为 43434。
 *
 *   [C5] 校验失败只 printf 一句 "cannot read the .ini file" 就 exit，
 *        运维根本不知道是缺 Password 还是端口写飞了。现在 reason 带具体行号+原因。
 *
 *   [C6] 补回 [Log] 5 项 + 正则文件 2 项 + Daemon + MaxQueue 的解析
 *        （这些键旧 .ini 里就有，上游重写时把读取代码弄丢了）。
 *        section 行 [General]/[Log]/[DAPNET] 依然被忽略 => 新旧两种 .ini 都能吃。
 */

#include "Conf.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <string>
#include <vector>

namespace {

const unsigned int BUFFER_SIZE = 513U;

/* [C4] DAPNET 官方接入端口。旧默认值 8070 是错的。 */
const unsigned short DEFAULT_DAPNET_PORT = 43434U;
const size_t         DEFAULT_MAX_QUEUE   = 500U;

inline char asciiLower(char c)
{
    return static_cast<char>(::tolower(static_cast<unsigned char>(c)));
}

std::string toLowerCopy(const std::string& s)
{
    std::string t = s;
    for (std::string::iterator it = t.begin(); it != t.end(); ++it)
        *it = asciiLower(*it);
    return t;
}

std::string trim(const std::string& s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return std::string();
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

/* [C3] 严格无符号解析：必须整个 token 都是数字，且落在 [1, limit] 内 */
bool strictUInt(const std::string& s, uint32_t limit, uint32_t& out)
{
    if (s.empty()) return false;

    const char* p = s.c_str();
    for (const char* q = p; *q != '\0'; ++q) {
        if (!::isdigit(static_cast<unsigned char>(*q))) return false;   // 尾随垃圾 → 拒
    }

    char* end = nullptr;
    unsigned long v = ::strtoul(p, &end, 10);
    if (end == p || *end != '\0') return false;
    if (v == 0UL || v > static_cast<unsigned long>(limit)) return false;

    out = static_cast<uint32_t>(v);
    return true;
}

bool parseBool(const std::string& s, bool& out)
{
    std::string t = toLowerCopy(trim(s));
    if (t == "1" || t == "yes" || t == "true" || t == "on" || t == "enable")  { out = true;  return true; }
    if (t == "0" || t == "no"  || t == "false" || t == "off" || t == "disable") { out = false; return true; }
    return false;
}

} // namespace


CConf::CConf(const std::string& file) :
    m_file(file),
    m_callsign(),
    m_password(),
    m_masterHost(),
    m_masterPort(DEFAULT_DAPNET_PORT),
    m_backupHost(),
    m_backupPort(0U),
    m_localHost("127.0.0.1"),
    m_localPort(4800U),
    m_whiteList(),
    m_blackList(),
    m_wlRegexFile(),
    m_blRegexFile(),
    m_logFilePath("."),
    m_logFileRoot("DAPNETGateway"),
    m_logFileLevel(1U),
    m_logDisplayLevel(1U),
    m_logFileRotate(true),
    m_debug(false),
    m_daemon(false),
    m_maxQueue(DEFAULT_MAX_QUEUE)
{
}

CConf::~CConf()
{
}

bool CConf::parsePort(const std::string& s, unsigned short& port, const char* what, std::string& reason) const
{
    uint32_t v = 0U;
    if (!strictUInt(s, 65535U, v)) {
        reason = std::string("invalid ") + what + " '" + s + "' (need 1..65535)";
        return false;
    }
    port = static_cast<unsigned short>(v);
    return true;
}

bool CConf::parseIDList(const std::string& s, std::vector<uint32_t>& list, const char* what, std::string& reason) const
{
    list.clear();
    std::string t = trim(s);
    if (t.empty()) return true;                       // 空 = 不限制，合法

    size_t pos = 0U;
    while (pos <= t.size()) {
        size_t comma = t.find(',', pos);
        std::string tok = trim(t.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos));
        if (!tok.empty()) {
            uint32_t id = 0U;
            if (!strictUInt(tok, 9999999U, id)) {     // POCSAG RIC 最多 7 位
                reason = std::string("invalid ") + what + " entry '" + tok + "' (need 1..9999999)";
                return false;
            }
            list.push_back(id);
        }
        if (comma == std::string::npos) break;
        pos = comma + 1U;
    }
    return true;
}

bool CConf::read(std::string& reason)
{
    reason.clear();

    FILE* fp = ::fopen(m_file.c_str(), "rt");
    if (fp == nullptr) {
        reason = "cannot open config file '" + m_file + "'";
        return false;
    }

    char buffer[BUFFER_SIZE];
    unsigned int lineNo = 0U;
    bool sawPassword = false;
    bool sawMaster   = false;

    while (::fgets(buffer, BUFFER_SIZE, fp) != nullptr) {
        ++lineNo;

        /* [C1] 只剥行首注释；行内 '#' 保留（密码里真的会有 #） */
        std::string raw = buffer;
        std::string line = trim(raw);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        { size_t sc = line.find(';'); if (sc != std::string::npos) line = trim(line.substr(0U, sc)); if (line.empty()) continue; }

        /* section 头 [General] / [Log] / [DAPNET] —— 兼容旧三段式，直接跳过 */
        if (line[0] == '[') continue;

        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key   = toLowerCopy(trim(line.substr(0U, eq)));
        std::string value = trim(line.substr(eq + 1U));

        if (value.size() >= 2U && value[0]=='"' && value.back()=='"') value = value.substr(1U, value.size()-2U);
        /* ── 身份 ─────────────────────────────────────────────── */
        if (key == "callsign") {
            m_callsign = value;

        } else if (key == "password" || key == "authkey") {   // AuthKey = 旧名，继续认
            m_password = value;
            sawPassword = true;

        /* ── DAPNET 主 / 备 ───────────────────────────────────── */
        } else if (key == "masterhost" || key == "address" || key == "dapnetaddress") {
            m_masterHost = value;
            sawMaster = true;
        } else if (key == "masterport" || key == "dapnetport") {
            if (!parsePort(value, m_masterPort, "MasterPort", reason)) goto bail;
            sawMaster = true;

        } else if (key == "backuphost") {
            m_backupHost = value;
        } else if (key == "backupport") {
            if (!parsePort(value, m_backupPort, "BackupPort", reason)) goto bail;

        /* ── 本地 MMDVMHost 侧 ────────────────────────────────── */
        } else if (key == "localhost" || key == "rptaddress" || key == "myaddress") {
            m_localHost = value;
        } else if (key == "localport" || key == "rptport" || key == "myport") {
            if (!parsePort(value, m_localPort, "LocalPort", reason)) goto bail;

        /* ── RIC 黑白名单 ─────────────────────────────────────── */
        } else if (key == "whitelist") {
            if (!parseIDList(value, m_whiteList, "WhiteList", reason)) goto bail;
        } else if (key == "blacklist") {
            if (!parseIDList(value, m_blackList, "BlackList", reason)) goto bail;

        /* ── 正则黑白名单文件（上游重写时被删，此处补回） ──────── */
        } else if (key == "whitelistregexfile" || key == "wlregexfile") {
            m_wlRegexFile = value;
        } else if (key == "blacklistregexfile" || key == "blregexfile") {
            m_blRegexFile = value;

        /* ── 日志（补回） ─────────────────────────────────────── */
        } else if (key == "logfilepath") {
            m_logFilePath = value.empty() ? "." : value;
        } else if (key == "logfileroot") {
            m_logFileRoot = value.empty() ? "DAPNETGateway" : value;
        } else if (key == "logfilelevel") {
            uint32_t v; if (!strictUInt(value, 6U, v)) { reason = "LogFileLevel must be 0..6"; goto bail; }
            m_logFileLevel = (unsigned int)v;
        } else if (key == "displaylevel") {
            uint32_t v; if (!strictUInt(value, 6U, v)) { reason = "DisplayLevel must be 0..6"; goto bail; }
            m_logDisplayLevel = (unsigned int)v;
        } else if (key == "filerotate") {
            if (!parseBool(value, m_logFileRotate)) { reason = "FileRotate must be 0/1"; goto bail; }

        /* ── 杂项 ─────────────────────────────────────────────── */
        } else if (key == "debug") {
            if (!parseBool(value, m_debug)) { reason = "Debug must be 0/1"; goto bail; }
        } else if (key == "daemon") {
            if (!parseBool(value, m_daemon)) { reason = "Daemon must be 0/1"; goto bail; }
        } else if (key == "maxqueue" || key == "queuelimit") {
            uint32_t v; if (!strictUInt(value, 100000U, v)) { reason = "MaxQueue must be 1..100000"; goto bail; }
            m_maxQueue = (size_t)v;
        }
        /* 未知键：不报错，只静默忽略，保证向前兼容 */
    }

bail:
    ::fclose(fp);

    if (!reason.empty()) {
        char buf[64];
        ::snprintf(buf, sizeof(buf), " (line %u)", lineNo);
        reason += buf;
        return false;
    }

    /* ───────── 必填项与语义校验（失败原因说人话） ───────── */

    if (m_callsign.empty()) {
        reason = "Callsign is missing";
        return false;
    }
    if (!sawPassword) {
        reason = "Password is missing (old key name 'AuthKey' also accepted)";
        return false;
    }
    if (m_password == "TOPSECRET" || m_password == "CHANGE_ME") {
        /* 上游把 AuthKey 改名 Password 后，这道防呆检查跟着失效了。补回来。 */
        reason = "Password is still the sample value ('" + m_password +
                 "') — edit the .ini before going on air";
        return false;
    }
    if (!sawMaster || m_masterHost.empty()) {
        reason = "MasterHost is missing (old key names 'Address'/'DAPNETAddress' also accepted)";
        return false;
    }
    if (m_localHost.empty()) {
        reason = "LocalHost is missing";
        return false;
    }
    if (m_localPort == 0U) {
        reason = "LocalPort must be 1..65535, and must equal [DAPNET] LocalPort in MMDVMHost.ini";
        return false;
    }
    if (m_backupHost.empty()) m_backupPort = 0U;
    else if (m_backupPort == 0U) m_backupPort = DEFAULT_DAPNET_PORT;

    /* 同一 RIC 同时进黑白名单 = 配置自相矛盾，直接拒，别让运维猜为什么收不到 */
    for (std::vector<uint32_t>::const_iterator w = m_whiteList.begin(); w != m_whiteList.end(); ++w) {
        for (std::vector<uint32_t>::const_iterator b = m_blackList.begin(); b != m_blackList.end(); ++b) {
            if (*w == *b) {
                char buf[96];
                ::snprintf(buf, sizeof(buf), "RIC %lu is in both WhiteList and BlackList", (unsigned long)*w);
                reason = buf;
                return false;
            }
        }
    }

    return true;
}