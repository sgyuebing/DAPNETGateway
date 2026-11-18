/*
 *   Copyright (C) 2018,2026 by Jonathan Naylor G4KLX & contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   ------------------------------------------------------------------
 *   2026-11-18  FIXED BRANCH
 *   逐条对应 DAPNETNetwork.h 里的 [N1]~[N5] 注释，协议语义与上游一致：
 *     '+' ACK / '-' NACK / '2' 时间同步 / '3' keepalive / '4' 时隙表
 *     '7' 登录失败 / '#' 寻呼报文
 *   唯一对外行为变化：不再丢长报文，不再因一条畸形报文崩进程。
 */

#include "DAPNETNetwork.h"
#include "Thread.h"
#include "Utils.h"
#include "Log.h"
#include "Version.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace {
/* [N4] 唯一一份退避表，任何下标访问都过 clampBackoff() */
const unsigned int BACKOFF_MS[] = {2000U, 4000U, 8000U, 10000U, 20000U,
                                   60000U, 120000U, 240000U, 480000U, 600000U};
const unsigned int BACKOFF_N = sizeof(BACKOFF_MS) / sizeof(unsigned int);

unsigned int clampBackoff(unsigned int n)
{
    return (n < BACKOFF_N) ? n : (BACKOFF_N - 1U);
}

inline char asciiLower(char c)
{
    return static_cast<char>(::tolower(static_cast<unsigned char>(c)));
}
} // namespace


CDAPNETNetwork::CDAPNETNetwork(const std::vector<std::string>& addresses, const std::vector<unsigned short>& ports,
                               const std::string& callsign, const std::string& authKey, bool debug) :
    m_addresses(addresses),
    m_ports(ports),
    m_endpoint(0U),
    m_callsign(callsign),
    m_authKey(authKey),
    m_debug(debug),
    m_socket(NULL),
    m_state(STATE_DISCONNECTED),
    m_loggedInFlag(false),
    m_inbuf(),
    m_message(NULL),
    m_scheduleValid(false),
    m_slot(0U),
    m_totalCodewords(0U),
    m_failCount(0U),
    m_malformedCount(0U),
    m_oversizeCount(0U)
{
    m_inbuf.reserve(1024U);
    for (unsigned int i = 0U; i < 16U; ++i) m_schedule[i] = false;

    if (m_addresses.empty()) {
        LogError("CDAPNETNetwork: no server address configured");
    } else {
        m_socket = new CTCPSocket(m_addresses[0U], ports.empty() ? 43434U : m_ports[0U]);
    }
    if (m_addresses.size() != m_ports.size())
        LogWarning("CDAPNETNetwork: address/port count mismatch (%zu vs %zu)", m_addresses.size(), m_ports.size());
}

CDAPNETNetwork::~CDAPNETNetwork()
{
    delete m_message;
    m_message = NULL;
    close();
    delete m_socket;
    m_socket = NULL;
}

bool CDAPNETNetwork::rebuildSocket()
{
    if (m_addresses.empty()) return false;

    delete m_socket;
    m_socket = NULL;

    if (m_endpoint >= m_addresses.size()) m_endpoint = 0U;

    unsigned short port = (m_ports.size() > m_endpoint) ? m_ports[m_endpoint] : 43434U;
    m_socket = new CTCPSocket(m_addresses[m_endpoint], port);
    return true;
}

/* ────────────────────────── 连接 / 登录 ────────────────────────── */

bool CDAPNETNetwork::open()
{
    if (m_addresses.empty()) return false;

    /* [N5] 主挂了切备：m_endpoint 由 reconnectBackoffMs() 推进 */
    if (m_endpoint >= m_addresses.size())
        m_endpoint = 0U;

    if (m_endpoint >= m_addresses.size()) m_endpoint = 0U;

    LogInfo("Opening DAPNET connection to %s:%u%s", m_addresses[m_endpoint].c_str(), m_ports[m_endpoint],
            m_endpoint == 0U ? " (primary)" : " (backup)");

    rebuildSocket();

    m_state = STATE_CONNECTING;
    m_inbuf.clear();

    if (m_socket == NULL || !m_socket->open()) {
        m_state = STATE_DISCONNECTED;
        return false;
    }

    m_state = STATE_CONNECTED;
    return true;
}

bool CDAPNETNetwork::login()
{
    LogInfo("Logging into DAPNET as %s", m_callsign.c_str());

    /* [C2 同类] 上游直接 ::tolower(char) 对 UTF-8 呼号是 UB */
    std::string call = m_callsign;
    for (std::string::iterator it = call.begin(); it != call.end(); ++it)
        *it = asciiLower(*it);

    char login[256U];
    ::snprintf(login, sizeof(login), "[DAPNETGateway v%s %s %s]\r\n", VERSION, call.c_str(), m_authKey.c_str());

    return sendRaw(login);
}

void CDAPNETNetwork::close()
{
    if (m_state != STATE_DISCONNECTED)
        LogInfo("Closing DAPNET connection");

    if (m_socket != NULL) m_socket->close();
    m_state = STATE_DISCONNECTED;
    m_loggedInFlag = false;
    m_inbuf.clear();
}

/* ────────────────────────── 收发原语 ────────────────────────── */

bool CDAPNETNetwork::sendRaw(const std::string& s)
{
    if (m_state != STATE_CONNECTED || m_socket == NULL) return false;

    if (m_debug)
        CUtils::dump(1U, "DAPNET Data Transmitted", reinterpret_cast<const unsigned char*>(s.data()), (unsigned int)s.size());

    if (!m_socket->write(reinterpret_cast<const unsigned char*>(s.data()), (unsigned int)s.size())) {
        LogWarning("Error when writing to DAPNET");
        m_state = STATE_DISCONNECTED;
        return false;
    }
    return true;
}

/* [N1] 核心修复：从累积缓冲里切**完整**报文，处理 TCP 粘包 / 拆包。
   返回 true = 切出一条放在 line 里；false = 数据不够，等下一轮。      */
bool CDAPNETNetwork::extractOneMessage(std::string& line)
{
    line.clear();

    if (m_inbuf.empty()) return false;

    // 找帧起始 '#'
    size_t start = 0U;
    while (start < m_inbuf.size() && m_inbuf[start] != '#') ++start;

    if (start == m_inbuf.size()) {
        // 整缓冲没有 '#'：全是垃圾（或对端乱发），丢掉，但留最后一个字节防 '#' 被劈两半
        if (m_inbuf.size() > 1U) {
            LogDebug("Discarding %zu byte(s) with no frame start", m_inbuf.size() - 1U);
            m_inbuf.erase(m_inbuf.begin(), m_inbuf.end() - 1);
        }
        return false;
    }
    if (start > 0U) {
        LogDebug("Skipping %zu byte(s) of inter-frame garbage", start);
        m_inbuf.erase(m_inbuf.begin(), m_inbuf.begin() + start);
    }

    // 找帧结束 "\r\n"
    for (size_t i = 1U; i + 1U < m_inbuf.size(); ++i) {
        if (m_inbuf[i] == '\r' && m_inbuf[i + 1U] == '\n') {
            line.assign(reinterpret_cast<const char*>(&m_inbuf[0U]), i + 2U);
            m_inbuf.erase(m_inbuf.begin(), m_inbuf.begin() + i + 2U);
            return true;
        }
    }

    // 半帧：等更多数据
    if (m_inbuf.size() > MSG_HARD_LIMIT) {
        // 超过单条上限还没有 \r\n → 对端不守规矩或攻击，整段丢弃保护内存
        ++m_oversizeCount;
        LogWarning("Oversize/incomplete frame (%zu B) dropped, oversize=%lu",
                   m_inbuf.size(), m_oversizeCount);
        m_inbuf.clear();
    }
    return false;
}

bool CDAPNETNetwork::read()
{
    if (m_state != STATE_CONNECTED) return false;

    unsigned char chunk[4096U];
    if (m_socket == NULL) return false;
    int length = m_socket->read(chunk, 4096U, 0U);

    if (length == -1) {                       // 错误
        LogWarning("DAPNET socket read error");
        m_state = STATE_DISCONNECTED;
        return false;
    }
    if (length == -2) {                       // 对端断开
        LogWarning("DAPNET connection lost (peer closed, %zu B buffered)", m_inbuf.size());
        m_state = STATE_DISCONNECTED;
        return false;
    }
    if (length == 0) return true;             // 无数据，正常

    if (m_debug)
        CUtils::dump(1U, "DAPNET Data Received", chunk, (unsigned int)length);

    /* [N1] 只追加，绝不就地改写接收缓冲 */
    if (m_inbuf.size() + (size_t)length > INBUF_HARD_LIMIT) {
        ++m_oversizeCount;
        LogWarning("DAPNET ingest buffer overflow (%zu+%d B) — reset, oversize=%lu",
                   m_inbuf.size(), length, m_oversizeCount);
        m_inbuf.clear();
        return true;                          // 不判死，下一轮重新同步到 '#'
    }
    m_inbuf.insert(m_inbuf.end(), chunk, chunk + length);

    /* 把缓冲里所有完整帧一次吐完（一趟 read 可能含多条，上游只处理一条=丢消息） */
    for (;;) {
        std::string line;
        if (!extractOneMessage(line)) break;

        if (line.size() < 3U) {               // "#x\r\n" 都不够
            ++m_malformedCount;
            LogDebug("Runt frame dropped (%zu B), malformed=%lu", line.size(), m_malformedCount);
            continue;
        }

        char c = line[0U];

        if (c == '+') {
            // ACK，无事发生
            continue;

        } else if (c == '-') {
            LogWarning("An error has been reported by DAPNET: %s", line.c_str());
            continue;

        } else if (c == '2') {
            // 首次同步 = 登录成功；随后回带 0000 的时间戳 + ACK
            if (!m_loggedInFlag) {
                m_loggedInFlag = true;
                m_failCount = 0U;
                LogInfo("Logged into the DAPNET network");
            }
            std::string reply = line;
            if (reply.size() >= 2U && reply[reply.size() - 2U] == '\r')
                reply.erase(reply.size() - 2U, 2U);         // 剥原 \r\n
            reply += ":0000\r\n";                            // [N1] std::string 追加，无栈溢出
            if (!sendRaw(reply)) return false;
            if (!sendRaw("+\r\n"))   return false;
            continue;

        } else if (c == '3') {
            if (!sendRaw("+\r\n")) return false;             // keepalive
            continue;

        } else if (c == '4') {
            if (!parseSchedule(line)) return false;
            continue;

        } else if (c == '7') {
            if (!parseFailedLogin(line)) return false;
            continue;

        } else if (c == '#') {
            if (!parseMessage(line)) return false;
            continue;

        } else {
            LogDebug("Unknown DAPNET frame '%c', replying -", c);
            CUtils::dump(3U, "An unknown message from DAPNET",
                         reinterpret_cast<const unsigned char*>(line.data()), (unsigned int)line.size());
            if (!sendRaw("-\r\n")) return false;
            continue;
        }
    }

    return true;
}

/* ────────────────────────── 报文解析 ────────────────────────── */

bool CDAPNETNetwork::parseMessage(const std::string& line)
{
    /* 线格式： #<id2hex>:<type>:<ric6hex>:<func>:<payload>\r\n
       上游用 strtok 原地改串 + assert 兜底；Release 下 assert 消失 →
       strtoul(NULL) 段错误（远程 DoS）。这里改用 find/ substr，无 NULL 可能。 */

    unsigned int id = 0U;
    if (line.size() >= 3U)
        ::sscanf(line.c_str() + 1U, "%2x", &id);

    // 找 4 个冒号
    size_t c[4];
    size_t pos = 1U;
    int    n   = 0;
    while (n < 4 && pos < line.size()) {
        size_t colon = line.find(':', pos);
        if (colon == std::string::npos || colon + 1U >= line.size()) break;
        c[n++] = colon;
        pos = colon + 1U;
    }

    auto trimCRLF = [&](std::string s) {
        while (!s.empty() && (s[s.size()-1U] == '\r' || s[s.size()-1U] == '\n')) s.erase(s.size()-1U);
        return s;
    };

    if (n != 4) {
        ++m_malformedCount;
        LogWarning("Malformed paging frame (only %d separators), malformed=%lu", n, m_malformedCount);
        CUtils::dump(3U, "Received a malformed message from DAPNET",
                     reinterpret_cast<const unsigned char*>(line.data()), (unsigned int)line.size());
        char reply[24U];
        ::snprintf(reply, sizeof(reply), "#%02X -\r\n", (id + 1U) % 256U);
        return sendRaw(reply);
    }

    std::string sType = line.substr(c[0] + 1U, c[1] - c[0] - 1U);
    std::string sAddr = line.substr(c[1] + 1U, c[2] - c[1] - 1U);
    std::string sFunc = line.substr(c[2] + 1U, c[3] - c[2] - 1U);
    std::string sBody = trimCRLF(line.substr(c[3] + 1U));

    if (sType.empty() || sAddr.empty() || sFunc.empty()) {
        ++m_malformedCount;
        LogWarning("Malformed paging frame (empty field), malformed=%lu", m_malformedCount);
        char reply[24U];
        ::snprintf(reply, sizeof(reply), "#%02X -\r\n", (id + 1U) % 256U);
        return sendRaw(reply);
    }

    unsigned int type = (unsigned int)::strtoul(sType.c_str(), NULL, 10);
    unsigned int addr = (unsigned int)::strtoul(sAddr.c_str(), NULL, 16);
    unsigned int func = (unsigned int)::strtoul(sFunc.c_str(), NULL, 10);

    if (addr == 0U || addr > 2097151U) {      // POCSAG RIC 合法域 1..0x1FFFFF
        ++m_malformedCount;
        LogWarning("RIC %u out of POCSAG range — rejected, malformed=%lu", addr, m_malformedCount);
        char reply[24U];
        ::snprintf(reply, sizeof(reply), "#%02X -\r\n", (id + 1U) % 256U);
        return sendRaw(reply);
    }

    /* [N3] 先删旧的再赋新的：服务器连发两条而网关还没取走时，上游会泄一条 */
    delete m_message;
    m_message = NULL;

    // CPOCSAGMessage 构造签名要 unsigned char*（它内部 memcpy 后不保留指针），
    // sBody 是本函数栈上的 std::string，生命周期覆盖构造过程，安全。
    m_message = new CPOCSAGMessage((unsigned char)type, addr, (unsigned char)func,
                                   reinterpret_cast<unsigned char*>(&sBody[0U]),
                                   (unsigned int)sBody.size());

    LogDebug("Queued page ric=%u func=%u type=%u len=%u", addr, func, type, (unsigned int)sBody.size());

    char reply[24U];
    ::snprintf(reply, sizeof(reply), "#%02X +\r\n", (id + 1U) % 256U);
    return sendRaw(reply);
}

bool CDAPNETNetwork::parseSchedule(const std::string& line)
{
    // 线格式： 4<16进制时隙掩码>\r\n
    if (line.size() < 3U) {
        ++m_malformedCount;
        LogWarning("Truncated schedule frame, malformed=%lu", m_malformedCount);
        return sendRaw("+\r\n");
    }

    std::string mask = line.substr(1U);
    while (!mask.empty() && (mask[mask.size()-1U] == '\r' || mask[mask.size()-1U] == '\n'))
        mask.erase(mask.size() - 1U);

    LogInfo("Schedule information received: %s", mask.c_str());

    bool sched[16U];
    for (unsigned int i = 0U; i < 16U; ++i) sched[i] = false;

    static const char HEX[] = "0123456789ABCDEF";
    for (std::string::const_iterator it = mask.begin(); it != mask.end(); ++it) {
        const char* p = ::strchr(HEX, asciiLower(*it));
        if (p == NULL) continue;
        int v = (int)(p - HEX);
        if (v >= 0 && v < 16) sched[(unsigned int)v] = true;
    }

    for (unsigned int i = 0U; i < 16U; ++i) m_schedule[i] = sched[i];
    m_scheduleValid = true;

    return sendRaw("+\r\n");
}

bool CDAPNETNetwork::parseFailedLogin(const std::string& line)
{
    std::string reason = line.size() > 2U ? line.substr(2U) : std::string("(no reason)");
    while (!reason.empty() && (reason[reason.size()-1U] == '\r' || reason[reason.size()-1U] == '\n'))
        reason.erase(reason.size() - 1U);

    LogError("Login failed: %s  (attempt %u, next wait %ums)",
             reason.c_str(), m_failCount + 1U, clampBackoff(m_failCount));

    /* [N4] 先 clamp 再下标；上游是先取下标后 if(<9) 兜底，
       而 m_failCount 是构造传入的，传 ≥10 直接越界读全局数组 */
    CThread::sleep(clampBackoff(m_failCount));
    if (m_failCount < BACKOFF_N - 1U) ++m_failCount;

    // 凭据错就别无限重试刷人家服务器：连续 10 次直接举手
    if (m_failCount == BACKOFF_N - 1U)
        LogError("Still rejected after %u attempts — check Callsign/Password in the .ini", m_failCount);

    return sendRaw("+\r\n");
}

/* ────────────────────────── 对外状态 ────────────────────────── */

void CDAPNETNetwork::setSlotUsage(unsigned int slot, unsigned int totalCodewords)
{
    m_slot           = slot & 0xFU;
    m_totalCodewords = totalCodewords;
}

bool CDAPNETNetwork::getSchedule(bool sched[16U], unsigned int& slot, unsigned int& codewords) const
{
    if (!m_scheduleValid) return false;
    for (unsigned int i = 0U; i < 16U; ++i) sched[i] = m_schedule[i];
    slot      = m_slot;
    codewords = m_totalCodewords;
    return true;
}

CPOCSAGMessage* CDAPNETNetwork::getMessage()
{
    if (m_message == NULL) return NULL;

    CPOCSAGMessage* message = m_message;
    m_message = NULL;                 // 所有权移交，调用方负责 delete
    return message;
}

bool CDAPNETNetwork::writeMsgType(bool text)
{
    // 上游同名函数语义：告诉服务器本端要收 numeric/alpha
    char buf[16U];
    ::snprintf(buf, sizeof(buf), "M:%s\r\n", text ? "ALPHA" : "NUMERIC");
    return sendRaw(buf);
}

int  CDAPNETNetwork::reconnectBackoffMs()
{
    // 主备轮转：每失败一轮换下一个端点，退避按 clamp 后的表走
    unsigned int wait = clampBackoff(m_failCount);

    if (m_addresses.size() > 1U) {
        m_endpoint = (m_endpoint + 1U) % m_addresses.size();
        LogInfo("Failover -> %s:%u (attempt %u, wait %ums)",
                m_addresses[m_endpoint].c_str(), m_ports[m_endpoint], m_failCount + 1U, wait);
    }

    if (m_failCount < BACKOFF_N - 1U) ++m_failCount;

    rebuildSocket();          // 下一个端点准备好，供 open() 使用

    return (int)wait;
}

void CDAPNETNetwork::resetBackoff()
{
    m_failCount = 0U;
    m_endpoint  = 0U;
}