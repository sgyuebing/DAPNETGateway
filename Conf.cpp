/*
 *   Copyright (C) 2016,2017 by Jonathan Naylor G4KLX
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#include "Conf.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cstdint>      // ← 新增：uint32_t
#include <string>
#include <vector>
#include <algorithm>

#if !defined(_WIN32) && !defined(_WIN64)
#include <strings.h>
#endif

const int BUFFER_SIZE = 512;

// ─────────────────────────── 工具函数 ───────────────────────────

static bool myStrToBool(const std::string& s)
{
    std::string t = s;
    std::transform(t.begin(), t.end(), t.begin(), ::tolower);
    return t == "1" || t == "yes" || t == "true" || t == "on";
}

static uint16_t myStrToUInt16(const std::string& s, uint16_t def = 0U)
{
    char* end = nullptr;
    long v = ::strtol(s.c_str(), &end, 10);
    if (end == s.c_str() || v < 0 || v > 65535)
        return def;
    return (uint16_t)v;
}

static uint32_t myStrToUInt32(const std::string& s, uint32_t def = 0U)
{
    char* end = nullptr;
    unsigned long v = ::strtoul(s.c_str(), &end, 10);
    if (end == s.c_str())
        return def;
    return (uint32_t)v;
}

static std::string trim(const std::string& s)
{
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return {};
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// 解析 "1234,5678,9012" → vector<uint32_t>
static std::vector<uint32_t> parseIDList(const std::string& s)
{
    std::vector<uint32_t> list;
    size_t pos = 0;
    while (pos < s.size()) {
        size_t comma = s.find(',', pos);
        std::string tok = trim(s.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos));
        if (!tok.empty()) {
            uint32_t id = myStrToUInt32(tok, 0U);
            if (id > 0U)
                list.push_back(id);
        }
        if (comma == std::string::npos) break;
        pos = comma + 1U;
    }
    return list;
}

// ─────────────────────────── 构造 / 析构 ───────────────────────────

CConf::CConf(const std::string& file) :
m_file(file),
m_callsign(),
m_password(),
m_masterHost(),
m_masterPort(0U),
m_backupHost(),
m_backupPort(0U),
m_localHost(),
m_localPort(0U),
m_whiteList(),
m_blackList(),
m_debug(false)
{
}

CConf::~CConf()
{
}

// ─────────────────────────── 读取配置 ───────────────────────────

bool CConf::read()
{
    FILE* fp = ::fopen(m_file.c_str(), "rt");
    if (fp == nullptr) {
        ::fprintf(stderr, "Cannot open the config file - %s\n", m_file.c_str());
        return false;
    }

    char buffer[BUFFER_SIZE];
    while (::fgets(buffer, BUFFER_SIZE, fp) != nullptr) {
        // 去注释
        char* p = ::strchr(buffer, '#');
        if (p != nullptr) *p = '\0';

        std::string line = trim(buffer);
        if (line.empty()) continue;

        // 拆 key = value
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key   = trim(line.substr(0U, eq));
        std::string value = trim(line.substr(eq + 1U));

        if (key == "Callsign")        m_callsign   = value;
        else if (key == "Password")   m_password   = value;

        else if (key == "MasterHost") m_masterHost = value;
        else if (key == "MasterPort") m_masterPort = myStrToUInt16(value, 8070U);
        else if (key == "BackupHost") m_backupHost = value;
        else if (key == "BackupPort") m_backupPort = myStrToUInt16(value, 8070U);

        else if (key == "LocalHost")  m_localHost  = value;
        else if (key == "LocalPort")  m_localPort  = myStrToUInt16(value, 7620U);

        else if (key == "WhiteList")  m_whiteList  = parseIDList(value);
        else if (key == "BlackList")  m_blackList  = parseIDList(value);

        else if (key == "Debug")      m_debug      = myStrToBool(value);
    }

    ::fclose(fp);

    // 必填校验
    if (m_callsign.empty()) {
        ::fprintf(stderr, "Config: Callsign is missing\n");
        return false;
    }
    if (m_password.empty()) {
        ::fprintf(stderr, "Config: Password is missing\n");
        return false;
    }
    if (m_masterHost.empty()) {
        ::fprintf(stderr, "Config: MasterHost is missing\n");
        return false;
    }
    if (m_localHost.empty())
        m_localHost = "127.0.0.1";

    return true;
}

// ─────────────────────────── Getter ───────────────────────────

std::string CConf::getCallsign() const { return m_callsign; }
std::string CConf::getPassword() const { return m_password; }

std::string CConf::getMasterHost() const { return m_masterHost; }
uint16_t    CConf::getMasterPort() const { return m_masterPort; }
std::string CConf::getBackupHost() const { return m_backupHost; }
uint16_t    CConf::getBackupPort() const { return m_backupPort; }

std::string CConf::getLocalHost() const { return m_localHost; }
uint16_t    CConf::getLocalPort() const { return m_localPort; }

std::vector<uint32_t> CConf::getWhiteList() const { return m_whiteList; }
std::vector<uint32_t> CConf::getBlackList() const { return m_blackList; }

bool CConf::getDebug() const { return m_debug; }
