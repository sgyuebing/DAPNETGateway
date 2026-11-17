/*
 *   Copyright (C) 2016,2017 by Jonathan Naylor G4KLX
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 */

#ifndef CONF_H
#define CONF_H

#include <string>
#include <vector>
#include <cstdint>      // ← 新增：uint32_t

class CConf
{
public:
    CConf(const std::string& file);
    ~CConf();

    bool read();

    // 网关身份
    std::string  getCallsign() const;
    std::string  getPassword() const;

    // DAPNET 主/备服务器
    std::string  getMasterHost() const;
    uint16_t     getMasterPort() const;
    std::string  getBackupHost() const;
    uint16_t     getBackupPort() const;

    // MMDVMHost 本地 UDP
    std::string  getLocalHost() const;
    uint16_t     getLocalPort() const;

    // 黑白名单（统一 uint32_t，与 .cpp 严格一致）
    std::vector<uint32_t> getWhiteList() const;
    std::vector<uint32_t> getBlackList() const;

    // 调试
    bool         getDebug() const;

private:
    std::string  m_file;

    std::string  m_callsign;
    std::string  m_password;

    std::string  m_masterHost;
    uint16_t     m_masterPort;
    std::string  m_backupHost;
    uint16_t     m_backupPort;

    std::string  m_localHost;
    uint16_t     m_localPort;

    std::vector<uint32_t> m_whiteList;
    std::vector<uint32_t> m_blackList;

    bool         m_debug;
};

#endif /* CONF_H */
