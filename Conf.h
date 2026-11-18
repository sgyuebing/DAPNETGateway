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
 *   2026-11-18  FIXED BRANCH
 *   ------------------------------------------------------------------
 *   上游 2026-11-17 的提交只重写了 Conf.cpp/.h，没同步 DAPNETGateway.cpp，
 *   导致 15 个 "no member named 'getXxx'" 编译错误。
 *
 *   本文件的修法：**不改动 DAPNETGateway.cpp 的调用面**，而是在 CConf 上
 *   把新命名 (getMasterHost/getLocalPort/getPassword...) 作为"真身"，
 *   把旧命名 (getDAPNETAddress/getRptPort/getDAPNETAuthKey...) 作为
 *   inline 兼容别名补回来。这样：
 *     - 现在能编过、能跑；
 *     - 以后想把调用方迁移到新命名时，别名可以逐个删，不会二次断裂。
 *
 *   同时补回了被误删的三类配置（删了就是功能性回归）：
 *     - 日志 5 项        : getLogFilePath / FileRoot / FileLevel / DisplayLevel / FileRotate
 *     - 正则黑白名单文件  : getWhitelistRegexfile / getBlacklistRegexfile
 *     - getDaemon()      : 141 行还在调用，Windows 分支也在用
 *   并新增备份服务器访问器 + 队列上限，供网关主循环真正使用。
 */

#ifndef CONF_H
#define CONF_H

#include <string>
#include <vector>
#include <cstdint>

class CConf {
public:
    explicit CConf(const std::string& file);
    ~CConf();

    /** 读取并校验配置。返回 false 时 *reason 会带上人类可读的失败原因。 */
    bool read(std::string& reason);

    /* ─────────── 新命名（真身，配置层的唯一事实来源） ─────────── */

    std::string           getCallsign()      const { return m_callsign; }
    std::string           getPassword()      const { return m_password; }

    std::string           getMasterHost()    const { return m_masterHost; }
    unsigned short        getMasterPort()    const { return m_masterPort; }

    std::string           getBackupHost()    const { return m_backupHost; }
    unsigned short        getBackupPort()    const { return m_backupPort; }
    bool                  hasBackup()        const { return !m_backupHost.empty() && m_backupPort != 0U; }

    std::string           getLocalHost()     const { return m_localHost; }
    unsigned short        getLocalPort()     const { return m_localPort; }

    std::vector<uint32_t> getWhiteList()     const { return m_whiteList; }
    std::vector<uint32_t> getBlackList()     const { return m_blackList; }

    bool                  getDebug()         const { return m_debug; }
    bool                  getDaemon()        const { return m_daemon; }

    /* 日志（补回被删项；.ini 没写时返回安全默认值，绝不返回空串给 fopen） */
    std::string           getLogFilePath()   const { return m_logFilePath.empty()   ? std::string(".")           : m_logFilePath; }
    std::string           getLogFileRoot()   const { return m_logFileRoot.empty()   ? std::string("DAPNETGateway"): m_logFileRoot; }
    unsigned int          getLogFileLevel()  const { return m_logFileLevel; }
    unsigned int          getLogDisplayLevel() const { return m_logDisplayLevel; }
    bool                  getLogFileRotate() const { return m_logFileRotate; }

    /* 正则黑白名单文件（补回被删项；空串 = 不启用该维度） */
    std::string           getWhitelistRegexfile() const { return m_wlRegexFile; }
    std::string           getBlacklistRegexfile() const { return m_blRegexFile; }

    /* 发射队列上限，防止 MMDVM 长时间占用时无限涨内存被 OOM-kill */
    size_t                getMaxQueue()      const { return m_maxQueue; }

    /* ───────── 旧命名兼容别名（一个字都不用改 DAPNETGateway.cpp） ─────────
       注意 getDAPNETAddress/Port/AuthKey 一律指向 **主** 服务器，
       故障切换由 CDAPNETNetwork 内部按 hasBackup() 自行接管。          */

    std::string    getDAPNETAddress() const { return getMasterHost(); }
    unsigned short getDAPNETPort()    const { return getMasterPort(); }
    std::string    getDAPNETAuthKey() const { return getPassword(); }
    bool           getDAPNETDebug()   const { return getDebug(); }

    std::string    getRptAddress()    const { return getMasterHost(); }
    unsigned short getRptPort()       const { return getMasterPort(); }
    std::string    getMyAddress()     const { return getLocalHost(); }
    unsigned short getMyPort()        const { return getLocalPort(); }

    /* 旧代码里是小写 b/w 开头的方法名，原样保留 */
    std::string    getblacklistRegexfile() const { return getBlacklistRegexfile(); }
    std::string    getwhitelistRegexfile() const { return getWhitelistRegexfile(); }

private:
    std::string           m_file;

    std::string           m_callsign;
    std::string           m_password;

    std::string           m_masterHost;
    unsigned short        m_masterPort;
    std::string           m_backupHost;
    unsigned short        m_backupPort;

    std::string           m_localHost;
    unsigned short        m_localPort;

    std::vector<uint32_t> m_whiteList;
    std::vector<uint32_t> m_blackList;

    std::string           m_wlRegexFile;
    std::string           m_blRegexFile;

    std::string           m_logFilePath;
    std::string           m_logFileRoot;
    unsigned int          m_logFileLevel;
    unsigned int          m_logDisplayLevel;
    bool                  m_logFileRotate;

    bool                  m_debug;
    bool                  m_daemon;
    size_t                m_maxQueue;

    bool parseIDList(const std::string& s, std::vector<uint32_t>& list, const char* what, std::string& reason) const;
    bool parsePort(const std::string& s, unsigned short& port, const char* what, std::string& reason) const;
};

#endif /* CONF_H */