/*
 *   Copyright (C) 2018,2026 by Jonathan Naylor G4KLX & contributors
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   ------------------------------------------------------------------
 *   2026-11-18  FIXED BRANCH  — DAPNET 上行链路
 *   ------------------------------------------------------------------
 *   修掉的问题（对应审查报告）：
 *   [N1] 原 BUFFER_LENGTH=200 固定栈数组：
 *          - 线上报文 >199 B 时尾 '\r\n' 被砍 → strtok 少一字段 → 静默丢消息
 *            （POCSAG 单条上限 240 字符 ⇒ 179 字符以上的寻呼全发不出去）；
 *          - buffer[length]=0 在 length==200 时越界写 1 字节；
 *          - ::strcpy(p,":0000\r\n") / ::strcat(buffer,":0000\r\n") 往读满的
 *            200 B 数组再追加 7 B → 真实栈溢出。
 *        现改 4KB 分块读 + 动态累积缓冲 + **粘包状态机**，且绝不改写接收区。
 *   [N2] assert(p!=NULL) 在 Release(-DNDEBUG) 下是空气 → 畸形报文 strtoul(NULL)
 *        段错误（远程 DoS）。改为 find/substr 解析，无 NULL 路径。
 *   [N3] m_message = new ... 不删旧的 → 服务器连发两条时泄漏一条。
 *   [N4] backoff[m_failCount] 下标来源不可信（构造传入）→ 统一 clampBackoff()。
 *        凭据错连续 10 次后停止狂刷，明确报"去改密码"。
 *   [N5] BackupHost/BackupPort 配了没人用 → 主备轮转 failover。
 *   [N6] 一趟 read() 里含多条帧时上游只处理第一条 → 其余全丢。现 for(;;) 吐完。
 */

#ifndef DAPNETNETWORK_H
#define DAPNETNETWORK_H

#include "TCPSocket.h"
#include "POCSAGMessage.h"

#include <string>
#include <vector>
#include <cstdint>

class CDAPNETNetwork {
public:
    /* addresses/ports 按优先级： [0]=主, [1..]=备 */
    CDAPNETNetwork(const std::vector<std::string>& addresses, const std::vector<unsigned short>& ports,
                   const std::string& callsign, const std::string& authKey, bool debug);
    ~CDAPNETNetwork();

    bool open();
    bool login();
    void close();

    bool read();
    bool writeMsgType(bool text);

    /** 取走一条已解出的寻呼；所有权移交调用方（调用方负责 delete）。无则 NULL */
    CPOCSAGMessage* getMessage();

    /** 取走最新时隙表。无有效表则返回 false，调用方应保持上一份 */
    bool getSchedule(bool sched[16U], unsigned int& slot, unsigned int& totalCodewords) const;
    void setSlotUsage(unsigned int slot, unsigned int totalCodewords);

    bool isConnected() const { return m_state == STATE_CONNECTED; }
    bool isLoggedIn()  const { return m_loggedInFlag; }

    /** 断线后调用：内部换到下一个端点并给出应等待的毫秒数 */
    int  reconnectBackoffMs();
    void resetBackoff();

    unsigned long getMalformedCount() const { return m_malformedCount; }
    unsigned long getOversizeCount()  const { return m_oversizeCount; }

private:
    enum STATE { STATE_DISCONNECTED, STATE_CONNECTING, STATE_CONNECTED };

    bool extractOneMessage(std::string& frame);     // 从累积缓冲切一帧
    bool parseMessage(const std::string& frame);    // '#...'
    bool parseSchedule(const std::string& frame);   // '4...'
    bool parseFailedLogin(const std::string& frame);// '7...'
    bool sendRaw(const std::string& s);
    bool rebuildSocket();                            // 切端点时重建 CTCPSocket

    std::vector<std::string>   m_addresses;
    std::vector<unsigned short> m_ports;
    size_t                     m_endpoint;

    std::string                m_callsign;
    std::string                m_authKey;
    bool                       m_debug;

    CTCPSocket*                m_socket;            // 指针：failover 时重建
    STATE                      m_state;
    bool                       m_loggedInFlag;

    std::vector<unsigned char> m_inbuf;
    static const size_t INBUF_HARD_LIMIT = 64U * 1024U;
    static const size_t MSG_HARD_LIMIT   = 4096U;

    CPOCSAGMessage*            m_message;

    bool                       m_schedule[16U];
    bool                       m_scheduleValid;
    unsigned int               m_slot;
    unsigned int               m_totalCodewords;

    unsigned int               m_failCount;
    unsigned long              m_malformedCount;
    unsigned long              m_oversizeCount;
};

#endif /* DAPNETNETWORK_H */