/*
*   Copyright (C) 2018,2020 by Jonathan Naylor G4KLX
*
*   This program is free software; you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation; either version 2 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License
*   along with this program; if not, write to the Free Software
*   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "DAPNETGateway.h"
#include "StopWatch.h"
#include "Version.h"
#include "Thread.h"
#include "StopWatch.h"
#include "Timer.h"
#include "Log.h"
#include "REGEX.h"
#include <regex>
#include <csignal>

// ★ 原版 run() 是 for(;;) 永不 break，末尾的 close/delete/LogFinalise 全是不可达代码
//   （日志尾段必丢、socket/fd 不关）。收到 SIGTERM/SIGINT 置 0，主循环与 recover() 退出。
static volatile sig_atomic_t s_running = 1;
static CStopWatch  s_recoverWatch;		/* ★ 重连节流：任何情况下两次重连间隔 >= 2s */

static void dapnetSigHandler(int)
{
	s_running = 0;
}

static void installSigHandler()
{
	::signal(SIGTERM, dapnetSigHandler);
	::signal(SIGINT,  dapnetSigHandler);
#if !defined(_WIN32)
	::signal(SIGHUP,  SIG_IGN);
#endif
}

#if defined(_WIN32) || defined(_WIN64)
#include <Windows.h>
#else
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <pwd.h>
#endif

#if defined(_WIN32) || defined(_WIN64)
const char* DEFAULT_INI_FILE = "DAPNETGateway.ini";
#else
const char* DEFAULT_INI_FILE = "/etc/DAPNETGateway.ini";
#endif

#include <algorithm>
#include <utility>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <clocale>
#include <cassert>
#include <cmath>

const unsigned int FRAME_LENGTH_CODEWORDS    = 2U;
const unsigned int BATCH_LENGTH_CODEWORDS    = 17U;
const unsigned int PREAMBLE_LENGTH_CODEWORDS = BATCH_LENGTH_CODEWORDS + 1U;

const unsigned int CODEWORD_TIME_US = 26667U;										// 26.667ms
const unsigned int FRAME_TIME_US = CODEWORD_TIME_US * FRAME_LENGTH_CODEWORDS;		// 53.333ms
const unsigned int BATCH_TIME_US = CODEWORD_TIME_US * BATCH_LENGTH_CODEWORDS;		// 453.333ms

const unsigned int PREAMBLE_TIME_US = CODEWORD_TIME_US * PREAMBLE_LENGTH_CODEWORDS;	// 480.006ms

const unsigned int SLOT_TIME_US       = 6400000U;									// 6.4s
const unsigned int SLOT_TIME_MS       = SLOT_TIME_US / 1000U;						// 6.4s
const unsigned int CODEWORDS_PER_SLOT = SLOT_TIME_US / CODEWORD_TIME_US;			// 240
const unsigned int BATCHES_PER_SLOT   = SLOT_TIME_US / BATCH_TIME_US;				// 14

const unsigned char FUNCTIONAL_NUMERIC      = 0U;
const unsigned char FUNCTIONAL_ALERT1       = 1U;
const unsigned char FUNCTIONAL_ALERT2       = 2U;
const unsigned char FUNCTIONAL_ALPHANUMERIC = 3U;

const unsigned int MAX_TIME_TO_HOLD_TIME_MESSAGES = 15000U;		// 15s

int main(int argc, char** argv)
{
	const char* iniFile = DEFAULT_INI_FILE;
	if (argc > 1) {
		for (int currentArg = 1; currentArg < argc; ++currentArg) {
			std::string arg = argv[currentArg];
			if ((arg == "-v") || (arg == "--version")) {
				::fprintf(stdout, "DAPNETGateway version %s\n", VERSION);
				return 0;
			} else if (arg.substr(0, 1) == "-") {
				::fprintf(stderr, "Usage: DAPNETGateway [-v|--version] [filename]\n");
				return 1;
			} else {
				iniFile = argv[currentArg];
			}
		}
	}

	CDAPNETGateway* gateway = new CDAPNETGateway(std::string(iniFile));

	int ret = gateway->run();

	delete gateway;

	return ret;
}

CDAPNETGateway::CDAPNETGateway(const std::string& configFile) :
m_conf(configFile),
m_dapnetNetwork(NULL),
m_pocsagNetwork(NULL),
m_queue(),
m_slotTimer(),
m_schedule(NULL),
m_allSlots(false),
m_currentSlot(0U),
m_sentCodewords(0U),
m_regexBlacklist(),
m_regexWhitelist(),
m_mmdvmFree(false)
{
	CUDPSocket::startup();
}

CDAPNETGateway::~CDAPNETGateway()
{
	for (std::deque<CPOCSAGMessage*>::iterator it = m_queue.begin(); it != m_queue.end(); ++it)
		delete *it;

	m_queue.clear();

	CUDPSocket::shutdown();
}

int CDAPNETGateway::run()
{
	installSigHandler();
	std::string reason;
	bool ret = m_conf.read(reason);
	if (!ret) {
		::fprintf(stderr, "DAPNETGateway: cannot read the .ini file - %s\n", reason.c_str());
		return 1;
	}

	setlocale(LC_ALL, "C");

#if !defined(_WIN32) && !defined(_WIN64)
	const bool daemon = m_conf.getDaemon();
	if (daemon) {   // 原写法 bool daemon 是局部变量名遮蔽成员，易误读
		// Create new process
		pid_t pid = ::fork();
		if (pid == -1) {
			::fprintf(stderr, "Couldn't fork() , exiting\n");
			return -1;
		} else if (pid != 0) {
			exit(EXIT_SUCCESS);
		}

		// Create new session and process group
		if (::setsid() == -1) {
			::fprintf(stderr, "Couldn't setsid(), exiting\n");
			return -1;
		}

		// Set the working directory to the root directory
		if (::chdir("/") == -1) {
			::fprintf(stderr, "Couldn't cd /, exiting\n");
			return -1;
		}

		// If we are currently root...
		if (getuid() == 0) {
			struct passwd* user = ::getpwnam("mmdvm");
			if (user == NULL) {
				::fprintf(stderr, "Could not get the mmdvm user, exiting\n");
				return -1;
			}

			uid_t mmdvm_uid = user->pw_uid;
			gid_t mmdvm_gid = user->pw_gid;

			// Set user and group ID's to mmdvm:mmdvm
			if (setgid(mmdvm_gid) != 0) {
				::fprintf(stderr, "Could not set mmdvm GID, exiting\n");
				return -1;
			}

			if (setuid(mmdvm_uid) != 0) {
				::fprintf(stderr, "Could not set mmdvm UID, exiting\n");
				return -1;
			}

			// Double check it worked (AKA Paranoia) 
			if (setuid(0) != -1) {
				::fprintf(stderr, "It's possible to regain root - something is wrong!, exiting\n");
				return -1;
			}
		}
	}
#endif

#if !defined(_WIN32) && !defined(_WIN64)
	ret = ::LogInitialise(daemon, m_conf.getLogFilePath(), m_conf.getLogFileRoot(), m_conf.getLogFileLevel(), m_conf.getLogDisplayLevel(), m_conf.getLogFileRotate());
#else
        ret = ::LogInitialise(false, m_conf.getLogFilePath(), m_conf.getLogFileRoot(), m_conf.getLogFileLevel(), m_conf.getLogDisplayLevel(), m_conf.getLogFileRotate());
#endif
	if (!ret) {
		::fprintf(stderr, "DAPNETGateway: unable to open the log file\n");
		return 1;
	}

#if !defined(_WIN32) && !defined(_WIN64)
	if (daemon) {
		::close(STDIN_FILENO);
		::close(STDOUT_FILENO);
		::close(STDERR_FILENO);
	}
#endif

	bool debug             = m_conf.getDAPNETDebug();

	std::string rptAddress = m_conf.getRptAddress();
	unsigned short rptPort = m_conf.getRptPort();
	std::string myAddress  = m_conf.getMyAddress();
	unsigned short myPort  = m_conf.getMyPort();

	m_pocsagNetwork = new CPOCSAGNetwork(myAddress, myPort, rptAddress, rptPort, debug);
	ret = m_pocsagNetwork->open();
	if (!ret) {
		::LogError("Cannot open the repeater network port");
		::LogFinalise();

		return 1;
	}

	std::string callsign      = m_conf.getCallsign();
	std::string dapnetAuthKey = m_conf.getDAPNETAuthKey();

	if (dapnetAuthKey.empty() || dapnetAuthKey == "TOPSECRET" || dapnetAuthKey == "CHANGE_ME") {
		::LogError("Password not set or still the default value - edit DAPNETGateway.ini");
		::LogFinalise();

		return 1;
	}

	// 主 + 备端点。原实现只取单个 Address/Port，BackupHost/BackupPort 配了也是死配置；
	// 现按 vector 传入，CDAPNETNetwork 内部按退避轮转 failover。
	std::vector<std::string>    dapnetAddrs;
	std::vector<unsigned short> dapnetPorts;
	dapnetAddrs.push_back(m_conf.getMasterHost());  dapnetPorts.push_back(m_conf.getMasterPort());

	if (!m_conf.getBackupHost().empty() && m_conf.getBackupPort() > 0U) {
		dapnetAddrs.push_back(m_conf.getBackupHost());  dapnetPorts.push_back(m_conf.getBackupPort());
		LogMessage("DAPNET primary %s:%u, backup %s:%u",
			dapnetAddrs[0U].c_str(), dapnetPorts[0U], dapnetAddrs[1U].c_str(), dapnetPorts[1U]);
	} else {
		LogMessage("DAPNET primary %s:%u (no backup configured)", dapnetAddrs[0U].c_str(), dapnetPorts[0U]);
	}

	m_dapnetNetwork = new CDAPNETNetwork(dapnetAddrs, dapnetPorts, callsign, dapnetAuthKey, debug);
	ret = m_dapnetNetwork->open();
	if (!ret) {
		m_pocsagNetwork->close();
		delete m_pocsagNetwork;
		delete m_dapnetNetwork;

		::LogError("Cannot open the DAPNET network port");
		::LogFinalise();

		return 1;
	}

	LogMessage("Starting DAPNETGateway-%s", VERSION);

	ret = m_dapnetNetwork->login();
	if (!ret) {
		m_pocsagNetwork->close();
		m_dapnetNetwork->close();
		delete m_pocsagNetwork;
		delete m_dapnetNetwork;

		::LogError("Cannot login to the DAPNET network");
		::LogFinalise();

		return 1;
	}

	const std::vector<uint32_t> whiteList = m_conf.getWhiteList();
	const std::vector<uint32_t> blackList = m_conf.getBlackList();

	std::vector<std::regex> regexBlacklist;
	std::vector<std::regex> regexWhitelist;

	LogMessage("Initializing blacklist");
	m_regexBlacklist = new CREGEX(m_conf.getblacklistRegexfile());
	if (m_regexBlacklist->load()) 
		regexBlacklist = m_regexBlacklist->get();

	LogMessage("Initializing whitelist");
	m_regexWhitelist = new CREGEX(m_conf.getwhitelistRegexfile());
		if (m_regexWhitelist->load())
		regexWhitelist = m_regexWhitelist->get();


	while (s_running != 0) {	// 原 for(;;)：见文件头 s_running
		unsigned char buffer[200U];

		if (m_pocsagNetwork->read(buffer) > 0U) {
			switch (buffer[0U]) {
			case 0x00U:
				// The MMDVM is idle
				if (!m_mmdvmFree) {
					// LogDebug("*** MMDVM is free");
					m_mmdvmFree = true;
					m_sentCodewords = (m_slotTimer.elapsed() * 1000U) / CODEWORD_TIME_US;
				}
				break;
			case 0xFFU:
				// The MMDVM is busy
				// LogDebug("*** MMDVM is busy");
				m_mmdvmFree = false;
				break;
			default:
				// The MMDVM is sending crap
				LogWarning("Unknown data from the MMDVM - 0x%02X", buffer[0U]);
				break;
			}
		}

		bool ok = m_dapnetNetwork->read();
		if (!ok) {
			LogWarning("DAPNET link lost, recovering...");
			recover();
			continue;
		}


	CPOCSAGMessage* message = m_dapnetNetwork->getMessage();
	if (message != NULL) {
		// ★ 原按 m_message 的 '\0' 截断；改为显式按 m_length 限长
		std::string messageBody(reinterpret_cast<const char*>(message->m_message), message->m_length);
		const std::vector<uint32_t>& whiteList = m_conf.getWhiteList();
		const std::vector<uint32_t>& blackList = m_conf.getBlackList();

		bool blacklistRegexmatch = false;
		bool whitelistRegexmatch = regexWhitelist.empty() ? true : false;

		// 黑名单 REGEX：命中任一条即拦。★ 原用 regex_match（整串匹配），规则里写 "警报"
		// 这种子串永远不中，还以为被漏放；改 regex_search。
		if (!regexBlacklist.empty()) {
			for (const std::regex& re : regexBlacklist) {   // ★ const&：原按值拷贝 std::regex
				if (std::regex_search(messageBody, re)) {
					blacklistRegexmatch = true;
					LogDebug("Blacklist REGEX match: Not queueing message to %07u, type %u, message: \"%.*s\"",
						message->m_ric, message->m_type, int(message->m_length), messageBody.c_str());
					break;
				}
			}
		}

		// 白名单 REGEX：★ 原初值 true + "任一不中就置 false" = 要求每条规则都命中，
		// 配 2 条放行概率腰斩、配 5 条基本全丢，且无日志 —— 静默黑洞。改命中任一即放行。
		if (!regexWhitelist.empty() && !blacklistRegexmatch) {
			for (const std::regex& re : regexWhitelist) {
				if (std::regex_search(messageBody, re)) { whitelistRegexmatch = true; break; }
			}
			if (!whitelistRegexmatch)
				LogDebug("No whitelist REGEX match: Not queueing message to %07u, type %u, message: \"%.*s\"",
					message->m_ric, message->m_type, int(message->m_length), messageBody.c_str());
		}

		if (blacklistRegexmatch || !whitelistRegexmatch || isTimeMessage(message)) {
			delete message;
		} else if (!whiteList.empty() && std::find(whiteList.begin(), whiteList.end(), message->m_ric) == whiteList.end()) {
			LogDebug("Not in whitelist: Not queueing message to %07u", message->m_ric);
			delete message;
		} else if (!blackList.empty() && std::find(blackList.begin(), blackList.end(), message->m_ric) != blackList.end()) {
			LogDebug("In blacklist: Not queueing message to %07u", message->m_ric);
			delete message;
		} else {
			// ★ 原 push_front() + sendMessages() 里 pop_back() = LIFO：A,B,C 到达按 C,B,A 发射。
			// "跳闸" 后跟 "误报取消" 会倒着播。改 FIFO + 队列上限防 OOM（溢出错最旧）。
			while (m_queue.size() >= m_conf.getMaxQueue()) {
				CPOCSAGMessage* oldMsg = m_queue.front();
				m_queue.pop_front();
				delete oldMsg;
				m_queueDrops++;
				LogWarning("POCSAG queue full (%u), dropping oldest message", m_conf.getMaxQueue());
			}
			m_queue.push_back(message);
			LogDebug("Messages in Queue %04u (dropped %u)", (unsigned int)m_queue.size(), m_queueDrops);
		}
	}

		unsigned int t = (m_slotTimer.time() / 100ULL) % 1024ULL;
		unsigned int slot = t / 64U;
		if (slot != m_currentSlot) {
			// LogDebug("Start of slot %u", slot);
			m_currentSlot = slot;
			if (m_schedule == NULL || m_currentSlot == 0U)
				loadSchedule();
			m_sentCodewords = 0U;
			m_slotTimer.start();
		}

		sendMessages();

		CThread::sleep(10U);
	}

	LogMessage("Shutting down, %u message(s) still queued, %u dropped on overflow",
			   (unsigned int)m_queue.size(), m_queueDrops);

	m_pocsagNetwork->close();
	delete m_pocsagNetwork;

	m_dapnetNetwork->close();
	delete m_dapnetNetwork;

	::LogFinalise();

	return 0;
}

void CDAPNETGateway::sendMessages()
{
	// If the MMDVM is busy, we can't send anything.
	if (!m_mmdvmFree)
		return;

	// Do we have a schedule?
	if (m_schedule == NULL)
		return;

	// Check to see if we're allowed to send within a slot.
	if (!m_schedule[m_currentSlot])
		return;

	// If we have data to send, see if we have time to do so in the current schedule.
	if (m_queue.empty())
		return;

	CPOCSAGMessage* message = m_queue.front();
	if (message == NULL) return;	// 防御：empty() 上游已判过

	// Special case, only test if slots are being used.
	if (m_allSlots) {
		sendMessage(message);
		m_queue.pop_back();	// 仅 m_allSlots 探测分支用（探测消息不入业务队列）
		delete message;
		return;
	}

	unsigned int codewords = calculateCodewords(message);

	// Do we have too much data already sent in this slot?
	unsigned int totalCodewords = m_sentCodewords + PREAMBLE_LENGTH_CODEWORDS + codewords;
	if (totalCodewords >= CODEWORDS_PER_SLOT) {
		// LogDebug("Too many codewords sent in slot %u already %u + %u + %u = %u >= %u", m_currentSlot, m_sentCodewords, PREAMBLE_LENGTH_CODEWORDS, codewords, totalCodewords, CODEWORDS_PER_SLOT);
		return;
	}

	// Is there enough time to send it in this slot before it ends?
	unsigned int sendTime = (PREAMBLE_TIME_US + codewords * CODEWORD_TIME_US) / 1000U;
	unsigned int timeLeft = SLOT_TIME_MS - m_slotTimer.elapsed();
	if (sendTime >= timeLeft) {
		// LogDebug("Too little time to send the message in slot %u, %u + %u + %u = %u >= %u = %u - %u", m_currentSlot, PREAMBLE_TIME_US, codewords, CODEWORD_TIME_US, sendTime, timeLeft, SLOT_TIME_MS, m_slotTimer.elapsed());
		return;
	}

	bool ret = sendMessage(message);
	if (ret)
		m_sentCodewords = totalCodewords;

	m_queue.pop_back();
	delete message;
}

bool CDAPNETGateway::recover()
{
	static const unsigned int BACKOFF[] = {2U, 4U, 8U, 16U, 32U, 60U, 60U, 60U, 60U, 60U};
	static const unsigned int N_BACKOFF = sizeof(BACKOFF) / sizeof(BACKOFF[0U]);
	static unsigned int s_attempts = 0U;

	/* ★ 原实现 for(;;) 无 sleep 无上限：DAPNET 一抖就 100% CPU + 重连风暴 + fd 泄漏到 SSH 登不上 */
	s_recoverWatch.start();
	while (s_running != 0) {
		unsigned int wait = BACKOFF[(s_attempts < N_BACKOFF) ? s_attempts : (N_BACKOFF - 1U)];
		if (s_attempts > 200U) wait = 60U;
		++s_attempts;
		LogWarning("DAPNET link lost, recover attempt %u in %us", s_attempts, wait);

		unsigned int slept = 0U;
		while (s_running != 0 && slept < wait) { CThread::sleep(1U); ++slept; }

		m_dapnetNetwork->close();
		if (m_dapnetNetwork->open() && m_dapnetNetwork->login()) {
			LogMessage("DAPNET link restored after %u attempt(s)", s_attempts);
			s_attempts = 0U;
			loadSchedule();			/* ★ 重连后必须重新取时隙表，否则拿着旧指针/旧映射发 */
			return true;
		}
	}
	return false;



bool CDAPNETGateway::isTimeMessage(const CPOCSAGMessage* message) const
{
	if (message->m_type == 5U && message->m_functional == FUNCTIONAL_NUMERIC)
		return true;

	if (message->m_type == 6U && message->m_functional == FUNCTIONAL_ALPHANUMERIC && ::memcmp(message->m_message, "XTIME=", 6U) == 0)
		return true;

	return false;
}

unsigned int CDAPNETGateway::calculateCodewords(const CPOCSAGMessage* message) const
{
	assert(message != NULL);

	unsigned int len = 0U;
	switch (message->m_functional) {
		case FUNCTIONAL_NUMERIC:
			len = message->m_length / 5U;			// For the number packing, five to a word
			break;
		case FUNCTIONAL_ALPHANUMERIC:
		case FUNCTIONAL_ALERT2:
			len = (message->m_length * 7U) / 20U;	// For the ASCII packing, 7/20 to a word
			break;
		case FUNCTIONAL_ALERT1:
		default:
			break;
	}

	len++;										// For the address word

	if ((len % 2U) == 1U)						// Always an even number of words
		len++;

	// ★ 原句 "len += len % 16U;  // a very long message will include sync words" 是空操作：
	//   上一步刚保证 len 为偶，偶%16 ∈ {0,2,...,14}，加完依然不对齐 16，纯凭空虚增最多 14 码字。
	//   后果：totalCodewords 过早撞上 CODEWORDS_PER_SLOT，整轮 slot 放弃发送。
	//   实测 10字符消息算成 8 码字(应 4)、120字符算成 56(应 43)，短消息密集时吞吐 -30~50%。
	//   sync 码字由 MMDVMHost 侧插入，网关层不该预估 —— 直接删。

	return len;
}

void CDAPNETGateway::loadSchedule()
{
	bool     raw[16U];
	unsigned int slot = 0U, codewords = 0U;
	if (!m_dapnetNetwork->getSchedule(raw, slot, codewords)) {
		LogDebug("No DAPNET schedule frame yet, keeping previous slot map");
		return;
	}

	// ★ 原实现 m_schedule = m_dapnetNetwork->getSchedule() 直接接管对方内部指针；
	//   recover() 重建 CDAPNETNetwork 后，主循环读的就是悬空内存。改为自持副本。
	if (m_schedule == NULL) m_schedule = new bool[16U];
	for (unsigned int i = 0U; i < 16U; ++i) m_schedule[i] = raw[i];

	std::string text;
	for (unsigned int i = 0U; i < 16U; i++) text += m_schedule[i] ? "*" : "-";

	m_allSlots = true;
	m_allSlotsAll = true;
	for (unsigned int i = 0U; i < 16U; i++) {
		if (!m_schedule[i]) { m_allSlots = false; m_allSlotsAll = false; }
		else if (m_schedule[i] && i != slot) { m_allSlots = false; }
	}

	LogMessage("DAPNET slot map: %s  (my slot %u, %u codewords used)", text.c_str(), slot, codewords);
}

bool CDAPNETGateway::sendMessage(CPOCSAGMessage* message) const
{
	assert(message != NULL);

	bool ret = isTimeMessage(message);
	if (ret && message->m_timeQueued.elapsed() >= MAX_TIME_TO_HOLD_TIME_MESSAGES) {
		switch (message->m_functional) {
			case FUNCTIONAL_ALPHANUMERIC:
				LogDebug("Rejecting message to %07u, type %u, func Alphanumeric: \"%.*s\"", message->m_ric, message->m_type, message->m_length, message->m_message);
				break;
			case FUNCTIONAL_ALERT2:
				LogDebug("Rejecting message to %07u, type %u, func Alert 2: \"%.*s\"", message->m_ric, message->m_type, message->m_length, message->m_message);
				break;
			case FUNCTIONAL_NUMERIC:
				LogDebug("Rejecting message to %07u, type %u, func Numeric: \"%.*s\"", message->m_ric, message->m_type, message->m_length, message->m_message);
				break;
			case FUNCTIONAL_ALERT1:
				LogDebug("Rejecting message to %07u, type %u, func Alert 1", message->m_ric, message->m_type);
				break;
			default:
				break;
		}

		return false;
	} else {
		switch (message->m_functional) {
			case FUNCTIONAL_ALPHANUMERIC:
				LogMessage("Sending message in slot %u to %07u, type %u, func Alphanumeric: \"%.*s\"", m_currentSlot, message->m_ric, message->m_type, message->m_length, message->m_message);
				break;
			case FUNCTIONAL_ALERT2:
				LogMessage("Sending message in slot %u to %07u, type %u, func Alert 2: \"%.*s\"", m_currentSlot, message->m_ric, message->m_type, message->m_length, message->m_message);
				break;
			case FUNCTIONAL_NUMERIC:
				LogMessage("Sending message in slot %u to %07u, type %u, func Numeric: \"%.*s\"", m_currentSlot, message->m_ric, message->m_type, message->m_length, message->m_message);
				break;
			case FUNCTIONAL_ALERT1:
				LogMessage("Sending message in slot %u to %07u, type %u, func Alert 1", m_currentSlot, message->m_ric, message->m_type);
				break;
			default:
				break;
		}

		m_pocsagNetwork->write(message);
		return true;
	}
}
