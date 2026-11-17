#if !defined(CONF_H)
#define	CONF_H

#include <cstdint>
#include <string>
#include <vector>

class CConf
{
public:
	enum SECTION {
		SECTION_NONE,
		SECTION_GENERAL,
		SECTION_MQTT,
		SECTION_LOGGING
	};

	CConf(const std::string& file);
	~CConf();

	bool read();

	// Section General
	std::string  getCallsign() const;
	unsigned int getTimeout() const;
	bool         getSlot1() const;
	bool         getSlot2() const;
	bool         getRFH() const;
	std::string  getLatitude() const;
	std::string  getLongitude() const;
	std::string  getDescription() const;
	std::vector<unsigned int> getWhiteList() const;
	std::vector<unsigned int> getBlackList() const;

	// Section MQTT
	std::string  getMQTTAddress() const;
	unsigned int getMQTTPort() const;
	std::string  getMQTTLogin() const;
	std::string  getMQTTPassword() const;
	bool         getMQTTDebug() const;

	// Section Logging
	bool         getLogDisplay() const;
	unsigned int getLogLevel() const;
	std::string  getLogFilePath() const;
	bool         getLogFileRotate() const;
	unsigned int getLogFileSize() const;
	unsigned int getLogFileCount() const;

private:
	std::string m_file;

	SECTION m_section;

	// Section General
	std::string  m_callsign;
	unsigned int m_timeout;
	bool         m_slot1;
	bool         m_slot2;
	bool         m_rfh;
	std::string  m_latitude;
	std::string  m_longitude;
	std::string  m_description;
	std::vector<unsigned int> m_whiteList;
	std::vector<unsigned int> m_blackList;

	// Section MQTT
	std::string  m_mqttAddress;
	unsigned int m_mqttPort;
	std::string  m_mqttLogin;
	std::string  m_mqttPassword;
	bool         m_mqttDebug;

	// Section Logging
	bool         m_logDisplay;
	unsigned int m_logLevel;
	std::string  m_logFilePath;
	bool         m_logFileRotate;
	unsigned int m_logFileSize;
	unsigned int m_logFileCount;

	static bool      myIsSpace(int c);
	static std::string myTrim(const std::string& s);

	bool readList(const std::string& value, std::vector<unsigned int>& list) const;
};

#endif /* CONF_H */
