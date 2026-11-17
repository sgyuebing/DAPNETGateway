/*
 *   Copyright (C) 2017-2020 by Jonathan Naylor G4KLX
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

#include "Conf.h"
#include "Log.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cctype>

const int BUFFER_SIZE = 500;

bool CConf::myIsSpace(int c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

std::string CConf::myTrim(const std::string& s)
{
	if (s.empty())
		return s;

	std::string::size_type start = 0U;
	while (start < s.size() && myIsSpace(s[start]))
		start++;

	if (start == s.size())
		return std::string();

	std::string::size_type end = s.size() - 1U;
	while (end > start && myIsSpace(s[end]))
		end--;

	return s.substr(start, end - start + 1U);
}

CConf::CConf(const std::string& file) :
m_file(file),
m_section(SECTION_NONE),
m_callsign(),
m_timeout(30U),
m_slot1(true),
m_slot2(false),
m_rfh(false),
m_latitude(),
m_longitude(),
m_description(),
m_whiteList(),
m_blackList(),
m_mqttAddress(),
m_mqttPort(1883U),
m_mqttLogin(),
m_mqttPassword(),
m_mqttDebug(false),
m_logDisplay(true),
m_logLevel(2U),
m_logFilePath(),
m_logFileRotate(true),
m_logFileSize(100U),
m_logFileCount(10U)
{
}

CConf::~CConf()
{
}

bool CConf::read()
{
	FILE* fp = ::fopen(m_file.c_str(), "rt");
	if (fp == NULL) {
		::fprintf(stderr, "Couldn't open the .ini file - %s\n", m_file.c_str());
		return false;
	}

	char buffer[BUFFER_SIZE];
	while (::fgets(buffer, BUFFER_SIZE, fp) != NULL) {
		std::string line(myTrim(buffer));

		if (line.empty() || line.at(0U) == '#')
			continue;

		if (line.at(0U) == '[') {
			std::string::size_type pos = line.find(']');
			if (pos == std::string::npos) {
				::fclose(fp);
				::fprintf(stderr, "Invalid section in the .ini file - %s\n", line.c_str());
				return false;
			}

			std::string section = myTrim(line.substr(1U, pos - 1U));

			if (section == "General")
				m_section = SECTION_GENERAL;
			else if (section == "MQTT")
				m_section = SECTION_MQTT;
			else if (section == "Log")
				m_section = SECTION_LOGGING;
			else
				m_section = SECTION_NONE;

			continue;
		}

		std::string::size_type pos = line.find('=');
		if (pos == std::string::npos) {
			::fclose(fp);
			::fprintf(stderr, "Invalid line in the .ini file - %s\n", line.c_str());
			return false;
		}

		std::string key   = myTrim(line.substr(0U, pos));
		std::string value = myTrim(line.substr(pos + 1U));

		bool valid = true;

		switch (m_section) {
			case SECTION_GENERAL:
				if (key == "Callsign")
					m_callsign = value;
				else if (key == "Timeout")
					m_timeout = (unsigned int)::atoi(value.c_str());
				else if (key == "Slot1")
					m_slot1 = ::atoi(value.c_str()) == 1;
				else if (key == "Slot2")
					m_slot2 = ::atoi(value.c_str()) == 1;
				else if (key == "RFH")
					m_rfh = ::atoi(value.c_str()) == 1;
				else if (key == "Latitude")
					m_latitude = value;
				else if (key == "Longitude")
					m_longitude = value;
				else if (key == "Description")
					m_description = value;
				else if (key == "WhiteList")
					valid = readList(value, m_whiteList);
				else if (key == "BlackList")
					valid = readList(value, m_blackList);
				else
					valid = false;
				break;

			case SECTION_MQTT:
				if (key == "Address")
					m_mqttAddress = value;
				else if (key == "Port")
					m_mqttPort = (unsigned int)::atoi(value.c_str());
				else if (key == "Login")
					m_mqttLogin = value;
				else if (key == "Password")
					m_mqttPassword = value;
				else if (key == "Debug")
					m_mqttDebug = ::atoi(value.c_str()) == 1;
				else
					valid = false;
				break;

			case SECTION_LOGGING:
				if (key == "DisplayLevel")
					m_logDisplay = ::atoi(value.c_str()) == 1;
				else if (key == "Level")
					m_logLevel = (unsigned int)::atoi(value.c_str());
				else if (key == "FilePath")
					m_logFilePath = value;
				else if (key == "FileRotate")
					m_logFileRotate = ::atoi(value.c_str()) == 1;
				else if (key == "FileSize")
					m_logFileSize = (unsigned int)::atoi(value.c_str());
				else if (key == "FileCount")
					m_logFileCount = (unsigned int)::atoi(value.c_str());
				else
					valid = false;
				break;

			default:
				::fprintf(stderr, "Unknown section in the .ini file - %s\n", line.c_str());
				break;
		}

		if (!valid)
			LogWarning("Invalid keyword/value in the .ini file - %s", line.c_str());
	}

	::fclose(fp);

	return true;
}

bool CConf::readList(const std::string& value, std::vector<unsigned int>& list) const
{
	list.clear();

	if (value.empty())
		return true;

	std::string::size_type start = 0U;
	while (start < value.size()) {
		while (start < value.size() && value[start] == ',')
			start++;

		if (start == value.size())
			break;

		std::string::size_type end = value.find(',', start);
		if (end == std::string::npos)
			end = value.size();

		std::string token = myTrim(value.substr(start, end - start));
		if (!token.empty()) {
			char* p = NULL;
			unsigned long id = ::strtoul(token.c_str(), &p, 10);
			if (p != NULL && *p != '\0') {
				::fprintf(stderr, "Invalid numeric entry in list - %s\n", token.c_str());
				return false;
			}
			list.push_back((unsigned int)id);
		}

		start = end;
	}

	return true;
}

std::string CConf::getCallsign() const
{
	return m_callsign;
}

unsigned int CConf::getTimeout() const
{
	return m_timeout;
}

bool CConf::getSlot1() const
{
	return m_slot1;
}

bool CConf::getSlot2() const
{
	return m_slot2;
}

bool CConf::getRFH() const
{
	return m_rfh;
}

std::string CConf::getLatitude() const
{
	return m_latitude;
}

std::string CConf::getLongitude() const
{
	return m_longitude;
}

std::string CConf::getDescription() const
{
	return m_description;
}

std::vector<uint32_t> CConf::getWhiteList() const
{
	return m_whiteList;
}

std::vector<uint32_t> CConf::getBlackList() const
{
	return m_blackList;
}

std::string CConf::getMQTTAddress() const
{
	return m_mqttAddress;
}

unsigned int CConf::getMQTTPort() const
{
	return m_mqttPort;
}

std::string CConf::getMQTTLogin() const
{
	return m_mqttLogin;
}

std::string CConf::getMQTTPassword() const
{
	return m_mqttPassword;
}

bool CConf::getMQTTDebug() const
{
	return m_mqttDebug;
}

bool CConf::getLogDisplay() const
{
	return m_logDisplay;
}

unsigned int CConf::getLogLevel() const
{
	return m_logLevel;
}

std::string CConf::getLogFilePath() const
{
	return m_logFilePath;
}

bool CConf::getLogFileRotate() const
{
	return m_logFileRotate;
}

unsigned int CConf::getLogFileSize() const
{
	return m_logFileSize;
}

unsigned int CConf::getLogFileCount() const
{
	return m_logFileCount;
}
