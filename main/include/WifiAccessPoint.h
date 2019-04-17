/*
 * WifiAccessPoint.h
 *
 *  Created on: 22 ott 2018
 *      Author: eriklevi
 */

#ifndef MAIN_WIFIACCESSPOINT_H_
#define MAIN_WIFIACCESSPOINT_H_

#include <cstdint>
#include <string>

class WifiAccessPoint {
public:
	WifiAccessPoint();
	virtual ~WifiAccessPoint();
	void setSSID(std::string source, int length);
	void setPassword(std::string source, int length);
	uint8_t* getPassword();
	int getPasswordLength();
	uint8_t* getSSID();
	int getSSIDLength();
	std::string getSSIDAsString();

private:
	uint8_t SSID[32];
	int SSIDLength;
	uint8_t password[64];
	int passwordLength;
};

#endif /* MAIN_WIFIACCESSPOINT_H_ */
