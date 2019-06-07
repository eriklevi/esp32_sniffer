/*
 * ProbeRequestData.h
 *
 *  Created on: 22 ott 2018
 *      Author: eriklevi
 */

#ifndef MAIN_PROBEREQUESTDATA_H_
#define MAIN_PROBEREQUESTDATA_H_

#include <cstdint>

class ProbeRequestData {
public:
	ProbeRequestData();
	virtual ~ProbeRequestData();
	void setFingerprint(uint8_t *source, int size);
	void setSignalStrength(int8_t source);
	void setDeviceMAC(uint8_t *source, int size);
	void setSSID(uint8_t *source, uint8_t size);
	void getSSID(uint8_t buffer[32]);
	int  getSSIDLen();
	void getDeviceMAC(uint8_t *buffer);
	int getDataBuffer(uint8_t *buffer, uint8_t *sniffer_mac);
	void setGlobalMac(uint8_t value);
	void setAppleSpecificTag(uint8_t value);
	void setFingerprintLen(int value);
	void setSequenceNumber(uint8_t* number);
	void setFCS(uint8_t* data, uint16_t data_len);
	
	
private:
	uint8_t deviceMAC[6];
	uint8_t fingerprint[16];
	int8_t signalStrength;
	uint8_t ssid[32];
	uint8_t ssid_len;
	int fingerprint_len;
	uint8_t global_mac;
	uint8_t apple_specific_tag;
	uint16_t sequence_number;
	uint32_t fcs;
};

#endif /* MAIN_PROBEREQUESTDATA_H_ */
