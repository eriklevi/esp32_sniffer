/*
 * ProbeRequestData.cpp
 *
 *  Created on: 22 ott 2018
 *      Author: eriklevi
 */

#include "ProbeRequestData.h"
#include <cstring>

ProbeRequestData::ProbeRequestData() {
}

ProbeRequestData::~ProbeRequestData() {
}

void ProbeRequestData::setDeviceMAC(uint8_t *source, int size){
	memcpy((void*)this->deviceMAC, (void*)source, size*sizeof(uint8_t));
}

void ProbeRequestData::setFingerprint(uint8_t *source, int size){
	memcpy((void*)this->fingerprint, (void*)source, size*sizeof(uint8_t));
}

void ProbeRequestData::setSignalStrength(int8_t source){
	this->signalStrength = source;
}

void ProbeRequestData::getDeviceMAC(uint8_t* buffer){
	memcpy(buffer, this->deviceMAC, 6*sizeof(uint8_t));
}

int ProbeRequestData::getDataBuffer(uint8_t *buffer, uint8_t *sniffer_mac){
	memcpy(buffer, sniffer_mac, 6*sizeof(uint8_t));
	memcpy(buffer + (6*sizeof(uint8_t)), this->deviceMAC , 6*sizeof(uint8_t));
	memcpy(buffer + (12*sizeof(uint8_t)), &this->signalStrength, sizeof(uint8_t));
	memcpy(buffer + 13*sizeof(uint8_t), &this->global_mac, sizeof(uint8_t));
	memcpy(buffer + 14*sizeof(uint8_t), &this->apple_specific_tag, sizeof(uint8_t));
	memcpy(buffer + 15*sizeof(uint8_t), this->ssid, this->ssid_len*sizeof(uint8_t));
	memcpy(buffer + 15*sizeof(uint8_t) + this->ssid_len*sizeof(uint8_t) , this->fingerprint, this->fingerprint_len*sizeof(uint8_t));
	return 15 + this->ssid_len + this->fingerprint_len;
}
void ProbeRequestData::setSSID(uint8_t *source, int size){
	memcpy((void*)this->ssid, source, size);
	this->ssid_len = size;
}
void ProbeRequestData::getSSID(uint8_t buffer[32]){
	memcpy((void*)buffer, this->ssid, this->ssid_len);
}
int  ProbeRequestData::getSSIDLen(){
	return this->ssid_len;
}

void ProbeRequestData::setGlobalMac(uint8_t value){
	this->global_mac = value;
}
void ProbeRequestData::setAppleSpecificTag(uint8_t value){
	this->apple_specific_tag = value;
}
void ProbeRequestData::setFingerprintLen(int value){
	this->fingerprint_len = value;
}

