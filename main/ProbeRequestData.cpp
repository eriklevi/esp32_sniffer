/*
 * ProbeRequestData.cpp
 *
 *  Created on: 22 ott 2018
 *      Author: eriklevi
 */

#include "ProbeRequestData.h"
#include <cstring>
#include <cstdint>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <queue>
#include <list>
#include <mutex>
#include <atomic>
#include <iostream>
#include <thread>
#include <ctime>
#include <memory>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdlib>

ProbeRequestData::ProbeRequestData() {
	this->fingerprint_len = 0;
	this->sequence_number = 0;
	this->ssid_len = 0;
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
	memcpy(buffer + 12*sizeof(uint8_t), &this->sequence_number, sizeof(uint16_t));
	memcpy(buffer + 12*sizeof(uint8_t) + sizeof(uint16_t), &this->signalStrength, sizeof(int8_t));
	memcpy(buffer + 12*sizeof(uint8_t) + sizeof(uint16_t) + sizeof(int8_t), &this->ssid_len, sizeof(uint8_t));
	memcpy(buffer + 13*sizeof(uint8_t) + sizeof(uint16_t) + sizeof(int8_t), this->ssid, this->ssid_len*sizeof(uint8_t));
	memcpy(buffer + 13*sizeof(uint8_t) + this->ssid_len*sizeof(uint8_t) + sizeof(uint16_t) + sizeof(int8_t), this->fingerprint, this->fingerprint_len*sizeof(uint8_t));
	return 16 + this->ssid_len + this->fingerprint_len;
}
void ProbeRequestData::setSSID(uint8_t *source, uint8_t size){
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
void ProbeRequestData::setSequenceNumber(uint8_t* number){
	memcpy(&this->sequence_number, number, 2);
}
void ProbeRequestData::setFCS(uint8_t* data, uint16_t data_len){
	memcpy(&this->fcs, &data[data_len - 4], 4);
}

