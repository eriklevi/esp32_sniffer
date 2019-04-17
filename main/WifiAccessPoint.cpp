/*
 * WifiAccessPoint.cpp
 *
 *  Created on: 22 ott 2018
 *      Author: eriklevi
 */

#include "WifiAccessPoint.h"
#include <stdio.h>
#include <string>
#include <cstring>

WifiAccessPoint::WifiAccessPoint() {
}

WifiAccessPoint::~WifiAccessPoint() {
}

void WifiAccessPoint::setSSID(std::string source, int length){
	const uint8_t* p = reinterpret_cast<const uint8_t*>(source.c_str());
	this->SSIDLength = length+1;
	memcpy(this->SSID, p, length+1);
}

void WifiAccessPoint::setPassword(std::string source, int length){
	const uint8_t* p = reinterpret_cast<const uint8_t*>(source.c_str());
	this->passwordLength = length+1;
	memcpy(this->password, p, length+1);
}

uint8_t* WifiAccessPoint::getPassword(){
	return this->password;
}

uint8_t* WifiAccessPoint::getSSID(){
	return this->SSID;
}

int WifiAccessPoint::getPasswordLength(){
	return this->passwordLength;
}

int WifiAccessPoint::getSSIDLength(){
	return this->SSIDLength;
}

std::string WifiAccessPoint::getSSIDAsString(){
	return (char *)this->SSID;
}

