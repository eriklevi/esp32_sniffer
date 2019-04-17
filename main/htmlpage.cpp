/*
 * htmlpage.cpp
 *
 *  Created on: 30 ott 2018
 *      Author: eriklevi
 */

#include "htmlpage.h"
#include "WifiAccessPoint.h"
#include <string>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <queue>
#include <list>
#include <mutex>
#include <iostream>
#include <thread>
#include <ctime>
#include <memory>
#include <fstream>
#include <cstring>
#include <sstream>

std::shared_ptr<std::string> getHomePage(std::list<std::shared_ptr<WifiAccessPoint>> *list, std::string broker, uint8_t *mac, int port){
	std::stringstream ss;
	ss << "<!doctype html><html lang=\"en\">";
	ss << "<head>";
	ss << "<meta charset=\"utf-8\">";
	ss << "<title>";
	ss << "Probe Request Sniffer Setup";
	ss << "</title>";
	ss << "</head>";
	ss << "<body>";
	ss << "<header><h1 style=\"background-color: steelblue; color: white; text-align:center\">Sniffer Configuration</h1></header>";
		ss << "<h3 style=\"background-color: steelblue; color: white;\">Current Configuration</h3>";
		ss << "<p>";
			ss << "Stored networks:";
			ss << "</p>";
			ss << "<ul>";
				for (std::list<std::shared_ptr<WifiAccessPoint>>::const_iterator iterator = list->begin(), end = list->end(); iterator != end; ++iterator) {
					std::shared_ptr<WifiAccessPoint> p = *iterator;
					ss << "<li>" << p->getSSIDAsString() << "</li>";
				}
			ss << "</ul>";
		ss << "<p>";
			ss << "Configuration server address: " << broker <<"<br>";
		ss << "</p>";
		ss << "<p>";
			ss << "Configuration server port: " << port <<"<br>";
		ss << "</p>";
		ss << "<p>";
			ss << "Sniffer MAC address: ";
			for(int i = 0; i < 6; i++){
				int j = mac[i];
				ss << std::hex << j;
				if(i < 5){
					ss << ":";
				}
			}
		ss << "</p>";
	ss << "<h3 style=\"background-color: steelblue; color: white;\">Insert new WIFI Network</h3>";
	ss << "<form action=\"/\" method=\"post\" enctype=\"application/x-www-form-urlencoded\">";
		ss << "SSID:<br><input type=\"text\" name=\"SSID\" required>";
		ss << "<br>";
		ss << "Password:<br><input type=\"password\" name=\"Password\" required>";
		ss << "<br>";
		ss << "<input style=\"background-color: steelblue; color: white;\" type=\"submit\" value=\"Submit\">";
	ss << "</form>";
		ss << "<h3 style=\"background-color: steelblue; color: white;\">Update Configuration Server</h3>";
	ss << "<form action=\"/\" method=\"post\" enctype=\"application/x-www-form-urlencoded\">";
		ss << "Address:<br><input type=\"text\" name=\"ws\" required>";
		ss << "<br>";
		ss << "Port:<br><input type=\"text\" name=\"port\" required>";
		ss << "<br>";
		ss << "<input style=\"background-color: steelblue; color: white;\" type= \"submit\" value=\"Submit\">";
	ss << "</form>";
			ss << "<h3 style=\"background-color: steelblue; color: white;\">Actions</h3>";
	ss << "<form action=\"/\" method=\"post\" enctype=\"application/x-www-form-urlencoded\"><input type=\"hidden\" name=\"reset\"><br><input style=\"background-color: steelblue; color: white;\" type=\"submit\" value=\"Reset sniffer\"></form><form action=\"/\" method=\"post\" enctype=\"application/x-www-form-urlencoded\"><input type=\"hidden\" name=\"clear\"><br><input style=\"background-color: steelblue; color: white;\" type=\"submit\" value=\"Clear known networks\"></form>";
	ss << "</body>";
	ss << "</html>";
	std::shared_ptr<std::string> res = std::make_shared<std::string>(ss.str());
	return res;
}

std::shared_ptr<std::string> getHomePageCustomMessage(std::list<std::shared_ptr<WifiAccessPoint>> *list, std::string ws_server, std::string message){
	std::stringstream ss;
	ss << "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Probe Request Sniffer Setup</title></head><body><h3 style= \"color: red;\">"<<message<<"</h3><p>Stored networks:</p><ul>";
	for (std::list<std::shared_ptr<WifiAccessPoint>>::const_iterator iterator = list->begin(), end = list->end(); iterator != end; ++iterator) {
		std::shared_ptr<WifiAccessPoint> p = *iterator;
		ss << "<li>" << p->getSSIDAsString() << "</li>";
	}
ss << "</ul><p>WS server: </p>" << ws_server <<"<br><form action=\"/\" method=\"post\" enctype=\"application/x-www-form-urlencoded\"><p>Insert new wifi network:</p>SSID:<br><input type=\"text\" name=\"SSID\" required><br>Password:<br><input type=\"password\" name=\"Password\" required><br><input type=\"submit\" value=\"Submit\"></form><form action=\"/\" method=\"post\" enctype=\"application/x-www-form-urlencoded\"><p>Update configuration server address:</p>Address:<br><input type=\"text\" name=\"ws\" required><br><input type=\"submit\" value=\"Submit\"></form><form action=\"/\" method=\"post\" enctype=\"application/x-www-form-urlencoded\"><input type=\"hidden\" name=\"reset\"><br><input type=\"submit\" value=\"Reset\"></form><form action=\"/\" method=\"post\" enctype=\"application/x-www-form-urlencoded\"><input type=\"hidden\" name=\"clear\"><br><input type=\"submit\" value=\"Clear known networks\"></form></body></html>";
	std::shared_ptr<std::string> res = std::make_shared<std::string>(ss.str());
	return res;
}

