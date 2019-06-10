/*
 * htmlpage.h
 *
 *  Created on: 30 ott 2018
 *      Author: eriklevi
 */

#ifndef MAIN_HTMLPAGE_H_
#define MAIN_HTMLPAGE_H_

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

std::shared_ptr<std::string> getHomePage(std::list<std::shared_ptr<WifiAccessPoint>> *list, std::string broker, uint8_t* mac, int port, std::string message);

#endif /* MAIN_HTMLPAGE_H_ */
