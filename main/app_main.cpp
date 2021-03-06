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
#include <iomanip>
#include <esp_http_server.h>
#include "soc/rtc_cntl_reg.h"
#include "md5.h"
#include "lwip/apps/sntp.h"
#include <sys/param.h>

#include "esp_wifi.h"
#include "esp_system.h"
#include "nvs_flash.h"
#include "esp_event_loop.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "esp_spiffs.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "freertos/event_groups.h"

#include "os.h"
#include "sniffer.h"
#include "ProbeRequestData.h"
#include "WifiAccessPoint.h"
#include "htmlpage.h"
#include "mqtt_client.h"
#include "cJSON.h"
static const char* TAG = "SNIFFER";
static EventGroupHandle_t wifi_event_group;
const static int CONNECTED_BIT = BIT0;
/* Filter out the common ESP32 MAC */
static const uint8_t esp_module_mac[32][3] = {
		{0x54, 0x5A, 0xA6}, {0x24, 0x0A, 0xC4}, {0xD8, 0xA0, 0x1D}, {0xEC, 0xFA, 0xBC},
		{0xA0, 0x20, 0xA6}, {0x90, 0x97, 0xD5}, {0x18, 0xFE, 0x34}, {0x60, 0x01, 0x94},
		{0x2C, 0x3A, 0xE8}, {0xA4, 0x7B, 0x9D}, {0xDC, 0x4F, 0x22}, {0x5C, 0xCF, 0x7F},
		{0xAC, 0xD0, 0x74}, {0x30, 0xAE, 0xA4}, {0x24, 0xB2, 0xDE}, {0x68, 0xC6, 0x3A},
};

enum mqtt_save_data_type {
    data_type_full_json = 0x01,
    data_type_bin = 0x02,
    data_type_simple_json_without_time = 0x03,
    data_type_simple_json_with_time = 0x04,
    data_type_string = 0x05,
    data_type_string_with_time = 0x06,
    data_type_float  = 0x07
};
/* The device num in ten minutes */
int s_device_info_num           = 0;
station_info_t *station_info    = NULL;
station_info_t *g_station_list  = NULL;
uint8_t global_mac_byte = 0;
uint8_t mac[6];
time_t now;
int s_is_connected = 0;
int connection_lost = 0;
int first = 0;
std::atomic<bool> mqtt_connection_lost;
std::atomic<bool> wifi_connection_lost;
bool mqtt_disconnection_thread_running = false;
std::mutex mqtt_disconnection_mutex;
bool wifi_disconnection_thread_running = false;
std::mutex wifi_disconnection_mutex;
struct mg_connection *nc;

std::string configurationProxy = "0.0.0.0"; //default to avoid problems
int configurationProxyPort = 0;

/**
 * MQTT related variables
 */
std::string brokerHost = "0.0.0.0";
int brokerPort = 0;
bool dump_mode_bool = false;
bool privacy_mode_bool = false;
std::string broker_username;
std::string broker_password;
std::string topic_to_publish;
std::string lwt_message;
std::string lwt_topic;
std::string other_topic;


std::string oauthToken;
std::string secret = "secret12345";
std::string deviceName;
std::string devicePassword;

int power_thrashold = 0;

bool httpRequestSuccess = false;
struct tm timeinfo;
bool wifiConnected = false;
httpd_handle_t server = NULL;
httpd_config_t config = HTTPD_DEFAULT_CONFIG();
esp_mqtt_client_handle_t client1 = NULL;
char data_buffer[2048];
int data_len = 0;
std::string message = "";


extern "C"{
	void app_main(void);
}

template <class T>
class SharedQueue {
	std::queue<T> queue;
	std::mutex m;
	public:
		SharedQueue(){}
		int size(){
			std::lock_guard<std::mutex> l(m);
			return queue.size();
		}
		T popFront(){
			T t;
			std::lock_guard<std::mutex> l(m);
			t = queue.front();
			queue.pop();
			return t;
		}
		void pushBack(T t){
			std::lock_guard<std::mutex> l(m);
			queue.push(t);
		}
		bool checkEmpty(){
			return queue.empty();
		}
};

SharedQueue<std::shared_ptr<ProbeRequestData>> *sq = new SharedQueue<std::shared_ptr<ProbeRequestData>>();
std::list<std::shared_ptr<WifiAccessPoint>> *list = new std::list<std::shared_ptr<WifiAccessPoint>>();

bool get_mqtt_disconnection_thread_running(){
	std::lock_guard<std::mutex> lg(mqtt_disconnection_mutex);
	return mqtt_disconnection_thread_running;
}

void set_mqtt_disconnection_thread_running(bool val){
	std::lock_guard<std::mutex> lg(mqtt_disconnection_mutex);
	mqtt_disconnection_thread_running = val;
}

bool get_wifi_disconnection_thread_running(){
	std::lock_guard<std::mutex> lg(wifi_disconnection_mutex);
	return wifi_disconnection_thread_running;
}

void set_wifi_disconnection_thread_running(bool val){
	std::lock_guard<std::mutex> lg(wifi_disconnection_mutex);
	wifi_disconnection_thread_running = val;
}

/**
 * Checks if the connection is re-established the restart the device accordingly.
 * This is needed in case of unknown behaviour to try to avoid losing too many data.
 */
void mqttDisconnectionTask(){
	vTaskDelay(300000 / portTICK_PERIOD_MS);
	if(mqtt_connection_lost.load()){
		ESP_LOGI(TAG,"Restarting device after mqtt disconnection!");
		esp_restart();
	}
	ESP_LOGI(TAG, "Connection reestablished, disconnectionTask returning!");
	set_mqtt_disconnection_thread_running(false);
	return;		
}

void wifiDisconnectionTask(){
	ESP_LOGI(TAG, "Started Wifi disconnection task");
	vTaskDelay(300000 / portTICK_PERIOD_MS);
	if(wifi_connection_lost.load()){
		ESP_LOGI(TAG,"Restarting device after wifi disconnection!");
		esp_restart();
	}
	ESP_LOGI(TAG, "Connection reestablished, disconnectionTask returning!");
	set_wifi_disconnection_thread_running(false);
	return;		
}

/**
 * This function parses the received probe request and calculate the fingerprint.
 * payload -> pointer to packet payload
 * size -> size of payload
 * buffer -> stores the fp
 * ssid -> stores the advertised ssid if present
 * ssid_size -> stores the length of ssid
 */
void pkt_parser(uint8_t *payload, uint16_t size, uint8_t * buffer, uint8_t *ssid, uint8_t *ssid_size)
{
	//len = in the end it contains the length of payload without eventual SSID tag
	uint16_t len;
	//length of tag string
	int tag_c = 0;
	int tag = 0;
	int tag_size = 0;
	//first 2 bytes are sequence number
	int i = 2;
	int offset = 0;
	int data_len;
	uint8_t str_tags[70];
	uint8_t *data;
	//we use this variable to store the data needed to make the hash more specific
	//to be shure to allocate enough data we use the payload length
	uint8_t *tagData = (uint8_t*)malloc(size*sizeof(uint8_t));
	tag_size = payload[3];
	len = size;
	std::cout << std::endl;
	std::cout << "len -> " << len << std::endl;
	/**
	 * Parsing
	 */

	/* 
	std::cout << "payload -> " << std::endl;
		for(int j = 0; j < size; j++)
			printf("%02X", payload[j]);
		std::cout << std::endl;*/
	while(i < size){
		tag = payload[i];
		//std::cout << "tag -> " << tag << std::endl;
		i++;
		tag_size = payload[i];
		//std::cout << "len size -> " << tag_size << std::endl;
		i++;
		/*
		 * We have to consider the vendor specific tag inside a DD tag
		 */
		if(tag == 221){
			memcpy(&str_tags[tag_c], &tag, sizeof(uint8_t));
			tag_c++;
			/**
			 * we have to read the vendor specific oui and the vendor specific oui type
			 * DD XX XXXXXX XX
			 * || |||||| ||
			 * || |||||| vendor specific OUI type
			 * || vendor specific OUI
			 * length
			 */

			memcpy(&str_tags[tag_c], &payload[i], 4*sizeof(uint8_t));
			tag_c += 4;
		}
		else{
			/**
			 * We check if tag 00 has a length > 0
			 * In this case we have to len -= tag_length
			 * since we don't need to consider the SSID
			 */
			if(tag == 0){
				//tag '00'
				len -= tag_size;
				//we copy the ssid in the ssid buffer
				memcpy(ssid, &payload[i], tag_size);
				*ssid_size = payload[i-1];
//				std::cout << "lunghezza tag 00 -> " << tag_size << std::endl;
//				std::cout << "len -> " << len << std::endl;
//				//dobbiamo aggiornare i!!!
//				std::cout << "i -> " << i << std::endl;
			}
			memcpy(&str_tags[tag_c], &tag, sizeof(uint8_t));
			tag_c++;
		}
		/**
		 * in case of a tag of the following we save the payload inside tag data to produce the hash
		 * DD == 221 Vendor specific IE
		 * 01 == 1 supported rates
		 * 32 == 50 extended supported rates
		 * 7F == 127 extended capabilities
		 * 2D == 45 ht capabilities
		 * BF == 191 vht capabilities
		 */
		if(tag == 221 || tag == 1 || tag == 50 || tag == 127 || tag == 45 || tag == 191){
			memcpy(tagData+offset, &payload[i], tag_size*sizeof(uint8_t));
			offset += tag_size;
		}
		i += tag_size;
		//std::cout << "i -> " << i << std::endl;
	}
	data_len = tag_c+sizeof(uint16_t)+offset;// lungezza del tag + totale byte del payload + byte del tagData
	data = (uint8_t *)malloc(data_len*sizeof(uint8_t));
	memcpy(data, &len, sizeof(uint16_t));
	memcpy(data+sizeof(uint16_t), str_tags, tag_c*sizeof(uint8_t));
	memcpy(data+sizeof(uint16_t)+tag_c*sizeof(uint8_t), tagData, offset*sizeof(uint8_t));
	//std::cout << "tag list -> " << std::endl;
	//for(int j = 0; j < data_len; j++)
		//printf("%02X", data[j]);
	//std::cout << std::endl;
	md5(data, data_len, buffer);
	free(data);
	free(tagData);
	std::cout << "finito parser" << std::endl;
}

void get_ssid_from_payload(uint8_t* data,uint8_t* ssid,uint8_t *ssid_size){
	uint8_t tag_len = 0;
	if(data[2] == 0){
		tag_len = data[3];
		memcpy(ssid, &data[4], tag_len*sizeof(uint8_t));
		*ssid_size = tag_len;
	}
	else{
		ssid = NULL;
		*ssid_size = 0;
	}
}


/*
 * Parses x-www-form-urlencoded data coming from POST request data
 */
std::string urlencodedTranslator(std::string s)
{
	for(std::string::size_type i = 0; i < s.size(); ++i){
		if(s[i] == '+')
			s.replace(i, 1, " ");
	}
	for(std::string::size_type i = 0; i < s.size(); ++i){
		if(s[i] == '%'){
			if (i <= s.length() - 3){
				char chr[2] = {(char)(int)strtol(s.substr(i+1,2).c_str(), NULL, 16), '\0'};
				s.replace(i, 3, chr);
			}
		}
	}
	return s;
}

int addNetwork(std::string ssid, std::string password)
{
	if(ssid.length() != 0 && password.length() != 0){
		std::ofstream ofs;
		ofs.open("/spiffs/wifi.txt", std::ofstream::out | std::ofstream::app);
		ofs << ssid << " " << password << std::endl;
		ofs.close();
		std::shared_ptr<WifiAccessPoint> p = std::make_shared<WifiAccessPoint>();
		p->setPassword(password, password.length());
		p->setSSID(ssid, ssid.length());
		list->push_back(p);
		return 1;
	}
	else
		return 0;
}

int clearSavedNetworks()
{
	std::ofstream ofs;
	ofs.open("/spiffs/wifi.txt", std::ofstream::out | std::ofstream::trunc);
	ofs.close();
	//we empty the list so that when we GET index.html the displayed data are up to date
	list->clear();
	std::cout << "List of networks deleted!" << std::endl;
	return 1;
}

int updateWSServer(std::string server, std::string port)
{
	if(server.length() != 0 /*&& std::regex_match(server, b)*/){
		std::ofstream ofs;
		ofs.open("/spiffs/ws.txt", std::ofstream::out | std::ofstream::trunc);
		ofs << server << " " << port << std::endl;
		ofs.close();
		configurationProxy = server;
		std::cout << "Proxy server updated! Now it is : " << server << " port: " << port << std::endl;
		return 1;
	}else
		return 0;
}

/*
 * Parses received string and executes commands.
 * It's possible to :
 * -update ws server
 * -delete saved access points credentials
 * -insert new access point credential
 * -reset the sniffer
 */
int POST_request_parser(std::string s)
{
	std::string t_s = urlencodedTranslator(s);
	size_t pos = 0;
	pos = t_s.find('&');
	if(pos != std::string::npos){
		//We have found an occurrence of & so we have to split the 2 commands
		std::string first = t_s.substr(0, pos);
		std::string second = t_s.substr(pos+1, std::string::npos);
		pos = first.find('=');
		std::string command1 = first.substr(0, pos);
		std::string value1 = first.substr(pos+1, std::string::npos);
		pos = second.find('=');
		std::string command2 = second.substr(0, pos);
		std::string value2 = second.substr(pos+1, std::string::npos);
		if(command1.compare("SSID") == 0
				&& command2.compare("Password") == 0){
			if(addNetwork(value1, value2) == 0){
				return 1;
			}
		}
		else{
			if(command1.compare("ws") == 0 && command2.compare("port") == 0){
				updateWSServer(value1, value2);
			}
		}
	}
	else{
		//We have only one command
		pos = t_s.find('=');
		std::string command = t_s.substr(0, pos);
		std::string value = t_s.substr(pos+1, std::string::npos);
		if(command.compare("reset") == 0){
			for (int i = 3; i >= 0; i--) {
				std::cout << "Restarting in " << i << std::endl;
			    vTaskDelay(1000 / portTICK_PERIOD_MS);
			}
			esp_restart();
		}
		if(command.compare("clear") == 0){
			clearSavedNetworks();
		}
	}
	return 0;
}

/*
 * The wifi sniffer callback
 */
void wifi_sniffer_cb(void *recv_buf, wifi_promiscuous_pkt_type_t type)
{
	uint8_t buffer[16];
	uint8_t ssid[32];
	uint8_t ssid_size = 0;
	//pacchetto compreso di header inseriti da esp 32 e pacchetto catturato
	wifi_promiscuous_pkt_t *sniffer = (wifi_promiscuous_pkt_t *)recv_buf;
	//pacchetto con header + payload del pacchetto
	sniffer_payload_t *sniffer_payload = (sniffer_payload_t *)sniffer->payload;
	//dati contenuti nel pacchetto, nel caso di P.R. abbiamo seqn + tagged parameters + fcs
	uint8_t *data = sniffer_payload->payload;
	//len rappresenta la lunghezza totale di header + payload(seq + tagged parameters) + i 4 byte finali di check
	uint16_t len =  sniffer->rx_ctrl.sig_len;
	

    /*bisogna togliere i 22 byte dell'header + gli ultimi 4 di check
     * ------------------- Header
	 * 4 byte header
     * 6 byte rec mac
     * 6 byte dest mac
     * 6 bssid
     * ------------------- Payload
	 * D021 <---- sequence number
	 * 0000 
	 * 010882848B0C12961824
	 * 030102
	 * 32043048606C
	 * 2D1A6D1117FF00000000000000000000000100000000000004060A00
	 * 7F080000008000000000
	 * (output preso da stampa di debug di paket parser)
	 * --------------------->  fine tagged parameters
	 * 4 di check alla fine
	 * 
	 * totale da togliere per avere solo la lunghezza del payload del pacchetto (tagged params + seq) = 26
     */
	uint16_t payload_len = len - 26;

	/* Check if the packet is Probe Request  */
	//0100 è il codice corrispondente al probe request
	if (sniffer_payload->header[0] != 0x40) {
		return;
	}
/* 
	std::cout << "len " << std::dec << len << std::endl;
	std::cout << "payload -> " << std::endl;
		for(int j = 0; j < len; j++)
			printf("%02X", sniffer->payload[j]);
		std::cout << std::endl;
*/


	if(sniffer->rx_ctrl.rssi < power_thrashold){
		std::cout << "pacchetto scartato potenza " << sniffer->rx_ctrl.rssi << std::endl;
		return;
	}

	printf("source mac: %02X.%02X.%02X.%02X.%02X.%02X\n", sniffer_payload->source_mac[0],sniffer_payload->source_mac[1],sniffer_payload->source_mac[2],sniffer_payload->source_mac[3],sniffer_payload->source_mac[4],sniffer_payload->source_mac[5]);
	uint8_t test = 2;

	if(dump_mode_bool){
		//mandiamo i pacchetti immediatamente

		int totalSize = 6+len;
		char* data_buffer = (char*) malloc(totalSize*sizeof(uint8_t));
		memcpy(data_buffer, mac, 6*sizeof(uint8_t));
		memcpy(data_buffer+6*sizeof(uint8_t), sniffer->payload, len*sizeof(uint8_t));
		esp_mqtt_client_publish(client1, "dump", (char*)data_buffer, totalSize, 0, 0);
		free(data_buffer);
	}else{
		if((sniffer_payload->source_mac[0] & test) == 0){
			std::cout << "pacchetto global" << std::endl;
			//Global MAC address
			std::shared_ptr<ProbeRequestData> p = std::make_shared<ProbeRequestData>();
			get_ssid_from_payload(data, ssid, &ssid_size);
			p->setSequenceNumber(data);
			//p->setGlobalMac(0);
			//p->setAppleSpecificTag(0);
			p->setFCS(sniffer->payload, len-4);
			p->setFingerprintLen(0);
			p->setDeviceMAC((unsigned char *)sniffer_payload->source_mac, 6);
			p->setSignalStrength((signed char)sniffer->rx_ctrl.rssi);
			p->setSSID(ssid, ssid_size);
			sq->pushBack(p);
			//E01A0000010802040B160C12182432043048606C0000D5B1
		}
		else{
			std::cout << "pacchetto local" << std::endl;
			pkt_parser(data, payload_len, buffer, ssid, &ssid_size);
			std::shared_ptr<ProbeRequestData> p = std::make_shared<ProbeRequestData>();
			//p->setGlobalMac(1);
			//p->setAppleSpecificTag(0);
			p->setSequenceNumber(data);
			p->setDeviceMAC((unsigned char *)sniffer_payload->source_mac, 6);
			p->setSignalStrength((signed char)sniffer->rx_ctrl.rssi);
			p->setFingerprint(buffer, 16);
			p->setFingerprintLen(16);
			p->setFCS(sniffer->payload, len-4);
			p->setSSID(ssid, ssid_size);
			sq->pushBack(p);
		}
	}
}

esp_err_t HttpRequestsHandler(esp_http_client_event_t *evt)
{

	switch(evt->event_id) {
	case HTTP_EVENT_ERROR:
            ESP_LOGI(TAG, "HTTP_EVENT_ERROR");
            break;
        case HTTP_EVENT_ON_CONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_CONNECTED");
            break;
        case HTTP_EVENT_HEADER_SENT:
            ESP_LOGI(TAG, "HTTP_EVENT_HEADER_SENT");
            break;
        case HTTP_EVENT_ON_HEADER:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_HEADER");
            printf("%.*s\n", evt->data_len, (char*)evt->data);
            break;
        case HTTP_EVENT_ON_DATA:
        	ESP_LOGI(TAG, "HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
            printf("%.*s\n", evt->data_len, (char*)evt->data);
        	if (esp_http_client_is_chunked_response(evt->client)) {
        		memcpy(&data_buffer[data_len], (char*)evt->data, evt->data_len);
        		data_len += evt->data_len;
        	}
            break;
        case HTTP_EVENT_ON_FINISH:
            ESP_LOGI(TAG, "HTTP_EVENT_ON_FINISH");
            break;
        case HTTP_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "HTTP_EVENT_DISCONNECTED");
            break;
    }
    return ESP_OK;
}

void stopHttpServer(){
	if(httpd_stop(&server) == ESP_OK){
		std::cout << "Stopped HTTP server" << std::endl;
	}
}

static esp_err_t mqtt_event_handler(esp_mqtt_event_handle_t event)
{
	//your_context_t *context = event->context;
	switch (event->event_id) {
	case MQTT_EVENT_CONNECTED:
		ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
		s_is_connected = 1;
		first = 0;
		mqtt_connection_lost.store(false);
		//esp_wifi_set_mode(WIFI_MODE_STA);
		//stopHttpServer();
		esp_mqtt_client_subscribe(client1, "commands", 0);
		esp_mqtt_client_subscribe(client1, other_topic.c_str(), 2);
		printf("avvio modalità promiscua\n");
		ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb));
		ESP_ERROR_CHECK(esp_wifi_set_promiscuous(1));
		break;
	case MQTT_EVENT_DISCONNECTED:
		ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
		s_is_connected = 0;
		//stop promiscous mode
		if(first == 0){
			ESP_LOGI(TAG, "Stopping promiscous mode, device will restart unless connection is reestablished");
			ESP_ERROR_CHECK(esp_wifi_set_promiscuous(0));
			first = 1;
			if(!get_mqtt_disconnection_thread_running()){
				set_mqtt_disconnection_thread_running(true);
				std::thread disconnection_thread(mqttDisconnectionTask);
				disconnection_thread.detach();
			}	
		}
		mqtt_connection_lost.store(true);
		//In case of disconnection the task waits for 5 seconds
		//before trying to reconnect to the broker
		//vTaskDelay(5000 / portTICK_PERIOD_MS);
		break;
	case MQTT_EVENT_SUBSCRIBED:
		ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
		break;
	case MQTT_EVENT_UNSUBSCRIBED:
		ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
		break;
	case MQTT_EVENT_PUBLISHED:
		ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
		break;
	case MQTT_EVENT_DATA:
		ESP_LOGI(TAG, "MQTT_EVENT_DATA");
		printf("TOPIC=%.*s\r\n", event->topic_len, event->topic);
		printf("DATA=%.*s\r\n", event->data_len, event->data);
		if(strcmp(event->data,"restart") == 0)
			for (int i = 3; i >= 0; i--) {
				std::cout << " Reset command received, restarting in " << i << std::endl;
			    vTaskDelay(1000 / portTICK_PERIOD_MS);
			}
			esp_restart();
		break;
	case MQTT_EVENT_ERROR:
		ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
		break;
	case MQTT_EVENT_BEFORE_CONNECT:
		break;
	}
	return ESP_OK;
}

static esp_err_t wifi_event_handler(void *ctx, system_event_t *event)
{
	switch (event->event_id) {
		case SYSTEM_EVENT_STA_START:
			ESP_LOGI(TAG, "Lanciato evento station start!");
			esp_wifi_connect();
			break;
		case SYSTEM_EVENT_STA_GOT_IP:
			ESP_LOGI(TAG, "Lanciato evento station gotip!");
			xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
			wifiConnected = true;
			connection_lost = 1;
			wifi_connection_lost.store(false);
			if (!g_station_list) {
				g_station_list = (station_info_t*)malloc(sizeof(station_info_t));
				g_station_list->next = NULL;
			}
			break;
			//TODO gestire la disconnessione dal wifi
		case SYSTEM_EVENT_STA_DISCONNECTED:
			ESP_LOGI(TAG, "Lanciato evento station disconnected!");
			if(connection_lost == 1){
				connection_lost = 0;
				/*for (int i = 3; i >= 0; i--) {
					std::cout << " Wifi connection lost, restarting in " << i << std::endl;
			    	vTaskDelay(1000 / portTICK_PERIOD_MS);
				}
				esp_restart();*/
				if(!get_wifi_disconnection_thread_running()){
					set_wifi_disconnection_thread_running(true);
					std::thread wifi_disconnection_thread(wifiDisconnectionTask);
					wifi_disconnection_thread.detach();
				}	
			}
			wifi_connection_lost.store(true);
			vTaskDelay(10000/portTICK_PERIOD_MS);
			esp_wifi_connect();
			break;
		default:
			break;
	}
	return ESP_OK;
}

/*
static void wifi_init_ap(){
	wifi_init_config_t wifiInitializationConfig = WIFI_INIT_CONFIG_DEFAULT();
	esp_wifi_init(&wifiInitializationConfig);
	esp_wifi_set_storage(WIFI_STORAGE_RAM);
	esp_wifi_set_mode(WIFI_MODE_AP);
	wifi_config_t ap_config = {};
	ap_config.ap = {};
	memcpy(ap_config.ap.ssid, "PROBE_CONFIG", 12);
	memcpy(ap_config.ap.password,"password1234",12);
	ap_config.ap.channel = 0;
	ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
	ap_config.ap.ssid_hidden = 0;
	ap_config.ap.max_connection = 1;
	ap_config.ap.beacon_interval = 100;
	esp_wifi_set_config(WIFI_IF_AP, &ap_config);
	esp_wifi_start();
}

static void wifi_init_sta()
{
	EventBits_t uxBits;
	//trying to connect to each station for 10 seconds
	const TickType_t xTicksToWait = 10000 / portTICK_PERIOD_MS;
	tcpip_adapter_init();
	wifi_event_group = xEventGroupCreate();
	ESP_ERROR_CHECK(esp_event_loop_init(wifi_event_handler, NULL));
	wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
	ESP_ERROR_CHECK(esp_wifi_init(&cfg));
	ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
	wifi_config_t wifi_config = {};
	for (std::list<std::shared_ptr<WifiAccessPoint>>::const_iterator iterator = list->begin(), end = list->end(); iterator != end; ++iterator) {
		std::shared_ptr<WifiAccessPoint> p = *iterator;
		memcpy(wifi_config.sta.ssid, p->getSSID(), p->getSSIDLength());
		memcpy(wifi_config.sta.password, p->getPassword(), p->getPasswordLength());
		ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
		ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config));
		std::cout << "Trying to connect to " << p->getSSIDAsString() << std::endl;
		ESP_ERROR_CHECK(esp_wifi_start());
		ESP_LOGI(TAG, "Waiting for wifi");
		uxBits = xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, xTicksToWait);
		if( ( uxBits & CONNECTED_BIT ) != 0 ) {
			std::cout << "Connected!" << std::endl;
			//check if xEventGroupWaitBits returned for wifi successfully connected or not
			wifiConnected = true;
			break;
		}
		else{
			std::cout << "Failed to connect, trying next network" << std::endl;
			ESP_ERROR_CHECK(esp_wifi_stop());
		}
	}
}
*/

	static void wifi_init(){
	EventBits_t uxBits;
	//trying to connect to each station for 10 seconds
	const TickType_t xTicksToWait = 10000 / portTICK_PERIOD_MS;
	tcpip_adapter_init();
	wifi_event_group = xEventGroupCreate();
	ESP_ERROR_CHECK(esp_event_loop_init(wifi_event_handler, NULL));
	wifi_init_config_t wifiInitializationConfig = WIFI_INIT_CONFIG_DEFAULT();
	//setup wifi AP mode
	esp_wifi_init(&wifiInitializationConfig);
	esp_wifi_set_storage(WIFI_STORAGE_RAM);
	esp_wifi_set_mode(WIFI_MODE_APSTA);
	wifi_config_t ap_config = {};
	ap_config.ap = {};
	std::string name = deviceName + "_CONFIG";
	memcpy(ap_config.ap.ssid, name.c_str(), name.length());
	memcpy(ap_config.ap.password,"password1234",12);
	ap_config.ap.channel = 0;
	ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
	ap_config.ap.ssid_hidden = 0;
	ap_config.ap.max_connection = 1;
	ap_config.ap.beacon_interval = 100;
	esp_wifi_set_config(WIFI_IF_AP, &ap_config);
	ap_config.sta = {};
	ESP_ERROR_CHECK(esp_wifi_start());
	for (std::list<std::shared_ptr<WifiAccessPoint>>::const_iterator iterator = list->begin(), end = list->end(); iterator != end; ++iterator) {
		std::shared_ptr<WifiAccessPoint> p = *iterator;
		memcpy(ap_config.sta.ssid, p->getSSID(), p->getSSIDLength());
		memcpy(ap_config.sta.password, p->getPassword(), p->getPasswordLength());
		ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &ap_config));
		std::cout << "Trying to connect to " << p->getSSIDAsString() << std::endl;
		ESP_LOGI(TAG, "Waiting for wifi");
		ESP_ERROR_CHECK(esp_wifi_connect());
		uxBits = xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, xTicksToWait);
		if( ( uxBits & CONNECTED_BIT ) != 0 ) {
			std::cout << "Connected!" << std::endl;
			//check if xEventGroupWaitBits returned for wifi successfully connected or not
			wifiConnected = true;
			break;
		}
		else{
			std::cout << "Failed to connect, trying next network" << std::endl;
			ESP_ERROR_CHECK(esp_wifi_disconnect());
		}
	}
}

static void wifi_reconnect(){
	wifi_config_t ap_config = {};
	EventBits_t uxBits;
	const TickType_t xTicksToWait = 10000 / portTICK_PERIOD_MS;
	for (std::list<std::shared_ptr<WifiAccessPoint>>::const_iterator iterator = list->begin(), end = list->end(); iterator != end; ++iterator) {
		std::shared_ptr<WifiAccessPoint> p = *iterator;
		memcpy(ap_config.sta.ssid, p->getSSID(), p->getSSIDLength());
		memcpy(ap_config.sta.password, p->getPassword(), p->getPasswordLength());
		ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &ap_config));
		std::cout << "Trying to connect to " << p->getSSIDAsString() << std::endl;
		ESP_LOGI(TAG, "Waiting for wifi");
		ESP_ERROR_CHECK(esp_wifi_connect());
		uxBits = xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT, false, true, xTicksToWait);
		if( ( uxBits & CONNECTED_BIT ) != 0 ) {
			std::cout << "Connected!" << std::endl;
			//check if xEventGroupWaitBits returned for wifi successfully connected or not
			wifiConnected = true;
			break;
		}
		else{
			std::cout << "Failed to connect, trying next network" << std::endl;
			ESP_ERROR_CHECK(esp_wifi_disconnect());
		}
	}
}

static void mqtt_app_start(void)
{
    esp_mqtt_client_config_t  mqtt_cfg = {};
	mqtt_cfg.event_handle = mqtt_event_handler;
	mqtt_cfg.host = brokerHost.c_str();
	mqtt_cfg.port = brokerPort;
	mqtt_cfg.client_id = deviceName.c_str();
	mqtt_cfg.lwt_topic = lwt_topic.c_str();
	mqtt_cfg.lwt_msg = lwt_message.c_str();
	mqtt_cfg.lwt_msg_len = lwt_message.length();
	mqtt_cfg.username = broker_username.c_str();
	mqtt_cfg.password = broker_password.c_str();
	mqtt_cfg.lwt_qos = 0;
	mqtt_cfg.lwt_retain = 0;
	mqtt_cfg.keepalive = 60;
	std::cout << mqtt_cfg.host << std::endl;
	client1 = esp_mqtt_client_init(&mqtt_cfg);
    esp_mqtt_client_start(client1);
}

/*
 * Task that takes ProbeRequestDataObject from shared queue and sends over
 * websocket to the specified server (serverUrl)
 */

void mqtt_task(){
	uint8_t dataToSend[68];
	int length = 0;
	/*
	 * dataToSend content:
	 *  6 bytes -> sniffer mac
	 *  6 bytes -> device mac
	 * 	2 bytes -> sequence number
	 *  1 byte  -> rssi
	 *  1 byte -> ssid len
	 * 	4 byte -> fcs
	 *  32 bytes -> eventual ssid
	 *  16 bytes -> fingerprint
	 *  total = 68 bytes
	 */
	std::shared_ptr<ProbeRequestData> prd(NULL);
	while (1) {
		if(!sq->checkEmpty()){
			prd = sq->popFront();
			length = prd->getDataBuffer(dataToSend, mac);

			esp_mqtt_client_publish(client1, topic_to_publish.c_str(), (char*)dataToSend, length, 0, 0);
			std::cout << "publicato" << std::endl;
		}
		else{
			//task sleeps for 100 ms if the queue is empty
			vTaskDelay(100 / portTICK_PERIOD_MS);
		}
	}
}

void httpFetchAuthTokenTask(){
	esp_http_client_config_t config = {};
	std::string out_string;
	std::stringstream ss;
	ss << configurationProxyPort;
	out_string = ss.str();
	std::string url = "http://" + configurationProxy +":"+ out_string + "/auth/oauth/token";
	config.url = url.c_str();
	//config.host = configurationProxy.c_str();
	//config.port = configurationProxyPort;
	//config.path = "auth/oauth/token";
	config.method = HTTP_METHOD_POST;
	config.event_handler = HttpRequestsHandler;
	config.max_redirection_count = 100;
	config.disable_auto_redirect = false;
	config.buffer_size = 2048;
	std:: cout << config.url << std::endl;
	esp_http_client_handle_t client = esp_http_client_init(&config);
	//Request header setup
	ESP_ERROR_CHECK(esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded"));
	ESP_ERROR_CHECK(esp_http_client_set_header(client, "Accept", "application/json"));
	ESP_ERROR_CHECK(esp_http_client_set_header(client, "Authorization", "Basic Y2xpZW50OnNlY3JldA=="));
	//POST data setup
	devicePassword = md5(deviceName+secret).substr(0,12);
	std::cout << "Hash :"<< devicePassword << std::endl;
	std::string POST_data = "username=" + deviceName + "&password=" + devicePassword + "&grant_type=password";
	ESP_ERROR_CHECK(esp_http_client_set_post_field(client, POST_data.c_str(), POST_data.length()));
	//Performing request
	esp_err_t err = esp_http_client_perform(client);
	if (err == ESP_OK) {
		ESP_LOGI(TAG, "Status = %d, content_length = %d",
				esp_http_client_get_status_code(client),
				esp_http_client_get_content_length(client));
	}
	esp_http_client_cleanup(client);
}

void httpFetchConfigurationTask(){
	esp_http_client_config_t config = {};
	std::string out_string;
	std::stringstream ss;
	ss << configurationProxyPort;
	out_string = ss.str();
	std::string url = "http://" + configurationProxy +":"+ out_string + "/sniffersapi/sniffers/" + deviceName + "/configuration";
	config.url = url.c_str();
	config.host = configurationProxy.c_str();
	config.port = configurationProxyPort;
	config.method = HTTP_METHOD_GET;
	config.event_handler = HttpRequestsHandler;
	config.max_redirection_count = 100;
	config.buffer_size = 1024;
	std::cout << "Fetching device configuration @ " << config.url << std::endl;
	esp_http_client_handle_t client = esp_http_client_init(&config);
	//Request header setup
	ESP_ERROR_CHECK(esp_http_client_set_header(client, "Content-Type", "application/x-www-form-urlencoded"));
	ESP_ERROR_CHECK(esp_http_client_set_header(client, "Accept", "application/json"));
	std::string auth = "Bearer " + oauthToken;
	std::cout << auth << std::endl;
	ESP_ERROR_CHECK(esp_http_client_set_header(client, "Authorization", auth.c_str()));
	//Performing request
	esp_err_t err = esp_http_client_perform(client);
	if (err == ESP_OK) {
		ESP_LOGI(TAG, "Status = %d, content_length = %d",
				esp_http_client_get_status_code(client),
				esp_http_client_get_content_length(client));
	}
	esp_http_client_cleanup(client);
}

esp_err_t hello_get_handler(httpd_req_t *req)
{
    char*  buf;
    size_t buf_len;

    /* Get header value string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
    if (buf_len > 1) {
        buf = (char*)malloc(buf_len);
        /* Copy null terminated value string into buffer */
        if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Host: %s", buf);
        }
        free(buf);
    }

    /*
    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
    if (buf_len > 1) {
        buf = (char*)malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Test-Header-2: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
    if (buf_len > 1) {
        buf = (char*)malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Test-Header-1: %s", buf);
        }
        free(buf);
    }
	*/


    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = (char*)malloc(buf_len);
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query => %s", buf);
            char param[32];
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "query1", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => query1=%s", param);
            }
            if (httpd_query_key_value(buf, "query3", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => query3=%s", param);
            }
            if (httpd_query_key_value(buf, "query2", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => query2=%s", param);
            }
        }
        free(buf);
    }

    /* Set some custom headers
    httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
    httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");
    */

    /* Send response with custom headers and body set as the
     * string passed in user context*/
    //const char* resp_str = (const char*) req->user_ctx;
    std::string responseHtml = *getHomePage(list, configurationProxy, mac, configurationProxyPort, message);
    const char* resp_str = responseHtml.c_str();
    httpd_resp_send(req, resp_str, strlen(resp_str));

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
        ESP_LOGI(TAG, "Request headers lost");
    }
    return ESP_OK;
}

httpd_uri_t hello = {
    .uri       = "/",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    .user_ctx  = NULL
};

esp_err_t echo_post_handler(httpd_req_t *req)
{
    char buf[100];
    int ret, remaining = req->content_len;
    std::string s;

    while (remaining > 0) {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf,
                        MIN(remaining, sizeof(buf)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }
        s.append(buf, ret);
        remaining -= ret;

        /* Log data received */
        ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        ESP_LOGI(TAG, "%.*s", ret, buf);
        ESP_LOGI(TAG, "====================================");
    }

    int res = POST_request_parser(s);
    switch(res){
		case 0:{
			//tutto ok
			message = "Reset the device to use the new configuration!";
			std::string responseHtml = *getHomePage(list, configurationProxy, mac, configurationProxyPort, message);
			const char* resp_str = responseHtml.c_str();
			httpd_resp_send(req, resp_str, strlen(resp_str));
			break;
		}
		case 1:{
			message = "Invalid SSID or password!";
			std::string responseHtml = *getHomePage(list, configurationProxy, mac, configurationProxyPort, message);
			break;
		}
		case 2:{
			message = "Invalid address!";
			std::string responseHtml = *getHomePage(list, configurationProxy, mac, configurationProxyPort,  message);
			break;
		}
    }
    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

httpd_uri_t echo = {
    .uri       = "/",
    .method    = HTTP_POST,
    .handler   = echo_post_handler,
    .user_ctx  = NULL
};

httpd_handle_t startHttpServer(void){
	// Start the httpd server
	ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
	if (httpd_start(&server, &config) == ESP_OK) {
		// Set URI handlers
		ESP_LOGI(TAG, "Registering URI handlers");
		httpd_register_uri_handler(server, &hello);
		httpd_register_uri_handler(server, &echo);
		return server;
	}
	else{
		ESP_LOGI(TAG, "Error starting server!");
		return NULL;
	}
}

void app_main(){
	ESP_LOGI(TAG, "[APP] Startup..");
	ESP_LOGI(TAG, "[APP] Free memory: %d bytes", esp_get_free_heap_size());
	ESP_LOGI(TAG, "[APP] IDF version: %s", esp_get_idf_version());
	esp_log_level_set("*", ESP_LOG_INFO);
	esp_log_level_set("MQTT_CLIENT", ESP_LOG_VERBOSE);
	esp_log_level_set("TRANSPORT_TCP", ESP_LOG_VERBOSE);
	esp_log_level_set("TRANSPORT_SSL", ESP_LOG_VERBOSE);
	esp_log_level_set("TRANSPORT", ESP_LOG_VERBOSE);
	esp_log_level_set("OUTBOX", ESP_LOG_VERBOSE);
	nvs_flash_init();
	/*
	 * Spiffs setup and mounting
	 */
	esp_vfs_spiffs_conf_t conf = {
	      .base_path = "/spiffs",
	      .partition_label = NULL,
	      .max_files = 5,
	      .format_if_mount_failed = true
	};
	esp_err_t ret = esp_vfs_spiffs_register(&conf);
	if (ret != ESP_OK) {
		if (ret == ESP_FAIL) {
			ESP_LOGE(TAG, "Failed to mount or format filesystem");
		} else if (ret == ESP_ERR_NOT_FOUND) {
			ESP_LOGE(TAG, "Failed to find SPIFFS partition");
		} else {
			ESP_LOGE(TAG, "Failed to initialize SPIFFS (%s)", esp_err_to_name(ret));
		}
		return;
	}
	size_t total = 0, used = 0;
	//getting station mac address to show in configuration page
	ret = esp_spiffs_info(NULL, &total, &used);
	if (ret != ESP_OK) {
		ESP_LOGE(TAG, "Failed to get SPIFFS partition information (%s)", esp_err_to_name(ret));
	} else {
		ESP_LOGI(TAG, "Partition size: total: %d, used: %d", total, used);
	}
	/*
	 * Reading files that stores saved SSID Password pairs and server info
	 */
	std::ifstream infile;
	std::string SSID, Password;
	if (FILE *file = fopen("/spiffs/wifi.txt", "r")) {
		fclose(file);
		infile.open("/spiffs/wifi.txt");
		while (infile >> SSID >> Password){
			std::shared_ptr<WifiAccessPoint> p = std::make_shared<WifiAccessPoint>();
			p->setPassword(Password, Password.length());
			p->setSSID(SSID, SSID.length());
			list->push_back(p);
		}
		infile.close();
	} else {
		//the file desn't exist
		std::fstream file1("/spiffs/wifi.txt");
		file1.close();
	}
	if (FILE *file = fopen("/spiffs/ws.txt", "r")) {
		fclose(file);
		infile.open("/spiffs/ws.txt");
		std::string port_as_string;
		infile >> configurationProxy >> port_as_string;
		configurationProxyPort = std::atoi(port_as_string.c_str());
		infile.close();
		std::cout << "WS Server: " << configurationProxy << std::endl;
	} else {
		//the file desn't exist
		std::fstream file2("/spiffs/ws.txt");
		file2.close();
	}
	/**
	 * The following MAC addresses are derived from the BASE MAC in the EFUSE BLK0.
	  #ESP_MAC_WIFI_STA
      #ESP_MAC_WIFI_SOFTAP
      #ESP_MAC_BT
      #ESP_MAC_ETH

	  For 2 universal MAC addresses, the BT and Wifi are both enabled. Ethernet is disabled. Here:
	  #ESP_MAC_WIFI_STA=ESP_MAC_WIFI_SOFTAP=BASE MAC.
	  #ESP_MAC_BT=BASE MAC+1

	  For 4 Universal MAC addresses, the BT, Wifi and ethernet are all enabled. Here:
	  #ESP_MAC_WIFI_STA=BASE MAC.
	  #ESP_MAC_WIFI_SOFTAP=BASE MAC+1
	  #ESP_MAC_BT=BASE MAC+2
	  #ESP_MAC_ETH=BASE MAC+3
	 */
	ESP_ERROR_CHECK(esp_efuse_mac_get_default(mac));
	std::stringstream ss;
	for(int i = 0; i < 6; i++){
		int j = mac[i];
		ss << std::hex << j;
	}
	deviceName = ss.str();
	std::cout << deviceName << std::endl;
	/*
	 * Iterating over saved AP, stting wifiConnected to true if connection is successfull
	 * otherwise switch to access point mode and set up http server to change setup
	 */
	wifi_connection_lost.store(false);
	connection_lost = 0;
	wifi_init();
	server = startHttpServer();
	if(server == NULL){
		//An error occurred during http server initialization
		std::cout << "An error occurred during http server initialization" << std::endl;
		for (int i = 10; i >= 0; i--) {
					std::cout << "Restarting in " << i << std::endl;
			    	vTaskDelay(1000 / portTICK_PERIOD_MS);
				}
				esp_restart();
	}
	else{
		int counter = 0;
		while(wifiConnected == false){
			std::cout << "Impossible to connect to known networks, switching to Access Point Mode" << std::endl;
			message = "ERROR: Impossible to connect to known networks!";
			//esp_wifi_set_mode(WIFI_MODE_AP);
			vTaskDelay(10000 / portTICK_PERIOD_MS);
			std::cout << "Trying to reconnect... " << std::endl;
			wifi_reconnect();
			counter++;
			if(counter == 30)
				esp_restart();
		}
		{
			//std::thread t2(httpFetchAuthTokenTask);
			//t2.join();
			//JSON parsing of the data
			httpFetchAuthTokenTask();
			data_buffer[data_len] = '\0';
			cJSON* root = cJSON_Parse((char*)data_buffer);
			cJSON* token;
			if(root == NULL){
				const char *error_ptr = cJSON_GetErrorPtr();
				if (error_ptr != NULL)
				{
					fprintf(stderr, "Error before: %s\n", error_ptr);
					httpRequestSuccess = false;
				}
			}
			else{
				token = cJSON_GetObjectItemCaseSensitive(root, "access_token");
				if(cJSON_IsString(token) && (token->valuestring != NULL)){
					std::cout << "Token: " << token->valuestring << std::endl;
					oauthToken = token->valuestring;
					httpRequestSuccess = true;
				}
				else{
					httpRequestSuccess = false;
					std::cout << "Errore nel parsing del token" << std::endl;
				}
			}
			cJSON_Delete(root); //free json object memory
			if(httpRequestSuccess){ //token aquired, fetching configuration
				httpRequestSuccess = false; //reset for next request
				data_len = 0; //reset data_len to store the new data
				//std::thread t3(httpFetchConfigurationTask);
				//t3.join();
				httpFetchConfigurationTask();
				data_buffer[data_len] = '\0';
				cJSON *root = cJSON_Parse((char*)data_buffer);
				cJSON *dump_mode = NULL;
				cJSON *privacy_mode = NULL;
				cJSON *broker_address = NULL;
				cJSON *broker_port = NULL;
				cJSON *topic_to_publish_JSON = NULL;
				cJSON *lwt_message_JSON = NULL;
				cJSON *lwt_topic_JSON = NULL;
				cJSON *power_thrashold_JSON = NULL;
				if(root == NULL){
					const char *error_ptr = cJSON_GetErrorPtr();
					if (error_ptr != NULL)
					{
						fprintf(stderr, "Error before: %s\n", error_ptr);
						httpRequestSuccess = false;
					}
				}
				else{
					httpRequestSuccess = true;
					//
					dump_mode = cJSON_GetObjectItemCaseSensitive(root, "dumpMode");
					if(cJSON_IsBool(dump_mode)){
						dump_mode_bool = cJSON_IsTrue(dump_mode);
						ESP_LOGI(TAG, "Dump mode: %s", dump_mode_bool ? "true" : "false");
					} else{
						dump_mode_bool = true;
						ESP_LOGE(TAG,"Error in JSON parsing: default value for dump mode = true");
					}
					//
					privacy_mode = cJSON_GetObjectItemCaseSensitive(root, "privacyMode");
					if(cJSON_IsBool(privacy_mode)){
						privacy_mode_bool = cJSON_IsTrue(privacy_mode);
						ESP_LOGI(TAG, "Privacy mode: %s", privacy_mode_bool ? "true" : "false");
					} else{
						privacy_mode_bool = true;
						ESP_LOGE(TAG,"Error in JSON parsing: default value for privacy mode = true");
					}
					//
					broker_address = cJSON_GetObjectItemCaseSensitive(root, "brokerAddress");
					if(cJSON_IsString(broker_address) && broker_address->valuestring != NULL){
						ESP_LOGI(TAG,"Broker address: %s", broker_address->valuestring);
						brokerHost = broker_address->valuestring;
					} else{
						//in this case we cant continue 
						ESP_LOGE(TAG,"Error in JSON parsing: unable to get broker address!");
						httpRequestSuccess = false;
					}
					//
					broker_port = cJSON_GetObjectItemCaseSensitive(root, "brokerPort");
					if(cJSON_IsNumber(broker_port) && broker_port != NULL){
						brokerPort = broker_port->valueint;
						ESP_LOGI(TAG, "Broker port: %d", brokerPort);
					} else{
						ESP_LOGE(TAG, "Error in JSON parsing: unable to get broker port! default value = 1883");
						brokerPort = 1883;
					}
					//
					topic_to_publish_JSON = cJSON_GetObjectItemCaseSensitive(root, "topic");
					if(cJSON_IsString(topic_to_publish_JSON) && topic_to_publish_JSON->valuestring != NULL){
						topic_to_publish = topic_to_publish_JSON->valuestring;
						ESP_LOGI(TAG, "Topic to publish: %s", topic_to_publish.c_str());
					} else{
						ESP_LOGE(TAG, "Error in JSON parsing: unable to get topic to publish!");
						httpRequestSuccess = false;
					}
					//
					lwt_message_JSON = cJSON_GetObjectItemCaseSensitive(root, "lwtMessage");
					if(cJSON_IsString(lwt_message_JSON) && lwt_message_JSON->valuestring != NULL){
						lwt_message = lwt_message_JSON->valuestring;
						ESP_LOGI(TAG, "lwt message: %s", lwt_message.c_str());
					} else{
						ESP_LOGE(TAG, "Error in JSON parsing: unable to get lwt message! default value = disconnected");
						lwt_message = "disconnected";
					}
					//
					lwt_topic_JSON = cJSON_GetObjectItemCaseSensitive(root, "lwtTopic");
					if(cJSON_IsString(lwt_topic_JSON) && lwt_topic_JSON->valuestring != NULL){
						lwt_topic = lwt_topic_JSON->valuestring;
						ESP_LOGI(TAG, "lwt topic: %s", lwt_topic.c_str());
					} else{
						ESP_LOGE(TAG, "Error in JSON parsing: unable to get lwt topic! default value = lwt_topic");
						lwt_topic = "lwt_topic";
					}
					power_thrashold_JSON = cJSON_GetObjectItemCaseSensitive(root, "powerThrashold");
					if(cJSON_IsNumber(power_thrashold_JSON)){
						/**
						 * Remember, power thrashold is negative and between 0 and -100 where closer to 0 stronger the signal
						 */
						power_thrashold = power_thrashold_JSON->valueint < 0 ? power_thrashold_JSON->valueint : -1*(power_thrashold_JSON->valueint);
						if(power_thrashold > 0 && power_thrashold < -100){
							ESP_LOGE(TAG, "Invalid power thrashold! default value = -100");
							power_thrashold = -100; //prendo tutto 
						} else
							ESP_LOGI(TAG, "power thrashold: %d", power_thrashold);
					} else{
						ESP_LOGE(TAG, "Error in JSON parsing: unable to get power threashold! default value = -100");
						power_thrashold = -100; //prendo tutto 
					}
					//other settings
					broker_password = devicePassword;
					broker_username = deviceName;
					other_topic = "commands/"+deviceName;
				}
				cJSON_Delete(root); //free json object memory
				if(httpRequestSuccess){
					mqtt_app_start();
					std::thread t1(mqtt_task);
					t1.join();
				}
				else{
					ESP_LOGI(TAG, "Unable to fetch configuration, wifi set to AP mode");
					message = "ERROR: Unable to fetch configuration!";
					connection_lost = 0;
					esp_wifi_set_mode(WIFI_MODE_AP);
					for (int i = 180; i >= 0; i--) {
					std::cout << "Restarting in " << i << std::endl;
			    	vTaskDelay(1000 / portTICK_PERIOD_MS);
					}
					esp_restart();
				}
			}
			else{
				/*
				 * An unsuccessful request could mean that the server is unreacheable or
				 * an error occurred, it's better to return in manual configuration mode
				 * to allow to change the configuration server address
				 */
				ESP_LOGI(TAG, "Unable to fetch auth token, wifi set to AP mode");
				message = "ERROR: Unable to fetch auth token!";
				connection_lost=0; //messo a zero visto che passare ad ap fa partire l'evento station disconnected
				esp_wifi_set_mode(WIFI_MODE_AP);
				for (int i = 180; i >= 0; i--) {
					std::cout << "Restarting in " << i << std::endl;
			    	vTaskDelay(1000 / portTICK_PERIOD_MS);
					}
					esp_restart();
			}
		}
	}
}
