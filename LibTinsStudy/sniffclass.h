#ifndef SNIFFCLASS_H
#define SNIFFCLASS_H
#include <iostream>
#include <map>
#include <tins/tins.h>


using namespace Tins;

class OpnSniffer{
    char* sniffDev;
    bool (*funcPtr)(PDU&); //loop Function Pointer variable
public:
    OpnSniffer(char* mDev,bool (*fp)(PDU &));
    void run();
};


class Wpa2Sniffer{
    char* sniffDev;
    bool (*funcPtr)(PDU&); //Decrypt Function Pointer variable
    std::string passwd;
    std::string ssid;
    Crypto::DecrypterProxy<bool(*)(PDU&), Crypto::WPA2Decrypter> *decryptProxy; //Crypto::DecrypterProxy<bool(*)(PDU&), Crypto::WPA2Decrypter> is
                                                                                //able to replace auto when init during declaration
                                                                                //This Variable init when run() called
public:
    Wpa2Sniffer(char* mDev,bool (*fp)(PDU&));
    void addDecryptInfo(std::string passwd,std::string ssid);   //after called must be call Deauth sender
    void run();
    std::string getPasswd() const;
    void setPasswd(const std::string &value);
    std::string getSsid() const;
    void setSsid(const std::string &value);
};

class APSniffer{
    char* sniffDev;
    typedef Dot11::address_type bssid;
    typedef std::map<bssid,std::string> apList;
    apList aplistMap;
    void upLinePrompt(int count);
    void showAPList();
    bool handle(PDU& pdu);
public:
    APSniffer(char* mDev);
    bssid findBSSID(std::string ssid);
    void run();

};

class DeauthSender{
    char* sniffDev;
    PacketSender sender;
    typedef Dot11::address_type MACAddr;

public :
    DeauthSender(char* mDev);
    bool sendDeauth(MACAddr bssid, MACAddr station, int sendCount);
};
#endif // SNIFFCLASS_H
