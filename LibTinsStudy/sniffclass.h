#ifndef SNIFFCLASS_H
#define SNIFFCLASS_H
#include <iostream>
#include <map>
#include <tins/tins.h>
#include <mutex>


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
    std::string passwd="";
    std::string ssid="";
    bool startFlag=false;
    Crypto::DecrypterProxy<bool(*)(PDU&), Crypto::WPA2Decrypter> *decryptProxy=nullptr; //Crypto::DecrypterProxy<bool(*)(PDU&), Crypto::WPA2Decrypter> is
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
    int apMaxNum=0;
    static std::mutex mtx;

    typedef Dot11::address_type bssid;
    typedef std::map<bssid,std::string> apList;
    apList aplistMap;
    void upLinePrompt(int count);
    void showAPList();
    bool handle(PDU& pdu);
public:
    APSniffer(char* mDev);
    bssid findBSSID(std::string ssid);
    void decryptProxyAdder(Wpa2Sniffer &wpa2Sniffer);
    void run();

};

class DeauthSender{
    char* sniffDev;
    PacketSender sender;
    typedef Dot11::address_type MACAddr;
    Dot11::address_type broadcast="ff:ff:ff:ff:ff:ff";


public :
    DeauthSender(char* mDev);
    bool sendDeauth(MACAddr bssid, MACAddr station, int sendCount);
    Dot11::address_type getBroadcast() const;
    void setBroadcast(const Dot11::address_type &value);
};
#endif // SNIFFCLASS_H
