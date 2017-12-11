#include "sniffclass.h"
#include <unistd.h>

OpnSniffer::OpnSniffer(char *mDev, bool (*fp)(PDU&))
{
    sniffDev=mDev;
    funcPtr=fp;
}

void OpnSniffer::run()
{
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    Sniffer sniffer(sniffDev,config);

    sniffer.sniff_loop(funcPtr);
}

std::string Wpa2Sniffer::getPasswd() const
{
    return passwd;
}

void Wpa2Sniffer::setPasswd(const std::string &value)
{
    passwd = value;
}

std::string Wpa2Sniffer::getSsid() const
{
    return ssid;
}

void Wpa2Sniffer::setSsid(const std::string &value)
{
    ssid = value;
}

Wpa2Sniffer::Wpa2Sniffer(char *mDev,bool (*fp)(PDU&))
{
    sniffDev=mDev;
    funcPtr=fp;
}

void Wpa2Sniffer::addDecryptInfo(std::string passwd, std::string ssid)
{
    this->decryptProxy->decrypter().add_ap_data(passwd,ssid);
}

void Wpa2Sniffer::run()
{
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    Sniffer sniffer(sniffDev,config);
    std::cout<<"Wpa2Sniffer Run()"<<std::endl;
    auto decryptProxy=Crypto::make_wpa2_decrypter_proxy(funcPtr);
    this->decryptProxy=&decryptProxy; //init decryptProxy Pointer to addDecryptInfo
    addDecryptInfo(passwd,ssid);
    sniffer.sniff_loop(decryptProxy);

    //if loop end
    this->decryptProxy=nullptr;
    std::cout<<"Wpa2Sniffer End!"<<std::endl;
}

void APSniffer::upLinePrompt(int count)
{

    for (int i = 0; i < count; ++i) {
        //printf("%c[2K",27);
        std::cout<<"\33[2K"; //line clear
        std::cout<<"\x1b[A"; //up line (ESC [ A) must be support VT100 escape seq
    }

}

void APSniffer::showAPList()
{
    std::cout<<"*************************Detected AP Lists**************************"<<std::endl;
    apList::iterator it;
    int count=0;
    for(it=aplistMap.begin();it!=aplistMap.end();it++)
    {
        count++;
        std::cout<<count<<" BSSID :  " <<it->first<<"   SSID :  "<<it->second<<std::endl;
    }

    upLinePrompt(count+1); //console Line clear & +1 == dectected AP List
}

APSniffer::bssid APSniffer::findBSSID(std::string ssid)
{
    apList::iterator it;
    int loopCount=3;
    int count=0;
    bssid retBSSID;
    while (loopCount--) //try to find BSSID 3 times
    {
        for(it=aplistMap.begin();it!=aplistMap.end();it++)
        {
//            std::cout<<"Compare "<<ssid<<" with "<<it->second<<std::endl;
            if(ssid.compare(it->second)==0) //if ssid as same as it->second
            {
                count++;
//                std::cout<<"true"<<std::endl;
                retBSSID=it->first;

            }
            //looping must be loop the end cuz it that possible to duplicate SSID
        }
//        std::cout<<"loop end count : "<<count<<std::endl;
        if(count>0) //if find BSSID
            break;  //out
        sleep(3);
    }
    if(count==1)
        return retBSSID;
    else
        return nullptr;
}

bool APSniffer::handle(PDU &pdu)
{
    // Get the Dot11 layer
    const Dot11Beacon& beacon = pdu.rfind_pdu<Dot11Beacon>();
    // All beacons must have from_ds == to_ds == 0
    if (!beacon.from_ds() && !beacon.to_ds()) {
        // Get the AP address
        bssid addr = beacon.addr2();
        // Look it up in our map
        apList::iterator it = aplistMap.find(addr);
        if (it == aplistMap.end()) //if not exist
        {
            // First time we encounter this BSSID.
            try {
                /* If no ssid option is set, then Dot11::ssid will throw
                 * a std::runtime_error.
                 */
                std::string ssid = beacon.ssid();
                aplistMap.insert(std::pair<bssid,std::string>(addr,ssid));

                //if new AP is dectected Show All Ap List
                showAPList();
            }
            catch (std::runtime_error&) {
                // No ssid, just ignore it.
            }
        }
    }
    return true;

}

APSniffer::APSniffer(char *mDev)
{
    sniffDev=mDev;
}

void APSniffer::run()
{
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    config.set_filter("type mgt subtype beacon");
    config.set_rfmon(true);
    Sniffer sniffer(sniffDev, config);
    sniffer.sniff_loop(make_sniffer_handler(this, &APSniffer::handle));
}

DeauthSender::DeauthSender(char *mDev)
{
    sniffDev=mDev;
}

bool DeauthSender::sendDeauth(DeauthSender::MACAddr bssid, DeauthSender::MACAddr station,int sendCount)
{
    //if bssid not inited
    if(bssid==nullptr) return false;

    Dot11Deauthentication deauth(station,bssid);
    deauth.addr3(bssid); //set BSSID to bssid(var) this field must be set
    RadioTap radio = RadioTap() / deauth;

    for (int i = 0; i < sendCount; ++i) {

        sender.send(radio,sniffDev);

    }
    return true;
}
