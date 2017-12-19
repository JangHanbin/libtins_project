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
    this->passwd=passwd;
    this->ssid=ssid;

    //waiting for init decryptProxy
    while(this->decryptProxy==nullptr);
    this->decryptProxy->decrypter().add_ap_data(passwd,ssid);
//    this->decryptProxy->decrypter().add_ap_data("angel1004","angel3");
    startFlag=true;


}

void Wpa2Sniffer::run()
{
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    Sniffer sniffer(sniffDev,config);

    auto decryptProxy=Crypto::make_wpa2_decrypter_proxy(funcPtr);
    this->decryptProxy=&decryptProxy; //init decryptProxy Pointer to addDecryptInfo
    //need to run after addDecryptInfo

    //Waiting for add_ap_data()
    while(!startFlag);

    sniffer.sniff_loop(decryptProxy);

    //if loop end
    this->decryptProxy=nullptr;
}

//This Line need to use static var
std::mutex APSniffer::mtx;

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

//    upLinePrompt(count+1); //console Line clear & +1 == dectected AP List
}

void APSniffer::decryptProxyAdder(Wpa2Sniffer& wpa2Sniffer)
{
    //a little bit not match origin purpose(APSniffer) So need to modify
    static DeauthSender deauthSender(sniffDev);

    while(true)
    {



        mtx.lock();
        showAPList();
        printf("\n\n\n");

        int num=0;
        std::cout<<"Choose number that add to Decrypt Info <Reload AP list : 0>  : ";
        std::cin>>num;
        if(num==0)
        {
            std::cout<<"Waiting for 3 Sec to capture.."<<std::endl;
            upLinePrompt(apMaxNum+6);
            mtx.unlock();

            //for Scan AP List
            sleep(3);

            continue;
        }

        if(num<0 || num>apMaxNum)
        {
            std::cout<<"You have a wrong choose Plz check the number"<<std::endl;
            mtx.unlock();
            continue;
        }
        apList::iterator it=aplistMap.begin();
        for (int i = 0; i < num-1; ++i) {
            it++;
        }
        std::string passwd;
        std::cout<<"Input \" "<<it->second<<" \" Password : ";
        std::cin>>passwd;

        wpa2Sniffer.addDecryptInfo(passwd,it->second);
        upLinePrompt(apMaxNum+6);

        //Send Deauth Packet for Capture EAPOL
        if(!deauthSender.sendDeauth(this->findBSSID(wpa2Sniffer.getSsid()),deauthSender.getBroadcast(), 2))
            std::cout<<"AP Not Found !, Can't send Deauth Packet"<<std::endl;
        mtx.unlock();
    }
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
                retBSSID=it->first;

            }
            //looping must be loop the end cuz it that possible to duplicate SSID
        }
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

                //Need To mutex for other process
                mtx.lock();
                aplistMap.insert(std::pair<bssid,std::string>(addr,ssid));
                apMaxNum++; //Add Maximum Map Count
//                showAPList();
                mtx.unlock();
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

Dot11::address_type DeauthSender::getBroadcast() const
{
    return broadcast;
}

void DeauthSender::setBroadcast(const Dot11::address_type &value)
{
    broadcast = value;
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
