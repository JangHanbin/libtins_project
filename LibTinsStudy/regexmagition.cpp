#include "regexmagition.h"

std::string RegexMagition::findHost(char *payload, int payloadSize, bool &flag)
{
    //set flag to false
    flag=false;

    //to avoid null exception(if end of payload has not null regex find overflow)
    if((uint32_t)payloadSize>sizeof(this->payload))
    {
        //memory exception
        std::cout<<"Payload Size Lager than Buf!"<<std::endl;
        std::cout<<"Payload Size : "<<payloadSize<<std::endl;
        std::cout<<"Buf Size : "<<sizeof(this->payload)<<std::endl;

        return "Host Not Found";
    }
    //to avoid null exception(if end of payload has not null regex find overflow)
    memset(this->payload,0,payloadSize+1);
    memcpy(this->payload,payload,payloadSize);

    if(std::regex_search(this->payload,m,host))
    {
        flag=true;
        return m[2];
    }

    return "Host Not Found";
}

std::string RegexMagition::findCookie(char *payload, int payloadSize,bool &flag)
{
    //set flag to false
    flag=false;

    //to avoid null exception(if end of payload has not null regex find overflow)
    if((uint32_t)payloadSize>sizeof(this->payload))
    {
        //memory exception
        std::cout<<"Payload Size Lager than Buf!"<<std::endl;
        std::cout<<"Payload Size : "<<payloadSize<<std::endl;
        std::cout<<"Buf Size : "<<sizeof(this->payload)<<std::endl;

        return "";
    }
    memset(this->payload,0,payloadSize+1);
    memcpy(this->payload,payload,payloadSize);


    if(std::regex_search(this->payload,m,cookie))
    {
        flag=true;
        return m[2];
    }

    return "";
}

RegexMagition::RegexMagition()
{

    host.assign("(Host: )(.*)");
    cookie.assign("(Cookie:)(.*)",std::regex_constants::icase); //init to insensitivity

}
