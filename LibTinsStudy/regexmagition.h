#ifndef REGEXMAGITION_H
#define REGEXMAGITION_H

#include <iostream>
#include <regex>

class RegexMagition
{
    std::regex host;
    std::regex cookie;
    std::cmatch m;
    char payload[1700];

public:
    std::string findHost(char *payload, int payloadSize,bool &flag);
    std::string findCookie(char* payload, int payloadSize, bool &flag);
    RegexMagition();


};

#endif // REGEXMAGITION_H
