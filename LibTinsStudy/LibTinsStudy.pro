TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -ltins
LIBS += -lmysqlcppconn
LIBS += -pthread
SOURCES += main.cpp \
    sniffclass.cpp \
    printdata.cpp \
    sqlmagician.cpp \
    regexmagician.cpp

HEADERS += \
    sniffclass.h \
    printdata.h \
    sqlmagician.h \
    regexmagician.h
