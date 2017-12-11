TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -ltins
LIBS += -lmysqlcppconn
LIBS += -pthread
SOURCES += main.cpp \
    sniffclass.cpp \
    sqlmagition.cpp \
    printdata.cpp \
    regexmagition.cpp

HEADERS += \
    sniffclass.h \
    sqlmagition.h \
    printdata.h \
    regexmagition.h
