#ifndef SQMMAGITION_H
#define SQMMAGITION_H

#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
#include <iostream>

using namespace std;

class SqlMagician
{
    sql::Driver *driver;
    sql::Connection *conn;
    sql::Statement *stmt;
    sql::ResultSet *res;
    string insertCmd="INSERT INTO ";
public:
    SqlMagician(string domain,string user, string passwd);
    SqlMagician(string domain,string user, string passwd,string dbName);
    ~SqlMagician();
    void useDatabase(string database);
    void insertSql(string tbName,string values);

};

#endif // SQMMAGITION_H
