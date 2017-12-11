#include "sqlmagition.h"

SqlMagition::SqlMagition(string domain, string user, string passwd)
{
    try {
        driver=get_driver_instance();
        conn=driver->connect(domain,user,passwd);


    } catch (sql::SQLException &e) {
        cout << "# ERR: SQLException in " << __FILE__;
        cout << "(" << __FUNCTION__ << ") on line "<< __LINE__ << endl;
        cout << "# ERR: " << e.what();
        cout << " (MySQL error code: " << e.getErrorCode();
        cout << ", SQLState: " << e.getSQLState() << " )" << endl;
    }


}

SqlMagition::SqlMagition(string domain, string user, string passwd, string dbName)
{
    try {
        driver=get_driver_instance();
        conn=driver->connect(domain,user,passwd);
        useDatabase(dbName);

    } catch (sql::SQLException &e) {
        cout << "# ERR: SQLException in " << __FILE__;
        cout << "(" << __FUNCTION__ << ") on line "<< __LINE__ << endl;
        cout << "# ERR: " << e.what();
        cout << " (MySQL error code: " << e.getErrorCode();
        cout << ", SQLState: " << e.getSQLState() << " )" << endl;
    }


}

SqlMagition::~SqlMagition()
{
    delete res;
    delete stmt;
    delete conn;
    //delete driver;
}

void SqlMagition::useDatabase(string database)
{
    try {
        conn->setSchema(database);
        stmt=conn->createStatement();

    } catch (sql::SQLException &e) {
        cout << "# ERR: SQLException in " << __FILE__;
        cout << "(" << __FUNCTION__ << ") on line "<< __LINE__ << endl;
        cout << "# ERR: " << e.what();
        cout << " (MySQL error code: " << e.getErrorCode();
        cout << ", SQLState: " << e.getSQLState() << " )" << endl;
    }

    std::cout<<"Call useDAtabase "<<std::endl;
}

void SqlMagition::insertSql(string tbName, string values)
{
//    cout<<"SQL COMMAND : "<<insertCmd+tbName+" values"+'('+values+");"<<endl;
    try {
        stmt->execute(insertCmd+tbName+" values"+'('+values+");");

    } catch (sql::SQLException &e) {
        cout << "# ERR: SQLException in " << __FILE__;
        cout << "(" << __FUNCTION__ << ") on line "<< __LINE__ << endl;
        cout << "# ERR: " << e.what();
        cout << " (MySQL error code: " << e.getErrorCode();
        cout << ", SQLState: " << e.getSQLState() << " )" << endl;

        cout <<"ERR CMD : "<<insertCmd+tbName+" values"+'('+values+");"<<endl;
    }

}

