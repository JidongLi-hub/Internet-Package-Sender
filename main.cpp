#include "mainwindow.h"
#include <QApplication>
#include "pcapParser.h"
#include <time.h>
#include <string.h>

class MsgParser : public PcapParser
{
private:
    int mCount;
public:
    MsgParser()
    {
        mCount = 0;
    }

public:
    int getCount() { return mCount; }
    int onUdpMsg(const char* buf, int len)
    {
        // do something
        return len;
    }
};

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    //测试解析pcap文件的代码
    char* arg = new char[60];
    strcpy(arg,"../Internet-Package-Sender/pcapeg/icmp_test.pcap");
    MsgParser parser;
    parser.parse(arg);
    printf("total quote count:%d\n", parser.getCount());

    //测试winpacap的代码
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        qDebug() << errbuf;
    }
    for(d = alldevs; d; d = d->next)
    {
        qDebug() << ++i << d->name;
        if(d->description)
            qDebug() << d->description;
        else
            qDebug("(No description available)");
    }
    if(i == 0)
    {
        qDebug("No interfaces found! Make sure WinPcap is installed.");
    }
    pcap_freealldevs(alldevs);




    return a.exec();
}
