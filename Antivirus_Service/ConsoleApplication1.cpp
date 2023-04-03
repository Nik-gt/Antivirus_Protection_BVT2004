#pragma once
//Программа проверки заданного файл на наличие в нем вируса
//Программа загружает файл антивирусной базы с описанием вирусов
//Для поиска вируса используются первые 8 байтов вируса и его дайджест типа SHA256
//ConsoleApplication1.cpp : 
#include "Acommon.h"
#include "VirusDBLoader.cpp"
#include "Monitoring.cpp"

using namespace std;

//Ручное сканирование
//Получить список файлов для заданной папки и проверить на вирус
void doManualScan(std::string filepath, std::multimap<uint64_t, Data_Base_Virus> virusmap, PipeServer PipeServer1)
{
    std::vector<std::string> files;//Содержит полные имена файлов из всех подкаталогов дл¤ их проверки
    /// Класс FilesSearch.cpp
    files = getFilesForFolder(filepath);//Получить список файлов для заданной папки
    //cout << "Files:" << endl;
    for (int i = 0; i < files.size(); i++) {
        cout << "Find file for processing: " << files[i] << endl;
        //Для подходящего файла вызываем проверку на наличие вируса в нем
        if (files[i].substr(files[i].find_last_of('.'), 4) == ".exe") checkVirusInFile(files[i], virusmap, PipeServer1); // по mz и pe заголовок ЗАМЕНИТЬ ПРОВЕРКУ ТИПА!
    }
    //Отправляем результат проверки на вирус по именованному каналу
    std::string Result = std::string("ResultScan|" + std::to_string(files.size()) + "|");// + Malware;
    PipeServer1.PipeWrite(Result);
}



//Прием запросов на сканирование, само сканирование и отправка результата сканирования  
void readPipeCommandAndProceesIt(std::multimap<uint64_t, Data_Base_Virus> virusmap, PipeServer PipeServer1) {
    while (true)
    {
        //read/write
        std::string message = PipeServer1.PipeRead();
        std::string messagescan = strtok((char*)message.c_str(), "|");
        if (messagescan == "ManualScan")
        {//Если пришел запрос на сканирование то стартуем сканирование
            messagescan = strtok(NULL, "|");
            //Получить список файлов для заданной папки и проверить на вирус
            //filepath = messagescan;
            //todo std::thread thr(getFilesForFolderAndCheckVirus, ref(messagescan));
            //std::thread thr(doManualScan, ref(messagescan), ref(VirusDBLoader1), ref(PipeServer1));
            //thr.join();
            std::async(std::launch::async, doManualScan, messagescan, virusmap, PipeServer1);

            //doManualScan(messagescan, VirusDBLoader1, PipeServer1);           
            //delete &ref(messagescan);
            //messagescan.erase();
            //delete std::string messagescan;
            //messagescan = "";
            //getFilesForFolderAndCheckVirus(messagescan);
        }
        if (messagescan == "MonitoringScan")
        {//Если пришел запрос на сканирование то стартуем сканирование и мониторинг
            std::string folderForMonitoring = strtok(NULL, "|"); //ВВОД ДИРЕКТОРИИ
//            Monitoring monitoring;
//            monitoring.WatchDirectory(folderForMonitoring);
        }
        //cout << "No folder" << endl;
        //PipeServer1.PipeWrite("ResultScan|0");
        //Sleep(50);    
    }
}

//////////////////
//Main function//
/////////////////
int main(){ 
    setlocale(LC_ALL, "rus");
    std::string VirusDbFileName = "D:\\Antivirus_Protection_BVT2004\\newdb.bin";

    VirusDBLoader virusDBLoader1;//загрузчик вирусной базы
    PipeServer pipeServer1;//сервер именованного канала
    
    //1.Загрузить антивирусную базу из файла бд в объект карты
    if (virusDBLoader1.loadAntiVirusDatabase(VirusDbFileName) == false) return 1;
    std::multimap<uint64_t, Data_Base_Virus> virusmap = virusDBLoader1.getVirusmap();
    
    //2.Подключить клиента  
    pipeServer1.WaitClientConnection();
    //3.Начать прием запросов на сканирование, само сканирование и отправку результата сканирования 
    readPipeCommandAndProceesIt(virusmap, pipeServer1);
    
    //test for Monitoring
    const std::string folderForMonitoring = "Q:\\!dima\\test_monitoring_files";
    //Monitoring monitoring1(virusmap, pipeServer1);
    //monitoring1.WatchDirectory(folderForMonitoring);
    
    //std::string fileName = "D:\\Antivirus_Protection_BVT2004\\EICAR\\eicar1.com";
    //checkVirusInFile(fileName); //
    std::cout << "finished ok" << std::endl;
    return 0;
}////////////


