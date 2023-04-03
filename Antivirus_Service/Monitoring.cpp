#pragma once
#include "Acommon.h"

// Мониторинг состояния заданной папки
//#ifndef _MONITORING_CPP_#define _MONITORING_CPP_
//#include "ConsoleApplication1.cpp"//нельзя!!
class Monitoring {

private:
    std::multimap<uint64_t, Data_Base_Virus> virusmap;//вирусной базы
    PipeServer PipeServer1;//сервер именованного канала


public:
    Monitoring(std::multimap<uint64_t, Data_Base_Virus> virusmap, PipeServer PipeServer1) {
        this->virusmap = virusmap;
        this->PipeServer1 = PipeServer1;
    }
    
    //constructor for debug
    //Monitoring() {}

private:
    //Информация о файле нужная для наблюдения
    struct FileInfoWatch {
        std::string path;
        std::filesystem::file_time_type last_write_time;
        uintmax_t file_size;
        //Сравнить два состояния файла для сортировки вектора
        bool operator() (FileInfoWatch V1, FileInfoWatch V2)
        {
            int i = V1.path.compare(V2.path);
            if (i < 0)
            {
                return 1;
            }
            else {
                if (i > 0)
                {
                    return 0;
                }
                if (i == 0)
                {
                    if (V1.last_write_time < V2.last_write_time)
                    {
                        return 1;
                    }
                    else
                    {
                        if (V1.last_write_time > V2.last_write_time) { return 0; }
                        if (V1.last_write_time == V2.last_write_time)
                        {
                            if (V1.file_size < V2.file_size)
                            {
                                return 1;
                            }
                            else { return 0; }

                        }
                    }
                }
            }
        }
    } filespecs;

    std::vector <FileInfoWatch>firsttake;//захват состояния файлов


    //Получить состояния файлов для заданной папки
    std::vector<FileInfoWatch> GetListOfFilesAndSizes(std::string pathA)
    {
        FileInfoWatch thisfile;
        std::vector<FileInfoWatch> allfiles;
        std::vector<FileInfoWatch> xxall;
        for (const auto& p : std::filesystem::directory_iterator(pathA))
        {
            if (p.is_regular_file()) //не директория
            {
                thisfile.path = (p.path().string()); // добавляем файл в вектор
                thisfile.last_write_time = last_write_time(p);
                thisfile.file_size = file_size(p);
                allfiles.push_back(thisfile);

            }
            else // если директория
            {
                //debug std::cout << p.path().string() << std::endl;
                xxall = GetListOfFilesAndSizes(p.path().string());
                for (int i = 0; i < xxall.size(); i++) { allfiles.push_back(xxall[i]); }
                xxall.erase(xxall.begin(), xxall.end());
            }
        }
        return allfiles;
    }

    //Вызвать проверку на вирусы изменившиеся файлы
    void React(std::string path)
    {
        _tprintf(TEXT("Changed.\n"));
        Sleep(50);
        std::vector <FileInfoWatch>nexttake = GetListOfFilesAndSizes(path);
        std::vector<FileInfoWatch>::iterator it;
        std::vector<FileInfoWatch> v;// МАССИВ ФАЙЛОВ ДЛЯ СКАНА 
        //error //https://cplusplus.com/reference/algorithm/sort/
        //std::sort(nexttake.begin(), nexttake.end(), compare2filesStatuses);
        std::sort(nexttake.begin(), nexttake.end(), filespecs);
        std::sort(firsttake.begin(), firsttake.end(), filespecs);
        std::set_difference(nexttake.begin(), nexttake.end(), firsttake.begin(), firsttake.end(), back_inserter(v), filespecs);

        std::cout << "The difference has " << (v.size()) << " elements." << std::endl;
        for (int j = 0; j < v.size(); j++)
        {
            std::cout << "Monitoring: init test for virus for file:" << v[j].path << std::endl;
            //Проверить файл на наличие вируса
             checkVirusInFile(v[j].path, virusmap, PipeServer1);//todo
             //todo if (v[j].path.substr(v[j].path.find_last_of('.'), 4) == ".exe") checkVirusInFile(v[j].path); // по mz и pe заголовок ЗАМЕНИТЬ ПРОВЕРКУ ТИПА!
        }
        firsttake = nexttake;

    }

public:
    //https://learn.microsoft.com/ru-ru/windows/win32/fileio/obtaining-directory-change-notifications
    // Чтобы закрыть дескриптор уведомления, используйте FindCloseChangeNotification .
    // Чтобы отсановить наблюдение видимо Нужна FindCloseChangeNotification. Нужно написать метод stopWatchingDirectory
    //Наблюдать за изменениями внутри папки 
    void WatchDirectory(std::string path)
    {
        DWORD dwWaitStatus;
        HANDLE dwChangeHandles;
        TCHAR lpDrive[4];
        TCHAR lpFile[_MAX_FNAME];
        TCHAR lpExt[_MAX_EXT];

        TCHAR* lpDirb = 0;
        lpDirb = new TCHAR[path.size() + 1];
        std::copy(path.begin(), path.end(), lpDirb);
        lpDirb[path.size()] = 0;
        LPTSTR lpDir = lpDirb;

        _tsplitpath_s(lpDir, lpDrive, 4, NULL, 0, lpFile, _MAX_FNAME, lpExt, _MAX_EXT);

        lpDrive[2] = (TCHAR)'\\';
        lpDrive[3] = (TCHAR)'\0';

        //указать набор условий, которые активируют уведомление об изменении с помощью функции FindFirstChangeNotification 
        dwChangeHandles = FindFirstChangeNotification(
            lpDir,
            TRUE,
            FILE_NOTIFY_CHANGE_SIZE + (FILE_NOTIFY_CHANGE_FILE_NAME || FILE_NOTIFY_CHANGE_DIR_NAME));

        if (dwChangeHandles == INVALID_HANDLE_VALUE)
        {
            printf("\n ERROR: FindFirstChangeNotification function failed.\n");
            ExitProcess(GetLastError());
        }

        while (TRUE)
        {
            printf("\nWaiting for notification...\n");

            dwWaitStatus = WaitForSingleObject(dwChangeHandles, INFINITE);
            switch (dwWaitStatus)
            {
            case WAIT_OBJECT_0:

                React(path);
                //предоставить дескриптор уведомления для ожидания последующих изменений
                if (FindNextChangeNotification(dwChangeHandles) == FALSE)
                {
                    printf("\n ERROR: FindNextChangeNotification function failed.\n");
                    ExitProcess(GetLastError());
                }
                break;
            case WAIT_TIMEOUT:

                printf("\nNo changes in the timeout period.\n");
                break;

            default:
                printf("\n ERROR: Unhandled dwWaitStatus.\n");
                ExitProcess(GetLastError());
                break;
            }
        }
    }

};//end of class

/*
//if (messagescan == "MonitoringScan")
//{//Если пришел запрос на сканирование то стартуем сканирование и мониторинг
const std::string folderName = "Q:\\!dima\\test_monitoring_files";
//test vector<FileInfoWatch> firsttake = GetListOfFilesAndSizes(folderName);
Monitoring monitoring;
monitoring.WatchDirectory(folderName);
std::cout << "finished ok" << std::endl;
*/
