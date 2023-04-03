#pragma once
//////////////////
//  PipeServer- Сервер именованного канала
//////////////////
#include <iostream>
#include <string>
#include <windows.h> 
#include <stdio.h> 
#include <tchar.h> 
#pragma warning(disable:4996)

class PipeServer {
private:
    //fields
    HANDLE hPipe;
public:
    //constructor and methods
    PipeServer() {
        //Create Named Pipe
        hPipe = CreateNamedPipe(TEXT("\\\\.\\pipe\\anti"),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            1024 * 16,
            1024 * 16,
            NMPWAIT_USE_DEFAULT_WAIT,
            NULL);
    }

    void WaitClientConnection() {
        //Waiting for client conection...
        std::cout << "PipeServer.Waiting for client connection..." << std::endl;
        ConnectNamedPipe(hPipe, NULL);
    }

    std::string PipeRead()
    {
        char buffer[1024 * 8];
        DWORD dwRead;
        BOOL success = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL);

        if (!success || dwRead == 0) {}
        //Result = gcnew System::String(buffer);
        return std::string(buffer, dwRead);
    }

    //destructor todo
    //disconnect    DisconnectNamedPipe(hPipe);

    void PipeWrite(std::string message) //Не строки int float duble char uint 8 uint 16
    {
        //LPCTSTR data = _T("ManualScan|0|");
        char buffer[1024 * 8];
        strcpy(buffer, message.c_str());
        DWORD dwWritten = 0;
        if (hPipe != INVALID_HANDLE_VALUE)
        {
            WriteFile(hPipe, buffer, strlen(buffer), &dwWritten, NULL);
        }
    }

};//end-class-PipeServer