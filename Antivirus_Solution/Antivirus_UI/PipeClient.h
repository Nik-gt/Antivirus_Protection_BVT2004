#pragma once
#include <iostream>
#include <string>
#include <windows.h> 
#include <stdio.h> 
#include <tchar.h> 

//////////////////
//  PipeClient ///
//////////////////
ref class PipeClient {
private:
	//fields
	HANDLE hPipe;
public:
	//constructor and methods
	PipeClient::PipeClient() { //Connecnt to Named Pipe
		hPipe = CreateFile(TEXT("\\\\.\\pipe\\anti"),
			GENERIC_READ | GENERIC_WRITE,
			0,
			NULL,
			OPEN_EXISTING,
			0,
			NULL);
	}
	//read data from pipe
	System::String^ PipeClient::PipeRead()
	{
		char buffer[1024 * 8];
		DWORD dwRead;
		BOOL success = ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL);
		if (!success || dwRead == 0) {}
		return gcnew System::String(buffer);
	}
	//write data to pipe
	void PipeClient::PipeWrite(std::string message, System::String^ folder)
	{
		//LPCTSTR data = _T("ManualScan|0|");
		char buffer[1024 * 8];
		strcpy(buffer, (char*)(void*)System::Runtime::InteropServices::Marshal::StringToHGlobalAnsi(gcnew System::String(message.c_str()) + folder + "|"));
		DWORD dwWritten = 0;
		if (hPipe != INVALID_HANDLE_VALUE)
		{
			WriteFile(hPipe, buffer, strlen(buffer), &dwWritten, NULL);
		}
	}
	//if (hPipe != INVALID_HANDLE_VALUE)
	//System::Windows::Forms::MessageBox::Show("text=");
};//end-class-PipeClient