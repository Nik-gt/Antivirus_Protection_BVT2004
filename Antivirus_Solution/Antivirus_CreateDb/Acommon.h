#pragma once

#include <iostream>
#include <fstream> 
#include <sstream>
#include <string>
#include <map>
#include <windows.h> 
#include <future>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <list>
#include <queue>
#include <filesystem>
#include <vector>
#include <array>
#include <algorithm>;
#include <ole2.h>  
#include <filesystem>

#include "icrsint.h"
#include "SHA256.h"
//#include "PipeServer.cpp"

#pragma warning(disable:4996)

//Запись описания одного вируса из файла антивирусной базы 
struct Data_Base_Virus
{
    char* virusName = new char[16]; //название вируса для его идентификации среди вирусов
    unsigned long long	lenBytes;   //длина вируса
    uint64_t			first8bytes;//первые 8 байт вируса
    std::array<uint8_t, 32> hash;   //дайджест вируса, SHA256, 32байт   
    unsigned long long	startOffset;//смещение начала поиска вируса
    unsigned long long	endOffset;  //смещение конца поиска вируса
    char fileType[4];              //тип файла в котором возможен данный вирус
};


//convert char* to uint64_t 8bytes
uint64_t asciiToUint64(char* str);

//Получить список файлов для заданной папки/рекурсивно
//std::vector<std::string> getFilesForFolder(std::string path);
//Получить тип файла
//char* getfileType(std::ifstream& infile);
//Проверить файл на наличие вируса
//void checkVirusInFile(std::string FileName, std::multimap<uint64_t, Data_Base_Virus> virusmap, PipeServer PipeServer1);// не стринг!!!


