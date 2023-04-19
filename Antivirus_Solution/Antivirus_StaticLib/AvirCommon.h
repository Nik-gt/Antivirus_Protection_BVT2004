#pragma once
//Основная функция:
//Содержит общие функции и 
//общая структура - Запись описания одного вируса из файла антивирусной базы  и 
//класс - реализация Антивирусная база данных для проектов
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
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <vector>
#include <array>
#include <list>
#include <queue>
#include <ole2.h>  
#include "icrsint.h"
#include "SHA256.h"
#include "PipeServer.cpp"
#pragma warning(disable:4996)

namespace AvirCommon{

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
std::vector<std::string> getFilesForFolder(std::string path);


//Получить тип файла
char* getfileType(std::ifstream& infile);

//Проверить файл на наличие вируса
void checkVirusInFile(std::string FileName, std::multimap<uint64_t, Data_Base_Virus> virusmap, PipeServer PipeServer1);


//void printHello2();



//Антивирусная база данных
//Хранится в файле с именем + путем= VirusDbFileName
class Adatabase
{
private:
	//fields
	std::string virusDbFileName;
	//Карта используется для хранения описаний вирусов и нужна для эффективного поиска вируса в заданных файлах
	std::multimap<uint64_t, Data_Base_Virus> virusmap; //1. std::vector<unit64_t>


public:

	//Коструктор. сохраняем имя файла антивирусной базы данных
	Adatabase(std::string VirusDbFileName);


	//*********************
	//****Методы внешние
	//Напечатать содержимое всей антивирусной базы данных
	void printAllDatabase();

	//Добавить файл вируса в антивирусную бд
	void addNewVirusToAdatabase(std::string virusFileName);

	//Прочитать файл антивирусной базы и загрузить описания вирусов в переменную типа карта/map 
	bool loadAntiVirusDatabase(std::multimap<uint64_t, Data_Base_Virus>& virusmap);


private:

	//*********************
	//****Методы внутренние для реализации внешних
	//Проверить правильность заголовка файла антивирусной базы данных
	unsigned long long validateDatabase(std::ifstream& isf, unsigned long long& fileLength);

	//Прочитать файл бд и получить из него нужные компоненты
	unsigned long long  getDbfile(char*& fileContent, unsigned long long& fileContentLength);

	//Заполнить новую запись антивирусной базы данными из файла вируса
	bool newRecordDb(std::string virusFileName, Data_Base_Virus& record, unsigned long long TotalRecords);

	//Напечатать запись одного вируса антивирусной базы данных
	void printRecord(Data_Base_Virus record);

	//Инициализация записи антивирусной базы//поле TotalRecords для отладки
	Data_Base_Virus initVirusRecord(std::string virusname, int virusLength, uint64_t first8bytes1, std::array<uint8_t, 32> hash1, unsigned long long TotalRecords, char* filetype);

	//Прочитать содержимое записи одного вируса антивирусной базы данных
	Data_Base_Virus readFileRecord(std::ifstream& isf);

	//Записать в поток одну запись антивирусной базы
	void writeRecordToFile(std::ofstream& outfile, Data_Base_Virus record);


	//*********************
	//****Методы утилиты
	//Получить тип файла
	//char* getfileType(std::ifstream& is);

	//Напечатать хэш, digest  
	//void printDigest(std::array<uint8_t, 32> hash);

	//Напечатать first8bytes
	//void print_uint64_t(uint64_t first8bytes);

	//convert char* to uint64_t 8bytes
	//uint64_t asciiToUint64(char* str);
};//class-end

}