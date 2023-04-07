//Антивирусная база данных
//Хранится в файле с именем + путем= VirusDbFileName
#pragma once
#include "Acommon.h"

class Adatabase
{
public:
	//Коструктор. сохраняем имя файла антивирусной базы данных
	Adatabase(std::string VirusDbFileName);

	//fields
	//VirusDatabase file
	std::string virusDbFileName;
	//Карта используется для хранения описаний вирусов и нужна для эффективного поиска вируса в заданных файлах
	std::multimap<uint64_t, Data_Base_Virus> virusmap; //1. std::vector<unit64_t>


	//*********************
	//****Методы внешние
	//Напечатать содержимое всей антивирусной базы данных
	bool printAllDatabase();

	//Добавить файл вируса в антивирусную бд
	void addNewAdatabase(std::string virusFileName);


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
	char* getfileType(std::ifstream& is);

	//Напечатать хэш, digest  
	void printDigest(std::array<uint8_t, 32> hash);

	//Напечатать first8bytes
	void print_uint64_t(uint64_t first8bytes);

};//class-end

/*
//using
Adatabase adatabase(std::string VirusDbFileName);
adatabase.printAllDatabase();
*/
