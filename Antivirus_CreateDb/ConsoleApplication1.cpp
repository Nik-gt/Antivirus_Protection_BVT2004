//Создание антивирусной базы
//Программа берет выбранный пользователем файл содержащий вирус,
//выбирает его длину, первые 8 байт, вычисляет его дайджест типа SHA256
//и сохраняет эти данные в файле антивирусной базы 
// ConsoleApplication1.cpp 
//
#include <windows.h> 
#include <iostream>
#include <fstream> 
#include <string>
#include <cstring>
#include <array>
#include <iostream>
#include <fstream> 
#include "SHA256.h"
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
} ;


//convert char* to uint64_t 8bytes
uint64_t asciiToUint64(char* str)
{
	uint64_t num = 0;
	//get 8 bytes of char* str
	//original version--> while (str[i] != '\0')
	for (int i = 0; i < 8; i++) {
		num = (num << 8) | str[i];
	}
	return num;
}

//printbytes
void printBytes(char* virusFile, int fileLength) {
	std::cout << "bytes(hex): ";
	std::cout << std::hex;//print hex
	for (int i = 0; i < fileLength; i++) std::cout << (int)virusFile[i];
	std::cout << std::dec;//print dec
	std::cout << std::endl;
}

//print hash=digest 32 bytes 
void printDigest(uint8_t* digest) {
	std::cout << "digest(hex): ";
	std::cout << std::hex;//print hex
	for (int i = 0; i < 32; i++) std::cout << (int)digest[i];
	std::cout << std::dec;//print dec
	std::cout << std::endl;
}

//print hash=digest 32 bytes 
void printDigest(std::array<uint8_t, 32> hash) {
	std::cout << "digest(hex): ";
	std::cout << std::hex;//print hex
	for (int i = 0; i < hash.size(); i++) std::cout << (int)hash[i] ;
	std::cout << std::dec;//print dec
	std::cout << std::endl;
}
//print_uint64_t_hex
void print_uint64_t_hex(uint64_t first8bytes) {
	std::cout << "8bytes(hex): ";
	std::cout << std::hex;//print hex
	std::cout << first8bytes ;
	std::cout << std::dec;//print dec
	std::cout << std::endl;

}

//print BaseData
void printRecord(Data_Base_Virus record) {
	std::cout << std::endl;
	std::cout << "virusName: " << record.virusName << std::endl;
	std::cout << "lenBytes: " << record.lenBytes << std::endl;
	print_uint64_t_hex(record.first8bytes);
	printDigest(record.hash);
	std::cout << "startOffset: " << record.startOffset << std::endl;
	std::cout << "endOffset: " << record.endOffset << std::endl;
	std::cout << "fileType: " << record.fileType << std::endl;
}

//Инициализация записи антивирусной базы//поле TotalRecords для отладки
Data_Base_Virus initVirusRecord(std::string virusname, int virusLength, uint64_t first8bytes1, std::array<uint8_t, 32> hash1, unsigned long long TotalRecords, char* filetype) {
	TotalRecords++;//отладка/номер следующей записи
	Data_Base_Virus record;
	strcpy(record.virusName, ("Virus-" + virusname).c_str());//const
	record.lenBytes = virusLength;
	record.first8bytes = first8bytes1;
	record.hash = hash1;
	record.startOffset = 0ull;//TotalRecords; 0ull;//const//debug
	record.endOffset = 128ull;//const
	strcpy(record.fileType, filetype);
	return record;
}

//Читать из потока одну запись антивирусной базы
Data_Base_Virus readFileRecord(std::ifstream &isf) {
	Data_Base_Virus record;
	//read values from file to struct fields
	isf.read(record.virusName, 16);
	isf.read((char*)&record.lenBytes, 8);
	isf.read((char*)&record.first8bytes, 8);
	for (int i = 0; i < record.hash.size(); i++) {
		isf.read((char*)&record.hash[i], 1);
	}
	isf.read((char*)&record.startOffset, 8);
	isf.read((char*)&record.endOffset, 8);
	isf.read(record.fileType, 4);
	return record;
}

//Записать в поток одну запись антивирусной базы
void writeRecordToFile(std::ofstream& outfile, Data_Base_Virus record) {
	//write one virus record
	outfile.write(record.virusName, 16);// write to file
	outfile.write((char*)&record.lenBytes, 8);// write to file
	outfile.write((char*)&record.first8bytes, 8);// ключа для multimap
	for (uint8_t it : record.hash) {
		outfile.write((char*)&it, 1);
	}
	outfile.write((char*)&record.startOffset, 8);// write to file
	outfile.write((char*)&record.endOffset, 8);// write to file
	outfile.write(record.fileType, 4);// write to file
}


//Распечатать все записи антивирусной базы/Для отладки
bool printAllDatabase(std::string VirusDbFileName) {
	std::cout << std::endl << "print VirusDatabase file=" << VirusDbFileName << std::endl;

	std::ifstream isf(VirusDbFileName, std::ifstream::binary);
	if (!isf.is_open()) {
		std::cout << "Can not open file=" << VirusDbFileName << std::endl;
		return false;
	}

	char filedId[9] = "Arkhipov";
	char filedIdcheck[9] = "";
	isf.read(filedIdcheck, 9);
	//check if file starts from family
	if (strcmp(filedId, filedIdcheck) != 0) {
		std::cout << "Wrong virus database, family field" << std::endl;
		return false;
	}

	//check if after family goes number of virus records 
	unsigned long long TotalRecords = 0; //8 bytes number
	isf.read((char*)&TotalRecords, 8);
	std::cout << "TotalRecords: " << TotalRecords << std::endl;
	if (TotalRecords < 1 || TotalRecords > 1000) {
		std::cout << "Wrong virus database, number of virus records field=" << TotalRecords << std::endl;
		return false;
	}
	
	//initialize current row number. starts from 0, 8 bytes
	unsigned long long FileRowNumber = 0;
	//while (isf.good()) {
	while (FileRowNumber < TotalRecords) {
		//std::cout << "FileRowNumber:"<< FileRowNumber << std::endl;
		Data_Base_Virus BaseData = readFileRecord(isf);
		//print fields
		printRecord(BaseData);
		FileRowNumber = FileRowNumber + 1;
	}
	isf.close();
	return true;
}


//Получить тип файла
char* getfileType(std::ifstream& is) {
	// Чтение заголовка файла
	//infile.seekg(0, infile.beg);
	char header[3];
	char* fileType = new char[3];
	is.read(header, sizeof(header));

	// Проверка типа файла PE
	if (header[0] == 'M' && header[1] == 'Z')
	{
		std::cout << "PE file" << std::endl;
		strcpy(fileType, std::string("PE" + '\0').c_str());
		return fileType;
	}
	// Проверка типа файла ZIP
	if (header[0] == 'P' && header[1] == 'K')
	{
		std::cout << "ZIP file" << std::endl;

		strcpy(fileType, std::string("ZIP" + '\0').c_str());
		return fileType;
	}
	// Проверка типа файла RAR
	if (header[0] == 'R' && header[1] == 'a' && header[2] == 'r')
	{
		std::cout << "RAR file" << std::endl;

		strcpy(fileType, std::string("RAR" + '\0').c_str());
		return fileType;
	}
	strcpy(fileType, std::string("COM" + '\0').c_str()); //wrong type in base
	std::cout << "Unknown file (COM)!" << std::endl;
	return fileType;
}

//Заполнить новую запись антивирусной базы данными из файла вируса
//Возвращает истино если успешно и ложно если неуспешно
//TotalRecords для отладки чтоб различать разные записи
bool newRecordDb(std::string virusFileName, Data_Base_Virus& record, unsigned long long TotalRecords) {
	//1.Прочитать заданный файл вируса/read virus file
	std::ifstream is(virusFileName, std::ifstream::binary);
	if (!is) {
		std::cout << "Not found file for virusFileName: " << virusFileName << std::endl;
		return false;
	}
	//Имя вируса
	std::string virusname = "";
	int index0 = virusFileName.find_last_of('\\') + 1;
	int index1 = virusFileName.find_last_of('.') - virusFileName.find_last_of('\\') - 1;
	virusname = virusFileName.substr(index0, index1); //".exe"

	std::cout << "!!!!virusname: " << virusname << std::endl;
	//Длина файла вируса
	is.seekg(0, is.end);
	int virusLength = is.tellg();
	is.seekg(0, is.beg);
	// Определяем тип файла
	char* filetype = getfileType(is);
	is.seekg(0, is.beg);
	std::cout << "Virus file length: " << virusLength << std::endl;
	//if (virusLength < 65536) {} //работает если файл меньше 64 кб
	char* virusFile = new char[virusLength];//allocate memory //plus end char
	is.read(virusFile, virusLength);
	//printBytes(virusFile, 8);//debug

	is.close();
	//отладка= print virusFile content
	//std::cout.write(virusFile, virusLength) << std::endl;
	virusFile[virusLength] = '\0';//add string end null char
	std::cout << "Processed ok virusFile" << std::endl;

	//2.Инициализировать запись антивирусной базы данными вируса
	//.1 вычислить дайджест
	SHA256 sha;
	sha.update(virusFile);
	uint8_t* digest = sha.digest();//get digest
	//printDigest(digest);	//отладка= print digest
	std::array<uint8_t, 32> hash;//convert digest to array
	memcpy(hash.data(), digest, 32);
	delete[] digest;
	//.2 Получить первые 8 байт файла вируса
	uint64_t first8bytes = asciiToUint64(virusFile); // преобразование строки в uint64_t
	//print_uint64_t_hex(first8bytes);//отладка

	//.3 Инициализировать запись
	record = initVirusRecord(virusname, virusLength, first8bytes, hash, TotalRecords, filetype);
	return true;
}

//Прочитать файл бд и получить из него нужные компоненты
//Возвращает из файла бд кол-во записей вирусов и сами записи в виде массива и длину массива
//Если файл отсутствует или неправильный то возвращает 0, его можно затереть
unsigned long long  getDbfile(std::string VirusDbFileName, char*& fileContent, int& fileContentLength) {
	std::ifstream isf(VirusDbFileName, std::ifstream::binary);
	if (!isf.is_open()) {
		std::cout << "Db-file not exist: " << VirusDbFileName << std::endl;
		return 0;
	}
	//Длина файла 
	isf.seekg(0, isf.end);
	int fileLength = isf.tellg();
	isf.seekg(0, isf.beg);
	//std::cout << "File length: " << fileLength << std::endl;
	//if (virusLength < 65536) {} //работает если файл меньше 64 кб

	char filedId[9] = "Arkhipov";
	char filedIdcheck[9] = "";
	isf.read(filedIdcheck, 9);
	//check if file starts from family
	if (strcmp(filedId, filedIdcheck) != 0) {
		std::cout << "Wrong family field in db-file" << std::endl;
		return 0;
	}
	//std::cout << "Family is ok" << std::endl;//debug

	//check if after family goes number of virus records 
	unsigned long long TotalRecords = 0; //8 bytes number
	isf.read((char*)&TotalRecords, 8);
	//std::cout << "db-file TotalRecords: " << TotalRecords << std::endl;
	if (TotalRecords < 1 || TotalRecords > 1000) {
		std::cout << "Wrong virus database, number of virus records field=" << TotalRecords << std::endl;
		return 0;
	}

	fileContentLength = fileLength - 17;//длина первых двух полей
	//std::cout << "fileLength=" << fileLength << " fileContentLength=" << fileContentLength << std::endl;//debug
	fileContent = new char[fileLength];//allocate memory //plus end char
	isf.read(fileContent, fileLength);
	isf.close();
	//std::cout << "fileContent=" << std::endl;printBytes(fileContent, fileContentLength);//debug
	return TotalRecords;
}

//////////////////
//Main function//
/////////////////
int main() {
	const std::string VirusDbFileName = "D:\\Antivirus_Protection_BVT2004\\newdb.bin";
	std::string virusFileName;
	//virusFileName = "D:\\Antivirus_Protection_BVT2004\\EICAR\\eicar.com";//отладка
	//printAllDatabase(VirusDbFileName);return 0;//debug напечатать записи о вирусах

	//Цикл 
	while (true) {
		std::cout << "\nEnter virus-file-path or e-exit or r-readDB: ";
		std::string virusFileName;
		std::cin >> virusFileName;
		if (virusFileName == "e") { break; }
		//Выводим все записи базы
		if (virusFileName == "r") {
			bool res = printAllDatabase(VirusDbFileName);
			if (!res) std::cout << "Printed fileVirusDatabase with error" << std::endl;
			continue;
		}
		//
		//Введено имя файла вируса в std::cin
		//Требуется добавить этот файл в антивирусную бд
		//1.Загрузить антивирусную бд
		std::cout << std::endl;
		int fileContentLength = 0;
		char* fileContent;
		unsigned long long TotalRecords = getDbfile(VirusDbFileName, fileContent, fileContentLength);
		std::cout << "Antivirus db-file contains TotalRecords: " << TotalRecords << std::endl;

		//2.Обработать файл вируса и заполнить данные одной записи вируса
		Data_Base_Virus record;
		bool isVirusOK = newRecordDb(virusFileName, record, TotalRecords);//TotalRecords for debug
		if (!isVirusOK) return 1;
	
		//3.Задать поле количество записей в файле бд антивирусов
		if (TotalRecords < 1) {
			//std::cout << "Not exist db file=" << VirusDbFileName << std::endl;
			TotalRecords = 1;//Начальное значение кол-ва записей, вводим первую запись
		}else {
			//std::cout << "Exist db file=" << VirusDbFileName << std::endl;
			TotalRecords = TotalRecords + 1;
		}

		//4.Записать заголовок файла бд
		std::ofstream outfile(VirusDbFileName, std::ofstream::binary);
		//std::cout << "Write header to db-file=" << VirusDbFileName << std::endl;
		char filedId[9] = "Arkhipov";//const for this file!
		//write header data to file
		outfile.write(filedId, 9);// write to file
		//counter of virus records in this file
		outfile.write((char*)&TotalRecords, 8);// write to file
	
		//5.Сохранить старые записи о вирусах в файл бд
		if (TotalRecords > 1) {
			//std::cout << "Write/save old virus-records to db-file=" << VirusDbFileName << std::endl;
			outfile.write(fileContent, fileContentLength);
		}
		//6.Добавить новую запись описания вируса в бд антивирусов
		writeRecordToFile(outfile, record);
		outfile.close();
		std::cout << "Added new virus-record to db-file" << std::endl;
	}//конец цикла ввода/обработки нового вируса

	std::cout << std::endl << "finished ok" << std::endl;
	return 0;
}

//проверка правильности=our eicar.com file starts from 9btes-->
//X5O!P%@AP --ascii
//58354F2150254041 --hex
//----------------------- 
//проверка правильности= digest for our eicar.com
//275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

/*
//Содержимое файла антивирусной базы
struct Data_Base_Content
{
	int fileLength;
	char filedId[9];
	unsigned long long TotalRecords = 0; //8 bytes number
	int fileContentLength;
	char*& fileContent;
};*/
/*----------------------------------------------------
* 		//std::ofstream outfile(VirusDbFileName, std::ofstream::binary | std::ios::app);
int main() {
	std::string VirusDbFileName = "D:\\Projects_antivirus\\newdb.bin";
	std::string virusFileName = "D:\\Antivirus_Protection_BVT2004\\EICAR\\eicar.com";

	//0. Создать файл антивирусной базы
	std::ofstream outfile(VirusDbFileName, std::ofstream::binary);//rewrite files content//debug
	char filedId[9] = "Arkhipov";//const for this file!
	outfile.write(filedId, 9);// write to file
	//Счетчик количества записей о вирусе в файле антивирусной бд
	unsigned long long TotalRecords = 0;

	//В цикле получаем имя файла вируса из std::cin
//	while (true) {
//		std::cout << "File path: ";
//		std::string virusFileName;
//		std::cin >> virusFileName;
//		if (virusFileName == "e") { break; }

		//Обработать файл вируса и заполнить данные одной записи вируса
		Data_Base_Virus BaseData;
		bool isVirusOK = newRecordDb(virusFileName, BaseData);
		if (!isVirusOK) {
			//todo
		}

		//3.Сохранить запись антивирусной базы в файле
		//.1 Сохранить счетчик количества записей о вирусе
		outfile.seekp(9, std::ios::beg);
		TotalRecords += 1;
		outfile.write((char*)&TotalRecords, 8);// write to file
		outfile.seekp(0, std::ios::end);
		//.2 Сохранить запись
		writeRecordToFile(outfile, BaseData);
//		}//конец цикла ввода/обработки нового вируса

	outfile.close();//finish with file

	//4.test the result/отладка
	bool res = printAllDatabase(VirusDbFileName);
	if (!res) std::cout << "Printed fileVirusDatabase with error" << std::endl;

	std::cout << "finished ok" << std::endl;
	return 0;
}
*/
