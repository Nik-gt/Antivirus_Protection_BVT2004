//Создание антивирусной базы
//Программа берет выбранный пользователем файл содержащий вирус,
//выбирает его длину, первые 8 байт, вычисляет его дайджест типа SHA256
//и сохраняет эти данные в файле антивирусной базы 
// ConsoleApplication1.cpp 
//////////////////////////
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

//Запись антивирусной базы 
struct Data_Base_Virus
{
	char* virusName = new char[16]; //virus name
	unsigned long long	lenBytes;   //virus length
	uint64_t			first8bytes;//unit64_t 8байт
	std::array<uint8_t, 32> hash;   //SHA256 std::array<unit8_t, 32>  32байт   
	unsigned long long	startOffset;
	unsigned long long	endOffset;
	//char* fileType = new char[3]; //virus name
	char fileType[4]; //virus name
} ;


//Инициализация записи антивирусной базы
Data_Base_Virus initVirusRecord(int virusLength, uint64_t first8bytes1, std::array<uint8_t, 32> hash1) {
	Data_Base_Virus BaseData;
	strcpy(BaseData.virusName, std::string("VirName0").c_str());//const
	BaseData.lenBytes= virusLength;   
	BaseData.first8bytes = first8bytes1;
	BaseData.hash = hash1;
	BaseData.startOffset = 0ull;//const
	BaseData.endOffset = 128ull;//const
	strcpy(BaseData.fileType, std::string("PE").c_str());
	return BaseData;
}

//Вспомогательные функции
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
//print8bytes
void print8bytes(char* virusFile) {
	std::cout << "8bytes(hex): ";
	std::cout << std::hex;//print hex
	for (int i = 0; i < 8; i++) std::cout << (int)virusFile[i] ;
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
void printRecord(Data_Base_Virus data) {
	std::cout << std::endl;
	std::cout << "virusName: " << data.virusName << std::endl;
	std::cout << "lenBytes: " << data.lenBytes << std::endl;
	print_uint64_t_hex(data.first8bytes);
	printDigest(data.hash);
	std::cout << "startOffset: " << data.startOffset << std::endl;
	std::cout << "endOffset: " << data.endOffset << std::endl;
	std::cout << "fileType: " << data.fileType << std::endl;
}

//Читать из потока одну запись антивирусной базы
Data_Base_Virus readFileRecord(std::ifstream &isf) {
	Data_Base_Virus BaseData;
	//read values from file to struct fields
	isf.read(BaseData.virusName, 16);
	isf.read((char*)&BaseData.lenBytes, 8);
	isf.read((char*)&BaseData.first8bytes, 8);
	for (int i = 0; i < BaseData.hash.size(); i++) {
		isf.read((char*)&BaseData.hash[i], 1);
	}
	isf.read((char*)&BaseData.startOffset, 8);
	isf.read((char*)&BaseData.endOffset, 8);
	isf.read(BaseData.fileType, 4);
	return BaseData;
}

////Записать в поток одну запись антивирусной базы
void writeRecordToFile(std::ofstream& outfile, Data_Base_Virus BaseData) {
	//write one virus record
	outfile.write(BaseData.virusName, 16);// write to file
	outfile.write((char*)&BaseData.lenBytes, 8);// write to file
	outfile.write((char*)&BaseData.first8bytes, 8);// ключа для multimap
	for (uint8_t it : BaseData.hash) {
		outfile.write((char*)&it, 1);
	}
	outfile.write((char*)&BaseData.startOffset, 8);// write to file
	outfile.write((char*)&BaseData.endOffset, 8);// write to file
	outfile.write(BaseData.fileType, 4);// write to file
}


//---print all file for debugging
//read file with viruses description to map variable
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
	std::cout << "Family is ok" << std::endl;

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
		std::cout << "FileRowNumber:"<< FileRowNumber << std::endl;
		Data_Base_Virus BaseData = readFileRecord(isf);
		//print fields
		printRecord(BaseData);
		FileRowNumber = FileRowNumber + 1;
	}
	isf.close();
	return true;
}


//Создать/Заполнить новую запись антивирусной базы данными из файла вируса
//Возвращает истино если успешно и ложно если неуспешно
bool newRecordDb(std::string virusFileName, Data_Base_Virus& BaseData) {
	//1.Прочитать заданный файл вируса/read virus file
	std::ifstream is(virusFileName, std::ifstream::binary);
	if (!is) {
		std::cout << "Not found virusFile for virusFileName: " << virusFileName << std::endl;
		return false;
	}
	std::cout << "Read ok virusFile: " << virusFileName << std::endl;

	//Длина файла вируса
	is.seekg(0, is.end);
	int virusLength = is.tellg();
	is.seekg(0, is.beg);
	std::cout << "Virus file length: " << virusLength << std::endl;
	//if (virusLength < 65536) {} //работает если файл меньше 64 кб
	char* virusFile = new char[virusLength + 1];//allocate memory //plus end char
	is.read(virusFile, virusLength);
	print8bytes(virusFile);//debug
	is.close();
	//отладка= print virusFile content
	std::cout.write(virusFile, virusLength) << std::endl;
	virusFile[virusLength] = '\0';//add string end null char
	std::cout << "Read ok virusFile: " << virusFileName << std::endl;

	//2.Инициализировать запись антивирусной базы данными вируса
	//.1 вычислить дайджест
	SHA256 sha;
	sha.update(virusFile);
	uint8_t* digest = sha.digest();//get digest
	printDigest(digest);	//отладка= print digest
	std::array<uint8_t, 32> hash;//convert digest to array
	memcpy(hash.data(), digest, 32);
	delete[] digest;
	//.2 Получить первые 8 байт файла вируса
	uint64_t first8bytes;
	first8bytes = asciiToUint64(virusFile); // преобразование строки в uint64_t
	print_uint64_t_hex(first8bytes);//отладка
	//.3 Инициализировать запись
	BaseData = initVirusRecord(virusLength, first8bytes, hash);
	return true;
}


//printbytes
void printBytes(char* virusFile, int fileLength) {
	std::cout << "bytes(hex): ";
	std::cout << std::hex;//print hex
	for (int i = 0; i < fileLength; i++) std::cout << (int)virusFile[i];
	std::cout << std::dec;//print dec
	std::cout << std::endl;
}



//Содержимое файла антивирусной базы
struct Data_Base_Content
{
	int fileLength;
	char filedId[9];
	unsigned long long TotalRecords = 0; //8 bytes number
	int fileContentLength;
	char*& fileContent;
};

//Прочитать файл бд и получить из него нужные компоненты
//Возвращает из файла бд кол-во записей вирусов и сами записи в виде массива и длину массива
unsigned long long  getDbfile(std::string VirusDbFileName, char*& fileContent) {
	std::ifstream isf(VirusDbFileName, std::ifstream::binary);
	if (!isf.is_open()) {
		std::cout << "Can not open file=" << VirusDbFileName << std::endl;
		return 0;
	}
	//Длина файла 
	isf.seekg(0, isf.end);
	int fileLength = isf.tellg();
	isf.seekg(0, isf.beg);
	std::cout << "File length: " << fileLength << std::endl;
	//if (virusLength < 65536) {} //работает если файл меньше 64 кб

	char filedId[9] = "Arkhipov";
	char filedIdcheck[9] = "";
	isf.read(filedIdcheck, 9);
	//check if file starts from family
	if (strcmp(filedId, filedIdcheck) != 0) {
		std::cout << "Wrong virus database, family field" << std::endl;
		return 0;
	}
	std::cout << "Family is ok" << std::endl;

	//check if after family goes number of virus records 
	unsigned long long TotalRecords = 0; //8 bytes number
	isf.read((char*)&TotalRecords, 8);
	std::cout << "TotalRecords: " << TotalRecords << std::endl;
	if (TotalRecords < 1 || TotalRecords > 1000) {
		std::cout << "Wrong virus database, number of virus records field=" << TotalRecords << std::endl;
		return 0;
	}

	std::cout << "fileLength=" << fileLength << std::endl;
	fileLength = fileLength - 17;
	std::cout << "fileLength2=" << fileLength << std::endl;
	fileContent = new char[fileLength];//allocate memory //plus end char
	isf.read(fileContent, fileLength);
	isf.close();
	std::cout << "fileContent=" << std::endl;
	printBytes(fileContent, fileLength);//debug

	return TotalRecords;
}


///*****************************************************************************************
int main() {
	std::string VirusDbFileName = "D:\\Antivirus_Protection_BVT2004\\newdb.bin";
	std::string virusFileName = "D:\\Antivirus_Protection_BVT2004\\EICAR\\eicar.com";

	//Обработать файл вируса и заполнить данные одной записи вируса
	Data_Base_Virus BaseData;
	bool isVirusOK = newRecordDb(virusFileName, BaseData);
	if (!isVirusOK) return 1;
	

	//3.write object to file
	//Возвращает из файла бд кол-во записей вирусов
	std::cout << std::endl;
	char* fileContent;
	unsigned long long TotalRecords = getDbfile(VirusDbFileName, fileContent);



	if (TotalRecords < 1) {
		std::cout << "Not exist db file=" << VirusDbFileName << std::endl;
		TotalRecords = 1;//Начальное значение кол-ва записей, вводим первую запись

		std::ofstream outfile(VirusDbFileName, std::ofstream::binary);
		std::cout << "Write header to db-file=" << VirusDbFileName << std::endl;
		char filedId[9] = "Arkhipov";//const for this file!
		//write header data to file
		outfile.write(filedId, 9);// write to file
		//counter of virus records in this file
		outfile.write((char*)&TotalRecords, 8);// write to file
		std::cout << "Write virus-record to db-file=" << VirusDbFileName << std::endl;
		writeRecordToFile(outfile, BaseData);
		outfile.close();
	}else{
		TotalRecords = TotalRecords + 1;
		std::cout << "Db file exist=" << VirusDbFileName << std::endl;
		
		//Записать все записи о вирусах уже находящиеся в файле
		std::ofstream outfile(VirusDbFileName, std::ofstream::binary);
		std::cout << "Write new db-header to virus file=" << VirusDbFileName << std::endl;
		char filedId[9] = "Arkhipov";//const for this file!
		//write header data to file
		outfile.write(filedId, 9);// write to file
		//counter of virus records in this file
		outfile.write((char*)&TotalRecords, 8);// write to file
		std::cout << "Write old virus-record()s to db-file=" << VirusDbFileName << std::endl;
		outfile.write(fileContent, 84);
		std::cout << "Write new virus-record to db-file=" << VirusDbFileName << std::endl;
		writeRecordToFile(outfile, BaseData);
		outfile.close();
	}
	

	
/*
TotalRecords: 1
fileLength=101
fileContent=
5669724e616d65300ffffffcdffffffcdffffffcdffffffcdffffffcdffffffcdffffffcd44000000041402550214f3558275a21bffffffbfffffffb648ffffff9e54ffffffd471ffffff89ffffff9f7dffffffb9ffffffd1663fffffffc6ffffff95ffffffec2fffffffe2ffffffa2ffffffc453ffffff8affffffabfffffff651fffffffdf00000000ffffff80000000050450ffffffcc
5669724E616D653000CDCDCDCDCDCD
CD440000000000000041402550214F35
58275A021BBFB6489E54D471899F7DB9
D1663FC695EC2FE2A2C4538AABF651FD
0F000000000000000080000000000000
00504500CC
*/

	//4.test the result/отладка
	bool res = printAllDatabase(VirusDbFileName);
	if (!res) std::cout << "Printed fileVirusDatabase with error" << std::endl;

	std::cout << "finished ok" << std::endl;
	return 0;
}

//проверка правильности=our eicar.com file starts from 9btes-->
//X5O!P%@AP --ascii
//58354F2150254041 --hex
//----------------------- 
//проверка правильности= digest for our eicar.com
//275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

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
