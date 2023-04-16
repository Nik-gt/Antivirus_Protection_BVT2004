#pragma once
#include "AvirCommon.h"

namespace AvirCommon {

	//convert char* to uint64_t 8bytes
	uint64_t asciiToUint64(char* str)
	{
		uint64_t num = 0;
		for (int i = 0; i < 8; i++) {
			num = (num << 8) | str[i];
		}
		return num;
	}


	std::vector<std::string> getFilesForFolder(std::string path)
	{//using namespace std::filesystem;
		std::vector<std::string> all;
		std::vector<std::string> xxall;
		for (const auto& p : std::filesystem::directory_iterator(path))
		{
			if (p.is_regular_file()) //не директория
			{
				all.push_back(p.path().string()); // добавляем файл в вектор
			}
			else // если директория
			{
				std::cout << p.path().string() << std::endl;
				xxall = getFilesForFolder(p.path().string());
				for (int i = 0; i < xxall.size(); i++) { all.push_back(xxall[i]); } // до
				xxall.erase(xxall.begin(), xxall.end());
			}
		}
		return all;
	}


	//Получить тип файла
	char* getfileType(std::ifstream& infile) {
		// Чтение заголовка файла
		char header[3];
		char* fileType = new char[3];
		infile.read(header, sizeof(header));

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
		strcpy(fileType, std::string("EXE" + '\0').c_str()); //wrong type in base
		std::cout << "getfileType() Unknown file" << std::endl;//debug
		return fileType;
	}


	//Проверить файл на наличие вируса
	void checkVirusInFile(std::string fileName, std::multimap<uint64_t, Data_Base_Virus> virusmap, PipeServer PipeServer1)// не стринг!!!
	{
		std::cout << std::endl;
		std::ifstream infile(fileName, std::ios_base::binary);
		if (!infile) {
			std::cout << "Not found file testing for virus: " << fileName << std::endl;
			return;
		}

		char* fileType = getfileType(infile);
		//Размер файла
		infile.seekg(0, infile.end);
		long long size = infile.tellg();
		infile.seekg(0);

		std::cout << "Start testing for viruses file: " << fileName << " /size: " << size << std::endl;
		//Получим 8 байтовый ключ для выбора из карты
		char first8bytes[8];//ключ это 8 байтов файла
		//Цикл чтения проверяемого на вирусы файла
		if (size == -1) return;
		for (unsigned long long i = 0; i <= size - 7; i++)
		{
			std::cout << "i: " << i << std::endl;//todo
			//Установим указатель файла на текущий байт
			infile.seekg(i);
			infile.read(first8bytes, 8);//читаем из файла по 8 байтов
			//преобразование строки в тип ключа/байты в uint64_t
			uint64_t bufferkey = asciiToUint64(first8bytes);

			//Поиск первых 8 байтов вирусов в файле 
			//Цикл по всем записям с таким ключом
			for (auto itr = virusmap.find(bufferkey); itr != virusmap.end(); itr++) {
				//Если поиск по 8 байтовому ключу успешный то такие 8 байт найдены
				std::cout << "Found first8bytes: " << itr->second.virusName << " /at i: " << i << std::endl;

				//Если размер вируса выходит за пределы файла то  пропускаем этот вирус  
				if (itr->second.lenBytes > (size - i)) continue;

				//отладка!!
				//Если вне диапазона действия данного вируса то пропускаем этот вирус
				//отладка!! if (itr->second.startOffset > i || itr->second.endOffset < i) continue;
				//Если неподходящий тип файла то пропускаем этот вирус
				//отладка!! if (memcmp(itr->second.fileType, fileType, 3) != 0) continue; //сравнение типа файла с базой
				//отладка!! 

				//Возьмем длину вируса из карты
				char* filehash = new char[itr->second.lenBytes];

				//Установим указатель файла на текущий байт(вернемся на 8байт назад)
				infile.seekg(i);
				//Загружаем байты для вычисления хеша, длина=lenBytes
				infile.read(filehash, itr->second.lenBytes);
				filehash[itr->second.lenBytes] = '\0';
				//std::cout << "filehash: " << filehash << std::endl;//отладка
				SHA256 sha;
				sha.update(filehash);//вычислить хэш
				uint8_t* digest = sha.digest();//получим хэш из проверяемого файла

				//3 Сравним два хэша из файла и из базы антивирусов
				int n = memcmp(itr->second.hash.data(), digest, 32);
				if (n != 0) { //если хэши не равны то  пропускаем этот вирус 
					continue; //проверим средующий вирус итератора
				}
				std::cout << "Found virus name: " << itr->second.virusName << " /virus_length: " << itr->second.lenBytes << " /at i: " << i << std::endl;
				PipeServer1.PipeWrite(std::string(itr->second.virusName) + " - " + fileName + "|");
				//PipeServer1.PipeWrite(itr->second.virusName + std::string("|"));
				//std::cout << "bufferkey: " << itr->first << std::endl;
				break;//Нашли совпадающие хэши и значит и вирус.Закончим с итератором //return;///
			}//Конец цикла по всем записям с таким ключом 
		}//Конец цикла по файлу
		infile.close();
		std::cout << "Finished testing for viruses file" << std::endl;
		return;
	}

	/*
	void printHello2() {
		std::cout << "hello from AvirCommon!" << std::endl;
	}
	*/

	//Коструктор. сохраняем имя файла антивирусной базы данных
	Adatabase::Adatabase(std::string VirusDbFileName)
	{
		this->virusDbFileName = VirusDbFileName;
	}

	//*********************
	//****Операции внешние= public
	//********************* 

	//Напечатать содержимое всей антивирусной базы данных
	void Adatabase::printAllDatabase() {
		std::ifstream isf(virusDbFileName, std::ifstream::binary);
		unsigned long long fileLength = 0;
		unsigned long long totalRecords = validateDatabase(isf, fileLength);
		if (totalRecords < 1) return;
		std::cout << "Adatabase contains records: " << totalRecords << std::endl;

		//initialize current row number
		unsigned long long rowNumber = 0;
		while (rowNumber < totalRecords) {
			Data_Base_Virus baseData = readFileRecord(isf);
			printRecord(baseData);	//print fields
			rowNumber = rowNumber + 1;
		}
		isf.close();
	}


	//Добавить файл вируса в антивирусную бд
	void Adatabase::addNewAdatabase(std::string virusFileName) {
		//1.Загрузить антивирусную бд
		std::cout << std::endl;
		unsigned long long fileContentLength = 0;
		char* fileContent;
		unsigned long long totalRecords = getDbfile(fileContent, fileContentLength);
		//std::cout << "Antivirus db-file contains TotalRecords: " << TotalRecords << std::endl;

		//2.Обработать файл вируса и заполнить данные одной записи вируса
		Data_Base_Virus record;
		bool isVirusOK = newRecordDb(virusFileName, record, totalRecords);//TotalRecords for debug
		if (!isVirusOK) return;

		//3.Задать поле количество записей в файле бд антивирусов
		if (totalRecords < 1) {
			//std::cout << "Not exist db file=" << VirusDbFileName << std::endl;
			totalRecords = 1;//Начальное значение кол-ва записей, вводим первую запись
		}
		else {
			//std::cout << "Exist db file=" << VirusDbFileName << std::endl;
			totalRecords = totalRecords + 1;
		}

		//4.Записать заголовок файла бд
		std::ofstream outfile(this->virusDbFileName, std::ofstream::binary);
		//std::cout << "Write header to db-file=" << VirusDbFileName << std::endl;
		char filedId[9] = "Arkhipov";//const for this file!
		//write header data to file
		outfile.write(filedId, 9);// write to file
		//counter of virus records in this file
		outfile.write((char*)&totalRecords, 8);// write to file

		//5.Сохранить старые записи о вирусах в файл бд
		if (totalRecords > 1) {
			//std::cout << "Write/save old virus-records to db-file=" << VirusDbFileName << std::endl;
			outfile.write(fileContent, fileContentLength);
		}
		//6.Добавить новую запись описания вируса в бд антивирусов
		writeRecordToFile(outfile, record);
		outfile.close();
		std::cout << "Added new virus-record to db-file" << std::endl;
	}



	//Прочитать файл антивирусной базы и загрузить описания вирусов в переменную типа карта/map 
	bool Adatabase::loadAntiVirusDatabase(std::multimap<uint64_t, Data_Base_Virus>& virusmap) {
		std::ifstream isf(virusDbFileName, std::ifstream::binary);
		unsigned long long fileLength = 0;
		unsigned long long totalRecords = validateDatabase(isf, fileLength);
		if (totalRecords < 1) return false;

		std::cout << "Loading AntiVirusDatabase to map" << std::endl;
		std::cout << "Adatabase contains records: " << totalRecords << std::endl;
		//initialize current row number. starts from 0, 8 bytes
		unsigned long long rowNumber = 0;
		while (rowNumber < totalRecords) {
			//std::cout << "FileRowNumber:"<< FileRowNumber << std::endl;
			Data_Base_Virus baseData = readFileRecord(isf);
			//добавляем описание вируса в карту
			virusmap.insert(std::pair<uint64_t, Data_Base_Virus>(baseData.first8bytes, baseData));
			rowNumber++;
		}
		isf.close();
		std::cout << "Records inserted in map: " << rowNumber << std::endl;
		return true;
	}


	//*********************
	//****Операции внутренние для реализации внешних= private
	//*********************

	//Проверить правильность заголовка файла антивирусной базы данных
	//Возвращаем totalRecords-количество записей о вирусах и fileLength-длина файла. 
	// Указатель isf после функции установлен на начало записей описания вирусов
	// Если totalRecords< 1 то базы данных неправильная и с ней нельзя работать
	//Иначе работае с ней. При этом указатель isf установлен на начало записей описания вирусов
	unsigned long long Adatabase::validateDatabase(std::ifstream& isf, unsigned long long& fileLength) {

		unsigned long long totalRecords = 0; //8 bytes number
		if (!isf.is_open()) {
			std::cout << "Adatabase not exist" << std::endl;
			return totalRecords;
		}
		//Длина файла 
		isf.seekg(0, isf.end);
		fileLength = isf.tellg();
		isf.seekg(0, isf.beg);
		std::cout << "Adatabase file length: " << fileLength << std::endl;

		const char filedId[9] = "Arkhipov";//todo create global const
		char filedIdcheck[9] = "";
		isf.read(filedIdcheck, 9);
		//check if file starts from family
		if (strcmp(filedId, filedIdcheck) != 0) {
			std::cout << "Wrong Adatabase, family field" << std::endl;
			return totalRecords;
		}
		//check if after family goes number of virus records 

		isf.read((char*)&totalRecords, 8);
		if (totalRecords < 1 || totalRecords > 1000) {
			std::cout << "Wrong Adatabase, totalRecords field=" << totalRecords << std::endl;
			return totalRecords;
		}
		return totalRecords;
	}


	//Прочитать файл бд и получить из него нужные компоненты
	//Возвращает из файла бд кол-во записей вирусов и сами записи в виде массива и длину массива
	//Если файл отсутствует или неправильный то возвращает 0, его можно затереть
	unsigned long long  Adatabase::getDbfile(char*& fileContent, unsigned long long& fileContentLength) {
		std::ifstream isf(this->virusDbFileName, std::ifstream::binary);
		unsigned long long fileLength = 0;
		unsigned long long totalRecords = validateDatabase(isf, fileLength);
		if (totalRecords < 1) return totalRecords;
		//std::cout << "Adatabase ok, TotalRecords: " << TotalRecords << std::endl;

		fileContentLength = fileLength - 17;//длина первых двух полей
		//std::cout << "fileLength=" << fileLength << " fileContentLength=" << fileContentLength << std::endl;//debug
		fileContent = new char[fileLength];//allocate memory //plus end char
		isf.read(fileContent, fileLength);
		isf.close();
		//std::cout << "fileContent=" << std::endl;printBytes(fileContent, fileContentLength);//debug
		return totalRecords;
	}


	//Заполнить новую запись антивирусной базы данными из файла вируса
	//Возвращает истино если успешно и ложно если неуспешно
	//TotalRecords для отладки чтоб различать разные записи
	bool Adatabase::newRecordDb(std::string virusFileName, Data_Base_Virus& record, unsigned long long totalRecords) {
		//1.Прочитать заданный файл вируса/read virus file
		std::ifstream is(virusFileName, std::ifstream::binary);
		if (!is) {
			std::cout << "Not found file for virusFileName: " << virusFileName << std::endl;
			return false;
		}

		//Длина файла вируса
		is.seekg(0, is.end);
		unsigned long long virusLength = is.tellg();
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
		std::cout << "Processed virusFile ok" << std::endl;

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


		//Имя вируса
		std::string virusname = "";
		int index0 = virusFileName.find_last_of('\\') + 1;
		int index1 = virusFileName.find_last_of('.') - virusFileName.find_last_of('\\') - 1;
		virusname = virusFileName.substr(index0, index1); //".exe"
		//std::cout << "assigned virusname: " << virusname << std::endl;

		//.3 Инициализировать запись
		record = initVirusRecord(virusname, virusLength, first8bytes, hash, totalRecords, filetype);
		return true;
	}


	//Напечатать запись одного вируса антивирусной базы данных
	void Adatabase::printRecord(Data_Base_Virus record) {
		std::cout << std::endl;
		std::cout << "virusName: " << record.virusName << std::endl;
		std::cout << "lenBytes: " << record.lenBytes << std::endl;
		//print_uint64(record.first8bytes);
		//printDigest(record.hash);
		std::cout << "startOffset: " << record.startOffset << std::endl;
		std::cout << "endOffset: " << record.endOffset << std::endl;
		std::cout << "fileType: " << record.fileType << std::endl;
	}

	//Прочитать содержимое записи одного вируса антивирусной базы данных
	Data_Base_Virus Adatabase::readFileRecord(std::ifstream& isf) {
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
	void Adatabase::writeRecordToFile(std::ofstream& outfile, Data_Base_Virus record) {
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




	//Инициализация записи антивирусной базы//поле TotalRecords для отладки
	Data_Base_Virus Adatabase::initVirusRecord(std::string virusname, int virusLength, uint64_t first8bytes1, std::array<uint8_t, 32> hash1, unsigned long long TotalRecords, char* filetype) {
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
}

	/*
	//*********************
	//****Операции утилиты
	//*********************
	//Получить тип файла
	char* Adatabase::getfileType(std::ifstream& is) {
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



	//Напечатать хэш, digest  
	void Adatabase::printDigest(std::array<uint8_t, 32> hash) {
		std::cout << "digest(hex): ";
		std::cout << std::hex;//print hex
		for (int i = 0; i < hash.size(); i++) std::cout << (int)hash[i];
		std::cout << std::dec;//print dec
		std::cout << std::endl;
	}
	//Напечатать first8bytes
	void Adatabase::print_uint64_t(uint64_t first8bytes) {
		std::cout << "8bytes(hex): ";
		std::cout << std::hex;//print hex
		std::cout << first8bytes;
		std::cout << std::dec;//print dec
		std::cout << std::endl;
	}
	*/