#pragma once
//Создание антивирусной базы
// ConsoleApplication1.cpp 
#include "Adatabase.h"

//////////////////
//Main function//
/////////////////
int main() {
	const std::string antivirusDbFileName = "D:\\Antivirus_Protection_BVT2004\\newdb.bin";
	//std::string virusFileName;
	//virusFileName = "D:\\Antivirus_Protection_BVT2004\\EICAR\\eicar2.exe";//отладка


	Adatabase antivirusDatabase(antivirusDbFileName);//создание объекта класса антивирусной базы данных

	
	//Загрузить антивирусную базу из файла бд в карту
	//std::multimap<uint64_t, Adatabase::Data_Base_Virus> virusmap;
	//if (antivirusDatabase.loadAntiVirusDatabase(virusmap) == false) return 1;
	 
	

	//Цикл обработки команд пользователя
	while (true) {
		std::cout << "\nEnter virus-file-path or e-exit or r-readDB: ";
		std::string virusFileName;
		std::cin >> virusFileName;
		if (virusFileName == "e") { break; }
		//Выводим все записи базы
		if (virusFileName == "r") {
			antivirusDatabase.printAllDatabase();
			continue;
		}

		//Введено имя файла вируса в std::cin
		//Добавить этот файл в антивирусную бд
		antivirusDatabase.addNewAdatabase(virusFileName);
	}//конец цикла 

	std::cout << std::endl << "finished ok" << std::endl;
	return 0;
}

//virusFileName = "D:\\Antivirus_Protection_BVT2004\\EICAR\\eicar.com";//отладка
//проверка правильности=our eicar.com file starts from 9btes-->
//X5O!P%@AP --ascii
//58354F2150254041 --hex
//----------------------- 
//проверка правильности= digest for our eicar.com
//275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f


