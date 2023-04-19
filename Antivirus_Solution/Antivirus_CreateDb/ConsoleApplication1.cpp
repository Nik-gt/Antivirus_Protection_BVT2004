#pragma once
//Проект DB - Создание антивирусной базы
// ConsoleApplication1.cpp 
#include "..\Antivirus_StaticLib\AvirCommon.h"

//////////////////
//Main function//
/////////////////
int main() {
	const std::string antivirusDbFileName = "D:\\Antivirus_Protection_BVT2004\\newdb.bin";
	
	//AvirCommon::printHello2();
	AvirCommon::Adatabase antivirusDatabase(antivirusDbFileName);

	//std::string virusFileName;
	//virusFileName = "D:\\Antivirus_Protection_BVT2004\\EICAR\\eicar2.exe";//отладка
	

	//Цикл обработки команд пользователя
	while (true) {
		std::cout << "\nEnter virus-file-path, p-printDB, e-exit: ";
		std::string virusFileName;
		std::cin >> virusFileName;
		if (virusFileName == "e") { 
			break; 
		}
		//Выводим все записи базы
		if (virusFileName == "p") {
			antivirusDatabase.printAllDatabase();
			continue;
		}

		//Введено имя файла вируса в std::cin
		//Добавить этот файл в антивирусную бд
		antivirusDatabase.addNewVirusToAdatabase(virusFileName);
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


