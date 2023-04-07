#include "Acommon.h"

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

