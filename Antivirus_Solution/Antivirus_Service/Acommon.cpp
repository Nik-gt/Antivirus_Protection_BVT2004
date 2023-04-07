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
        if (p.is_regular_file()) //�� ����������
        {
            all.push_back(p.path().string()); // ��������� ���� � ������
        }
        else // ���� ����������
        {
            std::cout << p.path().string() << std::endl;
            xxall = getFilesForFolder(p.path().string());
            for (int i = 0; i < xxall.size(); i++) { all.push_back(xxall[i]); } // ��
            xxall.erase(xxall.begin(), xxall.end());
        }
    }
    return all;
}


//�������� ��� �����
char* getfileType(std::ifstream& infile) {
    // ������ ��������� �����
    char header[3];
    char* fileType = new char[3];
    infile.read(header, sizeof(header));

    // �������� ���� ����� PE
    if (header[0] == 'M' && header[1] == 'Z')
    {
        std::cout << "PE file" << std::endl;
        strcpy(fileType, std::string("PE" + '\0').c_str());
        return fileType;
    }
    // �������� ���� ����� ZIP
    if (header[0] == 'P' && header[1] == 'K')
    {
        std::cout << "ZIP file" << std::endl;

        strcpy(fileType, std::string("ZIP" + '\0').c_str());
        return fileType;
    }
    // �������� ���� ����� RAR
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


//��������� ���� �� ������� ������
void checkVirusInFile(std::string fileName, std::multimap<uint64_t, Data_Base_Virus> virusmap, PipeServer PipeServer1)// �� ������!!!
{
    std::cout << std::endl;
    std::ifstream infile(fileName, std::ios_base::binary);
    if (!infile) {
        std::cout << "Not found file testing for virus: " << fileName << std::endl;
        return;
    }

    char* fileType = getfileType(infile);
    //������ �����
    infile.seekg(0, infile.end);
    long long size = infile.tellg();
    infile.seekg(0);

    std::cout << "Start testing for viruses file: " << fileName << " /size: " << size << std::endl;
    //������� 8 �������� ���� ��� ������ �� �����
    char first8bytes[8];//���� ��� 8 ������ �����
    //���� ������ ������������ �� ������ �����
    for (unsigned long long i = 0; i <= size - 7; i++)
    {
        std::cout << "i: " << i << std::endl;//todo
        //��������� ��������� ����� �� ������� ����
        infile.seekg(i);
        infile.read(first8bytes, 8);//������ �� ����� �� 8 ������
        //�������������� ������ � ��� �����/����� � uint64_t
        uint64_t bufferkey = asciiToUint64(first8bytes);

        //����� ������ 8 ������ ������� � ����� 
        //���� �� ���� ������� � ����� ������
        for (auto itr = virusmap.find(bufferkey); itr != virusmap.end(); itr++) {
            //���� ����� �� 8 ��������� ����� �������� �� ����� 8 ���� �������
            std::cout << "Found first8bytes: " << itr->second.virusName << " /at i: " << i << std::endl;

            //���� ������ ������ ������� �� ������� ����� ��  ���������� ���� �����  
            if (itr->second.lenBytes > (size - i)) continue;

            //�������!!
            //���� ��� ��������� �������� ������� ������ �� ���������� ���� �����
            //�������!! if (itr->second.startOffset > i || itr->second.endOffset < i) continue;
            //���� ������������ ��� ����� �� ���������� ���� �����
            //�������!! if (memcmp(itr->second.fileType, fileType, 3) != 0) continue; //��������� ���� ����� � �����
            //�������!! 

            //������� ����� ������ �� �����
            char* filehash = new char[itr->second.lenBytes];

            //��������� ��������� ����� �� ������� ����(�������� �� 8���� �����)
            infile.seekg(i);
            //��������� ����� ��� ���������� ����, �����=lenBytes
            infile.read(filehash, itr->second.lenBytes);
            filehash[itr->second.lenBytes] = '\0';
            //std::cout << "filehash: " << filehash << std::endl;//�������
            SHA256 sha;
            sha.update(filehash);//��������� ���
            uint8_t* digest = sha.digest();//������� ��� �� ������������ �����

            //3 ������� ��� ���� �� ����� � �� ���� �����������
            int n = memcmp(itr->second.hash.data(), digest, 32);
            if (n != 0) { //���� ���� �� ����� ��  ���������� ���� ����� 
                continue; //�������� ��������� ����� ���������
            }
            std::cout << "Found virus name: " << itr->second.virusName << " /virus_length: " << itr->second.lenBytes << " /at i: " << i << std::endl;
            PipeServer1.PipeWrite(std::string(itr->second.virusName) + " - " + fileName + "|");
            //PipeServer1.PipeWrite(itr->second.virusName + std::string("|"));
            //std::cout << "bufferkey: " << itr->first << std::endl;
            break;//����� ����������� ���� � ������ � �����.�������� � ���������� //return;///
        }//����� ����� �� ���� ������� � ����� ������ 
    }//����� ����� �� �����
    infile.close();
    std::cout << "Finished testing for viruses file" << std::endl;
    return;
}

