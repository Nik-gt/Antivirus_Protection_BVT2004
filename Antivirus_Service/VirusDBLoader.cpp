#pragma once
// ��������� ������������ ���� �� �����
// ��������� ��������� ���� ������������ ���� � ����� ��� ������������ ������ ������ � �������� ������.
// ���� ������������ ���� �������� �������� �������. ������ ������ ��������� ���� �����.
//////////////////
#include "Acommon.h"

class VirusDBLoader {
public:

    //����� ������������ ��� �������� �������� ������� � ����� ��� ������������ ������ ������ � �������� ������
    std::multimap<uint64_t, Data_Base_Virus> virusmap; //1. std::vector<unit64_t>

    //constructor 
    VirusDBLoader() {
    }

    //������ �� ������ ���� ������ ������������ ����
    Data_Base_Virus readFileRecord(std::ifstream& isf) {
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

    //��������� ���� ������������ ���� � ��������� �������� ������� � ���������� ���� �����/map 
    bool loadAntiVirusDatabase(std::string VirusFileName) {
        std::ifstream isf(VirusFileName, std::ifstream::binary);
        if (!isf.is_open()) {
            std::cout << "Can not open antivirus-db: " << VirusFileName << std::endl;
            return false;
        }
        //1.�������� ����� ������ ������������ ����
        char filedId[9] = "Arkhipov";
        char filedIdcheck[9] = "";
        isf.read(filedIdcheck, 9);
        if (filedId[9] != filedIdcheck[9]) {
            std::cout << "Wrong antivirus-db, family field: "<< filedIdcheck << std::endl;
            return false;
        }

        //2.�������� ���������� ������� ������������ ����
        unsigned long long TotalRecords = 0; //8 bytes number
        isf.read((char*)&TotalRecords, 8);
        if (TotalRecords < 1 || TotalRecords > 1000) {
            std::cout << "Wrong antivirus-db, number of virus records field: " << TotalRecords << std::endl;
            return false;
        }

        unsigned long long FileRowNumber = 0;        
        //3.���� ������ ������� �������� �������
        while (FileRowNumber < TotalRecords) {
            Data_Base_Virus BaseData = readFileRecord(isf);
            //��������� �������� ������ � �����
            virusmap.insert(std::pair<uint64_t, Data_Base_Virus>(BaseData.first8bytes, BaseData));
            FileRowNumber = FileRowNumber + 1;
        }
        std::cout << "Loaded ok antivirus-db, TotalRecords: " << TotalRecords << std::endl;
        isf.close();
        return true;
    }
   

    std::multimap<uint64_t, Data_Base_Virus> getVirusmap() {        return virusmap;   }
  



};//end-class

