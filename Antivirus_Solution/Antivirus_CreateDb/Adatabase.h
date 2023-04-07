//������������ ���� ������
//�������� � ����� � ������ + �����= VirusDbFileName
#pragma once
#include "Acommon.h"

class Adatabase
{
public:
	//����������. ��������� ��� ����� ������������ ���� ������
	Adatabase(std::string VirusDbFileName);

	//fields
	//VirusDatabase file
	std::string virusDbFileName;
	//����� ������������ ��� �������� �������� ������� � ����� ��� ������������ ������ ������ � �������� ������
	std::multimap<uint64_t, Data_Base_Virus> virusmap; //1. std::vector<unit64_t>


	//*********************
	//****������ �������
	//���������� ���������� ���� ������������ ���� ������
	bool printAllDatabase();

	//�������� ���� ������ � ������������ ��
	void addNewAdatabase(std::string virusFileName);


	//��������� ���� ������������ ���� � ��������� �������� ������� � ���������� ���� �����/map 
	bool loadAntiVirusDatabase(std::multimap<uint64_t, Data_Base_Virus>& virusmap);



private:

	//*********************
	//****������ ���������� ��� ���������� �������
	//��������� ������������ ��������� ����� ������������ ���� ������
	unsigned long long validateDatabase(std::ifstream& isf, unsigned long long& fileLength);

	//��������� ���� �� � �������� �� ���� ������ ����������
	unsigned long long  getDbfile(char*& fileContent, unsigned long long& fileContentLength);

	//��������� ����� ������ ������������ ���� ������� �� ����� ������
	bool newRecordDb(std::string virusFileName, Data_Base_Virus& record, unsigned long long TotalRecords);

	//���������� ������ ������ ������ ������������ ���� ������
	void printRecord(Data_Base_Virus record);

	//������������� ������ ������������ ����//���� TotalRecords ��� �������
	Data_Base_Virus initVirusRecord(std::string virusname, int virusLength, uint64_t first8bytes1, std::array<uint8_t, 32> hash1, unsigned long long TotalRecords, char* filetype);

	//��������� ���������� ������ ������ ������ ������������ ���� ������
	Data_Base_Virus readFileRecord(std::ifstream& isf);

	//�������� � ����� ���� ������ ������������ ����
	void writeRecordToFile(std::ofstream& outfile, Data_Base_Virus record);


	//*********************
	//****������ �������
	//�������� ��� �����
	char* getfileType(std::ifstream& is);

	//���������� ���, digest  
	void printDigest(std::array<uint8_t, 32> hash);

	//���������� first8bytes
	void print_uint64_t(uint64_t first8bytes);

};//class-end

/*
//using
Adatabase adatabase(std::string VirusDbFileName);
adatabase.printAllDatabase();
*/
