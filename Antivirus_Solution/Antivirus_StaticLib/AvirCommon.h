#pragma once
//�������� �������:
//�������� ����� ������� � 
//����� ��������� - ������ �������� ������ ������ �� ����� ������������ ����  � 
//����� - ���������� ������������ ���� ������ ��� ��������
#include <iostream>
#include <fstream> 
#include <sstream>
#include <string>
#include <map>
#include <windows.h> 
#include <future>
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <vector>
#include <array>
#include <list>
#include <queue>
#include <ole2.h>  
#include "icrsint.h"
#include "SHA256.h"
#include "PipeServer.cpp"
#pragma warning(disable:4996)

namespace AvirCommon{

//������ �������� ������ ������ �� ����� ������������ ���� 
struct Data_Base_Virus
{
    char* virusName = new char[16]; //�������� ������ ��� ��� ������������� ����� �������
    unsigned long long	lenBytes;   //����� ������
    uint64_t			first8bytes;//������ 8 ���� ������
    std::array<uint8_t, 32> hash;   //�������� ������, SHA256, 32����   
    unsigned long long	startOffset;//�������� ������ ������ ������
    unsigned long long	endOffset;  //�������� ����� ������ ������
    char fileType[4];              //��� ����� � ������� �������� ������ �����
};


//convert char* to uint64_t 8bytes
uint64_t asciiToUint64(char* str);

//�������� ������ ������ ��� �������� �����/����������
std::vector<std::string> getFilesForFolder(std::string path);


//�������� ��� �����
char* getfileType(std::ifstream& infile);

//��������� ���� �� ������� ������
void checkVirusInFile(std::string FileName, std::multimap<uint64_t, Data_Base_Virus> virusmap, PipeServer PipeServer1);


//void printHello2();



//������������ ���� ������
//�������� � ����� � ������ + �����= VirusDbFileName
class Adatabase
{
private:
	//fields
	std::string virusDbFileName;
	//����� ������������ ��� �������� �������� ������� � ����� ��� ������������ ������ ������ � �������� ������
	std::multimap<uint64_t, Data_Base_Virus> virusmap; //1. std::vector<unit64_t>


public:

	//����������. ��������� ��� ����� ������������ ���� ������
	Adatabase(std::string VirusDbFileName);


	//*********************
	//****������ �������
	//���������� ���������� ���� ������������ ���� ������
	void printAllDatabase();

	//�������� ���� ������ � ������������ ��
	void addNewVirusToAdatabase(std::string virusFileName);

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
	//char* getfileType(std::ifstream& is);

	//���������� ���, digest  
	//void printDigest(std::array<uint8_t, 32> hash);

	//���������� first8bytes
	//void print_uint64_t(uint64_t first8bytes);

	//convert char* to uint64_t 8bytes
	//uint64_t asciiToUint64(char* str);
};//class-end

}