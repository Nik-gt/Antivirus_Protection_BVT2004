#pragma once

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
#include <list>
#include <queue>
#include <filesystem>
#include <vector>
#include <array>
#include <algorithm>;
#include <ole2.h>  
#include <filesystem>

#include "icrsint.h"
#include "SHA256.h"
//#include "PipeServer.cpp"

#pragma warning(disable:4996)

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
//std::vector<std::string> getFilesForFolder(std::string path);
//�������� ��� �����
//char* getfileType(std::ifstream& infile);
//��������� ���� �� ������� ������
//void checkVirusInFile(std::string FileName, std::multimap<uint64_t, Data_Base_Virus> virusmap, PipeServer PipeServer1);// �� ������!!!


