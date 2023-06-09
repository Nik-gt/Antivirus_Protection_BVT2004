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
		strcpy(fileType, std::string("Un" + '\0').c_str()); //wrong type in base
		std::cout << "getfileType() Unknown file" << std::endl;//debug
		return fileType;
	}


	//��������� ���� �� ������� ������
	void checkVirusInFile(std::string fileName, std::multimap<uint64_t, Data_Base_Virus> virusmap, PipeServer PipeServer1)// �� ������!!!
	{
		std::cout << std::endl;
		std::ifstream infile(fileName, std::ios_base::binary);
		if (!infile) {
			std::cout << "Not found testing file to scan for virus: " << fileName << std::endl;
			return;
		}

		char* fileType = getfileType(infile);
		if (fileName.substr(fileName.find_last_of('.'), 4) == ".com") {
			strcpy(fileType, std::string("Com" + '\0').c_str()); //Com type in base
			std::cout << "Com file" << std::endl;
		}
		if (memcmp(fileType, std::string("Un" + '\0').c_str(), 3) == 0) return; //��������� ���� ����� � �����

		//������ �����
		infile.seekg(0, infile.end);
		unsigned long long size = infile.tellg();
		infile.seekg(0);

		std::cout << "Start testing for viruses file: " << fileName << " /size: " << size << std::endl;
		//������� 8 �������� ���� ��� ������ �� �����
		char first8bytes[8];//���� ��� 8 ������ �����
		//���� ������ ������������ �� ������ �����
		if (size == -1) return;
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

				//���� ��� ��������� �������� ������� ������ �� ���������� ���� �����
				if (itr->second.startOffset > i || itr->second.endOffset < i) continue;

				//���� ������������ ��� ����� �� ���������� ���� �����
				if (memcmp(itr->second.fileType, fileType, 3) != 0) continue; //��������� ���� ����� � �����
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
				//����� ����������� ���� � ������ � �����.
				i = i + itr->second.lenBytes;//���������� ���� �� ����� ���������� ������
				break;//������� �� ���������
			}//����� ����� �� ���� ������� � ����� ������ 
		}//����� ����� �� �����
		infile.close();
		std::cout << "Finished testing for viruses file" << std::endl;
		return;
	}


	//����������. ��������� ��� ����� ������������ ���� ������
	Adatabase::Adatabase(std::string VirusDbFileName)
	{
		this->virusDbFileName = VirusDbFileName;
	}

	//*********************
	//****�������� �������= public
	//********************* 

	//���������� ���������� ���� ������������ ���� ������
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


	//�������� ���� ������ � ������������ ��
	void Adatabase::addNewVirusToAdatabase(std::string virusFileName) {
		//1.��������� ������������ ��
		std::cout << std::endl;
		unsigned long long fileContentLength = 0;
		char* fileContent;
		unsigned long long totalRecords = getDbfile(fileContent, fileContentLength);
		//std::cout << "Antivirus db-file contains TotalRecords: " << TotalRecords << std::endl;

		//2.���������� ���� ������ � ��������� ������ ����� ������ ������
		Data_Base_Virus record;
		bool isVirusOK = newRecordDb(virusFileName, record, totalRecords);//TotalRecords for debug
		if (!isVirusOK) return;

		//3.������ ���� ���������� ������� � ����� �� �����������
		if (totalRecords < 1) {
			//std::cout << "Not exist db file=" << VirusDbFileName << std::endl;
			totalRecords = 1;//��������� �������� ���-�� �������, ������ ������ ������
		}
		else {
			//std::cout << "Exist db file=" << VirusDbFileName << std::endl;
			totalRecords = totalRecords + 1;
		}

		//4.�������� ��������� ����� ��
		std::ofstream outfile(this->virusDbFileName, std::ofstream::binary);
		//std::cout << "Write header to db-file=" << VirusDbFileName << std::endl;
		char filedId[9] = "Arkhipov";//const for this file!
		//write header data to file
		outfile.write(filedId, 9);// write to file
		//counter of virus records in this file
		outfile.write((char*)&totalRecords, 8);// write to file

		//5.��������� ������ ������ � ������� � ���� ��
		if (totalRecords > 1) {
			//std::cout << "Write/save old virus-records to db-file=" << VirusDbFileName << std::endl;
			outfile.write(fileContent, fileContentLength);
		}
		//6.�������� ����� ������ �������� ������ � �� �����������
		writeRecordToFile(outfile, record);
		outfile.close();
		std::cout << "Added new virus-record to db-file" << std::endl;
	}



	//��������� ���� ������������ ���� � ��������� �������� ������� � ���������� ���� �����/map 
	bool Adatabase::loadAntiVirusDatabase(std::multimap<uint64_t, Data_Base_Virus>& virusmap) {
		std::ifstream isf(virusDbFileName, std::ifstream::binary);
		unsigned long long fileLength = 0;
		unsigned long long totalRecords = validateDatabase(isf, fileLength);
		if (totalRecords < 1) {
			std::cout << "AntiVirusDatabase is empty" << std::endl;
			return false;
		}
		std::cout << "Loading AntiVirusDatabase to map" << std::endl;
		std::cout << "Adatabase contains records: " << totalRecords << std::endl;
		//initialize current row number. starts from 0, 8 bytes
		unsigned long long rowNumber = 0;
		while (rowNumber < totalRecords) {
			//std::cout << "FileRowNumber:"<< FileRowNumber << std::endl;
			Data_Base_Virus baseData = readFileRecord(isf);
			//��������� �������� ������ � �����
			virusmap.insert(std::pair<uint64_t, Data_Base_Virus>(baseData.first8bytes, baseData));
			rowNumber++;
		}
		isf.close();
		std::cout << "Records inserted in map: " << rowNumber << std::endl;
		return true;
	}


	//*********************
	//****�������� ���������� ��� ���������� �������= private
	//*********************

	//��������� ������������ ��������� ����� ������������ ���� ������
	//���������� totalRecords-���������� ������� � ������� � fileLength-����� �����. 
	// ��������� isf ����� ������� ���������� �� ������ ������� �������� �������
	// ���� totalRecords< 1 �� ���� ������ ������������ � � ��� ������ ��������
	//����� ������� � ���. ��� ���� ��������� isf ���������� �� ������ ������� �������� �������
	unsigned long long Adatabase::validateDatabase(std::ifstream& isf, unsigned long long& fileLength) {

		unsigned long long totalRecords = 0; //8 bytes number
		if (!isf.is_open()) {
			std::cout << "Adatabase not exist" << std::endl;
			return totalRecords;
		}
		//����� ����� 
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


	//��������� ���� �� � �������� �� ���� ������ ����������
	//���������� �� ����� �� ���-�� ������� ������� � ���� ������ � ���� ������� � ����� �������
	//���� ���� ����������� ��� ������������ �� ���������� 0, ��� ����� ��������
	unsigned long long  Adatabase::getDbfile(char*& fileContent, unsigned long long& fileContentLength) {
		std::ifstream isf(this->virusDbFileName, std::ifstream::binary);
		unsigned long long fileLength = 0;
		unsigned long long totalRecords = validateDatabase(isf, fileLength);
		if (totalRecords < 1) return totalRecords;
		//std::cout << "Adatabase ok, TotalRecords: " << TotalRecords << std::endl;

		fileContentLength = fileLength - 17;//����� ������ ���� �����
		//std::cout << "fileLength=" << fileLength << " fileContentLength=" << fileContentLength << std::endl;//debug
		fileContent = new char[fileLength];//allocate memory //plus end char
		isf.read(fileContent, fileLength);
		isf.close();
		//std::cout << "fileContent=" << std::endl;printBytes(fileContent, fileContentLength);//debug
		return totalRecords;
	}


	//��������� ����� ������ ������������ ���� ������� �� ����� ������
	//���������� ������ ���� ������� � ����� ���� ���������
	//TotalRecords ��� ������� ���� ��������� ������ ������
	bool Adatabase::newRecordDb(std::string virusFileName, Data_Base_Virus& record, unsigned long long totalRecords) {
		//1.��������� �������� ���� ������/read virus file
		std::ifstream is(virusFileName, std::ifstream::binary);
		if (!is) {
			std::cout << "Not found file for virusFileName: " << virusFileName << std::endl;
			return false;
		}

		//����� ����� ������
		is.seekg(0, is.end);
		unsigned long long virusLength = is.tellg();
		is.seekg(0, is.beg);

		// ���������� ��� �����
		char* filetype = getfileType(is);
		if (virusFileName.substr(virusFileName.find_last_of('.'), 4) == ".com") {
			strcpy(filetype, std::string("Com" + '\0').c_str()); //Com type in base
			std::cout << "Com file" << std::endl; 
		}
		is.seekg(0, is.beg);
		std::cout << "Virus file length: " << virusLength << std::endl;
		//if (virusLength < 65536) {} //�������� ���� ���� ������ 64 ��
		char* virusFile = new char[virusLength];//allocate memory //plus end char
		is.read(virusFile, virusLength);
		//printBytes(virusFile, 8);//debug

		is.close();

		//�������= print virusFile content
		//std::cout.write(virusFile, virusLength) << std::endl;
		virusFile[virusLength] = '\0';//add string end null char
		std::cout << "Processed virusFile ok" << std::endl;

		//2.���������������� ������ ������������ ���� ������� ������
		//.1 ��������� ��������
		SHA256 sha;
		sha.update(virusFile);
		uint8_t* digest = sha.digest();//get digest
		//printDigest(digest);	//�������= print digest
		std::array<uint8_t, 32> hash;//convert digest to array
		memcpy(hash.data(), digest, 32);
		delete[] digest;
		//.2 �������� ������ 8 ���� ����� ������
		uint64_t first8bytes = asciiToUint64(virusFile); // �������������� ������ � uint64_t
		//print_uint64_t_hex(first8bytes);//�������


		//��� ������
		std::string virusname = "";
		int index0 = virusFileName.find_last_of('\\') + 1;
		int index1 = virusFileName.find_last_of('.') - virusFileName.find_last_of('\\') - 1;
		virusname = virusFileName.substr(index0, index1); //".exe"
		//std::cout << "assigned virusname: " << virusname << std::endl;

		//.3 ���������������� ������
		record = initVirusRecord(virusname, virusLength, first8bytes, hash, totalRecords, filetype);
		return true;
	}


	//���������� ������ ������ ������ ������������ ���� ������
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

	//��������� ���������� ������ ������ ������ ������������ ���� ������
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

	//�������� � ����� ���� ������ ������������ ����
	void Adatabase::writeRecordToFile(std::ofstream& outfile, Data_Base_Virus record) {
		//write one virus record
		outfile.write(record.virusName, 16);// write to file
		outfile.write((char*)&record.lenBytes, 8);// write to file
		outfile.write((char*)&record.first8bytes, 8);// ����� ��� multimap
		for (uint8_t it : record.hash) {
			outfile.write((char*)&it, 1);
		}
		outfile.write((char*)&record.startOffset, 8);// write to file
		outfile.write((char*)&record.endOffset, 8);// write to file
		outfile.write(record.fileType, 4);// write to file
	}




	//������������� ������ ������������ ����//���� TotalRecords ��� �������
	Data_Base_Virus Adatabase::initVirusRecord(std::string virusname, int virusLength, uint64_t first8bytes1, std::array<uint8_t, 32> hash1, unsigned long long TotalRecords, char* filetype) {
		TotalRecords++;//�������/����� ��������� ������
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
	//****�������� �������
	//*********************
	//�������� ��� �����
	char* Adatabase::getfileType(std::ifstream& is) {
		// ������ ��������� �����
		//infile.seekg(0, infile.beg);
		char header[3];
		char* fileType = new char[3];
		is.read(header, sizeof(header));

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
		strcpy(fileType, std::string("COM" + '\0').c_str()); //wrong type in base
		std::cout << "Unknown file (COM)!" << std::endl;
		return fileType;
	}



	//���������� ���, digest  
	void Adatabase::printDigest(std::array<uint8_t, 32> hash) {
		std::cout << "digest(hex): ";
		std::cout << std::hex;//print hex
		for (int i = 0; i < hash.size(); i++) std::cout << (int)hash[i];
		std::cout << std::dec;//print dec
		std::cout << std::endl;
	}
	//���������� first8bytes
	void Adatabase::print_uint64_t(uint64_t first8bytes) {
		std::cout << "8bytes(hex): ";
		std::cout << std::hex;//print hex
		std::cout << first8bytes;
		std::cout << std::dec;//print dec
		std::cout << std::endl;
	}
	*/