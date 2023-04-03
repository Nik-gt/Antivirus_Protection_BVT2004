#pragma once
#include <iostream>
#include <fstream> 
#include <sstream>
#include <string>
#include <map>
#include <windows.h> 
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#pragma warning(disable:4996)

//////////////////
//  VirusDBLoader ///
//////////////////
class VirusDBLoader {
public:
    //virus description structure and variable
    struct Data_Base_Virus
    {
        std::string Name;//virus name to print
        long long LenBytes;    //virus length
        std::string Bytes;
        long long StartOffset;
        long long EndOffset;
        std::string FileType;
    } ;

    //fields
    //virusmap contains loaded viruses descriptions
    //map-key is first 8 bytes of Bytes field (virus signature)
    std::multimap<std::string, Data_Base_Virus> virusmap;

    //constructor and methods
    VirusDBLoader() {
    }
    //parse line to fields
    //string-->struct Data_Base_Virus
    Data_Base_Virus parseLine(std::string Line) {
        Data_Base_Virus BaseData;//parsed line data
        std::string Buffstr;
        std::stringstream LineStream;
        LineStream << Line;
        int i = 0; //field number inside one line
        while (std::getline(LineStream, Buffstr, ';'))
        {
            //parse values to struct fields
            if (i == 0) BaseData.Name = Buffstr;
            if (i == 1) BaseData.LenBytes = std::stoll(Buffstr, nullptr, 10);
            if (i == 2) BaseData.Bytes = Buffstr;
            if (i == 3) BaseData.StartOffset = std::stoll(Buffstr, nullptr, 10);
            if (i == 4) BaseData.EndOffset = std::stoll(Buffstr, nullptr, 10);
            if (i == 5) { BaseData.FileType = Buffstr; i = 0; }
            //debug std::cout << "i=" << i << " val=" << Buffstr << " ";
            i++;
        }
        //std::cout << std::endl;
        return BaseData;
    }

    //read file with viruses descriptiond to map variable
    bool readFileVirusDatabase(std::string VirusFileName) {
        //variables
        long long TotalRecords = 0; //8 bytes number

        //open file
        std::ifstream VirusFile;
        VirusFile.open(VirusFileName);
        std::string Line;
        if (!VirusFile.is_open()) {
            std::cout << "Can not open file=" << VirusFileName << std::endl;
            return false;
        }

        //row number starts from 0, 8 bytes
        long long FileRowNumber = 0;
        //read file by lines
        while (VirusFile) {
            std::getline(VirusFile, Line);
            //row 0--> check if file is correct for virus signatures
             //files first line must contain family
            if (FileRowNumber == 0) {
                if (Line == "Arkhipov") {
                    std::cout << "Database family=" << Line << std::endl;
                    FileRowNumber = FileRowNumber + 1;
                    continue;
                }
                else {
                    std::cout << "Wrong virus database, family field" << std::endl;
                    return false;
                }
            }
            //row 1--> must contain number of virus records   
            if (FileRowNumber == 1) {
                TotalRecords = std::stoll(Line, nullptr, 10);
                if (TotalRecords < 1 || TotalRecords > 1000) {
                    std::cout << "Wrong virus database, number of virus records field=" << TotalRecords << std::endl;
                    return false;
                }
                else {
                    std::cout << "Total virus records in file=" << TotalRecords << std::endl;
                    FileRowNumber = FileRowNumber + 1;
                    continue;
                }
            }
            //if read all records assigned in TotalRecords then finish read data
            if (FileRowNumber > (TotalRecords + 2)) {
                std::cout << "Read read all records assigned in TotalRecords, current recod number=" << FileRowNumber << " , skip it" << std::endl;
                break;
            }

            //if read empty line skip it
            if (Line.size() == 0) {
                //DEBUG std::cout << "Read empty line number=" << FileRowNumber << " , skip it" << std::endl;
                FileRowNumber = FileRowNumber + 1;
                continue;
            }

            Data_Base_Virus BaseData = parseLine(Line);
            //debug// printRecord(BaseData);
            
            //add to map virus data, one record=structure BaseData
            //map key is first 8 bytes of Bytes field (virus signature)
            std::string key = BaseData.Bytes.substr(0, 8);
            virusmap.insert(std::pair<std::string, Data_Base_Virus>(key, BaseData));
            Line = "";
            FileRowNumber = FileRowNumber + 1;
        }
        VirusFile.close();
        //check virus records number in virusmap
        std::cout << "Virus map size:" << virusmap.size() << std::endl;
        if (virusmap.size() < 1) {
            std::cout << "ERROR.No items loaded in virus map" << std::endl;
            return false;
        }
        //good virus-db map
        return true;
    }

    //print one virus record to debug
    void printRecord(Data_Base_Virus BaseData) {
        std::cout << "BaseData->";
        std::cout << " Name->" << BaseData.Name;
        std::cout << " Len->"<< BaseData.LenBytes ;
        std::cout << " Bytes8->"<< BaseData.Bytes.substr(0, 8);//first 8 bytes only!!
        std::cout << " Start->"<< BaseData.StartOffset;
        std::cout << " End->" << BaseData.EndOffset;
        std::cout << " FType->" << BaseData.FileType;
        std::cout << std::endl;
    }
   
};//end-class