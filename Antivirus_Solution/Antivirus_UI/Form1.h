#pragma once
//Программа антивирусной защиты
//Содержит графический интерфейс необходимый для запуска сканирования на вирус выбранных папок
//Для начала сканирования нажмите кнопку Сканирование папки
#include "PipeClient.h"
#include <iostream>
#include <string>
#include <windows.h> 
#include <stdio.h> 
#include <tchar.h> 

namespace CppCLRWinformsProjekt {
	public ref class Form1 : public System::Windows::Forms::Form
	{
	public:
		Form1(void)
		{
			InitializeComponent();
			//TODO: Konstruktorcode hier hinzufьgen.
		}
	protected:
		/// Verwendete Ressourcen bereinigen.
		~Form1()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Label^ label7;
	public: System::Windows::Forms::ListBox^ listBox1;
	private:


	private:

	private:
	protected:

		
	private: System::Windows::Forms::Button^ button2;
	private: System::Windows::Forms::Label^ label6;
	private: System::Windows::Forms::ComboBox^ comboBox1;
	private: System::Windows::Forms::Label^ label4;
	private: System::Windows::Forms::Label^ label5;
	private: System::Windows::Forms::Label^ label3;
	private: System::Windows::Forms::Label^ label2;
	private: System::Windows::Forms::Label^ label1;
	private: System::Windows::Forms::Button^ button1;
	private: System::Windows::Forms::CheckBox^ checkBox1;
	private: System::Windows::Forms::RadioButton^ radioButtonFolder;
	private: System::Windows::Forms::RadioButton^ radioButtonFile;


	private: System::Windows::Forms::GroupBox^ groupBox1;

	private: System::ComponentModel::IContainer^ components;

	private:


#pragma region Windows Form Designer generated code
		void InitializeComponent(void)
		{
			this->label7 = (gcnew System::Windows::Forms::Label());
			this->listBox1 = (gcnew System::Windows::Forms::ListBox());
			this->button2 = (gcnew System::Windows::Forms::Button());
			this->label6 = (gcnew System::Windows::Forms::Label());
			this->comboBox1 = (gcnew System::Windows::Forms::ComboBox());
			this->label4 = (gcnew System::Windows::Forms::Label());
			this->label5 = (gcnew System::Windows::Forms::Label());
			this->label3 = (gcnew System::Windows::Forms::Label());
			this->label2 = (gcnew System::Windows::Forms::Label());
			this->label1 = (gcnew System::Windows::Forms::Label());
			this->button1 = (gcnew System::Windows::Forms::Button());
			this->checkBox1 = (gcnew System::Windows::Forms::CheckBox());
			this->radioButtonFolder = (gcnew System::Windows::Forms::RadioButton());
			this->radioButtonFile = (gcnew System::Windows::Forms::RadioButton());
			this->groupBox1 = (gcnew System::Windows::Forms::GroupBox());
			this->groupBox1->SuspendLayout();
			this->SuspendLayout();
			// 
			// label7
			// 
			this->label7->AutoSize = true;
			this->label7->Location = System::Drawing::Point(183, 27);
			this->label7->Name = L"label7";
			this->label7->Size = System::Drawing::Size(0, 13);
			this->label7->TabIndex = 23;
			// 
			// listBox1
			// 
			this->listBox1->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Bottom)
				| System::Windows::Forms::AnchorStyles::Left)
				| System::Windows::Forms::AnchorStyles::Right));
			this->listBox1->BackColor = System::Drawing::SystemColors::GradientInactiveCaption;
			this->listBox1->FormattingEnabled = true;
			this->listBox1->Location = System::Drawing::Point(36, 139);
			this->listBox1->Name = L"listBox1";
			this->listBox1->Size = System::Drawing::Size(659, 290);
			this->listBox1->TabIndex = 22;
			// 
			// button2
			// 
			this->button2->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Right));
			this->button2->Enabled = false;
			this->button2->Location = System::Drawing::Point(469, 19);
			this->button2->Name = L"button2";
			this->button2->Size = System::Drawing::Size(222, 29);
			this->button2->TabIndex = 21;
			this->button2->Text = L"Открыть логи сканирования";
			this->button2->UseVisualStyleBackColor = true;
			// 
			// label6
			// 
			this->label6->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Right));
			this->label6->AutoSize = true;
			this->label6->Location = System::Drawing::Point(466, 64);
			this->label6->Name = L"label6";
			this->label6->Size = System::Drawing::Size(225, 13);
			this->label6->TabIndex = 20;
			this->label6->Text = L"Интервал автоматического сканирования:";
			// 
			// comboBox1
			// 
			this->comboBox1->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Top | System::Windows::Forms::AnchorStyles::Right));
			this->comboBox1->Enabled = false;
			this->comboBox1->FormattingEnabled = true;
			this->comboBox1->ImeMode = System::Windows::Forms::ImeMode::NoControl;
			this->comboBox1->Items->AddRange(gcnew cli::array< System::Object^  >(7) {
				L"Отключено", L"1 минута", L"10 минут", L"30 минут",
					L"1 час", L"6 часов", L"12 часов"
			});
			this->comboBox1->Location = System::Drawing::Point(570, 97);
			this->comboBox1->Name = L"comboBox1";
			this->comboBox1->Size = System::Drawing::Size(121, 21);
			this->comboBox1->TabIndex = 19;
			this->comboBox1->Text = L"Отключено";
			// 
			// label4
			// 
			this->label4->AutoSize = true;
			this->label4->Location = System::Drawing::Point(144, 64);
			this->label4->Name = L"label4";
			this->label4->Size = System::Drawing::Size(22, 13);
			this->label4->TabIndex = 18;
			this->label4->Text = L"-----";
			// 
			// label5
			// 
			this->label5->AutoSize = true;
			this->label5->Location = System::Drawing::Point(33, 64);
			this->label5->Name = L"label5";
			this->label5->Size = System::Drawing::Size(108, 13);
			this->label5->TabIndex = 17;
			this->label5->Text = L"Файлов проверено:";
			// 
			// label3
			// 
			this->label3->AutoSize = true;
			this->label3->Location = System::Drawing::Point(36, 27);
			this->label3->Name = L"label3";
			this->label3->Size = System::Drawing::Size(161, 13);
			this->label3->TabIndex = 16;
			this->label3->Text = L"Сканер готов к сканированию";
			// 
			// label2
			// 
			this->label2->AutoSize = true;
			this->label2->Location = System::Drawing::Point(144, 97);
			this->label2->Name = L"label2";
			this->label2->Size = System::Drawing::Size(22, 13);
			this->label2->TabIndex = 15;
			this->label2->Text = L"-----";
			// 
			// label1
			// 
			this->label1->AutoSize = true;
			this->label1->Location = System::Drawing::Point(33, 97);
			this->label1->Name = L"label1";
			this->label1->Size = System::Drawing::Size(105, 13);
			this->label1->TabIndex = 14;
			this->label1->Text = L"Угроз обнаружено:";
			// 
			// button1
			// 
			this->button1->Anchor = static_cast<System::Windows::Forms::AnchorStyles>(((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Left)
				| System::Windows::Forms::AnchorStyles::Right));
			this->button1->BackColor = System::Drawing::SystemColors::Control;
			this->button1->FlatStyle = System::Windows::Forms::FlatStyle::Popup;
			this->button1->Font = (gcnew System::Drawing::Font(L"Microsoft Sans Serif", 12.25F, System::Drawing::FontStyle::Regular, System::Drawing::GraphicsUnit::Point,
				static_cast<System::Byte>(204)));
			this->button1->Location = System::Drawing::Point(39, 492);
			this->button1->Name = L"button1";
			this->button1->Size = System::Drawing::Size(656, 59);
			this->button1->TabIndex = 13;
			this->button1->Text = L"Начать cканирование";
			this->button1->UseVisualStyleBackColor = false;
			this->button1->Click += gcnew System::EventHandler(this, &Form1::button1_Click);
			// 
			// checkBox1
			// 
			this->checkBox1->Anchor = static_cast<System::Windows::Forms::AnchorStyles>((System::Windows::Forms::AnchorStyles::Bottom | System::Windows::Forms::AnchorStyles::Right));
			this->checkBox1->AutoSize = true;
			this->checkBox1->Location = System::Drawing::Point(566, 19);
			this->checkBox1->Name = L"checkBox1";
			this->checkBox1->Size = System::Drawing::Size(87, 17);
			this->checkBox1->TabIndex = 24;
			this->checkBox1->Text = L"Мониторинг";
			this->checkBox1->UseVisualStyleBackColor = true;
			// 
			// radioButtonFolder
			// 
			this->radioButtonFolder->AutoSize = true;
			this->radioButtonFolder->Checked = true;
			this->radioButtonFolder->Location = System::Drawing::Point(6, 19);
			this->radioButtonFolder->Name = L"radioButtonFolder";
			this->radioButtonFolder->Size = System::Drawing::Size(131, 17);
			this->radioButtonFolder->TabIndex = 25;
			this->radioButtonFolder->TabStop = true;
			this->radioButtonFolder->Text = L"Сканирование папки";
			this->radioButtonFolder->UseVisualStyleBackColor = true;
			this->radioButtonFolder->CheckedChanged += gcnew System::EventHandler(this, &Form1::radioButtonFolder_CheckedChanged);
			// 
			// radioButtonFile
			// 
			this->radioButtonFile->AutoSize = true;
			this->radioButtonFile->Location = System::Drawing::Point(147, 19);
			this->radioButtonFile->Name = L"radioButtonFile";
			this->radioButtonFile->Size = System::Drawing::Size(133, 17);
			this->radioButtonFile->TabIndex = 26;
			this->radioButtonFile->Text = L"Сканирование файла";
			this->radioButtonFile->UseVisualStyleBackColor = true;
			this->radioButtonFile->CheckedChanged += gcnew System::EventHandler(this, &Form1::radioButtonFile_CheckedChanged);
			// 
			// groupBox1
			// 
			this->groupBox1->Controls->Add(this->radioButtonFolder);
			this->groupBox1->Controls->Add(this->checkBox1);
			this->groupBox1->Controls->Add(this->radioButtonFile);
			this->groupBox1->Location = System::Drawing::Point(36, 435);
			this->groupBox1->Name = L"groupBox1";
			this->groupBox1->Size = System::Drawing::Size(659, 45);
			this->groupBox1->TabIndex = 27;
			this->groupBox1->TabStop = false;
			this->groupBox1->Text = L"Параметры сканирования";
			// 
			// Form1
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(6, 13);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->ClientSize = System::Drawing::Size(728, 571);
			this->Controls->Add(this->groupBox1);
			this->Controls->Add(this->label7);
			this->Controls->Add(this->listBox1);
			this->Controls->Add(this->button2);
			this->Controls->Add(this->label6);
			this->Controls->Add(this->comboBox1);
			this->Controls->Add(this->label4);
			this->Controls->Add(this->label5);
			this->Controls->Add(this->label3);
			this->Controls->Add(this->label2);
			this->Controls->Add(this->label1);
			this->Controls->Add(this->button1);
			this->MinimumSize = System::Drawing::Size(650, 604);
			this->Name = L"Form1";
			this->Text = L"Form1";
			this->Load += gcnew System::EventHandler(this, &Form1::Form1_Load);
			this->groupBox1->ResumeLayout(false);
			this->groupBox1->PerformLayout();
			this->ResumeLayout(false);
			this->PerformLayout();

		}
#pragma endregion

///////////////////
//  ПЕРЕМЕННЫЕ  //
PipeClient^ PipeClient1;

//////////////////////		
//Инициализируем форму
private: System::Void Form1_Load(System::Object^ sender, System::EventArgs^ e) {
	//Получаем имя пользователя, сопоставленное с текущим потоком
	System::String^ userName = System::Environment::UserName;
	char* userName2 = (char*)(void*)System::Runtime::InteropServices::Marshal::StringToHGlobalAnsi(userName);
	LPCSTR userName3 = userName2;
	//System::Windows::Forms::MessageBox::Show("userName="+ userName);//отладка

	//Предотвращаем повторный запуск прораммы с помощью мютекса
	HANDLE mutex = OpenMutexA(MUTEX_ALL_ACCESS, TRUE, userName3);
	if (mutex == NULL) {
		mutex = CreateMutexA(NULL, FALSE, userName3);//Создать мютекс first
	}
	else {
		System::Windows::Forms::MessageBox::Show("Приложение уже запущено.");
		System::Windows::Forms::Application::Exit();
	}
	//Создать клиента именованного канала
	PipeClient1 = gcnew PipeClient();
}
/////////////////////////////////////
//Нажатие кнопки= Сканирование папки	   
private: System::Void button1_Click(System::Object^ sender, System::EventArgs^ e) {
	listBox1->Items->Clear();
	label2->Text = "0";
	label4->Text = "0";

	if (!radioButtonFolder->Checked & !radioButtonFile->Checked) System::Windows::Forms::MessageBox::Show("Выберите тип сканирования.");
	System::String^ BtnText = button1->Text;
	if (BtnText == "Остановить мониторинг" || BtnText == "Остановить сканирование") {
		PipeClient1->PipeWrite("StopScan|", "");
	}
	if (BtnText == "Начать cканирование") {
		button1->Text = "Остановить сканирование";
		if (checkBox1->Checked) button1->Text = "Остановить мониторинг";
		//Выполнить сканирование
		if (radioButtonFolder->Checked) RunFolderScan();
		if (radioButtonFile->Checked) RunFileScan();
	}	
}

/////////////////
//Запуск сканирования папки
//delegate void SetVoidDelegate();
int count = 0;
//std::string messageresult = "";
System::String^ Result;

//void ChangeText(int count, std::string messageresult)
void ChangeText()
{
	std::string messageresult = strtok((char*)(void*)System::Runtime::InteropServices::Marshal::StringToHGlobalAnsi(Result), "|");
	if (messageresult != "ResultScan")
	{
		count += 1;
		listBox1->Items->Add(gcnew System::String(messageresult.c_str()));
		label2->Text = count.ToString();
		return;
	}
	messageresult = strtok(NULL, "|");
	label4->Text = gcnew System::String(messageresult.c_str());
	label3->Text = "Последнее сканирование: ";
	label7->Text = System::DateTime::Now.ToString("yyyy-MM-dd-HH:mm");
	button1->Text = "Начать cканирование";
	button1->Enabled = true;
	listBox1->Items->Add("");
	listBox1->Items->Add("Конец сканирования!");
}

void ScanResult() {
	count = 0;
	std::string messageresult;
	do
	{//get data
		//System::String^ Result = PipeClient1->PipeRead();
		Result = PipeClient1->PipeRead();
		//messageresult = strtok((char*)(void*)System::Runtime::InteropServices::Marshal::StringToHGlobalAnsi(Result), "|");
		messageresult = strtok((char*)(void*)System::Runtime::InteropServices::Marshal::StringToHGlobalAnsi(Result), "|");

		this->Invoke(gcnew System::Action(this, &Form1::ChangeText));

		//SetVoidDelegate^ d = gcnew SetVoidDelegate(this, &Form1::ChangeText(count, messageresult));
		//this->Invoke(d);
		//this->ChangeText(count, messageresult);
	} while (messageresult != "ResultScan");	
	Result = "";
}

void RunFileScan() {
	std::string message = "ManualFileScan|";
	
	System::IO::Stream^ myStream;
	System::Windows::Forms::OpenFileDialog^ openFileDialog1 = gcnew System::Windows::Forms::OpenFileDialog;
	//Setup dialog box
	openFileDialog1->InitialDirectory = "D:\\";
	openFileDialog1->Filter = "All files (*.*)|*.*|Exe files(*.*) | *.exe";
	openFileDialog1->FilterIndex = 2;
	openFileDialog1->RestoreDirectory = true;

	if (openFileDialog1->ShowDialog() == System::Windows::Forms::DialogResult::OK)
	{
		if ((myStream = openFileDialog1->OpenFile()) != nullptr)
		{
			// Insert code to read the stream here.
			myStream->Close();
			//put data
			System::String^ SelectedDirectory = openFileDialog1->FileName;
			PipeClient1->PipeWrite(message, SelectedDirectory);
		}
	}
	ScanResult();
}

void RunFolderScan()
{
	std::string message = "ManualFolderScan|";
	if (checkBox1->Checked) std::string message = "MonitoringScan|";
	System::String^ SelectedDirectory;
	//SelectedDirectory = "D:\\Projects_antivirus\\EICAR";	PipeClient1->PipeWrite(message, SelectedDirectory);//отладка
	System::Windows::Forms::FolderBrowserDialog^ SelectFolderDialog = gcnew System::Windows::Forms::FolderBrowserDialog();
	//Setup dialog box
	SelectFolderDialog->Description = "Select directory to scan";
	SelectFolderDialog->ShowNewFolderButton = false;
	SelectFolderDialog->GetType();
	SelectFolderDialog->RootFolder = System::Environment::SpecialFolder::Desktop;

	SelectFolderDialog->SelectedPath = SelectedDirectory;
	//Display dialog box
	if (SelectFolderDialog->ShowDialog() == System::Windows::Forms::DialogResult::OK)
	{
		SelectedDirectory = SelectFolderDialog->SelectedPath;
		//put data
		PipeClient1->PipeWrite(message, SelectedDirectory);
	}
	else return; 

	ScanResult();
	//System::Threading::ThreadStart(ScanResult());
	//System::Threading::Thread^ thread1 = gcnew System::Threading::Thread(gcnew System::Threading::ThreadStart(this, &Form1::ScanResult));
	//thread1->Name = "thread1";
	//thread1->Start();

	//ScanResult();
		/*
		if (messageresult != "ResultScan")
		{
			count += 1;			
			listBox1->Items->Add(gcnew System::String(messageresult.c_str()));
			label2->Text = count.ToString();
		}
	} while (messageresult != "ResultScan");
	messageresult = strtok(NULL, "|");
	label4->Text = gcnew System::String(messageresult.c_str());
	*/
}


private: System::Void radioButtonFile_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	checkBox1->Enabled = false;
}
private: System::Void radioButtonFolder_CheckedChanged(System::Object^ sender, System::EventArgs^ e) {
	checkBox1->Enabled = true;
}
};//end-class
}//end-namespace
/*
	CHAR userName[MAX_PATH];
	DWORD size;
	size = sizeof(userName);		// размер буфера
	UINT us = GetUserNameA(userName, &size);
	*/
	//button1->Enabled = false;