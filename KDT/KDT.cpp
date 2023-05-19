#include <iostream>
#include <fstream>
#include <string>
#include "Windows.h"
#include <sstream>

using namespace std;

string PIN_DIR = "C:\\pin";
string PINTOOL_DIR = "C:\\pintool";
string PINEXE;
string PINTOOL32;
string PINTOOL64;
string LOADDLL32;
string LOADDLL64;
string GETFILEINFO = "DIE\\diec.exe";
string CONFIG = "KDT.cfg";

string ExePath() {
	wchar_t buffer[MAX_PATH];
	GetModuleFileName(NULL, (LPWSTR)buffer, MAX_PATH);
	wstring ws(buffer);
	string current_directory(ws.begin(), ws.end());
	string::size_type pos = current_directory.find_last_of("\\/");
	return current_directory.substr(0, pos);
}

string WorkingPath() {
	wchar_t buffer[MAX_PATH];
	GetCurrentDirectory(MAX_PATH, buffer);
	wstring ws(buffer);
	string working_directory(ws.begin(), ws.end());
	/*string::size_type pos = working_directory.find_last_of("\\/");
	return working_directory.substr(0, pos);*/
	return working_directory;
}

int read_config_file(string config_file) {
	CONFIG = ExePath() + "\\" + CONFIG;	

	ifstream infile(CONFIG);
	if (!infile) {
		cout << "No config file." << endl;
		exit(1);
	}

	string line;
	
	while (!infile.eof()) {
		getline(infile, line);
		if (line.find("PIN_DIR") != string::npos) {
			size_t pos = line.find("=");
			PIN_DIR = line.substr(pos + 1);
		}
		else if (line.find("PINTOOL_DIR") != string::npos) {
			size_t pos = line.find("=");
			PINTOOL_DIR = line.substr(pos + 1);
		}
	}
	PINEXE = PIN_DIR + "\\pin.exe";
	PINTOOL32 = PINTOOL_DIR + "\\ThemidaPinAnalyzer32.dll";
	PINTOOL64 = PINTOOL_DIR + "\\ThemidaPinAnalyzer64.dll";
	LOADDLL32 = PINTOOL_DIR + "\\LoadDLL32.exe";
	LOADDLL64 = PINTOOL_DIR + "\\LoadDLL64.exe";
	GETFILEINFO = PINTOOL_DIR + "\\" + GETFILEINFO;
	CONFIG = PINTOOL_DIR + "\\" + CONFIG;
}

int check_output_file(string out_file_path) {
	if (out_file_path.substr(0, 2) == ".\\") {
		out_file_path = out_file_path.substr(2);
	}
	out_file_path = WorkingPath() + "\\" + out_file_path;
	cout << out_file_path << endl;
	ifstream infile(out_file_path);
	if (!infile) {
		return 0;
	}
	return -1;
}

string read_last_log(string log_file_path) {	
	ifstream fin(log_file_path);
	if (!fin) {
		return "";
	}
	fin.seekg(-1, ios_base::end);
	bool keepLooping = true;
	while (keepLooping) {
		char ch;
		fin.get(ch);                            

		if ((int)fin.tellg() <= 1) {            
			fin.seekg(0);                      
			keepLooping = false;               
		}
		else if (ch == '\n') {                 
			keepLooping = false;               
		}
		else {                                 
			fin.seekg(-2, ios_base::cur);      
		}
	}
	string lastLine;
	getline(fin, lastLine);
	fin.close();
	return lastLine;
}


int main(int argc, char** argv)
{	
	
	string packer_type, file_name, machine, file_type, cmd_line, ir_file = "", cmd_line2;
	char psBuffer[256];
	FILE* pPipe;
	
	if (argc != 3 && argc != 4) {
		cout << "Usage: " << endl;
		cout << "    KDT packer_type file_type file_name" << endl;
		cout << "    or" << endl;
		cout << "    KDT packer_type file_name" << endl;
		cout << "        packer_type : tmd2 or tmd3 or vmp or enigma" << endl;		
		cout << "        file_type : exe32 exe64 dll32 dll64" << endl;
		cout << "        file_name : obfuscated file name" << endl;
		exit(-1);
	}
	
	read_config_file(CONFIG);	

	packer_type = string(argv[1]);	
	cmd_line = PINEXE + " -t ";

	if (argc == 4) {
		file_name = string(argv[3]);
		string input_file_type = string(argv[2]);		
		if (input_file_type.find("exe") != string::npos) file_type = "exe";
		if (input_file_type.find("dll") != string::npos) file_type = "dll";
		if (input_file_type.find("32") != string::npos) machine = "x86";
		if (input_file_type.find("64") != string::npos) machine = "x64";

	}
	else if (argc ==3) {		
		file_name = string(argv[2]);
		if ((pPipe = _popen((GETFILEINFO + " \"" + file_name + "\"").c_str(), "rt")) == NULL)
			exit(1);
		while (fgets(psBuffer, 256, pPipe)) {
			string line;
			line = string(psBuffer);
			if (line.find("PE32") != string::npos) machine = "x86";
			if (line.find("PE64") != string::npos) machine = "x64";
			if (line.find("GUI") != string::npos || line.find("Console") != string::npos) file_type = "exe";
			if (line.find("DLL") != string::npos) file_type = "dll";
		}
	}
	
	if (machine == "x64") {
		cmd_line += " " + string(PINTOOL64);
	}
	else if (machine == "x86") {		
		cmd_line += " " + string(PINTOOL32);
	}
	else {
		cout << "not x86 or x64" << endl;
		exit(1);
	}

	if (file_type != "exe" && file_type != "dll") {
		cout << "not pe exe or dll" << endl;
		exit(1);
	}
	
	if (packer_type == "vmp") {
		cmd_line += " -packer vmp";
	} 
	else if (packer_type == "enigma") {
		cmd_line += " -packer enigma";
	}
	else if (packer_type == "tmd3") {
		cmd_line += " -packer tmd3";
	}
	else if (packer_type == "tmd2") {
		cmd_line += " -packer tmd2";
	}
	else {
		cout << "not supported packer" << endl;
		exit(1);
	}
	
	if (file_type == "dll") {
		cmd_line += " -dll " + file_name;
	}
	
	bool continue_execute = true;
	while (continue_execute) {
		continue_execute = false;
		if (ir_file == "") {
			cmd_line2 = cmd_line + " -- ";
		}
		else {
			cmd_line2 = cmd_line + " -ir " + ir_file + " -- ";
		}		

		if (file_type == "dll") {
			if (machine == "x86") {
				cmd_line2 += " " + string(LOADDLL32);
			}
			else if (machine == "x64") {
				cmd_line2 += " " + string(LOADDLL64);
			}
		}

		// delete previous dump file
		string out_file = file_name + "_dmp." + file_type;
		cout << out_file << endl;
		remove(out_file.c_str());

		cmd_line2 += " " + file_name;
		cout << cmd_line2 << endl;
		system(cmd_line2.c_str());
		if (ir_file != "") break;
		string last_log = read_last_log("pintool.log");		
		if (last_log.find("Continue") != string::npos) {
			stringstream ss(last_log);
			string msg;
			ss >> msg >> ir_file;
			cout << "continue with " << ir_file << endl;
			continue_execute = true;
			continue;
		}

		continue_execute = false;		
		if (check_output_file(out_file)) {
			cout << out_file << " is generated." << endl;
		}
		else {
			cout << "Failed to deobfuscate! Check log file." << endl;
		}
	}


}
