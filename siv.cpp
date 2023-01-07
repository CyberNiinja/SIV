// Author: Elias Mjoen
// Date: (08/01/2022)
// Description: This program is a simple integrity verifier. It can be used to verify the integrity of a directory.
//              The program can be used in two modes: initialization mode and verification mode.
//              In initialization mode, the program will generate a verification file.
//              In verification mode, the program will verify the integrity of the directory against a verification file.
//              The program can also generate a report file that contains the results of the verification.
// Dependencies: Crypto++ library, C++20, g++ compiler
// compile: g++ -std=c++20 -o siv SIV.cpp -l cryptopp
// run: ./siv -h

#include <iostream>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <sys/stat.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <ctime>

// Crypto++ library
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/sha.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>

// namespaces
using namespace std;
namespace fs = filesystem;
namespace crp = CryptoPP;

// used to convert a std::filesystem::file_time_type to a string
// source:https://stackoverflow.com/questions/56788745/how-to-convert-stdfilesystemfile-time-type-to-a-string-using-gcc-9
template <typename TP>
std::time_t to_time_t(TP tp)
{
    using namespace std::chrono;
    auto sctp = time_point_cast<system_clock::duration>(tp - TP::clock::now() + system_clock::now());
    return system_clock::to_time_t(sctp);
}

struct stat info;
struct passwd *pw;
struct group *gr;

// print the help message
void help()
{
    cout << "Usage: siv <-i|-v|-h> -D <monitored_directory> -V <verification_file> " << endl;
    cout << "       -R <report_file> -H <hash-function>" << endl;
    cout << endl;
    cout << "Options:" << endl;
    cout << "  -i                       : starts siv in initialization mode" << endl;
    cout << "  -v                       : starts siv in verification mode" << endl;
    cout << "  -h                       : help mode" << endl;
    cout << "  -D <monitored_directory> : the path to the directory to be monitored" << endl;
    cout << "  -V <verification_file>   : the path to the verification file" << endl;
    cout << "  -R <report_file_>        : the path to the report file" << endl;
    cout << "  -H <hash-function>       : the hash function to be used" << endl;
    cout << endl;
    cout << "Examples: " << endl;
    cout << "siv -i -D /home/user/monitored -V /home/user/verification -R /home/user/report.txt -H md5" << endl;
    cout << "siv -v -V /home/user/verification -R /home/user/report.txt" << endl;
    cout << "siv -h" << endl;
    cout << endl;
    cout << "Notes: " << endl;
    cout << "- the verification file and the report file have to be outside the monitored directory" << endl;
    cout << "- the report file has to be a .txt file" << endl;
    cout << "- the hash function has to be either md5 or sha1" << endl;
    cout << "- the monitored directory has to be an absolute path" << endl;
    cout << "- the verification file has to be an absolute path" << endl;
    cout << "- the report file has to be an absolute path" << endl;
    cout << "- line 4 of the verification file shows the headers for the tsv format below." << endl;
}

// compute the message digest of a file
// path: the path of the file
// hashF: the hash function to be used
string hashFile(string path, string hashF)
{
    // open the file
    ifstream file(path, ios::binary);

    // read the file
    string content((istreambuf_iterator<char>(file)), (istreambuf_iterator<char>()));

    // compute the message digest
    string digest;
    if (hashF == "md5")
    {

        crp::Weak::MD5 md5;
        md5.Update((const crp::byte *)content.c_str(), content.length());
        digest.resize(md5.DigestSize());
        md5.Final((crp::byte *)&digest[0]);
    }
    else if (hashF == "sha1")
    {
        crp::SHA1 sha1;
        sha1.Update((const crp::byte *)content.c_str(), content.length());
        digest.resize(sha1.DigestSize());
        sha1.Final((crp::byte *)&digest[0]);
    }
    else
    {
        cout << "Invalid hash function" << endl;
        exit(EXIT_FAILURE);
    }

    // encode the message digest in hexadecimal using HexEncoder
    string hash;
    crp::StringSink *ss = new crp::StringSink(hash);
    crp::HexEncoder *he = new crp::HexEncoder(ss);
    crp::StringSource(digest, true, he);

    return hash;
}

// create a tsv string for a file or directory
// entry: the file or directory
// hashF: the hash function to be used
string createTsvString(const fs::directory_entry &entry, string hashF)
{
    // get the stat info of the file or directory

    stat(entry.path().c_str(), &info);

    // get the full path to file or directory
    string line = entry.path().string() + "\t";

    // get the file size
    line += to_string(info.st_size) + "\t";

    // get the name of the user owning the file or directory

    pw = getpwuid(info.st_uid);
    line += pw->pw_name;
    line += "\t";

    // get the name of the group owning the file or directory
    gr = getgrgid(info.st_gid);
    line += pw->pw_name;
    line += "\t";

    // get the access rights of the file or directory

    int statchmod = info.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO);
    ostringstream oss;
    oss << oct << statchmod;
    line += oss.str() + "\t";

    // get the last modification date
    time_t tt = to_time_t(entry.last_write_time());
    tm *gmt = gmtime(&tt);
    char date[80];
    strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", gmt);
    line += date;
    line += "\t";

    // only compute the message digest of files
    if (!entry.is_directory())
    {
        // get the computed message digest of the file (using the hash function specified by the user)
        line += hashFile(entry.path(), hashF);
    }
    else
    {
        line += "directory";
    }
    line += "\n";

    return line;
}

// initialize the monitoring of a directory.
// dirPath: the path to the directory to be monitored
// vFilePath: the path to the verification file
// rFile: the path to the report file
// hashF: the hash function to be used
void initialize(string dirPath, string vFilePath, string rFilePath, string hashF)
{
    // start a timer to measure the time of initialization
    auto start = chrono::high_resolution_clock::now();

    // make sure that specified directory exists
    if (!fs::exists(dirPath))
    {
        cout << "The specified of directory does not exist" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the verification file is not inside the monitored directory
    if (vFilePath.find(dirPath) != string::npos)
    {
        cout << "The path of verification file is inside the monitored directory" << endl;
        exit(EXIT_FAILURE);
    }
    // make sure that the report file is not inside the monitored directory
    if (rFilePath.find(dirPath) != string::npos)
    {
        cout << "The path of report file is inside the monitored directory" << endl;
        exit(EXIT_FAILURE);
    }
    // make sure that the path of verification file is not the same as the path of report file
    if (vFilePath == rFilePath)
    {
        cout << "The path of verification file is the same as the path of report file" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the report file is a text file with .txt extension
    if (rFilePath.find(".txt") == string::npos)
    {
        cout << "The report file is not a text file with .txt extension" << endl;
        exit(EXIT_FAILURE);
    }

    // create the verification file
    ofstream vFile;
    vFile.open(vFilePath, ios::out);
    int fileNum = 0;
    int dirNum = 0;

    // write the header of the verification file
    vFile << "SIV Verification File" << endl;
    vFile << "Directory: " << dirPath << endl;
    vFile << "Hash Function: " << hashF << endl;
    vFile << "File Name\tFile Size\tOwner\tGroup\tAccess Rights\tLast Modified\tHash" << endl;

    // read the directory
    for (const auto &entry : fs::recursive_directory_iterator(dirPath))
    {
        // write the tsv string of the file or directory to the verification file
        vFile << createTsvString(entry, hashF);

        // count the number of files and directories
        if (entry.is_directory())
        {
            dirNum++;
        }
        else
        {
            fileNum++;
        }
    }

    // create the report file
    ofstream rFile;
    rFile.open(rFilePath, ios::out);
    rFile << "SIV Report File" << endl;
    rFile << "Directory: " << dirPath << endl;
    rFile << "Verification File: " << vFilePath << endl;
    rFile << "Number of parsed Files: " << fileNum << endl;
    rFile << "Number of parsed Directories: " << dirNum << endl;
    rFile << "Hash Function: " << hashF << endl;
    string seconds = to_string(chrono::duration_cast<chrono::seconds>(chrono::high_resolution_clock::now() - start).count());
    rFile << "Time of Initialization (in seconds): " << seconds << endl;
    rFile.close();
}

// verify the integrity of a monitored directory against a verification file.
// vFile: the path to the verification file
// rFile: the path to the report file
void verify(string vFilePath, string rFilePath)
{
    // start a timer to measure the time of verification
    auto start = chrono::high_resolution_clock::now();

    // make sure that the verification file exists
    if (!fs::exists(vFilePath))
    {
        cout << "The verification file does not exist" << endl;
        exit(EXIT_FAILURE);
    }

    // open the verification file and read header information
    ifstream vFile;
    vFile.open(vFilePath, ios::in);
    string line;
    getline(vFile, line); // skip file title line

    // get the path of the monitored directory
    getline(vFile, line);
    string dirPath = line.substr(11); // read the path after "Directory: "

    // get the hash function
    getline(vFile, line);
    string hashF = line.substr(15); // read the hash function after "Hash Function: "

    getline(vFile, line); // skip column info line

    // make sure that the verification file is not inside the monitored directory
    if (vFilePath.find(dirPath) != string::npos)
    {
        cout << "The path of verification file is inside the monitored directory" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the report file is not inside the monitored directory
    if (rFilePath.find(dirPath) != string::npos)
    {
        cout << "The path of report file is inside the monitored directory" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the path of verification file is not the same as the path of report file
    if (vFilePath == rFilePath)
    {
        cout << "The path of verification file is the same as the path of report file" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the report file is a text file with .txt extension
    if (rFilePath.find(".txt") == string::npos)
    {
        cout << "The report file is not a text file with .txt extension" << endl;
        exit(EXIT_FAILURE);
    }

    int fileNum = 0;
    int dirNum = 0;

    // read verification file and create a dictionary of tsv strings with file names as keys
    map<string, string> vFileDict; // key: file name, value: tsv string
    while (getline(vFile, line))
    {
        string fileName = line.substr(0, line.find('\t'));
        vFileDict[fileName] = line;
    }

    // read the directory and create a dictionary of tsv strings with file names as keys
    map<string, string> dirFileDict; // key: file name, value: tsv string
    for (const auto &entry : fs::recursive_directory_iterator(dirPath))
    {
        string fileName = entry.path().string();
        string line = createTsvString(entry, hashF);
        line.erase(remove(line.begin(), line.end(), '\n'), line.end()); // remove the newline character for comparison
        dirFileDict[fileName] = line;
        if (entry.is_directory())
        {
            dirNum++;
        }
        else
        {
            fileNum++;
        }
    }

    // compare the two dictionaries and make a list of changed files, deleted files, and new files
    vector<string> changedFiles;
    vector<string> deletedFiles;
    vector<string> newFiles;
    for (auto it = vFileDict.begin(); it != vFileDict.end(); it++)
    {
        string fileName = it->first;
        string vFileLine = it->second;

        // if the file is in both the verification file and the directory, compare the tsv strings
        if (dirFileDict.find(fileName) != dirFileDict.end())
        {
            string dirFileLine = dirFileDict[fileName];
            if (vFileLine != dirFileLine)
            {
                changedFiles.push_back(fileName);
            }
        }
        else
        {
            // if the file is in the verification file but not in the directory, it is deleted
            deletedFiles.push_back(fileName);
        }
    }

    // if the file is in the directory but not in the verification file, it is new
    for (auto it = dirFileDict.begin(); it != dirFileDict.end(); it++)
    {
        string fileName = it->first;
        if (vFileDict.find(fileName) == vFileDict.end())
        {
            newFiles.push_back(fileName);
        }
    }

    vector<string> warnings;

    // iterate over the list of deleted files and print warnings for each one
    for (int i = 0; i < deletedFiles.size(); i++)
    {
        warnings.push_back(deletedFiles[i] + " is deleted");
    }

    // iterate over the list of new files and print warnings for each one
    for (int i = 0; i < newFiles.size(); i++)
    {
        warnings.push_back(newFiles[i] + " is new");
    }

    // iterate over the list of changed files
    for (int i = 0; i < changedFiles.size(); i++)
    {
        // get the tsv strings of the changed file from the two dictionaries
        string fileName = changedFiles[i];
        string vFileLine = vFileDict[fileName];
        string dirFileLine = dirFileDict[fileName];

        // split the tsv strings by tab
        vector<string> vFileLineSplit;
        vector<string> dirFileLineSplit;
        string temp;

        // split the tsv string of the verification file
        for (int i = 0; i < vFileLine.size(); i++)
        {
            if (vFileLine[i] == '\t')
            {
                vFileLineSplit.push_back(temp);
                temp = "";
            }
            else
            {
                temp += vFileLine[i];
            }
        }
        vFileLineSplit.push_back(temp);
        temp = "";

        // split the tsv string of the directory file
        for (int i = 0; i < dirFileLine.size(); i++)
        {
            if (dirFileLine[i] == '\t')
            {
                dirFileLineSplit.push_back(temp);
                temp = "";
            }
            else
            {
                temp += dirFileLine[i];
            }
        }
        dirFileLineSplit.push_back(temp);

        // compare the file size, owner, group, access rights, and last modified time and hash of the file

        // compare the file size
        if (vFileLineSplit[1] != dirFileLineSplit[1])
        {
            warnings.push_back(fileName + " file size is different: " + vFileLineSplit[1] + " " + dirFileLineSplit[1]);
        }
        // compare the owner, group, access rights, and last modified time
        if (vFileLineSplit[2] != dirFileLineSplit[2])
        {
            warnings.push_back(fileName + " owner is different: " + vFileLineSplit[2] + " " + dirFileLineSplit[2]);
        }

        // compare the group
        if (vFileLineSplit[3] != dirFileLineSplit[3])
        {
            warnings.push_back(fileName + " group is different: " + vFileLineSplit[3] + " " + dirFileLineSplit[3]);
        }

        // compare the access rights
        if (vFileLineSplit[4] != dirFileLineSplit[4])
        {
            warnings.push_back(fileName + " access rights are different: " + vFileLineSplit[4] + " " + dirFileLineSplit[4]);
        }

        // compare the last modified time
        if (vFileLineSplit[5] != dirFileLineSplit[5])
        {
            warnings.push_back(fileName + " last modified time is different: " + vFileLineSplit[5] + " " + dirFileLineSplit[5]);
        }

        // compare the hash
        if (vFileLineSplit[6] != dirFileLineSplit[6])
        {
            warnings.push_back(fileName + " hash is different: " + vFileLineSplit[6] + " " + dirFileLineSplit[6]);
        }
    }

    // write the report file
    ofstream rFile;
    rFile.open(rFilePath, ios::out);
    rFile << "SIV Report File" << endl;
    rFile << "Directory: " << dirPath << endl;
    rFile << "Verification File: " << vFilePath << endl;
    rFile << "Hash Function: " << hashF << endl;
    rFile << "Number of Parsed Files: " << fileNum << endl;
    rFile << "Number of Parsed Directories: " << dirNum << endl;
    rFile << "Number of Deleted Files: " << deletedFiles.size() << endl;
    rFile << "Number of New Files: " << newFiles.size() << endl;
    rFile << "Number of Changed Files: " << changedFiles.size() << endl;
    rFile << "Warnings:" << endl;
    for (int i = 0; i < warnings.size(); i++)
    {
        rFile << warnings[i] << endl;
    }
    rFile.close();
}

// main function
// parse command line arguments and call the appropriate function
int main(int argc, char *argv[])
{

    int opt;
    int mode;
    string dirPath, vFilePath, rFilePath, hashF;

    dirPath = "";
    vFilePath = "";
    rFilePath = "";
    hashF = "";
    mode = 0;

    // parse command line arguments
    while ((opt = getopt(argc, argv, "ivhD:V:R:H:")) != -1)
    {
        switch (opt)
        {
        case 'i':
            mode = 1;
            break;
        case 'v':
            mode = 2;
            break;
        case 'h':
            mode = 3;
            break;
        case 'D':
            dirPath = optarg;
            break;
        case 'V':
            vFilePath = optarg;
            break;
        case 'R':
            rFilePath = optarg;
            break;
        case 'H':
            hashF = optarg;
            break;
        default:
            cout << "Invalid command line argument" << endl;
            exit(EXIT_FAILURE);
        }
    }

    // make sure that the user has specified a mode
    if (mode == 0)
    {
        cout << "Please specify which mode you want to use (-i or -v). Consult -h for more info" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the user has specified a directory in initialization mode
    if (mode == 1 && dirPath == "")
    {
        cout << "Please specify a directory. Consult -h for more info" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the user has specified a verification file in initialization mode
    if (mode == 1 && vFilePath == "")
    {
        cout << "Please specify a verification file. Consult -h for more info" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the user has specified a report file in initialization mode
    if (mode == 1 && rFilePath == "")
    {
        cout << "Please specify a report file. Consult -h for more info" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the user has specified a hash function in initialization mode
    if (mode == 1 && hashF == "")
    {
        cout << "Please specify a hash function. Consult -h for more info" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the user has specified a verification file in verification mode
    if (mode == 2 && vFilePath == "")
    {
        cout << "Please specify a verification file. Consult -h for more info" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the user has specified a report file in verification mode
    if (mode == 2 && rFilePath == "")
    {
        cout << "Please specify a report file. Consult -h for more info" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the user has specified a valid hash function
    if (mode == 1 && hashF != "md5" && hashF != "sha1")
    {
        cout << "Please specify a valid hash function. Consult -h for more info" << endl;
        exit(EXIT_FAILURE);
    }

    // make sure that the user has specified a valid mode
    if (mode != 1 && mode != 2 && mode != 3)
    {
        cout << "Please specify a valid siv mode. Consult -h for more info" << endl;
        exit(EXIT_FAILURE);
    }

    // print the help message
    if (mode == 3)
    {
        help();
        exit(EXIT_SUCCESS);
    }

    // Initialization mode
    if (mode == 1)
    {
        initialize(dirPath, vFilePath, rFilePath, hashF);
        cout << "Initialization complete!" << endl;
        cout << "Verification file: " << vFilePath << endl;
        cout << "Report file: " << rFilePath << endl;

        exit(EXIT_SUCCESS);
    }

    // Verification mode
    if (mode == 2)
    {
        verify(vFilePath, rFilePath);
        cout << "Verification complete!" << endl;
        cout << "Report file: " << rFilePath << endl;

        exit(EXIT_SUCCESS);
    }
}
