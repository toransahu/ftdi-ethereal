// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "ftd2xx.h"
#include "ftdi_helpers.h"
//#include "FTDI_HELPER.h"

using namespace std;


#pragma region VARIABLES

//1. create_device_info_list
DWORD numDevs;
FT_STATUS ftStatus;

//2. get_device_info_list
FT_DEVICE_LIST_INFO_NODE *devInfo;

//3. get_device_info_detail
DWORD Flags;  
DWORD ID;  
DWORD Type;  
DWORD LocId;  
char SerialNumber[16];  
char Description[64]; 
FT_HANDLE ftHandleTemp;

//4. open_by_index
int index = 0;

//5. close_by_handle

//6. open_by_args
char serial[] = "EH34T3RP"; // "EM2BRNNA"; //"KFTFE1OY"; //"EM2WVI27";
void *open_by_arg = serial;  // assigning char[] to void pointer (for PVOID param)
DWORD open_by_flag = FT_OPEN_BY_SERIAL_NUMBER;
FT_HANDLE ftHandle;

#pragma endregion

// Driver 
int main()
{
	create_device_info_list();
	get_device_info_list();
	get_device_info_detail();
	open_by_index();
	close_by_handle();
	open_by_args();
	//write();
	//read();
	//write_ee();
	//read_ee();
	//erase_ee();

	size_ua_ee();
	read_ua_ee();
	write_ua_ee();
	//read_ua_ee();

	
	close_by_handle();
	_getch();
	return 0;
}


// get number of devices available
void create_device_info_list()
{
	int local_baud_rate = 115200; // 9600;

	ftStatus = FT_CreateDeviceInfoList(&numDevs);
	if (ftStatus == FT_OK) {
		printf("[Success] - create_device_info_list()\n");
		printf("	Number of devices is %d\n", numDevs);
	}
	else {
		printf("[Failed] - create_device_info_list()\n");
	}
}


// get the device information list
void get_device_info_list(){
	if (numDevs > 0) { 
		// allocate storage for list based on numDevs  
		devInfo = (FT_DEVICE_LIST_INFO_NODE*)malloc(sizeof(FT_DEVICE_LIST_INFO_NODE)*numDevs);   
		
		// create the device information in the list
		ftStatus = FT_GetDeviceInfoList(devInfo,&numDevs);   
		
		if (ftStatus == FT_OK) {
			printf("[Success] - get_device_info_list()\n");
			for (int i = 0; i < numDevs; i++) {    
				printf(" Dev %d:\n",i);     
				printf("  Flags=0x%x\n",devInfo[i].Flags);     
				printf("  Type=0x%x\n",devInfo[i].Type);     
				printf("  ID=0x%x\n",devInfo[i].ID);     
				printf("  LocId=0x%x\n",devInfo[i].LocId);     
				printf("  SerialNumber=%s\n",devInfo[i].SerialNumber);
				printf("  Description=%s\n",devInfo[i].Description);     
				printf("  ftHandle=0x%x\n",devInfo[i].ftHandle);    
			}  
		}
		else {
			printf("[Failed] - get_device_info_list()\n");
		}
	}
}


// get the device information by index of list:devInfo[]
void get_device_info_detail() {
	if (numDevs > 0) {
		ftStatus = FT_GetDeviceInfoDetail(0, &Flags, &Type, &ID, &LocId, SerialNumber, Description, &ftHandleTemp);   
		if (ftStatus == FT_OK) {
			printf("[Success] - get_device_info_detail()\n");
			printf(" Dev 0:\n");   
			printf("  Flags=0x%x\n", Flags);    
			printf("  Type=0x%x\n", Type);
			printf("  ID=0x%x\n", ID);    
			printf("  LocId=0x%x\n", LocId);    
			printf("  SerialNumber=%s\n", SerialNumber);    
			printf("  Description=%s\n", Description);    
			printf("  ftHandle=0x%x\n", ftHandleTemp);
		}
		else {
			printf("[Failed] - get_device_info_detail()\n");
		}
	}
}


void open_by_index() {
	// Note:  Windows CE and Linux do not support location IDs. 
	ftStatus = FT_Open(index, &ftHandle);

	if (ftStatus == FT_OK) {
		printf("[Success] - open_by_index()\n");
	}
	else {
		printf("[Failed] - open_by_index()\n");
	}
}


void close_by_handle() {
	ftStatus =  FT_Close(ftHandle);
	if (ftStatus == FT_OK) {
		printf("[Success] - close_by_handle()\n");
	}
	else {
		printf("[Failed] - close_by_handle()\n");
	}
}


void open_by_args() {
	// lets open by serial# and return a handle 
	ftStatus = FT_OpenEx(open_by_arg, open_by_flag, &ftHandle);

	if (ftStatus == FT_OK) {
		printf("[Success] - open_by_args()\n");
	}
	else {
		printf("[Failed] - open_by_args()\n");
	}
}


#pragma region "READ()"

char read_buffer[256];
void *rBuffer = read_buffer;  // void pointer
DWORD eventDWord;
DWORD noOfBytesInTransmitQ;
DWORD noOfBytesInReceiveQ=256;
DWORD bytesReceived=0;


// TODO: Not able to read data
void read() {
	ftStatus = 9999;
	ftStatus = FT_OK;

	// To get the receive queue status using FT_GetQueueStatus()
	//ftStatus = FT_GetStatus(ftHandle, &noOfBytesInReceiveQ, &noOfBytesInTransmitQ, &eventDWord);
	//ftStatus = FT_GetQueueStatus(ftHandle, &noOfBytesInReceiveQ);
	if (ftStatus == FT_OK) {
		ftStatus = 9999;

			ftStatus = FT_Read(ftHandle, &rBuffer, noOfBytesInReceiveQ, &bytesReceived);
		
		
		if (ftStatus == FT_OK) {
			printf("\n[Success] - read()");
			printf("\n	Read Buffer %s", rBuffer);
			printf("\n	Bytes Received %d", bytesReceived);
			printf("\n	noOfBytesInReceiveQ %d", noOfBytesInReceiveQ);

		}
		else {
			printf("\n[Failed] - read()");
		}
	}
	
	// To get the receive queue status using FT_GetStatus()
	/*FT_GetStatus(ftHandle, &noOfBytesInReceiveQ, &noOfBytesInTransmitQ, &eventDWord);
	if (noOfBytesInReceiveQ > 0) {
		ftStatus = FT_Read(ftHandle, buffer, noOfBytesInReceiveQ, &bytesReceived);
	}
	if (ftStatus == FT_OK) {
		printf("\n[Success] - read()");	
	}
	else {
		printf("\n[Failed] - read()");
	}*/
}

// TODO: read within time limit

#pragma endregion


#pragma region FT_WRITE()

DWORD bytesWritten=0;
char writeBuffer[256] = "        Hello World; Hello World; Hello World; Hello World;";  // contains data to write to the device
void *wBuffer = writeBuffer;


void write() {

		ftStatus = FT_Write(ftHandle, &wBuffer, sizeof(writeBuffer), &bytesWritten);

	
	
	if (ftStatus == FT_OK) {
		printf("\n[Success] - write()");
		printf("\n	wBuffer %s", wBuffer);
		printf("\n	bytesWritten %d", bytesWritten);
	}
	else {
		printf("\n[Failed] - write()\n");
	}
}

#pragma endregion


#pragma region READ_EE()

DWORD wordOffset = 0;
WORD value;

void read_ee() {
	ftStatus = 9999;
	ftStatus = FT_ReadEE(ftHandle, wordOffset, &value);
	cout << "Status" << ftStatus << endl;
	if (ftStatus == FT_OK) {
		cout << "[Success] - read_ee()\n";
		cout << value;
	}
	else {
		cout << "\n[Failed] - read_ee()\n";
	}

}

#pragma endregion


#pragma region WRITE_EE()
WORD write_value=123;

void write_ee() {
	ftStatus = 9999;
	ftStatus = FT_WriteEE(ftHandle, wordOffset, write_value);
	if (ftStatus == FT_OK) {
		cout << "[Success] - write_ee()\n";
		cout << write_value << endl;
	}
	else {
		cout << "[Failed] - write_ee()\n";
	}
}


#pragma endregion


#pragma region ERASE_EE()

void erase_ee() {
	ftStatus = FT_EraseEE(ftHandle);
	if (ftStatus == FT_OK) {
		cout << "[Success] - erase_ee()\n";
	}
	else {
		cout << "[Failed] - erase_ee()\n";
	}

}

#pragma endregion


#pragma region SIZE_UA_EE()

DWORD EEUA_Size = 0; // in bytes

void size_ua_ee() {
	ftStatus = FT_EE_UASize(ftHandle, &EEUA_Size);
	if (ftStatus == FT_OK) {
		cout << "[Success] - size_ua_ee()\n";
		cout << "	EEUA_Size: " << EEUA_Size << endl;
	}
	else {
		cout << "[Failed] - size_ua_ee()\n";
	}

}

#pragma endregion


#pragma region READ_UA_EE()

	unsigned char readBufferEEUA[64];
	UCHAR *readBufferPointerEEUA = readBufferEEUA;
	DWORD BytesReadEEUA;

	void read_ua_ee() {
		ftStatus = FT_EE_UARead(ftHandle, (unsigned char *)readBufferEEUA, 64, &BytesReadEEUA);
		if (ftStatus == FT_OK) {
			cout << "[Success] - read_ua_ee()\n";
			cout << "	BufferEEUA: " << readBufferEEUA << endl;
			cout << "	BytesReadEEUA: " << BytesReadEEUA << endl;
		}
		else {
			cout << "[Failed] - read_ua_ee()\n";
		}
	}

#pragma endregion


#pragma region WRITE_UA_EE()
	
	unsigned char writeBufferEEUA[64] = "Hello World";
	UCHAR *writeBufferPointerEEUA = writeBufferEEUA;
	DWORD dataLen = 11;

	void write_ua_ee() {
		if (EEUA_Size < dataLen) {
			cout << "[WARNING] - write_ua_ee() {Insufficient User Space in EEPROM}\n";
		}
		else {
			ftStatus = FT_EE_UAWrite(ftHandle, writeBufferPointerEEUA, dataLen);
			cout << ftStatus << endl;
			if (ftStatus == FT_OK) {
				cout << "[Success] - write_ua_ee()\n";
			}
			else {
				cout << "[Failed] - write_ua_ee()\n";
			}
		}

	}

#pragma endregion