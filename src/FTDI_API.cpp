// ConsoleApplication1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "ftd2xx.h"
#include "ftdi_helpers.h"
//#include "FTDI_HELPER.h"

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
char serial[] = "KFTFE1OY";
void *open_by_arg = serial;  // assigning char[] to void pointer (for PVOID param)
DWORD open_by_flag = FT_OPEN_BY_SERIAL_NUMBER;
FT_HANDLE ftHandle;


// Driver 
int main()
{
	create_device_info_list();
	get_device_info_list();
	get_device_info_detail();
	open_by_index();
	close_by_handle();
	open_by_args();
	read();
	close_by_handle();
	_getch();
	return 0;
}


// get number of devices available
void create_device_info_list()
{
	int local_baud_rate = 9600; // 115200;

	ftStatus = FT_CreateDeviceInfoList(&numDevs);
	if (ftStatus == FT_OK) {
		printf("\n[Success] - create_device_info_list()\n");
		printf("Number of devices is %d\n", numDevs);
	}
	else {
		printf("\n[Failed] - create_device_info_list()\n");
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
			printf("\n[Success] - get_device_info_list()\n");
			for (int i = 0; i < numDevs; i++) {    
				printf("Dev %d:\n",i);     
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
			printf("\n[Failed] - get_device_info_list()\n");
		}
	}
}


// get the device information by index of list:devInfo[]
void get_device_info_detail() {
	if (numDevs > 0) {
		ftStatus = FT_GetDeviceInfoDetail(0, &Flags, &Type, &ID, &LocId, SerialNumber, Description, &ftHandleTemp);   
		if (ftStatus == FT_OK) {
			printf("\n[Success] - get_device_info_detail()\n");
			printf("Dev 0:\n");   
			printf("  Flags=0x%x\n", Flags);    
			printf("  Type=0x%x\n", Type);
			printf("  ID=0x%x\n", ID);    
			printf("  LocId=0x%x\n", LocId);    
			printf("  SerialNumber=%s\n", SerialNumber);    
			printf("  Description=%s\n", Description);    
			printf("  ftHandle=0x%x\n", ftHandleTemp);
		}
		else {
			printf("\n[Failed] - get_device_info_detail()\n");
		}
	}
}


void open_by_index() {
	ftStatus = FT_Open(index, &ftHandle);

	if (ftStatus == FT_OK) {
		printf("\n[Success] - open_by_index()");
	}
	else {
		printf("\n[Failed] - open_by_index()");
	}
}


void close_by_handle() {
	ftStatus =  FT_Close(ftHandle);
	if (ftStatus == FT_OK) {
		printf("\n[Success] - close_by_handle()");
	}
	else {
		printf("\n[Failed] - close_by_handle()");
	}
}


void open_by_args() {
	// lets open by serial# and return a handle 
	ftStatus = FT_OpenEx(open_by_arg, open_by_flag, &ftHandle);

	if (ftStatus == FT_OK) {
		printf("\n[Success] - open_by_args()");
	}
	else {
		printf("\n[Failed] - open_by_args()");
	}
}


#pragma region "READ()"

DWORD bufferSize;
char buffer[256];

DWORD eventDWord;
DWORD noOfBytesInTransmitQ;
DWORD noOfBytesInReadQ;
DWORD bytesRetured;

void read() {
	FT_GetStatus(ftHandle, &noOfBytesInReadQ, &noOfBytesInTransmitQ, &eventDWord);

	if (noOfBytesInReadQ > 0) {
		bufferSize = noOfBytesInReadQ;
		ftStatus = FT_Read(ftHandle, buffer, bufferSize, &bytesRetured);
	}
	if (ftStatus == FT_OK) {
		printf("\n[Success] - read()");
	}
	else {
		printf("\n[Failed] - read()");
	}
}

#pragma endregion


