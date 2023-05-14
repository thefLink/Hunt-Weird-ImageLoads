#include "windows.h"
#include "stdio.h"

/*

	Based on: https://github.com/rad9800/misc/blob/main/bypasses/WorkItemLoadLibrary.c

*/

typedef NTSTATUS ( NTAPI* RtlQueueWorkItem )( PVOID, PVOID, ULONG );

HMODULE MyLoadLibrary ( PCSTR mName ) {

	HANDLE hThread = NULL;
	RtlQueueWorkItem _RtlQueueWorkItem = ( RtlQueueWorkItem ) GetProcAddress ( GetModuleHandleA ( "ntdll.dll" ), "RtlQueueWorkItem" );
	_RtlQueueWorkItem ( LoadLibraryA, ( PVOID ) mName, WT_EXECUTEDEFAULT );
	
	Sleep ( 1000 ); // Dirty :-)

	return GetModuleHandleA ( mName );

}


int 
main ( int argc, char** argv ) {

	HMODULE hModule = NULL;

	hModule = GetModuleHandleA ( "wininet.dll" );
	if ( hModule ) {
		printf ( "Dll already loaded\n" );
		return 0;
	}

	hModule = MyLoadLibrary ( "wininet.dll" );
	printf ( "Module at 0x%p\n", hModule );

	getchar ( );

	return 0;

}