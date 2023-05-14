#include "windows.h"

#include "stdio.h"

HMODULE MyLoadLibrary ( PCSTR mName ) {

	HANDLE hThread = NULL;

	hThread = CreateThread ( NULL, 0, ( LPTHREAD_START_ROUTINE ) LoadLibraryA, ( LPVOID ) mName, 0, NULL );
	if ( hThread == NULL )
		return 0;

	WaitForSingleObject ( hThread, INFINITE );

	return GetModuleHandleA ( mName );

}

int main ( int arg, char** argv ) {

	HMODULE hModule = NULL;

	hModule = GetModuleHandleA ( "dbghelp.dll" );
	if ( hModule ) {
		printf ( "Dll already loaded\n" );
		return 0;
	}

	hModule = MyLoadLibrary ( "dbghelp.dll" );
	printf ( "Module at 0x%p\n", hModule );

	getchar ( );

	return 0;

}