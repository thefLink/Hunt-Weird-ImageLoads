#include "../libs/krabs/krabs.hpp"
#include "dbghelp.h"
#include <vector>

#include "Detectors.h"
#include "Helpers.h"

#define EVENTID_THREADSTART 3
#define EVENTID_IMAGELOAD 5

VOID EnableProcessTracing ( krabs::user_trace& );
VOID Help ( VOID );
VOID OnImageLoad ( const EVENT_RECORD&, const krabs::trace_context& );
VOID OnThreadStart ( const EVENT_RECORD&, const krabs::trace_context& );
VOID ParseArgs ( int, char** );

std::vector<Detectors::DetectorImageLoad *> activeDetectorsImageLoad; 
std::vector<Detectors::DetectorThreadStart*> activeDetectorsThreadStart;

VOID EnableProcessTracing ( krabs::user_trace& userTrace ) {

	krabs::provider<>* providerProcess = new krabs::provider<> ( L"Microsoft-Windows-Kernel-Process" );
	providerProcess->any ( 0x20 | 0x40 );  // WINEVENT_KEYWORD_THREAD | WINEVENT_KEYWORD_IMAGE
	providerProcess->trace_flags ( providerProcess->trace_flags ( ) | EVENT_ENABLE_PROPERTY_STACK_TRACE );

	krabs::event_filter* imageLoad = new krabs::event_filter ( krabs::predicates::id_is ( EVENTID_IMAGELOAD ) );
	krabs::event_filter* threadStart = new krabs::event_filter ( krabs::predicates::id_is ( EVENTID_THREADSTART ) );

	imageLoad->add_on_event_callback ( OnImageLoad );
	threadStart->add_on_event_callback ( OnThreadStart );

	providerProcess->add_filter ( *imageLoad );
	providerProcess->add_filter ( *threadStart );

	userTrace.enable ( *providerProcess );

}

VOID OnThreadStart ( const EVENT_RECORD& record, const krabs::trace_context& trace_context ) {

	krabs::schema schema ( record, trace_context.schema_locator );
	krabs::parser parser ( schema );

	std::vector<ULONG_PTR> stack = schema.stack_trace ( );

	DWORD pid = parser.parse<DWORD> ( L"ProcessID" );
	DWORD tid = parser.parse<DWORD> ( L"ThreadID" );

	PVOID startAddr = parser.parse<PVOID> ( L"StartAddr" );

	HANDLE hProcess = NULL;
	BOOL bIs32Bit;

	hProcess = OpenProcess ( PROCESS_ALL_ACCESS, FALSE, pid );
	if ( hProcess == NULL )
		return;

	IsWow64Process ( hProcess, &bIs32Bit );
	if ( bIs32Bit )
		goto Cleanup;

	for ( Detectors::DetectorThreadStart* detector : activeDetectorsThreadStart )
		detector->Check ( hProcess, stack, pid, startAddr );

Cleanup:

	if ( hProcess )
		CloseHandle ( hProcess );

}

VOID OnImageLoad ( const EVENT_RECORD& record, const krabs::trace_context& trace_context ) {

	krabs::schema schema ( record, trace_context.schema_locator );
	krabs::parser parser ( schema );

	BOOL bIs32Bit = FALSE;
	DWORD pid = parser.parse<DWORD> ( L"ProcessID" );
	PVOID imageBase = parser.parse<PVOID> ( L"ImageBase" );
	std::wstring imageName = parser.parse<std::wstring> ( L"ImageName" );

	std::vector<ULONG_PTR> stack = schema.stack_trace ( );
	Helpers::RemoveKernelAddrs ( stack );

	HANDLE hProcess = NULL;

	hProcess = OpenProcess ( PROCESS_ALL_ACCESS, FALSE, pid );
	if ( hProcess == NULL ) 
		return;

	IsWow64Process ( hProcess, &bIs32Bit );
	if ( bIs32Bit )
		goto Cleanup;

	SymInitialize ( hProcess, NULL, TRUE );

	for ( Detectors::DetectorImageLoad *detector : activeDetectorsImageLoad ) 
		detector->Check ( hProcess, stack, pid, imageName );

Cleanup:

	if ( hProcess ) {

		SymCleanup ( hProcess );
		CloseHandle ( hProcess );

	}

}

VOID Go ( krabs::user_trace* userTrace ) {
	userTrace->start ( );
}

VOID Help ( VOID ) {
	printf ( "Hunt-Weird-ImageLoads.exe\n\n\t--all activates all alerts\n\t--rx alerts on private rx regions in callstack\n\t--rwx alerts on private rwx regions in callstack\n\t--stomped alerts on stomped modules in callstack\n\t--proxy alerts on abnormal calls to kernel32!loadlibrary from ntdll\n\t--dedicatedthread alerts on thread with baseaddr on loadlibrary*\n\n" );
	exit ( 1 );
}

VOID ParseArgs ( int argc, char** argv ) {

	if ( argc < 2 )
		Help ( );

	for ( int i = 1; i < argc; i++ ) { 

		if ( !_strcmpi ( argv [ i ], "--rx" ) ) {
			printf ( "\t- Enabling detector RX\n" );
			activeDetectorsImageLoad.push_back ( new Detectors::PrivateRX ( ) );
		}

		else if ( !_strcmpi ( argv [ i ], "--rwx" ) ) {
			printf ( "\t- Enabling detector RWX\n" );
			activeDetectorsImageLoad.push_back ( new Detectors::PrivateRWX ( ) );
		}

		else if ( !_strcmpi ( argv [ i ], "--stomped" ) ) {
			printf ( "\t- Enabling detector stomped\n" );
			activeDetectorsImageLoad.push_back ( new Detectors::ModuleStomped ( ) );
		}

		else if ( !_strcmpi ( argv [ i ], "--proxy" ) ) {
			printf ( "\t- Enabling detector for module proxying\n" );
			activeDetectorsImageLoad.push_back ( new Detectors::ModuleProxying ( ) );
		}

		else if ( !_strcmpi ( argv [ i ], "--dedicatedthread" ) ) {
			printf ( "\t- Enabling detector dedicatedthread\n" );
			activeDetectorsThreadStart.push_back ( new Detectors::DedicatedThread ( ) );
		}

		else if ( !_strcmpi ( argv [ i ], "--all" ) ) {

			printf ( "\t- Enabling all detectors\n" );

			activeDetectorsImageLoad.clear ( );

			activeDetectorsImageLoad.push_back ( new Detectors::PrivateRX ( ) );
			activeDetectorsImageLoad.push_back ( new Detectors::PrivateRWX ( ) );
			activeDetectorsImageLoad.push_back ( new Detectors::ModuleStomped ( ) );
			activeDetectorsImageLoad.push_back ( new Detectors::ModuleProxying ( ) );

			activeDetectorsThreadStart.push_back ( new Detectors::DedicatedThread ( ) );

		}

		else
			Help ( );

	}

}

int main ( int argc, char** argv ) {

	HANDLE traceThread = NULL;

	krabs::user_trace userTrace ( L"Hunt-Weird-Imageloads" );

	if ( !Helpers::IsElevated ( ) ) {
		printf ( "- Not elevated\n" );
		return 0;
	}

	printf ( "* Hunt-Weird-ImageLoads\n" );
	ParseArgs ( argc, argv );

	printf ( "* Enabling trace, might take a bit ... \n" );

	SymSetOptions ( SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS );

	EnableProcessTracing ( userTrace );
	traceThread = CreateThread ( NULL, 0, ( LPTHREAD_START_ROUTINE ) Go, &userTrace, 0, NULL );
	if ( traceThread == NULL )
		return 0; // o.0

	printf ( "* Started monitoring, press any key to exit ... \n" );

	getchar ( );
	printf ( "* exiting ... \n" );
	userTrace.stop ( );
	WaitForSingleObject ( traceThread, INFINITE );

	return 0;

}