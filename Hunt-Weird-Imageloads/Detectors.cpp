#include "Detectors.h"
#include <string>

namespace Detectors {

	VOID Detectors::PrivateRX::Check ( HANDLE hProcess, std::vector<ULONG_PTR> stack, DWORD dwPid, std::wstring imageName) {
		
		SIZE_T s = 0;
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		std::string processName;

		for ( ULONG_PTR pAddr : stack ) {

			s = VirtualQueryEx ( hProcess, ( LPCVOID ) pAddr, &mbi, sizeof ( MEMORY_BASIC_INFORMATION ) );
			if ( s == 0 ) 
				continue;

			if ( mbi.Type != MEM_PRIVATE )
				continue;

			if ( mbi.Protect == PAGE_EXECUTE_READ ) {

				Helpers::ModuleNameFromAddress ( hProcess, NULL, processName );

				wprintf ( L"! Process %S ( %d ) loaded %s and callstack contains RX Page: 0x%p\n", processName.c_str ( ), dwPid, imageName.c_str ( ), ( PVOID ) pAddr );
				break;

			}
			
		}

	}

	VOID Detectors::PrivateRWX::Check ( HANDLE hProcess, std::vector<ULONG_PTR> stack, DWORD dwPid, std::wstring imageName ) {

		SIZE_T s = 0;
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		std::string processName;

		for ( ULONG_PTR pAddr : stack ) {

			s = VirtualQueryEx ( hProcess, ( LPCVOID ) pAddr, &mbi, sizeof ( MEMORY_BASIC_INFORMATION ) );
			if ( s == 0 )
				continue;

			if ( mbi.Type != MEM_PRIVATE )
				continue;

			if ( mbi.Protect == PAGE_EXECUTE_READ ) { 
			
				Helpers::ModuleNameFromAddress ( hProcess, NULL, processName );

				wprintf ( L"! Process %S ( %d ) loaded %s and callstack contains RWX Page: 0x%p\n", processName.c_str ( ), dwPid, imageName.c_str ( ), ( PVOID ) pAddr );
				break;

			}

		}

	}

	VOID Detectors::ModuleStomped::Check ( HANDLE hProcess, std::vector<ULONG_PTR> stack, DWORD dwPid, std::wstring imageName ) {
	
		std::string stompedModule;
		std::string processName;

		for ( ULONG_PTR pAddr : stack ) {

			if ( Helpers::IsModuleStomped ( hProcess, ( PVOID ) pAddr ) ) {

				Helpers::ModuleNameFromAddress ( hProcess, ( PVOID ) pAddr, stompedModule );
				Helpers::ModuleNameFromAddress ( hProcess, NULL, processName );

				wprintf ( L"! Process %S ( %d ) loaded %s and callstack contains stomped module: %S\n", processName.c_str ( ), dwPid, imageName.c_str ( ), stompedModule.c_str ( ) );
				break;

			}
		}

	}
	
	// Was ist mit ZwMapViewOfSection ?
	VOID Detectors::ModuleProxying::Check ( HANDLE hProcess, std::vector<ULONG_PTR> stack, DWORD dwPid, std::wstring imageName ) {

		BOOL bSuccess = FALSE;

		std::string callingmodule;
		std::string processName;
		std::string symbol;

		if ( stack.size ( ) < 2 )
			return;

		for ( auto it = stack.begin ( ); it != stack.end ( ); ++it ) {

			bSuccess = Helpers::SymbolNameFromAddress ( hProcess, ( PVOID ) *it, symbol );
			if ( bSuccess == FALSE )
				break;

			if ( symbol.find ( "LoadLibrary" ) != std::string::npos ) {

				bSuccess = Helpers::ModuleNameFromAddress ( hProcess, ( PVOID ) * ( it + 1 ), callingmodule );
				if ( bSuccess == FALSE )
					break;

				if ( !_stricmp ( callingmodule.c_str ( ), "ntdll.dll" ) ){

					Helpers::ModuleNameFromAddress ( hProcess, NULL, processName );
					wprintf ( L"! Process %S ( %d ) loaded %s by proxying loadlibray through ntdll\n", processName.c_str ( ), dwPid, imageName.c_str ( ) );

				}

			}

		}

	}

	VOID Detectors::DedicatedThread::Check ( HANDLE hProcess, std::vector<ULONG_PTR> stack, DWORD dwPid, PVOID baseAddr) {

		BOOL bSuccess = FALSE;
		PVOID pLoadLibraryA = NULL, pLoadLibraryW = NULL, pLoadLibraryExA = NULL, pLoadLibraryExW = NULL;

		std::string baseModule;
		std::string processName;

		bSuccess = Helpers::ModuleNameFromAddress ( hProcess, ( PVOID ) baseAddr, baseModule );
		if ( bSuccess == FALSE )
			return;

		pLoadLibraryA = GetProcAddress ( GetModuleHandleA ( "kernel32.dll" ), "LoadLibraryA" );
		pLoadLibraryW = GetProcAddress ( GetModuleHandleA ( "kernel32.dll" ), "LoadLibraryW" );
		pLoadLibraryExA = GetProcAddress ( GetModuleHandleA ( "kernel32.dll" ), "LoadLibraryExA" );
		pLoadLibraryExW = GetProcAddress ( GetModuleHandleA ( "kernel32.dll" ), "LoadLibraryExW" );

		if ( !_stricmp ( baseModule.c_str ( ), "kernel32.dll" ) || !_stricmp ( baseModule.c_str ( ), "kernelbase.dll" ) ) {

			Helpers::ModuleNameFromAddress ( hProcess, NULL, processName );

			wprintf ( L"! Process %S ( %d ) abnormally started a new thread in %S\n", processName.c_str ( ), dwPid, baseModule.c_str ( ) );

			if ( baseAddr == pLoadLibraryA || baseAddr == pLoadLibraryW || baseAddr == pLoadLibraryExA || baseAddr == pLoadLibraryExW )
				wprintf ( L"\t !! Thread is abnormally started in a LoadLibrary function :o\n" );

		}

	}


}