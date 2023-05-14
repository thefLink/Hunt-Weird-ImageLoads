#include "Helpers.h"
#include "Dbghelp.h"

namespace Helpers {

	BOOL IsModuleStomped ( HANDLE hProcess, PVOID pAddr ) {

		SIZE_T s = 0;
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		PSAPI_WORKING_SET_EX_INFORMATION workingSets = { 0 };
		BOOL bSuccess = FALSE;

		s = VirtualQueryEx ( hProcess, ( LPCVOID ) pAddr, &mbi, sizeof ( MEMORY_BASIC_INFORMATION ) );
		if ( s == 0 )
			goto Cleanup;

		if ( mbi.Type != MEM_IMAGE || mbi.AllocationProtect == PAGE_NOACCESS )
			goto Cleanup;

		workingSets.VirtualAddress = mbi.BaseAddress;

		bSuccess = K32QueryWorkingSetEx ( hProcess, &workingSets, sizeof ( PSAPI_WORKING_SET_EX_INFORMATION ) );
		if ( bSuccess == FALSE )
			goto Cleanup;

		bSuccess = FALSE;

		if ( workingSets.VirtualAttributes.Shared != 0 )
			goto Cleanup;

		bSuccess = TRUE;

	Cleanup:

		return bSuccess;

	}

	BOOL SymbolNameFromAddress ( HANDLE hProcess, PVOID pAddr, std::string& symbol ) {

		BOOL bSuccess = FALSE;
		DWORD64 dw64Displacement = 0;
		CHAR cSymName [ 256 ] = { 0 };

		PIMAGEHLP_SYMBOL64 pSymbol = NULL;

		pSymbol = ( PIMAGEHLP_SYMBOL64 ) HeapAlloc ( GetProcessHeap ( ), HEAP_ZERO_MEMORY, sizeof ( IMAGEHLP_SYMBOL64 ) + 256 * sizeof ( WCHAR ) );
		if ( pSymbol == NULL )
			goto Cleanup;

		pSymbol->SizeOfStruct = sizeof ( IMAGEHLP_SYMBOL64 );
		pSymbol->MaxNameLength = 255;

		bSuccess = SymGetSymFromAddr64 ( hProcess, ( ULONG64 ) pAddr, &dw64Displacement, pSymbol );
		if ( bSuccess == FALSE )
			goto Cleanup;

		UnDecorateSymbolName ( pSymbol->Name, cSymName, 256, UNDNAME_COMPLETE );
		symbol = std::string ( cSymName );

	Cleanup:

		if ( pSymbol )
			HeapFree ( GetProcessHeap ( ), 0, pSymbol );

		return bSuccess;

	}

	BOOL ModuleNameFromAddress ( HANDLE hProcess, PVOID pAddr, std::string& moduleName ) {

		BOOL bSuccess = FALSE;
		SIZE_T s = 0;
		MEMORY_BASIC_INFORMATION mbi = { 0 };
		CHAR cmoduleName [ MAX_PATH ] = { 0 };

		moduleName.clear ( );

		s = VirtualQueryEx ( hProcess, ( LPCVOID ) pAddr, &mbi, sizeof ( MEMORY_BASIC_INFORMATION ) );
		if ( s == 0 )
			goto Cleanup;

		bSuccess = K32GetModuleBaseNameA ( hProcess, ( HMODULE ) mbi.AllocationBase, ( LPSTR ) cmoduleName, MAX_PATH );
		if ( bSuccess == FALSE )
			goto Cleanup;

		moduleName = std::string ( cmoduleName );

		bSuccess = TRUE;

	Cleanup:

		return bSuccess;

	}

	VOID RemoveKernelAddrs ( std::vector<ULONG_PTR>& stack ) {

		auto it = stack.begin ( );
		while ( it != stack.end ( ) ) {

			ULONG_PTR addr = *it;
			if ( addr > 0xFFFF000000000000 ) {
				it = stack.erase ( it );
			}
			else {
				++it;
			}

		}

	}

	//https://github.com/outflanknl/Dumpert/blob/master/Dumpert/Outflank-Dumpert/Dumpert.c Is Elevated() was taken from here :).
	BOOL IsElevated ( VOID ) {
		BOOL fRet = FALSE;
		HANDLE hToken = NULL;
		if ( OpenProcessToken ( GetCurrentProcess ( ), TOKEN_QUERY, &hToken ) ) {
			TOKEN_ELEVATION Elevation = { 0 };
			DWORD cbSize = sizeof ( TOKEN_ELEVATION );
			if ( GetTokenInformation ( hToken, TokenElevation, &Elevation, sizeof ( Elevation ), &cbSize ) ) {
				fRet = Elevation.TokenIsElevated;
			}
		}
		if ( hToken ) {
			CloseHandle ( hToken );
		}
		return fRet;
	}


}