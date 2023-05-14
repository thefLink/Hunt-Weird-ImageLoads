#pragma once

#include "windows.h"
#include <vector>

#include "Helpers.h"

namespace Detectors {
		
	class DetectorImageLoad {
	public:
		virtual VOID Check ( HANDLE, std::vector<ULONG_PTR>, DWORD, std::wstring ) = 0;
	};

	class DetectorThreadStart {
	public:
		virtual VOID Check ( HANDLE, std::vector<ULONG_PTR>, DWORD, PVOID ) = 0;
	};

	class PrivateRX : public DetectorImageLoad { public: VOID Check ( HANDLE, std::vector<ULONG_PTR>, DWORD, std::wstring ); };
	class PrivateRWX : public DetectorImageLoad { public: VOID Check ( HANDLE, std::vector<ULONG_PTR>, DWORD, std::wstring ); };
	class ModuleStomped : public DetectorImageLoad { public: VOID Check ( HANDLE, std::vector<ULONG_PTR>, DWORD, std::wstring ); };
	class ModuleProxying : public DetectorImageLoad { public: VOID Check ( HANDLE, std::vector<ULONG_PTR>, DWORD, std::wstring ); };

	class DedicatedThread : public DetectorThreadStart { public: VOID Check ( HANDLE, std::vector<ULONG_PTR>, DWORD, PVOID); };

}