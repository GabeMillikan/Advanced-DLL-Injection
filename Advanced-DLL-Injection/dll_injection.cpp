#include "dll_injection.hpp"
#include <memory>
#include <fstream>

bool DLLInjection::Util::prettyPrintHeaders = false;
bool DLLInjection::Util::dumpWPM = false;
bool DLLInjection::Util::logs = false;

typedef HMODULE(__stdcall* pLoadLibraryA)(LPCSTR);
typedef FARPROC(__stdcall* pGetProcAddress)(HMODULE, LPCSTR);
typedef INT(__stdcall* dllmain)(HMODULE, DWORD, LPVOID);

struct LoaderData
{
	LPVOID ImageBase;

	PIMAGE_NT_HEADERS NtHeaders;
	PIMAGE_BASE_RELOCATION BaseReloc;
	PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;

	pLoadLibraryA fnLoadLibraryA;
	pGetProcAddress fnGetProcAddress;

};

DWORD __stdcall libraryLoader(LPVOID Memory)
{
	LoaderData* LoaderParams = (LoaderData*)Memory;

	PIMAGE_BASE_RELOCATION pIBR = LoaderParams->BaseReloc;

	DWORD delta = (DWORD)((LPBYTE)LoaderParams->ImageBase - LoaderParams->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			int count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			PWORD list = (PWORD)(pIBR + 1);

			for (int i = 0; i < count; i++)
			{
				if (list[i])
				{
					PDWORD ptr = (PDWORD)((LPBYTE)LoaderParams->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	PIMAGE_IMPORT_DESCRIPTOR pIID = LoaderParams->ImportDirectory;

	// Resolve DLL imports
	while (pIID->Characteristics)
	{
		PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->OriginalFirstThunk);
		PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)LoaderParams->ImageBase + pIID->FirstThunk);

		HMODULE hModule = LoaderParams->fnLoadLibraryA((LPCSTR)LoaderParams->ImageBase + pIID->Name);
		
		if (!hModule)
			return FALSE;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule,
					(LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			else
			{
				// Import by name
				PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)LoaderParams->ImageBase + OrigFirstThunk->u1.AddressOfData);
				DWORD Function = (DWORD)LoaderParams->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					return FALSE;

				FirstThunk->u1.Function = Function;
			}
			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	if (LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		dllmain EntryPoint = (dllmain)((LPBYTE)LoaderParams->ImageBase + LoaderParams->NtHeaders->OptionalHeader.AddressOfEntryPoint);

		return EntryPoint((HMODULE)LoaderParams->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}
	return TRUE;
}

constexpr size_t SHELL_CODE_IA32_SIZE = 512; // overestimate a little, actual size should be 0xf7 = 247

DLLInjection::InjectionError DLLInjection::Injector::inject(const HANDLE proc)
{
	/*
		PARSE HEADERS
	*/
	if (Util::logs) printf("Parsing headers\n");
	IMAGE_DOS_HEADER dosHeader;
	if (!this->readStruct(dosHeader, 0)) { return InjectionError::ReadFail_DOSHeader; }
	if (dosHeader.e_magic != 0x5A4D) { return InjectionError::ParseFail_DOSHeader_BadMagic; }
	if (dosHeader.e_lfanew <= sizeof(IMAGE_DOS_HEADER)) { return InjectionError::ParseFail_DOSHeader_BadNTPointer; }

	IMAGE_NT_HEADERS ntHeaders;
	if (!this->readStruct(ntHeaders, dosHeader.e_lfanew)) { return InjectionError::ReadFail_NTHeaders; }
	if (ntHeaders.FileHeader.NumberOfSections == 0) { return InjectionError::ParseFail_NTHeaders_BadSectionCount; }

	IMAGE_SECTION_HEADER* sectionHeaders = new IMAGE_SECTION_HEADER[ntHeaders.FileHeader.NumberOfSections];
	auto _loweffort_deallocate = std::unique_ptr<IMAGE_SECTION_HEADER>(sectionHeaders); // make the above de-allocate when function returns
	for (size_t i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
	{
		const size_t fptr = dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + i * sizeof(IMAGE_SECTION_HEADER);
		IMAGE_SECTION_HEADER& header = sectionHeaders[i];
		if (!this->readStruct(header, fptr)) { return InjectionError::ReadFail_SectionHeaders; }
	}

	/*
		OUTPUT HEADERS FOR DEBUGGING
	*/
	if (Util::prettyPrintHeaders)
	{
		Util::printHeader(dosHeader);
		Util::printHeader(ntHeaders);
		Util::printHeader(sectionHeaders, ntHeaders.FileHeader.NumberOfSections);
	}

	/*
		ALLOCATE SPACE IN THE HOST PROCESS
	*/
	if (Util::logs) printf("Allocating 0x%X bytes in host for main image sections\n", ntHeaders.OptionalHeader.SizeOfImage);
	void* RVABase = VirtualAllocEx(proc, NULL, ntHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!RVABase) return InjectionError::Remote_AllocateFailed; 
	if (Util::logs) printf("Got image base address: 0x%p\n", RVABase);

	/*
		WRITE RAW DLL DATA TO HOST PROCESS
	*/
	constexpr size_t blockSize = WPM_BLOCK_SIZE * 4;

	// headers
	if (Util::logs) printf("Writing headers to host\n");
	const InjectionError headerWriteError = this->writeBytesFromFile<blockSize>(proc, RVABase, 0, ntHeaders.OptionalHeader.SizeOfHeaders);
	switch (headerWriteError)
	{
	case InjectionError::Success:
		break;
	case InjectionError::_ReadFail:
		return InjectionError::ReadFail_Headers;
	default:
		return headerWriteError;
	}

	// sections
	for (size_t i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
	{
		if (Util::logs) printf("Writing section %u to host\n", i);
		IMAGE_SECTION_HEADER& sectionHeader = sectionHeaders[i];

		const InjectionError sectionError = this->writeBytesFromFile<blockSize>(
			proc,
			addPointers(RVABase, sectionHeader.VirtualAddress),
			sectionHeader.PointerToRawData,
			sectionHeader.SizeOfRawData
		);

		switch (sectionError)
		{
		case InjectionError::Success:
			break;
		case InjectionError::_ReadFail:
			return InjectionError::ReadFail_Sections;
		default:
			return headerWriteError;
		}
	}

	/*
		WRITE LOADER SHELL CODE & PARAMETERS TO HOST PROCESS
	*/
	if (Util::logs) printf("Allocating 0x%X bytes in host for loader shell code and its data\n", sizeof(LoaderData) + SHELL_CODE_IA32_SIZE);
	const void* shellCodeRVA = VirtualAllocEx(proc, 0, sizeof(LoaderData) + SHELL_CODE_IA32_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!shellCodeRVA) return InjectionError::Remote_AllocateFailed;
	if (Util::logs) printf("Got shell code address: 0x%p\n", shellCodeRVA);

	// loader parameters
	LoaderData loaderParameters{
		// image base
		RVABase,

		// TODO: the shellcode could definitely parse this information on its own...
		(IMAGE_NT_HEADERS*)addPointers(RVABase, dosHeader.e_lfanew),
		(IMAGE_BASE_RELOCATION*)addPointers(RVABase, ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress),
		(IMAGE_IMPORT_DESCRIPTOR*)addPointers(RVABase, ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress),

		// kernel32 should ALWAYS load in the same location
		// but it would be a better idea to actually determine their correct address
		// in the (extremely rare, maybe impossible) case where it loads elsewhere
		LoadLibraryA,
		GetProcAddress
	};
	if (Util::logs) printf("Writing loader params\n");
	if (!this->writeStruct(proc, shellCodeRVA, loaderParameters))
		return InjectionError::Remote_WriteFailed;

	// shellcode
	if (Util::logs) printf("Writing shell code\n");
	if (!this->wpm(proc, addPointers(shellCodeRVA, sizeof(LoaderData)), (byte*)libraryLoader, SHELL_CODE_IA32_SIZE))
		return InjectionError::Remote_WriteFailed;

	/*
		EXECUTE LOADER SHELL CODE
	*/
	// start the thread
	if (Util::logs) printf("Starting remote thread for shell code at 0x%p\n", addPointers(shellCodeRVA, sizeof(LoaderData)));
	HANDLE hThread = CreateRemoteThread(
		proc,
		NULL,
		0,
		(LPTHREAD_START_ROUTINE)addPointers(shellCodeRVA, sizeof(LoaderData)),
		(LPVOID)shellCodeRVA,
		0,
		NULL
	);
	if (!hThread)
		return InjectionError::Remote_CreateThreadFailed;

	// wait for it to complete
	if (Util::logs) printf("Waiting for shell code completion\n");
	WaitForSingleObject(hThread, INFINITE);

	// free loader code, it won't be used anymore
	// don't worry if this fails, it doesn't really matter...
	if (Util::logs) printf("Freeing shell code allocations\n");
	VirtualFreeEx(proc, (LPVOID)shellCodeRVA, 0, MEM_RELEASE);

	if (Util::logs) printf("Injection Complete!\n");
	return InjectionError::Success;
}

namespace SimpleInjection {
	struct ProviderData {
		byte* dll;
		size_t dllSize;
	};

	bool byteProvider(const size_t fileOffset, const size_t requestedBytes, byte*& out_bytes, size_t& out_size, void* callbackForwardData)
	{
		const ProviderData& data = *(ProviderData*)callbackForwardData;
		
		out_bytes = data.dll + fileOffset;
		out_size = data.dllSize - fileOffset;

		return true;
	}

	// we do not need a destructor
}

DLLInjection::InjectionError DLLInjection::inject(char* dll, size_t dllSize, DWORD pid)
{
	// setup the injector
	SimpleInjection::ProviderData data{ (byte*)dll , dllSize };
	Injector inj(SimpleInjection::byteProvider, &data);

	// open the process
	HANDLE proc = OpenProcess(PROCESS_MINIMUM_RIGHTS, false, pid);
	if (!proc) return InjectionError::OpenProcessFailed;

	// inject
	return inj.inject(proc);
}

DLLInjection::InjectionError DLLInjection::inject(char* dll, size_t dllSize, const char* procExeFile)
{
	// get pid
	DWORD pid = Util::getPIDByExeName(procExeFile);
	if (!pid)
		return InjectionError::HostNotFound;

	// inject
	return inject(dll, dllSize, pid);
}


DLLInjection::InjectionError DLLInjection::inject(const char* dllPath, const char* procExeFile)
{
	// open file
	std::fstream file(
		dllPath,
		std::ios::in | std::ios::binary
	);
	if (!file.is_open())
		return InjectionError::DLLNotFound;

	// read file size
	file.seekg(0, std::ios::end);
	size_t fileSize = (size_t)file.tellg();
	file.seekg(0);

	// read all file data
	std::unique_ptr<char> dll(new char[fileSize]);
	file.read(dll.get(), fileSize);

	// inject
	return inject(dll.get(), fileSize, procExeFile);
}
