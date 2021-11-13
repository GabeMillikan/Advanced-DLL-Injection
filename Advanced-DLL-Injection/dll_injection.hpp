#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <codecvt>

#if defined DEBUG || defined _DEBUG 

#error You cannot manual map in debug mode, it wouldn't be ossible to execute the shell code that way, sorry

#endif // defined DEBUG || defined NDEBUG  || defined _DEBUG

#ifdef _WIN64

#error Only 32 bit architectures are supported

#endif _WIN32

namespace DLLInjection {
	// main configurable property
	// this is how many dwords will be written to the host per WriteProcessMemory call
	// setting this to a low number like `1` will make sure that only 4 bytes of your dll
	// will be represented in the injector process's memory at a time, but it's conna call
	// WPM like 10,000 times which takes forever and will make a debugger freak out
	// alternatively, setting it to a high number like 4096 will mean that a large portion
	// of the DLL will exist in the injector's memory at a time, but there will be few WPM calls
	// also note that these will be held on the stack, so it can't actually get too big
	constexpr size_t WPM_BLOCK_SIZE = 4096; // measured in dwords (256 dwords = 1 kilobyte)

	namespace Util
	{
		// just set these to true, watch the output window :)
		extern bool prettyPrintHeaders;
		extern bool dumpWPM;
		extern bool logs;

		// if the EXE of a process equals procExeName, then return that process's id
		// else return 0
		inline DWORD getPIDByExeName(std::wstring const& procExeName)
		{
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

			PROCESSENTRY32 entry{};
			entry.dwSize = sizeof(entry);

			for (bool moreProcesses = Process32First(snapshot, &entry); moreProcesses; moreProcesses = Process32Next(snapshot, &entry))
			{
				if (procExeName == entry.szExeFile)
				{
					CloseHandle(snapshot);
					return entry.th32ProcessID;
				}
			}

			CloseHandle(snapshot);

			return 0;
		}
		inline DWORD getPIDByExeName(const char* procExeName)
		{
			static std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
			return getPIDByExeName(converter.from_bytes(procExeName));
		}

		// pretty print functions:
		inline void printHeader(const IMAGE_DOS_HEADER& header)
		{
			printf("/------ [ IMAGE_DOS_HEADER ]\n");
			printf("| e_magic    = 0x%04X\n", header.e_magic);
			printf("| e_cblp     = 0x%04X\n", header.e_cblp);
			printf("| e_cp       = 0x%04X\n", header.e_cp);
			printf("| e_crlc     = 0x%04X\n", header.e_crlc);
			printf("| e_cparhdr  = 0x%04X\n", header.e_cparhdr);
			printf("| e_minalloc = 0x%04X\n", header.e_minalloc);
			printf("| e_maxalloc = 0x%04X\n", header.e_maxalloc);
			printf("| e_ss       = 0x%04X\n", header.e_ss);
			printf("| e_sp       = 0x%04X\n", header.e_sp);
			printf("| e_csum     = 0x%04X\n", header.e_csum);
			printf("| e_ip       = 0x%04X\n", header.e_ip);
			printf("| e_cs       = 0x%04X\n", header.e_cs);
			printf("| e_lfarlc   = 0x%04X\n", header.e_lfarlc);
			printf("| e_ovno     = 0x%04X\n", header.e_ovno);
			printf("| e_res[4]   = { 0x%04X, 0x%04X, 0x%04X, 0x%04X }\n", header.e_res[0], header.e_res[1], header.e_res[2], header.e_res[3]);
			printf("| e_oemid    = 0x%04X\n", header.e_oemid    );
			printf("| e_oeminfo  = 0x%04X\n", header.e_oeminfo  );
			printf("| e_res2[10] = { 0x%04X, 0x%04X, 0x%04X, 0x%04X, 0x%04X, 0x%04X, 0x%04X, 0x%04X, 0x%04X, 0x%04X }\n", header.e_res2[0], header.e_res2[1], header.e_res2[2], header.e_res2[3], header.e_res2[4], header.e_res2[5], header.e_res2[6], header.e_res2[7], header.e_res2[8], header.e_res2[9] );
			printf("| e_lfanew   = 0x%08X\n", header.e_lfanew   );
			printf("\\------ [ IMAGE_DOS_HEADER ]\n\n");
		}
		inline void printHeader(const IMAGE_NT_HEADERS& header)
		{
			const IMAGE_FILE_HEADER fheader = header.FileHeader;
			const IMAGE_OPTIONAL_HEADER optheader = header.OptionalHeader;

			printf("/------ [ IMAGE_NT_HEADERS ]\n");
			printf("| Signature = 0x%08X\n", header.Signature);
			printf("| \n");
			printf("| FileHeader:\n");
			printf("| /------ [ IMAGE_FILE_HEADER ]\n");
			printf("| | Machine              = 0x%04X\n", fheader.Machine);
			printf("| | NumberOfSections     = 0x%04X\n", fheader.NumberOfSections);
			printf("| | TimeDateStamp        = 0x%08X\n", fheader.TimeDateStamp);
			printf("| | PointerToSymbolTable = 0x%08X\n", fheader.PointerToSymbolTable);
			printf("| | NumberOfSymbols      = 0x%08X\n", fheader.NumberOfSymbols);
			printf("| | SizeOfOptionalHeader = 0x%04X\n", fheader.SizeOfOptionalHeader);
			printf("| | Characteristics      = 0x%04X\n", fheader.Characteristics);
			printf("| \\------ [ IMAGE_FILE_HEADER ]\n");
			printf("| \n");
			printf("| OptionalHeader:\n");
			printf("| /------ [ IMAGE_OPTIONAL_HEADER ]\n");
			printf("| | Magic                       = 0x%04X\n", optheader.Magic);
			printf("| | MajorLinkerVersion          = 0x%02X\n", optheader.MajorLinkerVersion);
			printf("| | MinorLinkerVersion          = 0x%02X\n", optheader.MinorLinkerVersion);
			printf("| | SizeOfCode                  = 0x%08X\n", optheader.SizeOfCode);
			printf("| | SizeOfInitializedData       = 0x%08X\n", optheader.SizeOfInitializedData);
			printf("| | SizeOfUninitializedData     = 0x%08X\n", optheader.SizeOfUninitializedData);
			printf("| | AddressOfEntryPoint         = 0x%08X\n", optheader.AddressOfEntryPoint);
			printf("| | BaseOfCode                  = 0x%08X\n", optheader.BaseOfCode);
			printf("| | BaseOfData                  = 0x%08X\n", optheader.BaseOfData);
			printf("| | ImageBase                   = 0x%08X\n", optheader.ImageBase);
			printf("| | SectionAlignment            = 0x%08X\n", optheader.SectionAlignment);
			printf("| | FileAlignment               = 0x%08X\n", optheader.FileAlignment);
			printf("| | MajorOperatingSystemVersion = 0x%04X\n", optheader.MajorOperatingSystemVersion);
			printf("| | MinorOperatingSystemVersion = 0x%04X\n", optheader.MinorOperatingSystemVersion);
			printf("| | MajorImageVersion           = 0x%04X\n", optheader.MajorImageVersion);
			printf("| | MinorImageVersion           = 0x%04X\n", optheader.MinorImageVersion);
			printf("| | MajorSubsystemVersion       = 0x%04X\n", optheader.MajorSubsystemVersion);
			printf("| | MinorSubsystemVersion       = 0x%04X\n", optheader.MinorSubsystemVersion);
			printf("| | Win32VersionValue           = 0x%08X\n", optheader.Win32VersionValue);
			printf("| | SizeOfImage                 = 0x%08X\n", optheader.SizeOfImage);
			printf("| | SizeOfHeaders               = 0x%08X\n", optheader.SizeOfHeaders);
			printf("| | CheckSum                    = 0x%08X\n", optheader.CheckSum);
			printf("| | Subsystem                   = 0x%04X\n", optheader.Subsystem);
			printf("| | DllCharacteristics          = 0x%04X\n", optheader.DllCharacteristics);
			printf("| | SizeOfStackReserve          = 0x%08X\n", optheader.SizeOfStackReserve);
			printf("| | SizeOfStackCommit           = 0x%08X\n", optheader.SizeOfStackCommit);
			printf("| | SizeOfHeapReserve           = 0x%08X\n", optheader.SizeOfHeapReserve);
			printf("| | SizeOfHeapCommit            = 0x%08X\n", optheader.SizeOfHeapCommit);
			printf("| | LoaderFlags                 = 0x%08X\n", optheader.LoaderFlags);
			printf("| | NumberOfRvaAndSizes         = 0x%08X\n", optheader.NumberOfRvaAndSizes);

			for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
			{
				const IMAGE_DATA_DIRECTORY& datadir = optheader.DataDirectory[i];
				printf("| | \n");
				printf("| | DataDirectory[%d]:\n", i);
				printf("| | /------ [ IMAGE_DATA_DIRECTORY ]\n");
				printf("| | | VirtualAddress = 0x%08X\n", datadir.VirtualAddress);
				printf("| | | Size           = 0x%08X\n", datadir.Size);
				printf("| | \\------ [ IMAGE_DATA_DIRECTORY ]\n");
			}


			printf("| \\------ [ IMAGE_OPTIONAL_HEADER ]\n");
			printf("\\------ [ IMAGE_NT_HEADERS ]\n\n");
		}
		inline void printHeader(const IMAGE_SECTION_HEADER* headers, const size_t& count)
		{
			printf("/------ [ IMAGE_SECTION_HEADER[%u] ]\n", count);
			for (size_t i = 0; i < count; i++)
			{
				const IMAGE_SECTION_HEADER& header = headers[i];
				auto sname = std::string((char*)header.Name, IMAGE_SIZEOF_SHORT_NAME);
				const char* name = sname.c_str();

				printf("| \n");
				printf("| Index %u:\n", i);
				printf("| /------ [ IMAGE_SECTION_HEADER ]\n");
				printf("| | Name                 = \"%s\"\n", name);
				printf("| | Misc.PhysicalAddress = 0x%08X\n", header.Misc.PhysicalAddress);
				printf("| | Misc.VirtualSize     = 0x%08X\n", header.Misc.VirtualSize);
				printf("| | VirtualAddress       = 0x%08X\n", header.VirtualAddress);
				printf("| | SizeOfRawData        = 0x%08X\n", header.SizeOfRawData);
				printf("| | PointerToRawData     = 0x%08X\n", header.PointerToRawData);
				printf("| | PointerToRelocations = 0x%08X\n", header.PointerToRelocations);
				printf("| | PointerToLinenumbers = 0x%08X\n", header.PointerToLinenumbers);
				printf("| | NumberOfRelocations  = 0x%04X\n", header.NumberOfRelocations);
				printf("| | NumberOfLinenumbers  = 0x%04X\n", header.NumberOfLinenumbers);
				printf("| | Characteristics      = 0x%08X\n", header.Characteristics);
				printf("| \\------ [ IMAGE_SECTION_HEADER ]\n");
			}
			printf("\\------ [ IMAGE_SECTION_HEADER[%u] ]\n\n", count);
		}
	}
	namespace Utils = Util; // for convenience

	// in order to inject to a process, you must have AT LEAST these rights
	// you could add more if you want. For example, if you also wanted to read data, use:
	// `PROCESS_MINIMUM_RIGHTS | PROCESS_VM_READ`
	constexpr DWORD PROCESS_MINIMUM_RIGHTS = PROCESS_ALL_ACCESS;

	// utility so u don't have to do nasty conversions
	template<typename T1, typename T2> inline void* addPointers(T1 a, T2 b)
	{
		return (void*)((uintptr_t)a + (uintptr_t)b);
	}

	// returned by various injection functions to describe what went wrong (if anything)
	enum class InjectionError {
		Success = 0,
		
		// read fail
		ReadFail_DOSHeader,
		ReadFail_NTHeaders,
		ReadFail_SectionHeaders,
		ReadFail_Headers, 
		ReadFail_Sections,
		_ReadFail, // only used internally

		// parse fail
		ParseFail_DOSHeader_BadMagic,
		ParseFail_DOSHeader_BadNTPointer,
		ParseFail_NTHeaders_BadSectionCount,

		// anything that deals with the remote process
		Remote_AllocateFailed,
		Remote_WriteFailed,
		Remote_CreateThreadFailed,

		// Other
		OpenProcessFailed,
		HostNotFound,
		DLLNotFound
	};

	// util to refer to bytes
	typedef unsigned char byte;

	// called when the injector needs access to a certain portion of the dll file
	// NOTE: if you allocate memory in this function, then you are responsible for freeing it in the below ByteProviderDestructor
	// return true/false for success/error
	// fileOffset = location in file that the injector wants access to
	// requestedBytes = the ideal number of bytes that injector would like to access (you can provide more or less than this)
	// out_bytes = byte array containing the binary data in the file (such that out_bytes[0] equals to byte in the file at fileOffset)
	// out_size = number of bytes in the above array, can be any size convenient to you, but larger file portions = faster inject
	// callbackForwardData = pointer to any data structure. Forwarded from the `byteProviderData` in the Injector constructor
	typedef bool(*DLLByteProvider)(const size_t fileOffset, const size_t requestedBytes, byte*& out_bytes, size_t& out_size, void* callbackForwardData);

	// called after the injector is done with the bytes received from the above function
	// if you allocated a `new byte[]` array in the DLLByteProvider, then now is a good time to `delete[]` it
	// if you don't need to deconstruct/deallocate anything, then just pass `nullptr` (the default)
	// thePreviouslyProvidedBytes = pointer to the array returned by DLLByteProvider (equivalent to its `out_bytes`)
	// callbackForwardData = pointer to any data structure. Forwarded from the `byteProviderDestructorData` in the Injector constructor
	// NOTE: this will not be called if you return `false` from DLLByteProvider, or if DLLByteProvider gives a nullptr for `out_bytes`
	typedef void(*ByteProviderDestructor)(byte* thePreviouslyProvidedBytes, void* callbackForwardData);

	// Each `Injector` instance is used for one .dll file, but can inject into multiple processes (although it's not really intended for that)
	// A simple example of using the Injector class is found in DLLInjection::inject(const char* procExeFile, const char* dllPath)
	class Injector {
		// documented in the constructor
		DLLByteProvider fnByteProvider;
		void* byteProviderData;
		ByteProviderDestructor fnByteProviderDestructor;
		void* byteProviderDestructorData;

		// reads a struct `T` from the dll file at fileoffset `offset`
		template <typename T>
		bool readStruct(T& s, const size_t& offset, const size_t& onlyReadBytes = (size_t)-1)
		{
			const size_t readBytes = min(onlyReadBytes, sizeof(T));

			size_t bytesRead = 0;
			while (bytesRead < readBytes)
			{
				// read some data from the provider
				size_t bytesNeeded = readBytes - bytesRead;
				size_t read = 0;
				byte* data = nullptr;
				bool success = this->fnByteProvider(offset + bytesRead, bytesNeeded, data, read, this->byteProviderData) && data != nullptr;
				if (!success) return false;

				// copy it into our struct
				const size_t usingBytes = min(read, bytesNeeded);
				memcpy((byte*)&s, data, usingBytes);
				bytesRead += usingBytes;

				// deconstruct the read data
				if (this->fnByteProviderDestructor)
					this->fnByteProviderDestructor(data, this->byteProviderDestructorData);
			}

			return true;
		}

		// general purpose wpm interface, since the arguments for wpm are really bad, and type casting inline is annoying
		inline bool wpm(const HANDLE& proc, const void* const& RVA, const byte* const& buffer, const size_t& writeBytes)
		{
			size_t nBytesWritten = 0;
			if (Util::dumpWPM)
			{
				printf("Writing %d bytes starting at 0x%p:\n", writeBytes, RVA);
				for (size_t i = 0; i < writeBytes; i++)
				{
					printf("%02X ", buffer[i]);
				}
				printf("\n");
			}
			return WriteProcessMemory(proc, (void*)RVA, (void*)buffer, writeBytes, (SIZE_T*)&nBytesWritten) && nBytesWritten == writeBytes;
		}

		// writes a struct `T` at a certain RVA
		template <typename T>
		bool writeStruct(const HANDLE& proc, const void* const& RVA, const T& s, const size_t& onlyWriteBytes = (size_t)-1)
		{
			const size_t writeBytes = min(onlyWriteBytes, sizeof(T));
			if (Util::logs) printf("Writing struct w/ size = %d, and writing %d bytes from that struct\n", sizeof(T), writeBytes);
			return this->wpm(proc, RVA, (byte*)&s, writeBytes);
		}

		// copies bytes from the file
		template <size_t BlockSize>
		InjectionError writeBytesFromFile(const HANDLE& proc, const void* const& RVA, const size_t& fileOffset, const size_t& n)
		{
			if (Util::logs) printf("Writing %d bytes from file starting at file position %d using block size = %d and dest RVA = 0x%p\n", n, fileOffset, BlockSize, RVA);
			struct WPMBlock {
				byte data[BlockSize];
			};
			WPMBlock writeBuffer;

			size_t bytesWritten = 0;
			while (bytesWritten < n)
			{
				// how many bytes we still need to read
				size_t needToWrite = n - bytesWritten;

				// read the data
				if (!this->readStruct(writeBuffer, fileOffset + bytesWritten, needToWrite))
					return InjectionError::_ReadFail;

				// write the data
				if (!this->writeStruct(proc, addPointers(RVA, bytesWritten), writeBuffer, needToWrite))
					return InjectionError::Remote_WriteFailed;

				bytesWritten += min(sizeof(WPMBlock), needToWrite);
			}

			return InjectionError::Success;
		}

	public:
		// this is kinda a mess.. take your time
		inline Injector(
			DLLByteProvider fnByteProvider, // returns the bytes of the file at a certain location
			void* byteProviderData = nullptr, // forwarded to above callback
			ByteProviderDestructor fnByteProviderDestructor = nullptr, // called after injector is done with the above provided byte
			void* byteProviderDestructorData = nullptr // forwarded to above callback
		) : fnByteProvider(fnByteProvider),
			byteProviderData(byteProviderData),
			fnByteProviderDestructor(fnByteProviderDestructor),
			byteProviderDestructorData(byteProviderDestructorData)
		{};

		// 1. processes dll headers
		// 2. writes relevant information to host process
		// 3. injects shellcode which processes relocations etc. and calls the entry point
		// 4. invokes the shellcode
		// proc = result from OpenProcess(); MUST HAVE PERMISSIONS: TODO: figure out which perms I need lol
		InjectionError inject(const HANDLE proc);
	};

	InjectionError inject(char* dll, size_t dllSize, DWORD pid); // NOT RESPONSIBLE FOR DECONSTRUCTION
	InjectionError inject(char* dll, size_t dllSize, const char* procExeFile);
	InjectionError inject(const char* dllPath, const char* procExeFile);
}