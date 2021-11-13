#pragma once
#include <Windows.h>
#include <vector>

namespace DLLInjection {
	// main configurable property
	// this is how many dwords will be written to the host per WriteProcessMemory call
	// setting this to a low number like `1` will make sure that only 4 bytes of your dll
	// will be represented in the injector process's memory at a time, but it's conna call
	// WPM like 10,000 times which takes forever and will make a debugger freak out
	// alternatively, setting it to a high number like 4096 will mean that a large portion
	// of the DLL will exist in the injector's memory at a time, but there will be few WPM calls
	// also note that these will be held on the stack, so it can't actually get too big
	constexpr size_t WPM_BLOCK_SIZE = 256; // measured in dwords (256 dwords = 1 kilobyte)

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

		OpenProcessFailed,
		NoExecutableSection,
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

		// writes a struct `T` at a certain RVA
		template <typename T>
		bool writeStruct(const HANDLE& proc, const void* const& RVA, const T& s, const size_t& onlyWriteBytes = (size_t)-1)
		{
			const size_t writeBytes = min(onlyWriteBytes, sizeof(T));

			size_t nBytesWritten = 0;

			// sorry about the weird casts, its just because microsoft sucks lmao
			// "can't convert from size_t to SIZE_T" my ass
			return WriteProcessMemory(proc, (void*)RVA, (void*)&s, writeBytes, (SIZE_T*)&nBytesWritten) && nBytesWritten == writeBytes;
		}

		// copies bytes from the file
		template <size_t BlockSize>
		InjectionError writeBytesFromFile(const HANDLE& proc, const void* const& RVA, const size_t& fileOffset, const size_t& n)
		{
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
				if (!this->readStruct(writeBuffer, bytesWritten, needToWrite))
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

	InjectionError inject(DWORD pid, char* dll, size_t dllSize); // NOT RESPONSIBLE FOR DECONSTRUCTION
	InjectionError inject(const char* procExeFile, const char* dllPath);
}