#include "dll_injection.hpp"
#include <memory>
#include <iostream>

DLLInjection::InjectionError DLLInjection::Injector::inject(const HANDLE proc)
{
	/*
		PARSE HEADERS
	*/
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
		ALLOCATE SPACE IN THE HOST PROCESS
	*/
	void* RVABase = VirtualAllocEx(proc, NULL, ntHeaders.OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!RVABase) { return InjectionError::Remote_AllocateFailed; }

	/*
		WRITE DATA TO HOST PROCESS
	*/
	constexpr size_t blockSize = WPM_BLOCK_SIZE * 4;

	// headers
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
		IMAGE_SECTION_HEADER& sectionHeader = sectionHeaders[i];
		std::cout << "Copying section: "  << sectionHeader.Name << std::endl;

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

	// shellcode
	std::cout << "DONE" << std::endl;

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

DLLInjection::InjectionError DLLInjection::inject(DWORD pid, char* dll, size_t dllSize)
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