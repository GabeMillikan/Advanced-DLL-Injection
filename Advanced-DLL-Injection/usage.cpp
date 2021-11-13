#include "dll_injection.hpp"
#include <iostream>
#include <fstream>

int main()
{
	std::fstream file(
		"C:\\Users\\GabeLaptop\\Documents\\GitHub\\GabeMillikan\\SimpleDll\\Release\\SimpleDll.dll",
		std::ios::in | std::ios::binary
	);

	file.seekg(0, std::ios::end);
	size_t fileSz = (size_t)file.tellg();
	file.seekg(0);

	char* dll = new char[fileSz];
	file.read(dll, fileSz);

	DLLInjection::InjectionError err = DLLInjection::inject(23108, dll, fileSz);
	if (err != DLLInjection::InjectionError::Success)
	{
		std::cout << "Failed w/ error: " << (int)err << std::endl;
	}

	delete[] dll;
}