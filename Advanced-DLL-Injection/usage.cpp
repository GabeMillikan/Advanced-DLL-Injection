#include "dll_injection.hpp"
#include <iostream>

int main()
{
	//DLLInjection::Util::prettyPrintHeaders = true;
	//DLLInjection::Util::dumpWPM = true;
	DLLInjection::Util::logs = true;
	DLLInjection::InjectionError err = DLLInjection::inject(
		"C:\\Users\\GabeLaptop\\Documents\\GitHub\\GabeMillikan\\SimpleDll\\Release\\SimpleDll.dll",
		"sample.exe"
	);
	
	if (err != DLLInjection::InjectionError::Success)
	{
		std::cout << "Injection Error: " << (int)err << std::endl;
		std::cout << "Windows Error Code: " << (int)GetLastError() << std::endl;
	}
}