#include "dll_injection.hpp"

int main()
{
	DLLInjection::Util::prettyPrintHeaders = true;
	DLLInjection::Util::dumpWPM = true;
	DLLInjection::Util::logs = true;
	DLLInjection::inject("C:\\Users\\GabeLaptop\\Documents\\GitHub\\GabeMillikan\\SimpleDll\\Release\\SimpleDll.dll", "SimpleExe.exe");
}