#include "SilentJack2-Client.hpp"
#include <iostream>

int main()
{
	SilentJack sj;
	sj.Init();
	sj.GetHandle(L"Game.exe");

	DWORD64 world = 0;
	sj.qRVM(0x1000, &world, sizeof(DWORD64));

	cout << "read @ 0x" << hex << world << endl;

	system("pause");
	return EXIT_SUCCESS;
}