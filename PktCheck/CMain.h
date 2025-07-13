#pragma once


#include "CLog.h"
#include "CPacket.h"



class C_MAIN
{
private:
	C_PACKET *pPacket;

public:
	C_MAIN();
	~C_MAIN();

	long Init(HINSTANCE h, LPTSTR lpCmdLine);
	long Create();
	long Calculate();
	void Display();
	void Destroy();

};
