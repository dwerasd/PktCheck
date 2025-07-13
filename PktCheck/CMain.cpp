#include "stdafx.h"
#include "CMain.h"
#include "CLog.h"



C_MAIN::C_MAIN() : pPacket(nullptr)
{

}

C_MAIN::~C_MAIN()
{

}

long C_MAIN::Init(HINSTANCE h, LPTSTR lpCmdLine)
{
	h;
	lpCmdLine;
	CLOGPTR()->InitLog();
	if (nullptr == pPacket)
	{
		pPacket = new C_PACKET();
	}
	pPacket->Init();
	return(0);
}

long C_MAIN::Create()
{
	pPacket->Create();
	return(0);
}

long C_MAIN::Calculate()
{
	pPacket->Calculate();
	return(0);
}

void C_MAIN::Display()
{

}

void C_MAIN::Destroy()
{

}