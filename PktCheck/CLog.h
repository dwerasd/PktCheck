#pragma once


#include <windows.h>
#include <time.h>

#include <DarkCore/DLock.h>

#pragma warning(disable: 4201)   // nameless struct/union
#include <strstream>
#include <atlbase.h>       // USES_CONVERSION
#pragma warning(default: 4201)


#define MAX_LOG_BUFFER	(1 << 10)	// 64K



class C_LOG
{
private:
	C_LOG();
	~C_LOG();

	dk::C_LOCK cs;

	HANDLE hFile;
	WCHAR wszLogPath[1 << 10];

public:
	static C_LOG *GetInstance()
	{
		static C_LOG *pLog = nullptr;
		if (pLog == nullptr)
		{
			pLog = new C_LOG();
		}
		return(pLog);
	}

	void InitLog(LPCWSTR ptszLogName = 0);
	void InitLog(LPCSTR s);
	void Write(LPCWSTR ptszMessage, ...);
	void Write(LPCSTR ptszMessage, ...);
};

#define CLOGPTR		C_LOG::GetInstance
#define WRITELOG	CLOGPTR()->Write