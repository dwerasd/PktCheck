#include "stdafx.h"
#include "CLog.h"



C_LOG::C_LOG() : hFile(INVALID_HANDLE_VALUE)
{

}

C_LOG::~C_LOG()
{

}

void C_LOG::InitLog(LPCWSTR pwszLogName)
{
	::GetCurrentDirectoryW(sizeof(wszLogPath), wszLogPath);
	if (0 != pwszLogName)
	{
		wcscat_s(wszLogPath, L"\\");
		wcscat_s(wszLogPath, pwszLogName);
	}
	// 로그 폴더가 없으면 생성한다
	if (!PathIsDirectoryW(wszLogPath))
	{
		CreateDirectoryW(wszLogPath, NULL);
	}
}

void C_LOG::InitLog(LPCSTR s)
{
	if (0 != s)
	{
		WCHAR wszBuf[MAX_PATH];
		int len = (int)strlen(s) + 1;
		MultiByteToWideChar(CP_ACP, 0, s, len, wszBuf, len);
		InitLog(wszBuf);
	}
	else
	{
		::GetCurrentDirectoryW(sizeof(wszLogPath), wszLogPath);
		// 로그 폴더가 없으면 생성한다
		if (!PathIsDirectoryW(wszLogPath))
		{
			CreateDirectoryW(wszLogPath, NULL);
		}
	}
}

void C_LOG::Write(LPCSTR lpszFormat, ...)
{
	char szBuffer[MAX_LOG_BUFFER];
	va_list fmtList = NULL;
	va_start(fmtList, lpszFormat);
	_vsnprintf_s(szBuffer, MAX_LOG_BUFFER - 1, MAX_LOG_BUFFER - 1, lpszFormat, fmtList);
	va_end(fmtList);

	WCHAR wszBuf[MAX_PATH];
	int len = (int)strlen(szBuffer) + 1;
	MultiByteToWideChar(CP_ACP, 0, szBuffer, len, wszBuf, len);

	Write(wszBuf);
}

void C_LOG::Write(LPCWSTR lpszFormat, ...)
{
	if (0 != wszLogPath[0])
	{
		dk::C_REMOTE_RELEASE_LOCK lock(cs);

		//////////////////////////////////////////////////////////////////////////
		// 오늘 날짜를 구함
		//////////////////////////////////////////////////////////////////////////
		tm t;
		time_t tToday = time(0);
		localtime_s(&t, &tToday);
		WCHAR wszDate[1 << 5];
		wcsftime(wszDate, sizeof(wszDate), L"%Y-%m-%d", &t);
		//////////////////////////////////////////////////////////////////////////
		// \$(LogPath)\$(today).txt 파일에 로그를 남김
		//////////////////////////////////////////////////////////////////////////
		WCHAR wszSavePath[MAX_PATH];
		wsprintfW(wszSavePath, L"%s\\%s.txt", wszLogPath, wszDate);
		//////////////////////////////////////////////////////////////////////////
		// 파일이 있으면 열고 없으면 생성한다.
		//////////////////////////////////////////////////////////////////////////
		WIN32_FIND_DATAW finddata;
		BOOL bExistFile = (INVALID_HANDLE_VALUE != FindFirstFileW(wszSavePath, &finddata));
		DWORD dwCreationDisposition = bExistFile ? OPEN_ALWAYS : CREATE_ALWAYS;
		hFile = CreateFileW(wszSavePath, GENERIC_WRITE, NULL, NULL, dwCreationDisposition, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
		// 파일을 열었으면
		if (INVALID_HANDLE_VALUE != hFile)
		{
			DWORD dwWritten = 0;
			if (FALSE == bExistFile)	// 파일 생성한거면
			{
				BYTE buf[2] = { 0xff, 0xfe };
				WriteFile(hFile, buf, 2, &dwWritten, NULL);
			}
			WCHAR wszBuffer[MAX_LOG_BUFFER];
			ZeroMemory(wszBuffer, sizeof(wszBuffer));
			// 메시지를 tszBuffer 에 작성하고
			va_list fmtList;
			va_start(fmtList, lpszFormat);
			_vsnwprintf_s(wszBuffer, MAX_LOG_BUFFER - 1, MAX_LOG_BUFFER - 1, lpszFormat, fmtList);
			va_end(fmtList);

			//DBGPRINT(L"%s", wszBuffer);

			// 날짜와 시간을 얻음. 
			WCHAR wszTimeStamp[1 << 5];	// 32
			wcsftime(wszTimeStamp, sizeof(wszTimeStamp), L"%Y-%m-%d %H:%M:%S", &t);
			//////////////////////////////////////////////////////////////////////////
			// $(date)$(time)  $(data)\r\n 으로 작성한다
			//////////////////////////////////////////////////////////////////////////
			WCHAR wszSaveBuffer[MAX_LOG_BUFFER];
			ZeroMemory(wszSaveBuffer, sizeof(wszSaveBuffer));
			wsprintfW(wszSaveBuffer, L"(%s) %s\r\n", wszTimeStamp, wszBuffer);
			// 파일의 끝에 가서 쓴다.
			if (INVALID_SET_FILE_POINTER != SetFilePointer(hFile, 0, NULL, FILE_END))
			{
				WriteFile(hFile, wszSaveBuffer, (int)wcslen(wszSaveBuffer) * 2, &dwWritten, NULL);
			}
			CloseHandle(hFile);
		}
	}
}
