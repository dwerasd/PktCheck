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
	// �α� ������ ������ �����Ѵ�
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
		// �α� ������ ������ �����Ѵ�
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
		// ���� ��¥�� ����
		//////////////////////////////////////////////////////////////////////////
		tm t;
		time_t tToday = time(0);
		localtime_s(&t, &tToday);
		WCHAR wszDate[1 << 5];
		wcsftime(wszDate, sizeof(wszDate), L"%Y-%m-%d", &t);
		//////////////////////////////////////////////////////////////////////////
		// \$(LogPath)\$(today).txt ���Ͽ� �α׸� ����
		//////////////////////////////////////////////////////////////////////////
		WCHAR wszSavePath[MAX_PATH];
		wsprintfW(wszSavePath, L"%s\\%s.txt", wszLogPath, wszDate);
		//////////////////////////////////////////////////////////////////////////
		// ������ ������ ���� ������ �����Ѵ�.
		//////////////////////////////////////////////////////////////////////////
		WIN32_FIND_DATAW finddata;
		BOOL bExistFile = (INVALID_HANDLE_VALUE != FindFirstFileW(wszSavePath, &finddata));
		DWORD dwCreationDisposition = bExistFile ? OPEN_ALWAYS : CREATE_ALWAYS;
		hFile = CreateFileW(wszSavePath, GENERIC_WRITE, NULL, NULL, dwCreationDisposition, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
		// ������ ��������
		if (INVALID_HANDLE_VALUE != hFile)
		{
			DWORD dwWritten = 0;
			if (FALSE == bExistFile)	// ���� �����ѰŸ�
			{
				BYTE buf[2] = { 0xff, 0xfe };
				WriteFile(hFile, buf, 2, &dwWritten, NULL);
			}
			WCHAR wszBuffer[MAX_LOG_BUFFER];
			ZeroMemory(wszBuffer, sizeof(wszBuffer));
			// �޽����� tszBuffer �� �ۼ��ϰ�
			va_list fmtList;
			va_start(fmtList, lpszFormat);
			_vsnwprintf_s(wszBuffer, MAX_LOG_BUFFER - 1, MAX_LOG_BUFFER - 1, lpszFormat, fmtList);
			va_end(fmtList);

			//DBGPRINT(L"%s", wszBuffer);

			// ��¥�� �ð��� ����. 
			WCHAR wszTimeStamp[1 << 5];	// 32
			wcsftime(wszTimeStamp, sizeof(wszTimeStamp), L"%Y-%m-%d %H:%M:%S", &t);
			//////////////////////////////////////////////////////////////////////////
			// $(date)$(time)  $(data)\r\n ���� �ۼ��Ѵ�
			//////////////////////////////////////////////////////////////////////////
			WCHAR wszSaveBuffer[MAX_LOG_BUFFER];
			ZeroMemory(wszSaveBuffer, sizeof(wszSaveBuffer));
			wsprintfW(wszSaveBuffer, L"(%s) %s\r\n", wszTimeStamp, wszBuffer);
			// ������ ���� ���� ����.
			if (INVALID_SET_FILE_POINTER != SetFilePointer(hFile, 0, NULL, FILE_END))
			{
				WriteFile(hFile, wszSaveBuffer, (int)wcslen(wszSaveBuffer) * 2, &dwWritten, NULL);
			}
			CloseHandle(hFile);
		}
	}
}
