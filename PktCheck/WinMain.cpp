// PktCheck.cpp : ���� ���α׷��� ���� �������� �����մϴ�.
//

#include "stdafx.h"
#include "CMain.h"



int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine, int nCmdShow)
{
	UNREFERENCED_PARAMETER(hPrevInstance);
	UNREFERENCED_PARAMETER(lpCmdLine);
	UNREFERENCED_PARAMETER(nCmdShow);

	// TODO: ���⿡ �ڵ带 �Է��մϴ�.

	C_MAIN *pMain = new C_MAIN();
	if (0 == pMain->Init(hInstance, lpCmdLine))
	{
		if (0 == pMain->Create())
		{
			MSG msg;
			do
			{
				if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
				{
					TranslateMessage(&msg);
					DispatchMessage(&msg);
				}
				if (pMain->Calculate())
				{
					break;
				}
				pMain->Display();
			} while (msg.message != WM_QUIT);
		}
		pMain->Destroy();
	}
	delete pMain;
	return(0);
}
