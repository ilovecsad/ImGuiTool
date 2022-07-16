#include "Log.h"


send_notepad::send_notepad()
{
    m_create = FALSE;
    m_hwnd = 0;
    m_pi = { 0 };
}

send_notepad::~send_notepad()
{
    if (m_pi.dwProcessId && m_pi.hProcess)
    {
        TerminateProcess(m_pi.hProcess, 0);
    }
}

bool send_notepad::DoLogV(const char* fmt, va_list vargs)
{
    char varbuf[2048] = { 0 };
    char message[4096] = { 0 };
    char timebuf[256] = { 0 };

    // Format message time
    auto t = std::time(nullptr);
    tm stm;
    localtime_s(&stm, &t);
    std::strftime(timebuf, _countof(timebuf), "%Y-%m-%d %H:%M:%S", &stm);

    // Format messages
    vsprintf_s(varbuf, _countof(varbuf), fmt, vargs);
    sprintf_s(message, _countof(message), "%s:%s", timebuf, varbuf);

    SendMessageA(m_hwnd, EM_REPLACESEL, 0, (LPARAM)message);

    return true;
}


VOID send_notepad::init()
{

    if(m_create) return;

    WCHAR szDirectory[MAX_PATH] = { 0 };

    GetSystemDirectoryW(szDirectory, MAX_PATH);
    wcscat_s(szDirectory, L"\\notepad.exe");

    STARTUPINFOW si = { sizeof(si) };

    HWND hwnd = NULL;
    hwnd = FindWindowW(L"Notepad", NULL);
    if (hwnd)
    {
        m_hwnd = FindWindowEx(hwnd, NULL, TEXT("Edit"), NULL);
        if (m_hwnd)
        {
            m_create = TRUE;
        }
    }
    if (!m_hwnd)
    {
        if (CreateProcessW(NULL, szDirectory, NULL, NULL, FALSE, 0, NULL, NULL, &si, &m_pi))
        {
            Sleep(1000);
            hwnd = FindWindowW(L"Notepad", NULL);
            if (hwnd)
            {
                m_hwnd = FindWindowEx(hwnd, NULL, TEXT("Edit"), NULL);
                if (m_hwnd)
                {
                    m_create = TRUE;
                }
            }
        }
    }

    return VOID();
}

VOID send_notepad::send(char* szText, ...)
{
    if (m_create)
    {
        va_list alist;
        bool result = false;

        va_start(alist, szText);
        result = DoLogV(szText, alist);
        va_end(alist);
    }
    return VOID();
}

VOID send_notepad::clear()
{
    if (m_create) {
        SendMessageA(m_hwnd, WM_SETTEXT, 0, NULL);
    }
    return VOID();
}