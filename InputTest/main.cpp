#include <windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <deque>
#include <comdef.h>
#include <Wbemidl.h>
#include <strsafe.h>
#pragma comment(lib, "wbemuuid.lib")

HHOOK g_hMouseHook = NULL;
HWND  g_hMainWindow = NULL;
COLORREF g_bgColor = RGB(255, 255, 255);

// for synchronizing and storing raw input events timestamps
CRITICAL_SECTION g_csRawInput;
std::deque<DWORD> g_RawInputTimes;

// last hDevice from WM_INPUT
CRITICAL_SECTION g_csDevice;
HANDLE g_hMouseDevice = NULL;

struct DeviceInfo {
    UINT vendorId;
    UINT productId;
};


void LogMessage(const char* message) {
    OutputDebugStringA(message);
}

// 1 - compare mouse event with raw input events
// true = event exists in both windows message and raw input event
bool IsInRawInput(const MSLLHOOKSTRUCT* pMouse) {
    DWORD eventTime = pMouse->time;
    bool found = false;

    EnterCriticalSection(&g_csRawInput);
    for (auto it = g_RawInputTimes.begin(); it != g_RawInputTimes.end(); ) {
        if (abs((int)(*it - eventTime)) < 20) {
            found = true;
            break;
        }
        // Удаляем события, старше 100 мс
        if (eventTime - *it > 100)
            it = g_RawInputTimes.erase(it);
        else
            ++it;
    }
    LeaveCriticalSection(&g_csRawInput);
    return found;
}

// 2 - get the "HID\\VID_" from the device name (ignore generic HIDs)
// compare HID/VID with the device name
bool GetDeviceInfo(const MSLLHOOKSTRUCT* /*pMouse*/, DeviceInfo& info) {
    EnterCriticalSection(&g_csDevice);
    HANDLE hDevice = g_hMouseDevice;
    LeaveCriticalSection(&g_csDevice);

    if (hDevice == NULL)
        return false;

    RID_DEVICE_INFO ridInfo;
    ridInfo.cbSize = sizeof(RID_DEVICE_INFO);
    UINT size = sizeof(RID_DEVICE_INFO);
    if (GetRawInputDeviceInfo(hDevice, RIDI_DEVICEINFO, &ridInfo, &size) == (UINT)-1)
        return false;

    // get device name
    UINT nameSize = 0;
    if (GetRawInputDeviceInfoA(hDevice, RIDI_DEVICENAME, NULL, &nameSize) < 0)
        return false;

    char* deviceNameA = new char[nameSize];
    if (GetRawInputDeviceInfoA(hDevice, RIDI_DEVICENAME, deviceNameA, &nameSize) < 0) {
        delete[] deviceNameA;
        return false;
    }

#ifdef UNICODE
    int len = MultiByteToWideChar(CP_ACP, 0, deviceNameA, -1, NULL, 0);
    TCHAR* deviceName = new TCHAR[len];
    MultiByteToWideChar(CP_ACP, 0, deviceNameA, -1, deviceName, len);
#else
    TCHAR* deviceName = deviceNameA;
#endif

    if (_tcsstr(deviceName, _T("HID\\VID_")) == NULL) {
        info.vendorId = 0;
        info.productId = 0;
#ifdef UNICODE
        delete[] deviceName;
        delete[] deviceNameA;
#else
        delete[] deviceNameA;
#endif
        return true;
    }

    int vendor = 0, product = 0;
    TCHAR* vidStr = _tcsstr(deviceName, _T("VID_"));
    if (vidStr != NULL) {
        // expecting "VID_XXXX"
        if (_stscanf_s(vidStr, _T("VID_%04X"), &vendor) != 1)
            vendor = 0;
    }
    TCHAR* pidStr = _tcsstr(deviceName, _T("PID_"));
    if (pidStr != NULL) {
        if (_stscanf_s(pidStr, _T("PID_%04X"), &product) != 1)
            product = 0;
    }
    info.vendorId = vendor;
    info.productId = product;

#ifdef UNICODE
    delete[] deviceName;
    delete[] deviceNameA;
#else
    delete[] deviceNameA;
#endif

    return true;
}

// 3 - interruptions check via the WMI
bool CheckDeviceInterrupts() {
    HRESULT hres;

    // COM init
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
        return false;
    hres = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL);
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    // get IWbemLocator
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) {
        CoUninitialize();
        return false;
    }

    // get the ROOT\CIMV2 namespace
    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) {
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // no fucking idea tbh
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // track WMI event __InstanceModificationEvent every second
    BSTR queryLanguage = SysAllocString(L"WQL");
    BSTR query = SysAllocString(L"SELECT * FROM __InstanceModificationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PointingDevice'");
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecNotificationQuery(queryLanguage, query,
        WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_FORWARD_ONLY,
        NULL, &pEnumerator);
    SysFreeString(queryLanguage);
    SysFreeString(query);
    if (FAILED(hres)) {
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return false;
    }

    // wait for 2 seconds
    IWbemClassObject* pEvent = NULL;
    ULONG returned = 0;
    hres = pEnumerator->Next(2000, 1, &pEvent, &returned);
    bool interrupts = false;
    if (SUCCEEDED(hres) && returned > 0) {
        interrupts = true;
        pEvent->Release();
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    if (interrupts) {
        LogMessage("CheckDeviceInterrupts: Interrupt event received. Physical device confirmed.\n");
    }
    else {
        LogMessage("CheckDeviceInterrupts: No interrupt event received within timeout.\n");
    }
    return interrupts;
}


// mouse hood
LRESULT CALLBACK LowLevelMouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        MSLLHOOKSTRUCT* pMouse = (MSLLHOOKSTRUCT*)lParam;
        char logBuffer[256] = { 0 };
        bool valid = true;

        // check for LLMHF_INJECTED flag
        if (pMouse->flags & LLMHF_INJECTED) {
            sprintf_s(logBuffer, sizeof(logBuffer),
                "Invalid Virtual Input: LLMHF_INJECTED detected.\n");
            LogMessage(logBuffer);
            valid = false;
        }

        // find mouse event in raw input events
        if (!IsInRawInput(pMouse)) {
            sprintf_s(logBuffer, sizeof(logBuffer),
                "Invalid Virtual Input: Event missing in Raw Input.\n");
            LogMessage(logBuffer);
            valid = false;
        }

		// get device name and compare HID/VID
        DeviceInfo deviceInfo;
        if (!GetDeviceInfo(pMouse, deviceInfo)) {
            sprintf_s(logBuffer, sizeof(logBuffer),
                "Invalid Virtual Input: Cannot retrieve device info.\n");
            LogMessage(logBuffer);
            valid = false;
        }
        /*
        // check for interrupts via WMI
        // TODO DOESN'T WORK
        if (!CheckDeviceInterrupts()) {
            sprintf_s(logBuffer, sizeof(logBuffer),
                "Invalid Virtual Input: Device not generating interrupts.\n");
            LogMessage(logBuffer);
            valid = false;
        }*/

        if (valid) {
            sprintf_s(logBuffer, sizeof(logBuffer), "Valid Physical Input detected.\n");
            LogMessage(logBuffer);
        }
		// send 1 -> green, 0 -> red
        PostMessage(g_hMainWindow, WM_USER + 1, valid ? 1 : 0, 0);
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_INPUT: {
        UINT dwSize = 0;
        GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &dwSize, sizeof(RAWINPUTHEADER));
        BYTE* lpb = new BYTE[dwSize];
        if (lpb) {
            if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, lpb, &dwSize, sizeof(RAWINPUTHEADER)) == dwSize) {
                RAWINPUT* raw = (RAWINPUT*)lpb;
                if (raw->header.dwType == RIM_TYPEMOUSE) {
					// rawinput event timestamp
                    EnterCriticalSection(&g_csRawInput);
                    g_RawInputTimes.push_back(GetTickCount());
                    LeaveCriticalSection(&g_csRawInput);

                    // hDevice
                    EnterCriticalSection(&g_csDevice);
                    g_hMouseDevice = raw->header.hDevice;
                    LeaveCriticalSection(&g_csDevice);

                    LogMessage("Raw Input: Mouse event received.\n");
                }
            }
            delete[] lpb;
        }
        break;
    }
    case WM_USER + 1: {
        // 1 -> green, 0 -> red
        if (wParam == 1)
            g_bgColor = RGB(0, 255, 0);
        else
            g_bgColor = RGB(255, 0, 0);
        InvalidateRect(hWnd, NULL, TRUE);
        break;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hWnd, &ps);
        HBRUSH hBrush = CreateSolidBrush(g_bgColor);
        FillRect(hdc, &ps.rcPaint, hBrush);
        DeleteObject(hBrush);
        EndPaint(hWnd, &ps);
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
    LPTSTR lpCmdLine, int nCmdShow)
{
    // init rawinput event timestamps and our input device
    InitializeCriticalSection(&g_csRawInput);
    InitializeCriticalSection(&g_csDevice);

    // debug console
    FILE* fp = nullptr;
    freopen_s(&fp, "CONOUT$", "w", stdout);

    // window
    WNDCLASS wc = { 0 };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = _T("AntiCheatWindowClass");
    RegisterClass(&wc);

    HWND hWnd = CreateWindow(_T("AntiCheatWindowClass"), _T("AntiCheat Test Platform"),
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        NULL, NULL, hInstance, NULL);
    g_hMainWindow = hWnd;
    if (!hWnd) {
        MessageBox(NULL, _T("Window creation failed!"), _T("Error"), MB_ICONERROR);
        return 0;
    }
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);

    // register raw input
    RAWINPUTDEVICE rid;
    rid.usUsagePage = 0x01;
    rid.usUsage = 0x02; // for mouse
    rid.dwFlags = RIDEV_INPUTSINK;
    rid.hwndTarget = hWnd;
    if (!RegisterRawInputDevices(&rid, 1, sizeof(rid))) {
        MessageBox(hWnd, _T("Failed to register Raw Input device."), _T("Error"), MB_ICONERROR);
    }

    // mouse hook
    g_hMouseHook = SetWindowsHookEx(WH_MOUSE_LL, LowLevelMouseProc, hInstance, 0);
    if (!g_hMouseHook) {
        MessageBox(hWnd, _T("Failed to set mouse hook."), _T("Error"), MB_ICONERROR);
        return 0;
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    UnhookWindowsHookEx(g_hMouseHook);
    DeleteCriticalSection(&g_csRawInput);
    DeleteCriticalSection(&g_csDevice);

    return (int)msg.wParam;
}
