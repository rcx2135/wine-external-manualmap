#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
  if (reason == DLL_PROCESS_ATTACH) {
    MessageBoxA(NULL, "manual map worked", "sncajector", MB_OK);
  }

  return TRUE;
}
