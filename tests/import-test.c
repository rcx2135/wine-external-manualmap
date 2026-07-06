#include <windows.h>

volatile DWORD g_tick;

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
  if (reason == DLL_PROCESS_ATTACH) {
    g_tick = GetTickCount();
  }

  return TRUE;
}
