#include "../shared/mapping.h"
#include <windows.h>
// https://github.com/jokelbaf/proton-injector/blob/master/src/shellcode.c
#ifdef _WIN64
#define RELOC_FLAG(x) (((x) >> 12) == IMAGE_REL_BASED_DIR64)
#else
#define RELOC_FLAG(x) (((x) >> 12) == IMAGE_REL_BASED_HIGHLOW)
#endif

typedef HINSTANCE(WINAPI *f_LoadLibraryA_t)(const char *lpLibFilename);
typedef FARPROC(WINAPI *f_GetProcAddress_t)(HMODULE hModule, LPCSTR lpProcName);
typedef HMODULE(WINAPI *f_GetModuleHandleA_t)(const char *lpModuleName);
typedef BOOL(WINAPI *f_DllMain_t)(void *handle_dll, DWORD dwReason,
                                  void *pReserved);

#ifdef _WIN64
typedef BOOL(WINAPIV *f_RtlAddFunctionTable_t)(RUNTIME_FUNCTION *FunctionTable,
                                               DWORD EntryCount,
                                               DWORD64 BaseAddress);
#endif

__attribute__((noinline, section(".text.shellcode"))) void __stdcall
shellcode(mapping_data_t *p_data) {

  if (!p_data) {
    __asm__ __volatile__("int3");
    return;
  }

  uint8_t *p_base = p_data->pbase;
  IMAGE_NT_HEADERS *nt =
      (IMAGE_NT_HEADERS *)(p_base + ((IMAGE_DOS_HEADER *)p_base)->e_lfanew);
  IMAGE_OPTIONAL_HEADER *opt = &nt->OptionalHeader;

  f_LoadLibraryA_t _LoadLibraryA = (f_LoadLibraryA_t)p_data->load_library_a;
  f_GetProcAddress_t _GetProcAddress =
      (f_GetProcAddress_t)p_data->get_proc_address;
  f_GetModuleHandleA_t _GetModuleHandleA =
      (f_GetModuleHandleA_t)p_data->get_module_handle_a;
#ifdef _WIN64
  f_RtlAddFunctionTable_t _RtlAddFunctionTable =
      (f_RtlAddFunctionTable_t)p_data->rtl_add_function_table;
#endif
  f_DllMain_t _DllMain = (f_DllMain_t)(p_base + opt->AddressOfEntryPoint);
  ULONG_PTR delta = (ULONG_PTR)p_base - (ULONG_PTR)opt->ImageBase;
  if (delta) {
    IMAGE_DATA_DIRECTORY *reloc_dir =
        &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (reloc_dir->Size) {
      IMAGE_BASE_RELOCATION *reloc =
          (IMAGE_BASE_RELOCATION *)(p_base + reloc_dir->VirtualAddress);
      IMAGE_BASE_RELOCATION *p_reloc_end =
          (IMAGE_BASE_RELOCATION *)((BYTE *)reloc + reloc_dir->Size);

      while (reloc < p_reloc_end && reloc->SizeOfBlock) {
        DWORD count =
            (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD *p_info = (WORD *)(reloc + 1);

        for (DWORD i = 0; i < count; i++, p_info++) {
          if (RELOC_FLAG(*p_info)) {
            ULONG_PTR *pPatch = (ULONG_PTR *)(p_base + reloc->VirtualAddress +
                                              (*p_info & 0xFFF));
            *pPatch += delta;
          }
        }

        reloc = (IMAGE_BASE_RELOCATION *)((BYTE *)reloc + reloc->SizeOfBlock);
      }
    }
  }

  IMAGE_DATA_DIRECTORY *import_dir =
      &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (import_dir->VirtualAddress && import_dir->Size &&
      import_dir->VirtualAddress < opt->SizeOfImage) {
    IMAGE_IMPORT_DESCRIPTOR *p_import =
        (IMAGE_IMPORT_DESCRIPTOR *)(p_base + import_dir->VirtualAddress);

    DWORD max_imports = import_dir->Size / sizeof(IMAGE_IMPORT_DESCRIPTOR);
    if (!max_imports || max_imports > 1024)
      max_imports = 1024;

    for (DWORD import_i = 0; import_i < max_imports && p_import->Name;
         import_i++, p_import++) {

      char *mod_name = (char *)(p_base + p_import->Name);

      HINSTANCE handle_dll =
          _GetModuleHandleA ? (HINSTANCE)_GetModuleHandleA(mod_name) : NULL;

      if (!handle_dll) {
        __asm__ __volatile__("int3");
        return;
      }

      ULONG_PTR *p_thunk_ref =
          (ULONG_PTR *)(p_base + p_import->OriginalFirstThunk);
      ULONG_PTR *p_func_ref = (ULONG_PTR *)(p_base + p_import->FirstThunk);

      if (!p_import->OriginalFirstThunk)
        p_thunk_ref = p_func_ref;

      for (DWORD thunk_i = 0; thunk_i < 4096 && *p_thunk_ref;
           thunk_i++, p_thunk_ref++, p_func_ref++) {

        if (IMAGE_SNAP_BY_ORDINAL(*p_thunk_ref)) {
          *p_func_ref = (ULONG_PTR)_GetProcAddress(
              handle_dll, (char *)(*p_thunk_ref & 0xFFFF));
        } else {
          ULONG_PTR name_rva = *p_thunk_ref;
          if (name_rva >= opt->SizeOfImage) {
            __asm__ __volatile__("int3");
            return;
          }

          IMAGE_IMPORT_BY_NAME *pByName =
              (IMAGE_IMPORT_BY_NAME *)(p_base + name_rva);

          *p_func_ref = (ULONG_PTR)_GetProcAddress(handle_dll, pByName->Name);
        }

        if (!*p_func_ref) {
          __asm__ __volatile__("int3");
          return;
        }
      }
    }
  }

  IMAGE_DATA_DIRECTORY *tls_dir =
      &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
  if (tls_dir->Size) {
    IMAGE_TLS_DIRECTORY *p_tls =
        (IMAGE_TLS_DIRECTORY *)(p_base + tls_dir->VirtualAddress);
    PIMAGE_TLS_CALLBACK *p_callback =
        (PIMAGE_TLS_CALLBACK *)p_tls->AddressOfCallBacks;

    for (; p_callback && *p_callback; p_callback++)
      (*p_callback)(p_base, DLL_PROCESS_ATTACH, NULL);
  }

  BOOL seh_failed = FALSE;

#ifdef _WIN64
  if (p_data->seh_support) {
    IMAGE_DATA_DIRECTORY *excep_dir =
        &opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (excep_dir->Size) {
      if (!_RtlAddFunctionTable(
              (RUNTIME_FUNCTION *)(p_base + excep_dir->VirtualAddress),
              excep_dir->Size / sizeof(RUNTIME_FUNCTION), (DWORD64)p_base))
        seh_failed = TRUE;
    }
  }
#endif

  _DllMain(p_base, p_data->fwd_reason_param, p_data->reserved_param);

  p_data->success = !seh_failed;

  __asm__ __volatile__("int3");
}

/*
x86_64-w64-mingw32-gcc shellcode/shellcode.c -c -O0 \
       -fno-asynchronous-unwind-tables \
       -fno-unwind-tables \
       -ffunction-sections -fdata-sections \
       -o shell.o
objcopy -O binary -j .text.shellcode shell.o shellcode.bin

 */
