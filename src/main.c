#define _GNU_SOURCE
#include <stdio.h>
#include <sys/uio.h>

#include "pe.h"
#include "../shared/mapping.h"
#include "../lib/ptrace_do/libptrace_do.h"
#define HEADER_SIZE 0x1000


typedef struct {
  void *base;
  uint8_t *header;
  uint8_t *image;
  IMAGE_DOS_HEADER *dos;
  IMAGE_NT_HEADERS *nt;
} remote_module_t;

int remote_read(pid_t pid, void *remote, void *local, size_t size) {
  struct iovec local_iov = {local, size};
  struct iovec remote_iov = {remote, size};
  if (process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0) != size) {
    perror("process_vm_readv");
    return -1;
  }
  return 0;
}

int remote_write(pid_t pid, void *remote, void *local, size_t size) {
  struct iovec local_iov = {local, size};
  struct iovec remote_iov = {remote, size};
  if (process_vm_writev(pid, &local_iov, 1, &remote_iov, 1, 0) != size) {
    perror("process_vm_writev");
    return -1;
  }
  return 0;
}

void free_module(remote_module_t *module) {
  if (module->image) {
    free(module->image);
    module->image = NULL;
  }
  if (module->header) {
    free(module->header);
    module->header = NULL;
  }
}

int get_module(pid_t pid, const char *module_name, remote_module_t *module) {
  memset(module, 0, sizeof(remote_module_t));

  FILE *map_file = NULL;
  char map_path[256];
  snprintf(map_path, sizeof(map_path), "/proc/%d/maps", pid);
  map_file = fopen(map_path, "r");
  if (!map_file) {
    perror("fopen");
    return -1;
  }

  char line[4096];
  while (fgets(line, sizeof(line), map_file)) {
    unsigned long start, end;
    char perms[5];
    unsigned long offset;
    char dev[12];
    unsigned long inode;
    char pathname[4096] = "";

    int fields = sscanf(line, "%lx-%lx %4s %lx %11s %lu %4095[^\n]", &start,
                        &end, perms, &offset, dev, &inode, pathname);
    // kernel32.dll
    if (fields > 0 && strstr(pathname, module_name) != NULL) {
      printf("%s found: %s\n", module_name, pathname);
      module->base = (void *)start;
      break;
    }
  }

  fclose(map_file);
  if (module->base == NULL) {
    return -1;
  }

  module->header = malloc(HEADER_SIZE);
  if (!module->header) {
    perror("malloc module->header");
    return -1;
  }

  if (remote_read(pid, module->base, module->header, HEADER_SIZE) != 0) {
    free_module(module);
    return -1;
  }

  IMAGE_DOS_HEADER *kernel32_dos = (IMAGE_DOS_HEADER *)module->header;

  if (kernel32_dos->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("Invalid DOS header magic: 0x%X\n", kernel32_dos->e_magic);
    free_module(module);
    return -1;
  }

  if (kernel32_dos->e_lfanew > HEADER_SIZE - sizeof(IMAGE_NT_HEADERS)) {
    printf("Invalid e_lfanew: 0x%X\n", kernel32_dos->e_lfanew);
    free_module(module);
    return -1;
  }

  module->nt = (IMAGE_NT_HEADERS *)(module->header + kernel32_dos->e_lfanew);

  if (module->nt->Signature != IMAGE_NT_SIGNATURE) {
    printf("Invalid NT signature: 0x%X\n", module->nt->Signature);
    free_module(module);
    return -1;
  }

  if (module->nt->OptionalHeader.SizeOfHeaders > HEADER_SIZE) {
    // ignore this for a bit, will come back to this
  }

  printf("NT signature: 0x%X\n", module->nt->Signature);
  printf("img size: %d\n", module->nt->OptionalHeader.SizeOfImage);

  module->image = malloc(module->nt->OptionalHeader.SizeOfImage);
  if (!module->image) {
    perror("malloc");
    free_module(module);
    return -1;
  }

  if (remote_read(pid, module->base, module->image,
                  module->nt->OptionalHeader.SizeOfImage) != 0) {
    perror("remote_read");
    free_module(module);
    return -1;
  }

  return 0;
}

void *get_function_address(remote_module_t *module, char *function_name) {
  IMAGE_DATA_DIRECTORY export_dir =
      module->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

  if (export_dir.VirtualAddress == 0 ||
      export_dir.VirtualAddress >= module->nt->OptionalHeader.SizeOfImage) {
    printf("No valid export directory virt: %d, size: %d\n",
           export_dir.VirtualAddress, module->nt->OptionalHeader.SizeOfImage);
    return 0;
  }

  IMAGE_EXPORT_DIRECTORY *exp =
      (IMAGE_EXPORT_DIRECTORY *)(module->image + export_dir.VirtualAddress);

  uint32_t *names = (uint32_t *)(module->image + exp->AddressOfNames);
  uint16_t *ordinals = (uint16_t *)(module->image + exp->AddressOfNameOrdinals);
  uint32_t *funcs = (uint32_t *)(module->image + exp->AddressOfFunctions);
  for (uint32_t i = 0; i < exp->NumberOfNames; i++) {

    uint32_t name_rva = names[i];
    uint32_t ordinal = ordinals[i];
    uint32_t func_rva = funcs[ordinal];
    char *name = (char *)(module->image + name_rva);
    if (strcmp(name, function_name) == 0) {
      return (module->base + func_rva);
    }
  }
  return 0;
}

int main(int argc, char *argv[]) {
  int err = 0;
  char *src = NULL;

  remote_module_t kernel32 = {0};
  remote_module_t ntdll = {0};

  struct ptrace_do *ptrace_ctx = NULL;
  if (argc != 3) {
    printf("Usage: %s <pid> <dll_path>\n", argv[0]);
    return 1;
  }

  pid_t pid = atoi(argv[1]);
  printf("pid=%d\n", pid);
  if (kill(pid, 0) == -1) {
    printf("Invalid pid\n");
    return 1;
  }

  char *dll_path = argv[2];
  printf("dll_path=%s\n", dll_path);

  if (access(dll_path, F_OK) == -1) {
    printf("Invalid dll_path\n");
    return 1;
  }

  FILE *dll_file = fopen(dll_path, "rb");
  if (!dll_file) {
    perror("fopen dll_file");
    return 1;
  }

  fseek(dll_file, 0, SEEK_END);

  size_t dll_size = (size_t)ftell(dll_file);

  src = (char *)malloc(dll_size);

  if (!src) {
    perror("malloc src");
    fclose(dll_file);
    return 1;
  }

  fseek(dll_file, 0, SEEK_SET);
  if (fread(src, 1, dll_size, dll_file) != dll_size) {
    perror("fread src");
    fclose(dll_file);
    free(src);
    return 1;
  }

  fclose(dll_file);

  IMAGE_DOS_HEADER *dll_dos = (IMAGE_DOS_HEADER *)src;
  if (dll_dos->e_magic != IMAGE_DOS_SIGNATURE) {
    printf("Invalid PE: bad DOS signature\n");
    free(src);
    return 1;
  }

  IMAGE_NT_HEADERS *dll_nt = (IMAGE_NT_HEADERS *)(src + dll_dos->e_lfanew);
  if (dll_nt->Signature != IMAGE_NT_SIGNATURE) {
    printf("Invalid PE: bad NT signature\n");
    free(src);
    return 1;
  }

  // if (nt->FileHeader.Machine != CURRENT_ARCH) { // do this later
  //

  IMAGE_OPTIONAL_HEADER *dll_opt = &dll_nt->OptionalHeader;

  ptrace_ctx = ptrace_do_init(pid);
  if (!ptrace_ctx) {
    perror("ptrace_do_init");
    return 1;
  }

  char *local_header = (char *)ptrace_do_malloc(ptrace_ctx, dll_size);
  memset(local_header, 0, dll_size);
  memcpy(local_header, src, dll_nt->OptionalHeader.SizeOfHeaders);
  void *remote_header = ptrace_do_push_mem(ptrace_ctx, local_header);
  if (remote_header == NULL) {
    perror("ptrace_do_push_mem");
    err = 1;
    goto cleanup;
  }
  printf("remote_header=%p local_header=%p\n", remote_header, local_header);


  // err = ptrace_do_syscall(target, 10, (unsigned long)remote_addr, dll_size,
  // PROT_READ | PROT_WRITE | PROT_EXEC, 0, 0, 0); printf("fd=%d\n", err);
  //  call this after lol

  IMAGE_SECTION_HEADER *section = IMAGE_FIRST_SECTION(dll_nt);
  for (uint32_t i = 0; i < dll_nt->FileHeader.NumberOfSections;
       i++, section++) {
    if (!section->SizeOfRawData)
      continue;
    printf("section %d: name=%s size=%u\n", i, section->Name,
           section->SizeOfRawData);

    if (remote_write(pid, remote_header + section->VirtualAddress,
                     src + section->PointerToRawData,
                     section->SizeOfRawData) != 0) {
      perror("remote_write");
      err = 1;
      goto cleanup;
    }
  }

  if (get_module(pid, "kernel32.dll", &kernel32) == -1) {
    printf("kernel32.dll not found\n");
    err = 1;
    goto cleanup;
  }

  // kinda unoptimized but works
  mapping_data_t mapping_data = {0};
  mapping_data.load_library_a = get_function_address(&kernel32, "LoadLibraryA");
  mapping_data.get_proc_address =
      get_function_address(&kernel32, "GetProcAddress");
  mapping_data.get_module_handle_a =
      get_function_address(&kernel32, "GetModuleHandleA");
  mapping_data.seh_support = 0;

  if (kernel32.nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    if (get_module(pid, "ntdll.dll", &ntdll) == -1) {
      printf("ntdll.dll not found\n");
      err = 1;
      goto cleanup;
    }
    mapping_data.rtl_add_function_table =
        get_function_address(&ntdll, "RtlAddFunctionTable");
    mapping_data.seh_support = mapping_data.rtl_add_function_table != NULL;
  }

  mapping_data.pbase = remote_header;
  mapping_data.fwd_reason_param = DLL_PROCESS_ATTACH;
  mapping_data.reserved_param = NULL;

  char* local_mapping = (char *)ptrace_do_malloc(ptrace_ctx, sizeof(mapping_data_t));
  memcpy(local_mapping, &mapping_data, sizeof(mapping_data_t));
  void* remote_mapping = ptrace_do_push_mem(ptrace_ctx, local_mapping);
  if (remote_mapping == NULL) {
    perror("ptrace_do_push_mem");
    err = 1;
    goto cleanup;
  }
  printf("remote_mapping=%p\n", remote_mapping);






cleanup:


  printf("cleanup src: %p\n", src);
  if (src)
    free(src);

  free_module(&kernel32);
  free_module(&ntdll);

  printf("cleanup ptrace_ctx: %p\n", ptrace_ctx);
  if (ptrace_ctx)
    ptrace_do_cleanup(ptrace_ctx);

  return err;
}
