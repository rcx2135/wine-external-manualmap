#include <stdint.h>



// typedef int (WINAPIV *rtl_add_function_table_t)(
//     RUNTIME_FUNCTION *function_table,
//     uint32_t             entry_count,
//     uint64_t             base_address
// );
typedef struct {
  void *load_library_a;
  void *get_proc_address;
  void *get_module_handle_a;

  void *pbase;
  void *hmodule;
  uint32_t fwd_reason_param;
  void *reserved_param;
  uint8_t seh_support;

  void *rtl_add_function_table; // goes unused in x32
} mapping_data_t;
