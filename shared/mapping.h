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
  uint8_t loader_ran;
  uint8_t success;
  uint32_t fwd_reason_param;
  void *reserved_param;
  uint8_t seh_support;

  uint32_t stage;

  void *last_import_desc;
  void *last_thunk;
  void *last_module_name;
  void *last_function_name;
  void *last_resolved;


  void *rtl_add_function_table; // goes unused in x32
} mapping_data_t;
