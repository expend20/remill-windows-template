; Runtime stubs for remill intrinsics
; These are minimal implementations sufficient for simple lifted code

; Memory read/write - just access the address directly (for flat memory model)
define dso_local zeroext i8 @__remill_read_memory_8(ptr %mem, i64 %addr) {
  %ptr = inttoptr i64 %addr to ptr
  %val = load i8, ptr %ptr
  ret i8 %val
}

define dso_local ptr @__remill_write_memory_8(ptr %mem, i64 %addr, i8 zeroext %val) {
  %ptr = inttoptr i64 %addr to ptr
  store i8 %val, ptr %ptr
  ret ptr %mem
}

define dso_local zeroext i16 @__remill_read_memory_16(ptr %mem, i64 %addr) {
  %ptr = inttoptr i64 %addr to ptr
  %val = load i16, ptr %ptr
  ret i16 %val
}

define dso_local ptr @__remill_write_memory_16(ptr %mem, i64 %addr, i16 zeroext %val) {
  %ptr = inttoptr i64 %addr to ptr
  store i16 %val, ptr %ptr
  ret ptr %mem
}

define dso_local i32 @__remill_read_memory_32(ptr %mem, i64 %addr) {
  %ptr = inttoptr i64 %addr to ptr
  %val = load i32, ptr %ptr
  ret i32 %val
}

define dso_local ptr @__remill_write_memory_32(ptr %mem, i64 %addr, i32 %val) {
  %ptr = inttoptr i64 %addr to ptr
  store i32 %val, ptr %ptr
  ret ptr %mem
}

define dso_local i64 @__remill_read_memory_64(ptr %mem, i64 %addr) {
  %ptr = inttoptr i64 %addr to ptr
  %val = load i64, ptr %ptr
  ret i64 %val
}

define dso_local ptr @__remill_write_memory_64(ptr %mem, i64 %addr, i64 %val) {
  %ptr = inttoptr i64 %addr to ptr
  store i64 %val, ptr %ptr
  ret ptr %mem
}

define dso_local float @__remill_read_memory_f32(ptr %mem, i64 %addr) {
  %ptr = inttoptr i64 %addr to ptr
  %val = load float, ptr %ptr
  ret float %val
}

define dso_local double @__remill_read_memory_f64(ptr %mem, i64 %addr) {
  %ptr = inttoptr i64 %addr to ptr
  %val = load double, ptr %ptr
  ret double %val
}

; Flag computation stubs - just return the input
define dso_local zeroext i1 @__remill_flag_computation_carry(i1 zeroext %val, ...) {
  ret i1 %val
}

define dso_local zeroext i1 @__remill_flag_computation_zero(i1 zeroext %val, ...) {
  ret i1 %val
}

define dso_local zeroext i1 @__remill_flag_computation_sign(i1 zeroext %val, ...) {
  ret i1 %val
}

define dso_local zeroext i1 @__remill_flag_computation_overflow(i1 zeroext %val, ...) {
  ret i1 %val
}

; Comparison stubs
define dso_local zeroext i1 @__remill_compare_ule(i1 zeroext %val) {
  ret i1 %val
}

define dso_local zeroext i1 @__remill_compare_sle(i1 zeroext %val) {
  ret i1 %val
}

define dso_local zeroext i1 @__remill_compare_sgt(i1 zeroext %val) {
  ret i1 %val
}

define dso_local zeroext i1 @__remill_compare_eq(i1 zeroext %val) {
  ret i1 %val
}

define dso_local zeroext i1 @__remill_compare_neq(i1 zeroext %val) {
  ret i1 %val
}

define dso_local zeroext i1 @__remill_compare_slt(i1 zeroext %val) {
  ret i1 %val
}

define dso_local zeroext i1 @__remill_compare_sge(i1 zeroext %val) {
  ret i1 %val
}

define dso_local zeroext i1 @__remill_compare_ult(i1 zeroext %val) {
  ret i1 %val
}

define dso_local zeroext i1 @__remill_compare_uge(i1 zeroext %val) {
  ret i1 %val
}

define dso_local zeroext i1 @__remill_compare_ugt(i1 zeroext %val) {
  ret i1 %val
}

; Undefined value stubs
define dso_local zeroext i8 @__remill_undefined_8() {
  ret i8 0
}

define dso_local zeroext i16 @__remill_undefined_16() {
  ret i16 0
}

define dso_local i32 @__remill_undefined_32() {
  ret i32 0
}

define dso_local i64 @__remill_undefined_64() {
  ret i64 0
}

define dso_local float @__remill_undefined_f32() {
  ret float 0.0
}

define dso_local double @__remill_undefined_f64() {
  ret double 0.0
}

; Error handler - just returns memory unchanged
define dso_local ptr @__remill_error(ptr %state, i64 %pc, ptr %mem) {
  ret ptr %mem
}

; Mark as used - no-op
define dso_local void @__remill_mark_as_used(ptr %val) {
  ret void
}

; Atomic operations - stubs
define dso_local ptr @__remill_atomic_begin(ptr %mem) {
  ret ptr %mem
}

define dso_local ptr @__remill_atomic_end(ptr %mem) {
  ret ptr %mem
}

define dso_local zeroext i8 @__remill_fetch_and_add_8(ptr %mem, i64 %addr, i8 %val) {
  ret i8 0
}

define dso_local zeroext i16 @__remill_fetch_and_add_16(ptr %mem, i64 %addr, i16 %val) {
  ret i16 0
}

define dso_local i32 @__remill_fetch_and_add_32(ptr %mem, i64 %addr, i32 %val) {
  ret i32 0
}

define dso_local i64 @__remill_fetch_and_add_64(ptr %mem, i64 %addr, i64 %val) {
  ret i64 0
}

define dso_local zeroext i8 @__remill_fetch_and_sub_8(ptr %mem, i64 %addr, i8 %val) {
  ret i8 0
}

define dso_local zeroext i16 @__remill_fetch_and_sub_16(ptr %mem, i64 %addr, i16 %val) {
  ret i16 0
}

define dso_local i32 @__remill_fetch_and_sub_32(ptr %mem, i64 %addr, i32 %val) {
  ret i32 0
}

define dso_local i64 @__remill_fetch_and_sub_64(ptr %mem, i64 %addr, i64 %val) {
  ret i64 0
}

define dso_local zeroext i8 @__remill_fetch_and_and_8(ptr %mem, i64 %addr, i8 %val) {
  ret i8 0
}

define dso_local zeroext i16 @__remill_fetch_and_and_16(ptr %mem, i64 %addr, i16 %val) {
  ret i16 0
}

define dso_local i32 @__remill_fetch_and_and_32(ptr %mem, i64 %addr, i32 %val) {
  ret i32 0
}

define dso_local i64 @__remill_fetch_and_and_64(ptr %mem, i64 %addr, i64 %val) {
  ret i64 0
}

define dso_local zeroext i8 @__remill_fetch_and_or_8(ptr %mem, i64 %addr, i8 %val) {
  ret i8 0
}

define dso_local zeroext i16 @__remill_fetch_and_or_16(ptr %mem, i64 %addr, i16 %val) {
  ret i16 0
}

define dso_local i32 @__remill_fetch_and_or_32(ptr %mem, i64 %addr, i32 %val) {
  ret i32 0
}

define dso_local i64 @__remill_fetch_and_or_64(ptr %mem, i64 %addr, i64 %val) {
  ret i64 0
}

define dso_local zeroext i8 @__remill_fetch_and_xor_8(ptr %mem, i64 %addr, i8 %val) {
  ret i8 0
}

define dso_local zeroext i16 @__remill_fetch_and_xor_16(ptr %mem, i64 %addr, i16 %val) {
  ret i16 0
}

define dso_local i32 @__remill_fetch_and_xor_32(ptr %mem, i64 %addr, i32 %val) {
  ret i32 0
}

define dso_local i64 @__remill_fetch_and_xor_64(ptr %mem, i64 %addr, i64 %val) {
  ret i64 0
}

; Compare-exchange stubs
define dso_local zeroext i8 @__remill_compare_exchange_memory_8(ptr %mem, i64 %addr, i8 %expected, i8 %desired) {
  ret i8 0
}

define dso_local zeroext i16 @__remill_compare_exchange_memory_16(ptr %mem, i64 %addr, i16 %expected, i16 %desired) {
  ret i16 0
}

define dso_local i32 @__remill_compare_exchange_memory_32(ptr %mem, i64 %addr, i32 %expected, i32 %desired) {
  ret i32 0
}

define dso_local i64 @__remill_compare_exchange_memory_64(ptr %mem, i64 %addr, i64 %expected, i64 %desired) {
  ret i64 0
}

define dso_local i128 @__remill_compare_exchange_memory_128(ptr %mem, i64 %addr, i128 %expected, i128 %desired) {
  ret i128 0
}

; Barriers
define dso_local ptr @__remill_barrier_load_load(ptr %mem) {
  ret ptr %mem
}

define dso_local ptr @__remill_barrier_load_store(ptr %mem) {
  ret ptr %mem
}

define dso_local ptr @__remill_barrier_store_load(ptr %mem) {
  ret ptr %mem
}

define dso_local ptr @__remill_barrier_store_store(ptr %mem) {
  ret ptr %mem
}

; FPU operations
define dso_local i32 @__remill_fpu_get_rounding() {
  ret i32 0
}

define dso_local void @__remill_fpu_set_rounding(i32 %mode) {
  ret void
}

define dso_local void @__remill_fpu_exception_clear() {
  ret void
}

define dso_local void @__remill_fpu_exception_raise() {
  ret void
}

define dso_local zeroext i1 @__remill_fpu_exception_test() {
  ret i1 false
}

; FP memory operations
define dso_local ptr @__remill_write_memory_f32(ptr %mem, i64 %addr, float %val) {
  ret ptr %mem
}

define dso_local ptr @__remill_write_memory_f64(ptr %mem, i64 %addr, double %val) {
  ret ptr %mem
}

define dso_local x86_fp80 @__remill_read_memory_f80(ptr %mem, i64 %addr) {
  ret x86_fp80 0xK00000000000000000000
}

define dso_local ptr @__remill_write_memory_f80(ptr %mem, i64 %addr, x86_fp80 %val) {
  ret ptr %mem
}

define dso_local <16 x i8> @__remill_read_memory_128(ptr %mem, i64 %addr) {
  ret <16 x i8> zeroinitializer
}

define dso_local ptr @__remill_write_memory_128(ptr %mem, i64 %addr, <16 x i8> %val) {
  ret ptr %mem
}

; Control flow stubs
define dso_local ptr @__remill_function_call(ptr %state, i64 %pc, ptr %mem) {
  ret ptr %mem
}

define dso_local ptr @__remill_function_return(ptr %state, i64 %pc, ptr %mem) {
  ret ptr %mem
}

define dso_local ptr @__remill_jump(ptr %state, i64 %pc, ptr %mem) {
  ret ptr %mem
}

define dso_local ptr @__remill_missing_block(ptr %state, i64 %pc, ptr %mem) {
  ret ptr %mem
}

define dso_local ptr @__remill_async_hyper_call(ptr %state, i64 %pc, ptr %mem) {
  ret ptr %mem
}

; __remill_sync_hyper_call is defined in lifted.bc with different signature

; I/O port stubs
define dso_local zeroext i8 @__remill_read_io_port_8(ptr %mem, i64 %port) {
  ret i8 0
}

define dso_local zeroext i16 @__remill_read_io_port_16(ptr %mem, i64 %port) {
  ret i16 0
}

define dso_local i32 @__remill_read_io_port_32(ptr %mem, i64 %port) {
  ret i32 0
}

define dso_local void @__remill_write_io_port_8(ptr %mem, i64 %port, i8 %val) {
  ret void
}

define dso_local void @__remill_write_io_port_16(ptr %mem, i64 %port, i16 %val) {
  ret void
}

define dso_local void @__remill_write_io_port_32(ptr %mem, i64 %port, i32 %val) {
  ret void
}

; x86-specific stubs
define dso_local void @__remill_x86_set_segment_es(i16 %val) {
  ret void
}

define dso_local void @__remill_x86_set_segment_ss(i16 %val) {
  ret void
}

define dso_local void @__remill_x86_set_segment_ds(i16 %val) {
  ret void
}

define dso_local void @__remill_x86_set_segment_fs(i16 %val) {
  ret void
}

define dso_local void @__remill_x86_set_segment_gs(i16 %val) {
  ret void
}

; AMD64-specific stubs
define dso_local void @__remill_amd64_set_debug_reg(i32 %reg, i64 %val) {
  ret void
}

define dso_local void @__remill_amd64_set_control_reg_0(i64 %val) {
  ret void
}

define dso_local void @__remill_amd64_set_control_reg_1(i64 %val) {
  ret void
}

define dso_local void @__remill_amd64_set_control_reg_2(i64 %val) {
  ret void
}

define dso_local void @__remill_amd64_set_control_reg_3(i64 %val) {
  ret void
}

define dso_local void @__remill_amd64_set_control_reg_4(i64 %val) {
  ret void
}

define dso_local void @__remill_amd64_set_control_reg_8(i64 %val) {
  ret void
}

; Undefined f80
define dso_local x86_fp80 @__remill_undefined_f80() {
  ret x86_fp80 0xK00000000000000000000
}

; Delay slot stubs (for SPARC etc)
define dso_local ptr @__remill_delay_slot_begin(ptr %mem) {
  ret ptr %mem
}

define dso_local ptr @__remill_delay_slot_end(ptr %mem) {
  ret ptr %mem
}

; 128-bit division stubs (compiler-rt)
define i128 @__divti3(i128 %a, i128 %b) {
  ret i128 0
}

define i128 @__udivti3(i128 %a, i128 %b) {
  ret i128 1
}

; Math function stubs (only used if not linked with math library)
define weak x86_fp80 @sqrtl(x86_fp80 %x) {
  ret x86_fp80 %x
}

define weak x86_fp80 @sinl(x86_fp80 %x) {
  ret x86_fp80 0xK00000000000000000000
}

define weak x86_fp80 @cosl(x86_fp80 %x) {
  ret x86_fp80 0xK3FFF8000000000000000
}

define weak x86_fp80 @tanl(x86_fp80 %x) {
  ret x86_fp80 0xK00000000000000000000
}

define weak x86_fp80 @fmodl(x86_fp80 %x, x86_fp80 %y) {
  ret x86_fp80 0xK00000000000000000000
}

define weak x86_fp80 @atanl(x86_fp80 %x) {
  ret x86_fp80 0xK00000000000000000000
}
