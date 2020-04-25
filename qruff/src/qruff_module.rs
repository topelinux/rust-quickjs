use std::ops::Deref;
use std::os::raw::{c_int, c_char};
use std::sync::Mutex;
use std::ffi::CStr;
use std::sync::Once;

use crate::{ForeignTypeRef, Runtime,ClassId,Prop,ContextRef,ffi,mem};

lazy_static! {
    static ref QRUFF_TIMER_CLASS_ID: ClassId = Runtime::new_class_id();
}

fn qruff_timer_class_id() -> ClassId {
    *QRUFF_TIMER_CLASS_ID
}

pub fn register_timer_class(rt: &Runtime) -> bool {
    unsafe extern "C" fn qruff_timer_finalizer(_rt: *mut ffi::JSRuntime, obj: ffi::JSValue) {
        let ptr = ffi::JS_GetOpaque(obj, qruff_timer_class_id());

        trace!("free userdata {:p} @ {:?}", ptr, obj.u.ptr);

        mem::drop(Box::from_raw(ptr));
    }

    rt.new_class(
        qruff_timer_class_id(),
        &ffi::JSClassDef {
            class_name: cstr!(QRuffTimer).as_ptr(),
            finalizer: Some(qruff_timer_finalizer),
            gc_mark: None,
            call: None,
            exotic: core::ptr::null_mut(),
        },
    )
}

lazy_static!{
    static ref QRuffTimer :QRuffFunctionList = QRuffFunctionList([
        ffi::JSCFunctionListEntry {
            name: cstr!(QRuffTimer).as_ptr(),
            prop_flags: ffi::JS_PROP_CONFIGURABLE as u8,
            def_type: ffi::JS_DEF_PROP_INT32 as u8,
            magic: 0,
            u: ffi::JSCFunctionListEntry__bindgen_ty_1 { i32: 16 },
        }
    ]);
}

struct QRuffFunctionList([ffi::JSCFunctionListEntry;1]);
impl Deref for QRuffFunctionList {
    type Target = [ffi::JSCFunctionListEntry;1];

    fn deref(&self) -> &[ffi::JSCFunctionListEntry;1] {
        &self.0
    }
}

unsafe impl Send for QRuffFunctionList {}
unsafe impl Sync for QRuffFunctionList {}

unsafe extern "C" fn js_module_dummy_init(
    _ctx: *mut ffi::JSContext,
    _m: *mut ffi::JSModuleDef,
) -> c_int {
    let ctxt = ContextRef::from_ptr(_ctx);

    //register_timer_class(ctxt.runtime());

    ffi::JS_SetModuleExportList(_ctx, _m,
        QRuffTimer.as_ptr() as *mut _,
        1
    )
}


pub fn js_init_module_qruff(ctxt: &ContextRef, module_name: &str) {
    let m = ctxt.new_c_module(module_name, Some(js_module_dummy_init)).ok();

    unsafe {
        ffi::JS_AddModuleExportList(ctxt.as_ptr(), m.unwrap().as_ptr(),
        QRuffTimer.as_ptr() as *mut _,
        1
        );
    }
}
