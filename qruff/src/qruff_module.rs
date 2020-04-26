use std::ffi::CStr;
use std::ops::Deref;
use std::os::raw::{c_char, c_int};
use std::sync::Mutex;
use std::sync::Once;
use std::slice;

use crate::{ffi, mem, ClassId, ContextRef, ForeignTypeRef, Prop, Runtime, UnsafeCFunction, RJSTimerHandler, MsgType, Value, RuffCtx, NewValue};

lazy_static! {
    static ref QRUFF_TIMER_CLASS_ID: ClassId = Runtime::new_class_id();
}

fn qruff_timer_class_id() -> ClassId {
    *QRUFF_TIMER_CLASS_ID
}

unsafe extern "C" fn qruff_setTimeout(
    ctx: *mut ffi::JSContext,
    this_val: ffi::JSValue,
    argc: ::std::os::raw::c_int,
    argv: *mut ffi::JSValue,
) -> ffi::JSValue {
    let ctxt = ContextRef::from_ptr(ctx);
    let this = Value::from(this_val);
    let this = this.check_undefined();
    let args = slice::from_raw_parts(argv, argc as usize);
    let arg0 = Value::from(args[0]);
    let arg1 = Value::from(args[1]);

    let mut ruff_ctx = ctxt.userdata::<RuffCtx>().unwrap();
    if ctxt.is_function(&arg0) {
        let delay_ms = ctxt.to_int64(&arg1).unwrap() as u64;
        unsafe {
            let handle = RJSTimerHandler::new(
                ctxt,
                delay_ms,
                &arg0
                //Value::from((&arg0).new_value(&ctxt))
            );
            ruff_ctx
                .as_mut()
                .msg_tx
                .try_send(MsgType::ADD_TIMER(handle));
        }
    } else {
        println!("Not Function");
    }
    ffi::UNDEFINED
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

lazy_static! {
    static ref QRuffTimer: QRuffFunctionList = QRuffFunctionList(
        [
        ffi::JSCFunctionListEntry {
            name: cstr!(CONST_16).as_ptr(),
            prop_flags: ffi::JS_PROP_CONFIGURABLE as u8,
            def_type: ffi::JS_DEF_PROP_INT32 as u8,
            magic: 0,
            u: ffi::JSCFunctionListEntry__bindgen_ty_1 { i32: 16 },
        },
        ffi::JSCFunctionListEntry {
            name: cstr!(setTimeout).as_ptr(),
            prop_flags: (ffi::JS_PROP_WRITABLE | ffi::JS_PROP_CONFIGURABLE) as u8,
            def_type: ffi::JS_DEF_CFUNC as u8,
            magic: 0,
            u: ffi::JSCFunctionListEntry__bindgen_ty_1 {
                func: ffi::JSCFunctionListEntry__bindgen_ty_1__bindgen_ty_1 {
                    length: 2 as u8,
                    cproto: ffi::JSCFunctionEnum::JS_CFUNC_generic as u8,
                    cfunc: ffi::JSCFunctionType {
                        generic: Some(qruff_setTimeout)
                    }
                }
            },
        }
        ]);
}

struct QRuffFunctionList([ffi::JSCFunctionListEntry; 2]);
impl Deref for QRuffFunctionList {
    type Target = [ffi::JSCFunctionListEntry; 2];

    fn deref(&self) -> &[ffi::JSCFunctionListEntry; 2] {
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

    ffi::JS_SetModuleExportList(_ctx, _m, QRuffTimer.as_ptr() as *mut _, 2)
}

pub fn js_init_module_qruff(ctxt: &ContextRef, module_name: &str) {
    let m = ctxt
        .new_c_module(module_name, Some(js_module_dummy_init))
        .ok();

    unsafe {
        ffi::JS_AddModuleExportList(
            ctxt.as_ptr(),
            m.unwrap().as_ptr(),
            QRuffTimer.as_ptr() as *mut _,
            2,
        );
    }
}
