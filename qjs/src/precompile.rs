use std::ptr::NonNull;
use std::slice;

use failure::Error;
use foreign_types::ForeignTypeRef;

use crate::{ffi, ContextRef, Local, Value};

bitflags! {
    pub struct WriteObj: u32 {
        /// allow function/module
        const BYTECODE = ffi::JS_WRITE_OBJ_BYTECODE;
        /// byte swapped output
        const BSWAP = ffi::JS_WRITE_OBJ_BSWAP;
    }
}

bitflags! {
    pub struct ReadObj: u32 {
        /// allow function/module
        const BYTECODE = ffi::JS_READ_OBJ_BYTECODE;
        /// avoid duplicating 'buf' data
        const ROM_DATA = ffi::JS_READ_OBJ_ROM_DATA;
    }
}

impl Local<'_, Value> {
    pub fn write_bytecode(&self) -> Option<Vec<u8>> {
        self.ctxt.write_object(&self.inner, WriteObj::BYTECODE)
    }
}

impl ContextRef {
    pub fn write_object(&self, obj: &Value, flags: WriteObj) -> Option<Vec<u8>> {
        let mut len = 0;

        NonNull::new(unsafe {
            ffi::JS_WriteObject(self.as_ptr(), &mut len, obj.raw(), flags.bits as i32)
        })
        .map(|buf| unsafe {
            let data = slice::from_raw_parts(buf.cast().as_ptr(), len).to_vec();

            ffi::js_free(self.as_ptr(), buf.cast().as_ptr());

            data
        })
    }

    pub fn read_object(&self, buf: &[u8], flags: ReadObj) -> Result<Local<Value>, Error> {
        self.bind(unsafe {
            ffi::JS_ReadObject(
                self.as_ptr(),
                buf.as_ptr(),
                buf.len(),
                (flags | ReadObj::ROM_DATA).bits as i32,
            )
        })
        .ok()
    }

    pub fn eval_function<T: Into<ffi::JSValue>>(
        &self,
        func: T,
        this: &Value,
    ) -> Result<Local<Value>, Error> {
        self.bind(unsafe { ffi::JS_EvalFunction(self.as_ptr(), func.into(), this.raw()) })
            .ok()
    }
}