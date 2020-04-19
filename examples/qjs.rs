#[macro_use]
extern crate log;
#[macro_use]
extern crate cfg_if;

use std::ffi::{CStr, OsStr};
use std::mem;
use std::os::raw::{c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::null_mut;
use std::rc::Rc;
use std::time::{Duration, Instant};

use failure::Error;
use foreign_types::ForeignTypeRef;
use foreign_types_shared::ForeignTypeRef as OtherForeignTypeRef;
use structopt::StructOpt;

use tokio::time::{delay_queue, DelayQueue};

use qjs::{
    ffi, Args, Context, ContextRef, ErrorKind, Eval, Local, MallocFunctions, Runtime, Value,
};
use tokio::fs::File;
use tokio::prelude::*;

use std::ptr::NonNull;
//use std::sync::mpsc::{sync_channel, Sender};
use std::error::Error as StdError;
use tokio::stream::{self, StreamExt};
use tokio::sync::mpsc::{channel, Sender};

use std::collections::HashMap;

#[derive(Debug, StructOpt)]
#[structopt(name = "qjs", about = "QuickJS stand alone interpreter")]
pub struct Opt {
    /// Evaluate EXPR
    #[structopt(name = "EXPR", short = "e", long = "eval")]
    expr: Option<String>,

    /// Go to interactive mode
    #[structopt(short, long)]
    interactive: bool,

    /// Load as ES6 module (default if .mjs file extension)
    #[structopt(short, long)]
    module: bool,

    /// Load the QJSCalc runtime (default if invoked as qjscalc)
    #[cfg(feature = "qjscalc")]
    #[structopt(long = "qjscalc")]
    load_jscalc: bool,

    /// Trace memory allocation
    #[structopt(short = "T", long = "trace")]
    trace_memory: bool,

    /// Dump the memory usage stats
    #[structopt(short, long = "dump")]
    dump_memory: bool,

    /// Just instantiate the interpreter and quit
    #[structopt(short = "q", long = "quit")]
    empty_run: bool,

    /// Make 'std' and 'os' invisible to non module code
    #[structopt(long = "nostd")]
    no_std: bool,

    /// Script arguments
    args: Vec<String>,
}

cfg_if! {
    if #[cfg(any(target_os = "macos", target_os = "ios"))] {
        const MALLOC_OVERHEAD: usize = 0;
    } else {
        const MALLOC_OVERHEAD: usize = 8;
    }
}

unsafe extern "C" fn js_trace_malloc(s: *mut ffi::JSMallocState, size: usize) -> *mut c_void {
    let s = s.as_mut().expect("state");

    if s.malloc_size + size > s.malloc_limit {
        null_mut()
    } else {
        let ptr = libc::malloc(size);

        trace!(
            "A {} -> {:p}.{}",
            size,
            ptr,
            js_trace_malloc_usable_size(ptr)
        );

        if !ptr.is_null() {
            s.malloc_count += 1;
            s.malloc_size += js_trace_malloc_usable_size(ptr) + MALLOC_OVERHEAD;
        }

        ptr
    }
}

unsafe extern "C" fn js_trace_free(s: *mut ffi::JSMallocState, ptr: *mut c_void) {
    if !ptr.is_null() {
        trace!("F {:p}.{}", ptr, js_trace_malloc_usable_size(ptr));

        let s = s.as_mut().expect("state");

        s.malloc_count -= 1;
        s.malloc_size -= js_trace_malloc_usable_size(ptr) + MALLOC_OVERHEAD;

        libc::free(ptr);
    }
}

unsafe extern "C" fn js_trace_realloc(
    s: *mut ffi::JSMallocState,
    ptr: *mut c_void,
    size: usize,
) -> *mut c_void {
    if ptr.is_null() {
        if size == 0 {
            null_mut()
        } else {
            js_trace_malloc(s, size)
        }
    } else {
        let s = s.as_mut().expect("state");
        let old_size = js_trace_malloc_usable_size(ptr);

        if size == 0 {
            trace!("R {} {:p}.{}", size, ptr, js_trace_malloc_usable_size(ptr));

            s.malloc_count -= 1;
            s.malloc_size -= old_size + MALLOC_OVERHEAD;

            libc::free(ptr);

            null_mut()
        } else if s.malloc_size + size - old_size > s.malloc_limit {
            null_mut()
        } else {
            trace!("R {} {:p}.{}", size, ptr, js_trace_malloc_usable_size(ptr));

            let ptr = libc::realloc(ptr, size);

            trace!(" -> {:p}.{}", ptr, js_trace_malloc_usable_size(ptr));

            if !ptr.is_null() {
                s.malloc_size += js_trace_malloc_usable_size(ptr);
                s.malloc_size -= old_size;
            }

            ptr
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
unsafe extern "C" fn js_trace_malloc_usable_size(ptr: *const c_void) -> usize {
    libc::malloc_usable_size(ptr as *mut _)
}

cfg_if! {
    if #[cfg(any(target_os = "macos", target_os = "ios"))] {
        extern "C" {
            pub fn malloc_size(ptr: *const c_void) -> libc::size_t;
        }

        #[cfg(any(target_os = "macos", target_os = "ios"))]
        unsafe extern "C" fn js_trace_malloc_usable_size(ptr: *const c_void) -> usize {
            malloc_size(ptr)
        }
    }
}

unsafe extern "C" fn jsc_module_loader(
    ctx: *mut ffi::JSContext,
    module_name: *const c_char,
    _opaque: *mut c_void,
) -> *mut ffi::JSModuleDef {
    let ctxt = ContextRef::from_ptr(ctx);
    let module_name = Path::new(OsStr::from_bytes(CStr::from_ptr(module_name).to_bytes()));

    debug!("load module: {:?}", module_name);

    ctxt.eval_file(module_name, Eval::MODULE | Eval::COMPILE_ONLY)
        .ok()
        .map_or_else(null_mut, |func| func.as_ptr().as_ptr())
}

fn eval_buf<'a>(
    ctxt: &'a ContextRef,
    buf: &str,
    filename: &str,
    flags: Eval,
) -> Result<Local<'a, Value>, Error> {
    if flags.contains(Eval::MODULE) {
        let val = ctxt.eval_script(buf, filename, flags | Eval::COMPILE_ONLY)?;

        let _ = ctxt.set_import_meta(&val, true, true);

        ctxt.eval_function(val)
    } else {
        ctxt.eval_script(buf, filename, flags)
    }
}

enum MsgType<'a> {
    FS_READALL(String, RJSPromise<'a>),
}

enum RespType {
    FS_RESPONSE(u32, Result<Vec<u8>, Error>),
}
//use futures::executor::block_on;
async fn test_fs(path: String, mut tx: Sender<RespType>, job_id: u32) {
    println!("path is {:?}", path);
    let mut file = match File::open(path).await {
        Ok(file) => file,
        Err(err) => {
            println!("err is {}", err);
            tx.try_send(RespType::FS_RESPONSE(job_id, Err(err.into())));
            return;
        }
    };
    let mut contents = vec![];
    file.read_to_end(&mut contents).await.unwrap();
    //println!("Contents in rust: {:?}", std::str::from_utf8(&contents));

    tx.send(RespType::FS_RESPONSE(job_id, Ok(contents))).await;
}

struct RJSPromise<'a> {
    ctxt: &'a ContextRef,
    p: Local<'a, Value>,
    resolve: Local<'a, Value>,
    reject: Local<'a, Value>,
}

impl<'a> Drop for RJSPromise<'a> {
    fn drop(&mut self) {
        self.ctxt.free_value(self.resolve.raw());
        self.ctxt.free_value(self.reject.raw());
    }
}
impl<'a> RJSPromise<'a> {
    pub unsafe fn new(ctxt: &'a ContextRef, p: &Value, resolve: &Value, reject: &Value) -> Self {
        Self {
            ctxt,
            p: ctxt.clone_value(p),
            resolve: ctxt.clone_value(resolve),
            reject: ctxt.clone_value(reject),
        }
    }
}

struct RuffCtx<'a> {
    msg_tx: Sender<MsgType<'a>>,
    timer_queue: Rc<DelayQueue<u32>>,
}

impl RuffCtx<'static> {
    pub fn new(msg_tx: Sender<MsgType<'static>>, timer_queue: Rc<DelayQueue<u32>>) -> Self {
        RuffCtx {
            msg_tx,
            timer_queue,
        }
    }
}

fn handle_msg<'a>(
    msg: Option<MsgType<'a>>,
    job_id: &mut u32,
    mut resp_tx: Sender<RespType>,
    job_queue: &mut HashMap<u32, RJSPromise<'a>>,
) {
    match msg {
        Some(MsgType::FS_READALL(path, promise)) => {
            *job_id += 1;
            job_queue.insert(*job_id, promise);
            tokio::spawn(test_fs(path, resp_tx.clone(), *job_id));
        }
        None => {}
    }
}

fn handle_response(mut resp: Option<RespType>, job_queue: &mut HashMap<u32, RJSPromise>) {
    match resp {
        Some(RespType::FS_RESPONSE(job_id, ref mut content)) => {
            if let Some(promise) = job_queue.remove(&job_id) {
                let mut resp = None;
                let mut resp_err = String::new();
                let handle = {
                    match content {
                        Ok(content) => {
                            resp = Some(promise.ctxt.new_array_buffer(content));
                            //resp = Some(std::str::from_utf8(&content).unwrap());
                            &promise.resolve
                        }
                        Err(err) => {
                            resp_err.push_str(&format!("QJS Error {:?}", err));
                            &promise.reject
                        }
                    }
                };

                unsafe {
                    if let Some(resp_to_js) = resp {
                        ffi::JS_Call(
                            promise.ctxt.as_ptr(),
                            handle.raw(),
                            ffi::NULL,
                            1 as i32,
                            resp_to_js.into_values(&promise.ctxt).as_ptr() as *mut _,
                        );
                    } else {
                        ffi::JS_Call(
                            promise.ctxt.as_ptr(),
                            handle.raw(),
                            ffi::NULL,
                            1 as i32,
                            resp_err.into_values(&promise.ctxt).as_ptr() as *mut _,
                        );
                    }
                }
            }
        }
        None => {}
    }
}
fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    let (mut msg_tx, mut msg_rx) = channel::<MsgType>(2);
    let mut respmsg_pending_num = 0;

    let mut timer_queue: Rc<DelayQueue<u32>> = Rc::new(DelayQueue::new());

    let mut ruff_ctx = RuffCtx::new(msg_tx, Rc::clone(&timer_queue));

    let opt = Opt::from_clap(
        &Opt::clap()
            .version(qjs::LONG_VERSION.as_str())
            .get_matches(),
    );
    debug!("opts: {:?}", opt);

    let rt = if opt.trace_memory {
        Runtime::with_malloc_funcs::<()>(
            &MallocFunctions {
                js_malloc: Some(js_trace_malloc),
                js_free: Some(js_trace_free),
                js_realloc: Some(js_trace_realloc),
                js_malloc_usable_size: Some(js_trace_malloc_usable_size),
            },
            None,
        )
    } else {
        Runtime::new()
    };
    let ctxt = Context::new(&rt);

    ctxt.set_userdata(NonNull::new(&mut ruff_ctx));

    // loader for ES6 modules
    rt.set_module_loader::<()>(None, Some(jsc_module_loader), None);

    if !opt.empty_run {
        if cfg!(feature = "qjscalc") {
            if opt.load_jscalc {
                debug!("load jscalc.js");

                ctxt.eval_binary(&*ffi::QJSCALC, false)?;
            }
        }

        ctxt.std_add_helpers(opt.args.clone())?;

        // system modules
        ctxt.init_module_std()?;
        ctxt.init_module_os()?;

        if !opt.no_std {
            debug!("import `std` and `os` module");

            // make 'std' and 'os' visible to non module code
            eval_buf(
                &ctxt,
                r#"
import * as std from 'std';
import * as os from 'os';

globalThis.std = std;
globalThis.os = os;
"#,
                "<input>",
                Eval::MODULE,
            )?;
        }

        let mut event_rt = tokio::runtime::Builder::new()
            .threaded_scheduler()
            .build()
            .unwrap();

        let hello = ctxt
            .new_c_function(
                |ctxt, _this, args| {
                    let path = String::from(ctxt.to_cstring(&args[0]).unwrap().to_string_lossy());
                    let mut ruff_ctx = ctxt.userdata::<RuffCtx>().unwrap();

                    println!("In Rust Function path is {}", path);
                    let rfunc: [ffi::JSValue; 2] = [ffi::UNDEFINED; 2];
                    let ret = unsafe {
                        let promise =
                            ffi::JS_NewPromiseCapability(ctxt.as_ptr(), rfunc.as_ptr() as *mut _);
                        let handle = RJSPromise::new(
                            ctxt,
                            &Value::from(promise),
                            &Value::from(rfunc[0]),
                            &Value::from(rfunc[1]),
                        );
                        ruff_ctx
                            .as_mut()
                            .msg_tx
                            .try_send(MsgType::FS_READALL(String::from(path), handle));
                        //.expect("Fail to send msg");
                        promise
                    };
                    ret
                    //println!("refcount is {:?}", Value::from(rfunc[0]).ref_cnt());
                    //format!(
                    //    "hello {}",
                    //    ctxt.to_cstring(&args[0]).unwrap().to_string_lossy()
                    //);
                },
                Some("sayHello"),
                1,
            )
            .unwrap();

        ctxt.global_object()
            .set_property("sayHello", hello)
            .unwrap();
        let mut interactive = opt.interactive;

        let res = if let Some(expr) = opt.expr {
            debug!("eval expr: {}", expr);

            eval_buf(&ctxt, &expr, "<cmdline>", Eval::GLOBAL)
        } else if let Some(filename) = opt.args.first() {
            debug!("eval file: {}", filename);

            let buf = qjs::load_file(filename)?;
            let eval_flags =
                if opt.module || filename.ends_with(".mjs") || qjs::detect_module(buf.as_str()) {
                    Eval::MODULE
                } else {
                    Eval::GLOBAL
                };

            eval_buf(&ctxt, &buf, filename, eval_flags)
        } else {
            interactive = true;

            Ok(ctxt.undefined())
        };

        match res {
            Ok(res) => {
                if !res.is_undefined() {
                    println!("{}", res);
                }
            }
            Err(err) => {
                eprintln!("{}", err);

                if let Some(stack) = err.downcast_ref::<ErrorKind>().and_then(|err| err.stack()) {
                    eprintln!("{}", stack)
                }
            }
        }

        if interactive {
            ctxt.eval_binary(&*ffi::REPL, false)?;
            ctxt.std_loop();
        }

        let (mut resp_tx, mut resp_rx) = channel::<RespType>(2);
        let mut job_id = 0;
        let mut job_queue: HashMap<u32, RJSPromise> = HashMap::new();

        event_rt.block_on(async {
            loop {
                tokio::select! {
                    msg = msg_rx.recv() => {
                        handle_msg(msg, &mut job_id, resp_tx.clone(), &mut job_queue);
                    },
                    mut resp = resp_rx.recv() => {
                        handle_response(resp, &mut job_queue);
                    },
                }
                loop {
                    match rt.execute_pending_job() {
                        Ok(None) => {
                            break;
                        }
                        Ok(Some(_)) => {
                            //println!("@@@ Done some Job@@@@");
                            continue;
                        }
                        Err(_err) => {
                            println!("Error when do job!!!!");
                            break;
                        }
                    }
                }
            }
        });
    }
    if opt.dump_memory {
        let stats = rt.memory_usage();

        unsafe {
            ffi::JS_DumpMemoryUsage(cfile::stdout()?.as_ptr() as *mut _, &stats, rt.as_ptr())
        };
    }

    rt.std_free_handlers();

    if opt.empty_run && opt.dump_memory {
        let (d1, d2, d3, d4) = (0..100).fold(
            (
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_secs(1),
            ),
            |(d1, d2, d3, d4), _| {
                let ts0 = Instant::now();
                let rt = Runtime::new();
                let ts1 = Instant::now();
                let ctxt = Context::new(&rt);
                let ts2 = Instant::now();
                mem::drop(ctxt);
                let ts3 = Instant::now();
                mem::drop(rt);
                let ts4 = Instant::now();

                (
                    d1.min(ts1.duration_since(ts0)),
                    d2.min(ts2.duration_since(ts1)),
                    d3.min(ts3.duration_since(ts2)),
                    d4.min(ts4.duration_since(ts3)),
                )
            },
        );

        println!(
            "\nInstantiation times (ms): {:.3} = {:.3} + {:.3} + {:.3} + {:.3}",
            ((d1 + d2 + d3 + d4).as_micros() as f64) / 1000.0,
            (d1.as_micros() as f64) / 1000.0,
            (d2.as_micros() as f64) / 1000.0,
            (d3.as_micros() as f64) / 1000.0,
            (d4.as_micros() as f64) / 1000.0
        );
    }

    Ok(())
}
