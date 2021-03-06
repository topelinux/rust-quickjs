#[macro_use]
extern crate log;
#[macro_use]
extern crate cfg_if;

use failure::Error;
use foreign_types::ForeignTypeRef;
use foreign_types_shared::ForeignTypeRef as OtherForeignTypeRef;
use std::error::Error as StdError;
use std::ffi::{CStr, OsStr};
use std::mem;
use std::os::raw::{c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::ptr::NonNull;
use std::ptr::null_mut;
use std::time::{Duration, Instant};
use structopt::StructOpt;
use tokio::fs::File;
use tokio::prelude::*;
use tokio::stream::{self, StreamExt};
use tokio::sync::mpsc::{channel, Sender};
use tokio::time::{delay_queue, DelayQueue};

use qjs::{
    ffi, Args, Context, ContextRef, ErrorKind, Eval, Local, MallocFunctions, Runtime, Value, NewValue, jsc_module_loader, eval_buf, MsgType, RespType, fs_readall_async, RJSPromise, RJSTimerHandler, RuffCtx, RRId, RRIdManager, inner_fs_readall, inner_setTimeout,
};

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


fn main() -> Result<(), Error> {
    pretty_env_logger::init();

    let (mut msg_tx, mut msg_rx) = channel::<MsgType>(2);
    let mut ruff_ctx = RuffCtx::new(msg_tx);
    let mut timer_queue: DelayQueue<RJSTimerHandler> = DelayQueue::new();
    let mut resoure_manager = RRIdManager::new();

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
            .enable_all()
            .build()
            .unwrap();

        let fs_readall = ctxt.new_c_function(inner_fs_readall, Some("fs_readall"), 1).unwrap();
        let os_setTimeout = ctxt.new_c_function(inner_setTimeout, Some("os_setTimeout"), 2).unwrap();

        ctxt.global_object()
            .set_property("fs_readall", fs_readall)
            .unwrap();

        ctxt.global_object()
            .set_property("os_setTimeout", os_setTimeout)
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
        let mut should_poll_timer = true;

        event_rt.block_on(async {
            loop {
                tokio::select! {
                    msg = msg_rx.recv() => {
                        let ret = resoure_manager.handle_msg(msg, resp_tx.clone(), &mut timer_queue);
                        should_poll_timer = true;
                        println!("msg handle ret is {:?}", ret);
                    },
                    mut resp = resp_rx.recv() => {
                        resoure_manager.handle_response(resp);
                        should_poll_timer = true;
                    },
                    v = timer_queue.next(), if !resoure_manager.timer_is_empty() => {
                        match v {
                            Some(v) => {
                                match v {
                                    Ok(expire) => {
                                        //let timer_handler = expire.get_ref();
                                        resoure_manager.handle_timer(expire.into_inner());
                                        //timer_handler.callback.call(None, [0;0]);
                                    }

                                    Err(_) => {}
                                }
                            }
                            None => {
                                println!("Why come here??");
                            }
                        }
                    },
                }
                loop {
                    match rt.execute_pending_job() {
                        Ok(None) => break,
                        Ok(Some(_)) => continue,
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
