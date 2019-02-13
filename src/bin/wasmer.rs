#![feature(bind_by_move_pattern_guards)]

extern crate structopt;

use std::cell::Cell;
use std::fs::File;
use std::io;
use std::io::Read;
use std::path::PathBuf;
use std::process::exit;

use structopt::StructOpt;

use wasmer::webassembly::InstanceABI;
use wasmer::*;
use wasmer_emscripten;
use wasmer_runtime_core::error;

#[derive(Debug, StructOpt)]
#[structopt(name = "wasmer", about = "Wasm execution runtime.")]
/// The options for the wasmer Command Line Interface
enum CLIOptions {
    /// Run a WebAssembly file. Formats accepted: wasm, wast
    #[structopt(name = "run")]
    Run(Run),

    /// Update wasmer to the latest version
    #[structopt(name = "self-update")]
    SelfUpdate,
}

#[derive(Debug, StructOpt)]
struct Run {
    #[structopt(short = "d", long = "debug")]
    debug: bool,

    /// Input file
    #[structopt(parse(from_os_str))]
    path: PathBuf,

    /// Application arguments
    #[structopt(name = "--", raw(multiple = "true"))]
    args: Vec<String>,
}

/// Read the contents of a file
fn read_file_contents(path: &PathBuf) -> Result<Vec<u8>, io::Error> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut file = File::open(path)?;
    file.read_to_end(&mut buffer)?;
    // We force to close the file
    drop(file);
    Ok(buffer)
}

macro_rules! mem {
    ($mem:ident [($start:ident + $offset:expr) .. ($_start:ident + $end:expr)] as &[ Cell< $ty:ty > ]) => {
        &$mem.view::<$ty>()[($start as usize / std::mem::size_of::<$ty>() + $offset)
            ..($start as usize / std::mem::size_of::<$ty>() + ($end as usize))]
    };
    ($mem:ident [$start:ident .. ($_start:ident + $end:expr)] as &[ $ty:ty ]) => {
        unsafe {
            &std::mem::transmute::<&[std::cell::Cell<$ty>], &[$ty]>(
                &$mem.view::<$ty>()[($start as usize / std::mem::size_of::<$ty>())
                    ..($start as usize / std::mem::size_of::<$ty>() + ($end as usize))],
            )
        };
    };
    ($mem:ident [$start:ident .. ($_start:ident + $end:expr)] as &mut [ $ty:ty ]) => {
        unsafe {
            &mut std::mem::transmute::<&mut [std::cell::Cell<$ty>], &mut [$ty]>(
                &mut $mem.view::<$ty>()[($start as usize / std::mem::size_of::<$ty>())
                    ..($start as usize / std::mem::size_of::<$ty>() + ($end as usize))],
            )
        };
    };
    ($mem:ident [$idx:expr] as Cell<$ty:ty>) => {
        &$mem.view::<$ty>()[$idx as usize / std::mem::size_of::<$ty>()]
    };
    ($mem:ident [$idx:expr] as $ty:ty) => {
        mem!($mem[$idx] as Cell<$ty>).take()
    };
}

fn rust_wasm_syscall(
    syscall_id: u32,
    args_ptr: u32,
    ctx: &mut wasmer_runtime::Ctx,
) -> Result<i32, error::Error> {
    let mem = ctx.memory(0);
    match syscall_id {
        // ref: https://github.com/rust-lang/rust/blob/79d8a0/src/etc/wasm32-shim.js#L109
        1 => {
            let args = mem!(mem[args_ptr..(args_ptr + 3)] as &[u32]);
            let (stream_id, msg_ptr, msg_len) = (args[0], args[1], args[2]);
            let msg = String::from_utf8(mem!(mem[msg_ptr..(msg_ptr + msg_len)] as &[u8]).to_vec())
                .unwrap();
            match stream_id {
                1 => print!("{}", msg),
                2 => eprint!("{}", msg),
                _ => panic!("syscall print to invalid output stream {}", stream_id),
            }
            Ok(true as i32)
        }
        2 => {
            // exit
            let exit_code = mem!(mem[args_ptr] as u32);
            Err(error::RuntimeError::User {
                msg: format!("Program requested exit with code {}", exit_code),
            }
            .into())
        }
        3 => {
            // args
            let args = mem!(mem[args_ptr..(args_ptr + 2)] as &[u32]);
            let (args_buf_ptr, args_buf_len) = (args[0], args[1]);
            let mut prog_args = String::new();
            for prog_arg in std::env::args() {
                prog_args.push_str(&prog_arg);
            }
            let ret = mem!(mem[args_ptr + 2] as Cell<u32>);
            ret.set(prog_args.len() as u32);
            if args_buf_len as usize >= prog_args.len() {
                let ret_buf =
                    mem!(mem[args_buf_ptr..(args_buf_ptr + prog_args.len() as u32)] as &mut [u8]);
                ret_buf.copy_from_slice(prog_args.as_bytes());
            }
            Ok(true as i32)
        }
        4 => {
            // getenv
            let args = mem!(mem[args_ptr..(args_ptr + 4)] as &[u32]);
            let (key_ptr, key_len, value_ptr, value_maxlen) = (args[0], args[1], args[2], args[3]);
            let key = String::from_utf8(mem!(mem[key_ptr..(key_ptr + key_len)] as &[u8]).to_vec())
                .map_err(|err| error::RuntimeError::User {
                    msg: err.to_string(),
                })?;
            match std::env::var(key) {
                Ok(val) if val.len() <= value_maxlen as usize => {
                    let val_buf = mem!(mem[value_ptr..(value_ptr + val.len() as u32)] as &mut [u8]);
                    val_buf.copy_from_slice(val.as_bytes());
                    mem!(mem[args_ptr + 4] as Cell<u32>).set(val.len() as u32);
                }
                _ => {
                    mem!(mem[args_ptr + 4] as Cell<u32>).set(0u32);
                }
            };
            Ok(true as i32)
        }
        // 4 => syscall!(syscall_getenv, 4, 1, mem, args_ptr),
        6 => {
            //time
            // let rets = (high_s, low_s, subsec_nanos);
            let rets = mem!(mem[(args_ptr + 1)..(args_ptr + 4)] as &[Cell<u32>]);
            let now = std::time::SystemTime::now();
            let epoch_duration = now
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .expect("SystemTime must be greater than epoch.");
            let s = epoch_duration.as_secs();
            rets[0].set((s >> 32) as u32);
            rets[1].set((s & 0xffffffff) as u32);
            rets[2].set(epoch_duration.subsec_nanos());
            Ok(true as i32)
        }
        _ => Err(error::RuntimeError::User {
            msg: format!("Called reserved syscall #{}", syscall_id),
        }
        .into()),
    }
}

/// Execute a wasm/wat file
fn execute_wasm(options: &Run) -> Result<(), String> {
    let wasm_path = &options.path;

    let mut wasm_binary: Vec<u8> = read_file_contents(wasm_path).map_err(|err| {
        format!(
            "Can't read the file {}: {}",
            wasm_path.as_os_str().to_string_lossy(),
            err
        )
    })?;

    if !utils::is_wasm_binary(&wasm_binary) {
        wasm_binary = wabt::wat2wasm(wasm_binary)
            .map_err(|e| format!("Can't convert from wast to wasm: {:?}", e))?;
    }

    let module = webassembly::compile(&wasm_binary[..])
        .map_err(|e| format!("Can't compile module: {:?}", e))?;

    let (_abi, import_object, em_globals) = if wasmer_emscripten::is_emscripten_module(&module) {
        let mut emscripten_globals = wasmer_emscripten::EmscriptenGlobals::new(&module);
        (
            InstanceABI::Emscripten,
            wasmer_emscripten::generate_emscripten_env(&mut emscripten_globals),
            Some(emscripten_globals), // TODO Em Globals is here to extend, lifetime, find better solution
        )
    } else {
        (
            InstanceABI::None,
            wasmer_runtime_core::imports! {
                "env" => {
                    "rust_wasm_syscall" => wasmer_runtime_core::func!(rust_wasm_syscall),
                },
            },
            // wasmer_runtime_core::import::ImportObject::new(),
            None,
        )
    };

    let mut instance = module
        .instantiate(&import_object)
        .map_err(|e| format!("Can't instantiate module: {:?}", e))?;

    webassembly::run_instance(
        &module,
        &mut instance,
        options.path.to_str().unwrap(),
        options.args.iter().map(|arg| arg.as_str()).collect(),
    )
    .map_err(|e| format!("{:?}", e))?;

    Ok(())
}

fn run(options: Run) {
    match execute_wasm(&options) {
        Ok(()) => {}
        Err(message) => {
            eprintln!("{:?}", message);
            exit(1);
        }
    }
}

fn main() {
    let options = CLIOptions::from_args();
    match options {
        CLIOptions::Run(options) => run(options),
        CLIOptions::SelfUpdate => update::self_update(),
    }
}
