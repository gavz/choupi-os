// The MIT License (MIT)
//
// Copyright (c) 2020, National Cybersecurity Agency of France (ANSSI)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! Low-level emulator implementation

use context_ll::Context;
use ipc_channel::ipc;
use libc::{user_fpregs_struct, user_regs_struct};
use slog::Drain;
use spin::{Mutex, MutexGuard};
use std::panic::{RefUnwindSafe, UnwindSafe};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{io, mem, panic, str};
use {core, libc, mpu_ll, siginfo, slog, slog_term, syscall, RAM};

static ONE_TEST_AT_A_TIME: Mutex<()> = Mutex::new(());

/// One test at a time
pub fn one_test_at_a_time() -> MutexGuard<'static, ()> {
    ONE_TEST_AT_A_TIME.lock()
}

struct SafeDrain<D>(Mutex<D>); // Don't really know why this is required
impl<D: Drain> Drain for SafeDrain<D> {
    type Ok = D::Ok;
    type Err = D::Err;
    fn log(&self, r: &slog::Record, v: &slog::OwnedKVList) -> Result<D::Ok, D::Err> {
        self.0.lock().log(r, v)
    }
}
impl<D: Drain> UnwindSafe for SafeDrain<D> {}
impl<D: Drain> RefUnwindSafe for SafeDrain<D> {}

struct TestStdoutWriter;

impl io::Write for TestStdoutWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        print!(
            "{}",
            str::from_utf8(data).map_err(|x| io::Error::new(io::ErrorKind::InvalidData, x))?
        );
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stdout().flush()
    }
}

static IS_MASTER: AtomicBool = AtomicBool::new(true);
lazy_static! {
    static ref LOGGER: Mutex<slog::Logger> = Mutex::new(slog::Logger::root(
        SafeDrain(Mutex::new(
            slog_term::CompactFormat::new(slog_term::PlainDecorator::new(TestStdoutWriter))
                .use_custom_timestamp(|w: &mut dyn io::Write| {
                    let process = if IS_MASTER.load(Ordering::Relaxed) {
                        "MASTER"
                    } else {
                        "SLAVE"
                    };
                    write!(w, "{}", process)
                })
                .build()
                .fuse()
        )),
        o!()
    ));
    static ref LOGGER_STACK: Mutex<Vec<slog::Logger>> = Mutex::new(Vec::new());
}

/// Getting logger
pub fn logger() -> MutexGuard<'static, slog::Logger> {
    LOGGER.lock()
}

/// Pushing logger
pub fn push_logger(mut log: slog::Logger) {
    let mut logger = LOGGER.lock();
    let mut stack = LOGGER_STACK.lock();
    mem::swap(&mut *logger, &mut log);
    stack.push(log);
}

/// Poping logger
pub fn pop_logger() {
    let mut logger = LOGGER.lock();
    let mut stack = LOGGER_STACK.lock();
    *logger = stack.pop().expect("No logger to pop");
}

static IN_EMULATOR: AtomicBool = AtomicBool::new(false);

/// Is in emulator
pub fn in_emulator() -> bool {
    IN_EMULATOR.load(Ordering::SeqCst)
}

unsafe fn usr1_set() -> libc::sigset_t {
    let mut set = mem::MaybeUninit::<libc::sigset_t>::uninit();
    libc::sigemptyset(set.as_mut_ptr());
    libc::sigaddset(set.as_mut_ptr(), libc::SIGUSR1);
    set.assume_init()
}

unsafe fn block_usr1() -> libc::sigset_t {
    let set = usr1_set();
    let mut oldset = mem::MaybeUninit::<libc::sigset_t>::uninit();
    libc::sigprocmask(libc::SIG_BLOCK, &set, oldset.as_mut_ptr());
    oldset.assume_init()
}

unsafe fn wait_for_usr1() {
    block_usr1();
    let set = usr1_set();
    let mut sig = mem::MaybeUninit::<libc::c_int>::uninit();
    libc::sigwait(&set, sig.as_mut_ptr());
}

unsafe fn wait_for_stop(pid: libc::pid_t) -> libc::c_int {
    let mut status = mem::MaybeUninit::<libc::c_int>::uninit();
    libc::waitpid(pid, status.as_mut_ptr(), 0);
    status.assume_init()
}

#[no_mangle]
/// This being called inside preempted println!'s, trying to println! here would deadlock.
pub unsafe extern "C" fn please_mprotect_lock(addr: *const u8) {
    libc::mprotect((addr as u64 & !0xFFF) as *mut _, 1, libc::PROT_NONE);
}
#[naked]
unsafe fn please_mprotect_lock_entry() {
    asm!(
        "call please_mprotect_lock
          movq $$0, %rdi # EmulatorCall::DowncallReturn
          int3"
    );
}

/// This being called inside preempted println!'s, trying to println! here would deadlock.
#[no_mangle]
pub unsafe extern "C" fn please_mprotect_unlock(addr: *const u8) {
    libc::mprotect(
        (addr as u64 & !0xFFF) as *mut _,
        1,
        mpu_ll::allows_addr(addr),
    );
}
#[naked]
unsafe fn please_mprotect_unlock_entry() {
    asm!(
        "call please_mprotect_unlock
          movq $$0, %rdi # EmulatorCall::DowncallReturn
          int3"
    );
}

unsafe fn launch_test<F>(f: F, oldset: libc::sigset_t, tx: ipc::IpcSender<Result<(), String>>) -> !
where
    F: FnOnce() + panic::UnwindSafe,
{
    wait_for_usr1();
    IS_MASTER.store(false, Ordering::Relaxed);
    IN_EMULATOR.store(true, Ordering::SeqCst);
    libc::sigprocmask(libc::SIG_SETMASK, &oldset, null_mut());
    libc::mprotect(
        &mut RAM.get_mut()[0] as *mut _ as *mut _,
        RAM.get().len(),
        libc::PROT_NONE,
    );
    panic::take_hook();
    let new_logger = logger().new(o!("in test" => true));
    push_logger(new_logger);
    let res = panic::catch_unwind(f);
    pop_logger();
    if let Err(e) = res {
        // Mimic the behaviour of rustc
        match e.downcast::<&str>() {
            Ok(e) => tx.send(Err(e.to_string())),
            Err(e) => match e.downcast::<String>() {
                Ok(e) => tx.send(Err(*e)),
                Err(_) => tx.send(Err("[[unable to recover error message]]".to_string())),
            },
        }
        .expect("Unable to send the panic message to controller");
        libc::exit(132);
    } else {
        tx.send(Ok(()))
            .expect("Unable to send an Ok message to controller");
        libc::exit(0);
    }
}

#[derive(Debug)]
struct EmulatorState {
    privileged: bool,
    in_exception: bool,
    other_sp: u64,
}

fn exited(stop: libc::c_int, rx: ipc::IpcReceiver<Result<(), String>>) {
    // Process just exited
    let recv = rx
        .recv()
        .expect("Unable to receive result from sub-process");
    if let Err(e) = recv {
        panic!(e);
    } else {
        assert_eq!(unsafe { libc::WEXITSTATUS(stop) }, 0);
    }
}

fn get_regs(child: libc::pid_t) -> (user_regs_struct, user_fpregs_struct) {
    unsafe {
        let mut regs = mem::MaybeUninit::<libc::user_regs_struct>::uninit();
        let mut fpregs = mem::MaybeUninit::<libc::user_fpregs_struct>::uninit();
        libc::ptrace(libc::PTRACE_GETREGS, child, 0, &mut regs);
        libc::ptrace(libc::PTRACE_GETFPREGS, child, 0, &mut fpregs);
        (regs.assume_init(), fpregs.assume_init())
    }
}

fn set_regs(child: libc::pid_t, regs: &user_regs_struct, fpregs: &user_fpregs_struct) {
    unsafe {
        libc::ptrace(libc::PTRACE_SETREGS, child, 0, regs);
        libc::ptrace(libc::PTRACE_SETFPREGS, child, 0, fpregs);
    }
}

fn cont(child: libc::pid_t) {
    unsafe {
        libc::ptrace(libc::PTRACE_CONT, child, 0, 0);
    }
}

fn get_segfaulted_addr(child: libc::pid_t) -> *const u8 {
    unsafe {
        let mut siginfo = mem::MaybeUninit::<siginfo::siginfo_t>::uninit();
        libc::ptrace(libc::PTRACE_GETSIGINFO, child, 0, &mut siginfo);
        let addr: *const u8 = siginfo.assume_init()._sifields._sigfault.si_addr as *const u8;
        warn!(
            logger(),
            "Signal caught: signo={}, code={}, errno={}, address looks like {:?} (RAM is {:?})",
            siginfo.assume_init().si_signo,
            siginfo.assume_init().si_code,
            siginfo.assume_init().si_errno,
            addr,
            &RAM.get()[0] as *const _
        );
        addr
    }
}

#[derive(PartialEq, Eq, Debug)]
enum CatchSegfault {
    Yes,
    No,
}

#[repr(align(0x1000))]
/// RAM MProtect memory struct
pub struct MprotectRam(pub [u8; 0x1000]);
/// RAM MProtect RAM protection implementation
pub static mut MPROTECT_RAM: MprotectRam = MprotectRam([0; 0x1000]);

/// Call function
fn call_function(
    child: libc::pid_t,
    f: u64,
    arg: u64,
    state: &mut EmulatorState,
    catch_segf: CatchSegfault,
) {
    let new_logger = logger().new(o!(
            "calling function" => format!("{:#x}({:#x}) (catching segfaults? {:?})", f, arg, catch_segf)));
    push_logger(new_logger);
    info!(logger(), "emulator state: {:?}", state);
    let (mut regs, fpregs) = get_regs(child);
    let (rip, rdi, rsp) = (regs.rip, regs.rdi, regs.rsp);
    regs.rip = f;
    regs.rdi = arg;
    regs.rsp = unsafe { &MPROTECT_RAM.0[0xFFF] as *const _ as u64 } + 1;
    set_regs(child, &regs, &fpregs);
    cont(child);
    run_until_downcall_completion(child, state, catch_segf);
    regs.rip = rip;
    regs.rdi = rdi;
    regs.rsp = rsp;
    set_regs(child, &regs, &fpregs);
    pop_logger();
}

/// Single step with adress allowed
fn single_step_with_address_allowed(
    child: libc::pid_t,
    addr: *const u8,
    state: &mut EmulatorState,
) {
    // mprotect-unlock
    trace!(logger(), "About to call mprotect_unlock {:p}", addr);
    call_function(
        child,
        please_mprotect_unlock_entry as u64,
        addr as u64,
        state,
        CatchSegfault::No,
    );

    // Single-step
    unsafe {
        libc::ptrace(libc::PTRACE_SINGLESTEP, child, 0, 0);
        let ssstop = wait_for_stop(child);
        info!(logger(), "After single-step, stop is {}", ssstop);
        if libc::WIFSTOPPED(ssstop) && libc::WSTOPSIG(ssstop) == libc::SIGTRAP {
            return;
        } else if libc::WIFSTOPPED(ssstop) && libc::WSTOPSIG(ssstop) == libc::SIGSEGV {
            let a = get_segfaulted_addr(child);
            if a != addr {
                single_step_with_address_allowed(child, a, state);
            } else {
                libc::ptrace(libc::PTRACE_DETACH, child, 0, libc::SIGSEGV);
                panic!(
                    "Tried to use unauthorized address {:p} (RAM {:p}, offset {:#x}):\n{}",
                    addr,
                    &RAM.get()[0],
                    addr as isize - &RAM.get()[0] as *const _ as isize,
                    dump_ptrace_stop(ssstop)
                );
            }
        } else {
            libc::ptrace(libc::PTRACE_DETACH, child, 0, libc::SIGSEGV);
            panic!("Unknown failure condition...");
        }
    }

    // mprotect-lock
    trace!(logger(), "About to call mprotect_lock {:p}", addr);
    call_function(
        child,
        please_mprotect_lock_entry as u64,
        addr as u64,
        state,
        CatchSegfault::No,
    );
}

fn handle_segfault(child: libc::pid_t, state: &mut EmulatorState) {
    // Process just hit someplace not fully allowed by MPU
    let new_logger = logger().new(o!("handling" => "segfault"));
    push_logger(new_logger);
    trace!(logger(), "at RIP 0x{:X}", get_regs(child).0.rip);

    single_step_with_address_allowed(child, get_segfaulted_addr(child), state);

    // And restore state and run
    cont(child);
    pop_logger();
}

fn perform_is_in_exception(state: &mut EmulatorState, regs: &mut user_regs_struct) {
    info!(logger(), "is_in_exception: {}", state.in_exception);
    regs.rdi = state.in_exception as u64;
}

fn perform_drop_privileges(state: &mut EmulatorState, regs: &mut user_regs_struct) {
    info!(
        logger(),
        "Dropping privileges to interrupt stack {:#x}", regs.rsi
    );
    assert!(!state.in_exception && state.privileged);
    state.privileged = false;
    state.other_sp = regs.rsi;
}

fn perform_is_privileged(state: &mut EmulatorState, regs: &mut user_regs_struct) {
    info!(logger(), "is_privileged: {}", state.privileged);
    regs.rdi = state.privileged as u64;
}

fn perform_current_psp(state: &mut EmulatorState, regs: &mut user_regs_struct) {
    info!(logger(), "current_psp: {:#x}", state.other_sp);
    assert!(
        state.in_exception,
        "Tried to retrieve PSP outside of exception"
    );
    regs.rdi = state.other_sp;
}

fn perform_set_psp(state: &mut EmulatorState, regs: &mut user_regs_struct) {
    info!(logger(), "set_psp to {:#x}", regs.rsi);
    assert!(state.in_exception, "Tried to set PSP outside of exception");
    state.other_sp = regs.rsi;
}

fn dump_ptrace_stop(stop: libc::c_int) -> String {
    unsafe {
        format!(
            "{}:
exited {}: exitstatus {}
signaled {}: termsig {}
stopped {}: stopsig {}
continued {}",
            stop,
            libc::WIFEXITED(stop),
            libc::WEXITSTATUS(stop),
            libc::WIFSIGNALED(stop),
            libc::WTERMSIG(stop),
            libc::WIFSTOPPED(stop),
            libc::WSTOPSIG(stop),
            libc::WIFCONTINUED(stop)
        )
    }
}

fn push_data_to_child<T>(child: libc::pid_t, pos: u64, val: T) {
    unsafe {
        let wordlen = mem::size_of::<usize>() as u64;
        let datalen = mem::size_of::<T>() as u64;
        assert_eq!(datalen % wordlen, 0);
        for i in 0..(datalen / wordlen) {
            libc::ptrace(
                libc::PTRACE_POKEDATA,
                child,
                pos + wordlen * i,
                *((&val as *const T as *const usize).wrapping_offset(i as isize)),
            );
        }
    }
}

fn pop_data_from_child<T>(child: libc::pid_t, pos: u64) -> T {
    unsafe {
        let wordlen = mem::size_of::<usize>() as u64;
        let datalen = mem::size_of::<T>() as u64;
        assert_eq!(datalen % wordlen, 0);
        let mut res = mem::MaybeUninit::<T>::uninit();
        for i in 0..(datalen / wordlen) {
            *((res.as_mut_ptr() as *mut usize).wrapping_offset(i as isize)) =
                libc::ptrace(libc::PTRACE_PEEKDATA, child, pos + wordlen * i) as usize;
        }
        res.assume_init()
    }
}

fn perform_syscall(
    child: libc::pid_t,
    state: &mut EmulatorState,
    regs: &mut user_regs_struct,
    fpregs: &mut user_fpregs_struct,
) {
    let new_logger = logger().new(o!("handling" => "syscall"));
    push_logger(new_logger);
    info!(logger(), "syscall");
    assert!(!state.in_exception);

    // Push result context
    regs.rsp -= mem::size_of::<Context>() as u64;
    push_data_to_child(
        child,
        regs.rsp,
        Context {
            rip: regs.rip,
            rdi: regs.rdi,
            rsi: regs.rsi,
            rdx: regs.rdx,
            rcx: regs.rcx,
        },
    );

    // Fix metadata
    state.privileged = true;
    state.in_exception = true;
    trace!(
        logger(),
        "swapping RSP's rsp {:#x} <- {:#x} other_sp",
        regs.rsp,
        state.other_sp
    );
    mem::swap(&mut regs.rsp, &mut state.other_sp);

    // Shift all registers by one position to fit calling convention
    regs.rip = receive_syscall as u64;
    regs.rdi = regs.rsi;
    regs.rsi = regs.rdx;
    regs.rdx = regs.rcx;
    regs.rcx = regs.r8;

    // Run the syscall handler
    set_regs(child, &regs, &fpregs);
    cont(child);
    let stop = run_until_downcall_completion(child, state, CatchSegfault::Yes);
    trace!(logger(), "after syscall handler");
    unsafe {
        if !(libc::WIFSTOPPED(stop) && libc::WSTOPSIG(stop) == libc::SIGTRAP) {
            panic!("Syscall failed to execute: {}", dump_ptrace_stop(stop));
        }
    }

    // Fixup metadata
    state.privileged = false;
    state.in_exception = false;
    trace!(
        logger(),
        "swapping RSP's rsp {:#x} <- {:#x} other_sp",
        regs.rsp,
        state.other_sp
    );
    mem::swap(&mut regs.rsp, &mut state.other_sp);

    // Pop result context
    let c: Context = pop_data_from_child(child, regs.rsp);
    regs.rip = c.rip;
    regs.rdi = c.rdi;
    regs.rsi = c.rsi;
    regs.rdx = c.rdx;
    regs.rcx = c.rcx;
    regs.rsp = regs.rsp + mem::size_of::<Context>() as u64;

    pop_logger();
}

fn handle_trap(child: libc::pid_t, state: &mut EmulatorState) {
    let new_logger = logger().new(o!("handling" => "trap"));
    push_logger(new_logger);
    // Save state
    let (mut regs, mut fpregs) = get_regs(child);
    // Process is doing an "emulator call"
    info!(
        logger(),
        "emulator call {} (from {:#x})", regs.rdi, regs.rip
    );
    // Read emulator call
    let call =
        EmulatorCall::from_usize(regs.rdi as usize).expect("Unknown interpreter call received");
    match call {
        EmulatorCall::DowncallReturn => panic!("Unexpected downcall return"),
        EmulatorCall::IsInException => perform_is_in_exception(state, &mut regs),
        EmulatorCall::DropPrivileges => perform_drop_privileges(state, &mut regs),
        EmulatorCall::IsPrivileged => perform_is_privileged(state, &mut regs),
        EmulatorCall::CurrentPsp => perform_current_psp(state, &mut regs),
        EmulatorCall::SetPsp => perform_set_psp(state, &mut regs),
        EmulatorCall::Syscall => perform_syscall(child, state, &mut regs, &mut fpregs),
    }
    // Resume normal execution
    set_regs(child, &regs, &fpregs);
    cont(child);
    pop_logger();
}

fn run_until<F: Fn(i32) -> bool>(
    child: libc::pid_t,
    state: &mut EmulatorState,
    segf: CatchSegfault,
    time_to_stop: F,
) -> libc::c_int {
    unsafe {
        loop {
            let stop = wait_for_stop(child);
            if time_to_stop(stop) {
                info!(logger(), "time to stop");
                return stop;
            } else if libc::WIFSTOPPED(stop) && libc::WSTOPSIG(stop) == libc::SIGSEGV {
                if segf == CatchSegfault::Yes {
                    handle_segfault(child, state);
                } else {
                    error!(
                        logger(),
                        "Unhandled segfault at {:#x}:",
                        get_regs(child).0.rip
                    );
                    get_segfaulted_addr(child);
                    libc::ptrace(libc::PTRACE_DETACH, child, 0, libc::SIGSEGV);
                    panic!();
                }
            } else if libc::WIFSTOPPED(stop) && libc::WSTOPSIG(stop) == libc::SIGTRAP {
                handle_trap(child, state);
            } else if libc::WIFSTOPPED(stop) && libc::WSTOPSIG(stop) == libc::SIGILL {
                libc::ptrace(libc::PTRACE_DETACH, child, 0, libc::SIGILL);
                panic!("Quitting at user's request");
            } else {
                panic!("Unknown ptrace signal received: {}", dump_ptrace_stop(stop));
            }
        }
    }
}

fn run_until_downcall_completion(
    child: libc::pid_t,
    state: &mut EmulatorState,
    segf: CatchSegfault,
) -> libc::c_int {
    let new_logger = logger().new(o!("running until" => "downcall completion"));
    push_logger(new_logger);
    let res = run_until(child, state, segf, |stop| unsafe {
        libc::WIFSTOPPED(stop)
            && libc::WSTOPSIG(stop) == libc::SIGTRAP
            && get_regs(child).0.rdi == EmulatorCall::DowncallReturn as u64
    });
    info!(logger(), "Result: {}", res);
    pop_logger();
    res
}

fn run_until_exited(child: libc::pid_t, state: &mut EmulatorState) -> libc::c_int {
    let new_logger = logger().new(o!("running until" => "exited"));
    push_logger(new_logger);
    let res = run_until(child, state, CatchSegfault::Yes, |stop| unsafe {
        libc::WIFEXITED(stop)
    });
    info!(logger(), "Result: {}", res);
    pop_logger();
    res
}

/// Run emulator
pub fn run<F>(f: F)
where
    F: FnOnce() + panic::UnwindSafe,
{
    unsafe {
        let oldset = block_usr1();
        let (tx, rx) = ipc::channel().expect("Unable to open IPC channel for MPU testing");
        let child = match libc::fork() {
            -1 => panic!("Fork failed: {}", io::Error::last_os_error()),
            0 => launch_test(f, oldset, tx),
            pid => pid,
        };
        libc::sigprocmask(libc::SIG_SETMASK, &oldset, null_mut());
        libc::ptrace(libc::PTRACE_ATTACH, child, 0, 0);
        wait_for_stop(child);
        libc::ptrace(libc::PTRACE_SETOPTIONS, child, 0, libc::PTRACE_O_EXITKILL);
        libc::ptrace(libc::PTRACE_CONT, child, 0, 0);
        libc::kill(child, libc::SIGUSR1);

        let mut state = EmulatorState {
            privileged: true,
            in_exception: false,
            other_sp: 0,
        };
        trace!(logger(), "setting other_sp {:#x}", state.other_sp);

        let stop = run_until_exited(child, &mut state);
        exited(stop, rx);
    }
}

#[no_mangle]
/// Receive syscall impl
pub extern "C" fn receive_syscall_impl(num: usize, arg1: usize, arg2: usize, arg3: usize) {
    println!(
        "in receive_syscall_impl {}({:#x}, {}, {})",
        num, arg1, arg2, arg3
    );
    syscall::syscall_received(num, arg1, arg2, arg3);
}

#[naked]
extern "C" fn receive_syscall() {
    unsafe {
        asm!(
            "call receive_syscall_impl
              movq $$0, %rdi # EmulatorCall::DowncallReturn
              int3"
        );
        core::intrinsics::unreachable()
    }
}

#[repr(usize)]
#[derive(Debug, PartialEq, Eq)]
/// Emulator syscall value
pub enum EmulatorCall {
    /// DownCallReturn syscall
    DowncallReturn = 0,
    /// Is in exception syscall
    IsInException = 1,
    /// Drop privileges syscall
    DropPrivileges = 2,
    /// IsPrivileged syscall
    IsPrivileged = 3,
    /// Get Current PSP syscall
    CurrentPsp = 4,
    /// SetPSP syscall
    SetPsp = 5,
    /// Syscall
    Syscall = 6, // BEWARE this value is hardcoded in `arch/host/context_ll.rs`
}

impl EmulatorCall {
    fn from_usize(x: usize) -> Option<EmulatorCall> {
        match x {
            0 => Some(EmulatorCall::DowncallReturn),
            1 => Some(EmulatorCall::IsInException),
            2 => Some(EmulatorCall::DropPrivileges),
            3 => Some(EmulatorCall::IsPrivileged),
            4 => Some(EmulatorCall::CurrentPsp),
            5 => Some(EmulatorCall::SetPsp),
            6 => Some(EmulatorCall::Syscall),
            _ => None,
        }
    }
}

/// Call emulator syscalls
fn emulator_call(num: EmulatorCall, a1: usize, a2: usize, a3: usize, a4: usize) -> usize {
    if num != EmulatorCall::IsPrivileged {
        // IsPrivileged is called from inside preempted functions, including println!'s. Thus
        // trying to println! from here would deadlock.
        //println!("emulator call {:?}({:#x}, {}, {}, {})", num, a1, a2, a3, a4);
    }
    let res: usize;
    unsafe {
        asm!("int3"
             : "={rdi}"(res)
             : "{rdi}"(num), "{rsi}"(a1), "{rdx}"(a2), "{rcx}"(a3), "{r8}"(a4)
             :
             : "volatile");
    }
    res
}

/// Emulator syscalls calls
pub fn syscall(num: usize, arg1: usize, arg2: usize, arg3: usize) -> usize {
    emulator_call(EmulatorCall::Syscall, num, arg1, arg2, arg3)
}

/// Is emulator is in exception?
pub fn is_in_exception() -> bool {
    emulator_call(EmulatorCall::IsInException, 0, 0, 0, 0) != 0
}

/// Drop emulator privileges
pub fn drop_privileges(interrupt_stack: *mut ()) {
    emulator_call(
        EmulatorCall::DropPrivileges,
        interrupt_stack as usize,
        0,
        0,
        0,
    );
}

/// Emulator running in privileged mode?
pub fn is_privileged() -> bool {
    emulator_call(EmulatorCall::IsPrivileged, 0, 0, 0, 0) != 0
}

/// Get emulator PSP stack
pub fn current_psp() -> usize {
    emulator_call(EmulatorCall::CurrentPsp, 0, 0, 0, 0)
}

/// Set emulator PSP stack
pub fn set_psp(psp: usize) {
    emulator_call(EmulatorCall::SetPsp, psp, 0, 0, 0);
}
