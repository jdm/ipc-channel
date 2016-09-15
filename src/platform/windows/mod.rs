// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::cell::{Cell, RefCell};
use std::cmp::{min, PartialEq};
use std::default::Default;
use std::ffi::CString;
use std::fmt::{self, Debug, Formatter};
use std::io::{Error, ErrorKind};
use std::marker::{Send, Sync};
use std::mem;
use std::ops::Deref;
use std::ops::DerefMut;
use std::os::raw::c_void;
use std::ptr;
use std::slice;
use std::sync::{Arc, Mutex};
use std::thread;

use libc::{intptr_t};

use uuid::Uuid;

use bincode;
use bincode::serde::DeserializeError;

use winapi;
use winapi::{HANDLE, INVALID_HANDLE_VALUE};
use kernel32;

const INVALID_PID: u32 = 0xffffffffu32;
//const NMPWAIT_WAIT_FOREVER: u32 = 0xffffffffu32;
//const NMPWAIT_NOWAIT: u32 = 0x1u32;

const READ_BUFFER_SIZE: usize = 128 * 1024; //8192;
const READ_BUFFER_MAX_GROWTH: usize = 1 * 1024 * 1024; // 1MB max growth

#[allow(non_snake_case)]
fn GetLastError() -> u32 {
    unsafe {
        kernel32::GetLastError()
    }
}

pub fn channel() -> Result<(OsIpcSender, OsIpcReceiver),WinError> {
    let mut receiver = try!(OsIpcReceiver::new());
    let sender = try!(receiver.sender());
    Ok((sender, receiver))
}

#[derive(Serialize, Deserialize, Debug)]
struct OsIpcChannelHandle {
    // The pipe_id
    pipe_id: Uuid,

    // If this handle is for a sender or a receiver.
    // If it's for a receiver, then we'll call CreateNamedPipe to
    // set up a new server.
    // If it's for a sender, we'll save the pipe_id so that we
    // can use it with CallNamedPipe.
    sender: bool,
}

// If we have any channel handles or shmem segments,
// then we'll send an OsIpcOutOfBandMessage after
// the data message.
#[derive(Serialize, Deserialize, Debug)]
struct OsIpcOutOfBandMessage {
    channel_handles: Vec<OsIpcChannelHandle>,
    shmem_source_pid: u32,
    shmem_sizes: Vec<u64>,
    shmem_handles: Vec<intptr_t>,
}

fn make_pipe_id() -> Uuid {
    Uuid::new_v4()
}

fn make_pipe_name(pipe_id: &Uuid) -> CString {
    CString::new(format!("\\\\.\\pipe\\rust-ipc-{}", pipe_id.to_string())).unwrap()
}

#[allow(dead_code)]
fn safe_close_handle_cell(handle: &Cell<HANDLE>) -> () {
    unsafe {
        if handle.get() != INVALID_HANDLE_VALUE {
            kernel32::CloseHandle(handle.get());
            handle.set(INVALID_HANDLE_VALUE);
        }
    }
}

// duplicate a given handle in the source process to this one, closing it in the source process
#[allow(dead_code)]
fn get_process_handle(pid: u32) -> Result<HANDLE,WinError> {
    unsafe {
        let handle = kernel32::OpenProcess(winapi::PROCESS_DUP_HANDLE, winapi::FALSE, pid);
        if handle == INVALID_HANDLE_VALUE {
            return Err(WinError::last("OpenProcess"));
        }
        Ok(handle)
    }
}

#[allow(dead_code)]
fn take_handle_from_process(handle: HANDLE, source_pid: u32) -> Result<HANDLE,WinError> {
    unsafe {
        let mut newh: HANDLE = INVALID_HANDLE_VALUE;
        let other_process = try!(get_process_handle(source_pid));

        let ok = kernel32::DuplicateHandle(other_process, handle,
                                           kernel32::GetCurrentProcess(), &mut newh,
                                           0, winapi::FALSE, winapi::DUPLICATE_CLOSE_SOURCE | winapi::DUPLICATE_SAME_ACCESS);
        let err = GetLastError();

        kernel32::CloseHandle(other_process);

        if ok == winapi::FALSE {
            Err(WinError(err/*, "DuplicateHandle"*/))
        } else {
            Ok(newh)
        }
    }
}

// duplicate a given handle from this process to the target one
#[allow(dead_code)]
fn dup_handle_for_process(handle: HANDLE, target_pid: u32) -> Result<HANDLE,WinError> {
    unsafe {
        let mut newh: HANDLE = INVALID_HANDLE_VALUE;
        let other_process = try!(get_process_handle(target_pid));

        let ok = kernel32::DuplicateHandle(kernel32::GetCurrentProcess(), handle,
                                           other_process, &mut newh,
                                           0, winapi::FALSE, winapi::DUPLICATE_CLOSE_SOURCE | winapi::DUPLICATE_SAME_ACCESS);
        let err = GetLastError();
        
        kernel32::CloseHandle(other_process);

        if ok == winapi::FALSE {
            Err(WinError(err/*, "DuplicateHandle"*/))
        } else {
            Ok(newh)
        }
    }
}

// duplicate a handle in the current process
#[allow(dead_code)]
fn dup_handle(handle: HANDLE) -> Result<HANDLE,WinError> {
    unsafe {
        let mut newh: HANDLE = INVALID_HANDLE_VALUE;
        let ok = kernel32::DuplicateHandle(kernel32::GetCurrentProcess(), handle,
                                           kernel32::GetCurrentProcess(), &mut newh,
                                           0, winapi::FALSE, winapi::DUPLICATE_SAME_ACCESS);
        if ok == winapi::FALSE {
            Err(WinError::last("DuplicateHandle"))
        } else {
            Ok(newh)
        }
    }
}

macro_rules! take_handle {
    ($x:expr) => {{
        let h = $x.get();
        assert!(h != INVALID_HANDLE_VALUE, "taking handle that is already INVALID!");
        $x.set(INVALID_HANDLE_VALUE);
        h
    }}
}

// On Windows, a named pipe can have multiple servers (created via
// CreateNamedPipe), and multiple clients (via CreateFile, or other).
// A client connects to any available server, or blocks.
// We use CallNamedPipe to perform a connect, a send, a receive (which
// we don't do), and disconnect all in one go.
//
// When we send a named pipe, all we have to send is its name -- if it's
// a receiver, we can just close it on the source side, and the destination
// can just create a new server.

fn create_overlapped() -> RefCell<winapi::OVERLAPPED> {
    unsafe {
        //let ev = kernel32::CreateEventA(ptr::null_mut(), winapi::FALSE, winapi::FALSE, ptr::null_mut());
        //assert!(ev != INVALID_HANDLE_VALUE);
        RefCell::new(winapi::OVERLAPPED {
            Internal: 0,
            InternalHigh: 0,
            Offset: 0,
            OffsetHigh: 0,
            hEvent: 0 as HANDLE
        })
    }
}

fn reset_overlapped(ov: &mut winapi::OVERLAPPED) {
    ov.Internal = 0;
    ov.InternalHigh = 0;
    ov.Offset = 0;
    ov.OffsetHigh = 0;
}


#[derive(Debug, Clone, Copy, PartialEq, Display)]
enum ServerState {
    // the named pipe has been created, but it is not connected
    // or will not be connected to anything
    Disconnected,
    // a ConnectNamedPipe has been issued, but has not completed yet
    ConnectInProgress,
    // a ConnectNamedPipe has completed, and this server is connected.
    // next: ReadInProgress, Disconnected
    Connected,
    // a ReadFile has been issued, but has not completed yet
    // next: ReadComplete
    ReadInProgress,
    // a ReadFile has completed, and its data has not been consumed
    // next: ReadInProgress, Connected, Disconnected
    ReadComplete,
}

#[derive(Debug)]
struct NamedPipeServer {
    // The handle to the current server end of a named pipe
    handle: WinHandle,

    // The state that this server is in, which will also
    // indicate what the overlapped IO struct below is
    // waiting on, if anything
    state: Cell<ServerState>,

    // The OVERLAPPED struct for async IO
    ov: RefCell<winapi::OVERLAPPED>,

    // A read buffer for any pending reads
    read_buf: RefCell<Vec<u8>>,

    // the size of the last read that completed sync;
    // only valid if state == ReadComplete
    last_read_size: Cell<u32>,
}

unsafe impl Send for NamedPipeServer { }
unsafe impl Sync for NamedPipeServer { }

impl PartialEq for NamedPipeServer {
    fn eq(&self, other: &NamedPipeServer) -> bool {
        self.handle == other.handle
        // XXX should check others? but handle
        // equivalency should be enough..
    }
}

impl Drop for NamedPipeServer {
    fn drop(&mut self) {
        unsafe {
            kernel32::CancelIoEx(self.handle.as_win(), self.ov.borrow_mut().deref_mut());
        }
    }
}

impl NamedPipeServer {
    fn from_id(pipe_id: &Uuid) -> Result<NamedPipeServer,WinError> {
        unsafe {
            let pipe_name = make_pipe_name(&pipe_id);

            // create the pipe server
            let handle =
                kernel32::CreateNamedPipeA(pipe_name.as_ptr(),
                                           winapi::PIPE_ACCESS_INBOUND | winapi::FILE_FLAG_OVERLAPPED,
                                           winapi::PIPE_TYPE_BYTE | winapi::PIPE_READMODE_BYTE,
                                           winapi::PIPE_UNLIMITED_INSTANCES | winapi::PIPE_REJECT_REMOTE_CLIENTS,
                                           4096, 4096, // out/in buffer sizes
                                           0, // default timeout for WaitNamedPipe (0 == 50ms as default)
                                           ptr::null_mut());
            if handle == INVALID_HANDLE_VALUE {
                return Err(WinError::last("CreateNamedPipeA"));
            }

            let mut rec = NamedPipeServer {
                handle: WinHandle::new(handle),
                state: Cell::new(ServerState::Disconnected),
                ov: create_overlapped(),
                read_buf: RefCell::new(Vec::with_capacity(READ_BUFFER_SIZE)),
                last_read_size: Cell::new(0),
            };

            try!(rec.start_accept());

            Ok(rec)
        }
    }

    fn disconnect_and_reconnect(&mut self) -> Result<(),WinError> {
        panic!("disconnect_and_reconnect");
    }

    // The handle that we should wait for being signalled on; if we
    // use NULL for hEvent in the OVERLAPPED structure, then the named
    // pipe handle itself is signalled.  That can be a bad idea with
    // complex IO, but we have straightforward IO so we know what
    // will have completed each time.
    fn wait_handle(&self) -> HANDLE {
        self.handle.as_win()
    }

    fn io_completed(&self) -> bool {
        assert!(self.state.get() == ServerState::ConnectInProgress || self.state.get() == ServerState::ReadInProgress);
        self.ov.borrow().Internal != (winapi::STATUS_PENDING as u64)
    }
    
    // Start an asynchronous pipe connect
    fn start_accept(&mut self) -> Result<(),WinError> {
        println!("> start_accept");
        unsafe {
            let mut ov = self.ov.borrow_mut();
            reset_overlapped(ov.deref_mut());

            let ok = kernel32::ConnectNamedPipe(self.handle.as_win(),
                                                ov.deref_mut());
            // we should always get IO_PENDING or PIPE_CONNECTED with
            // OVERLAPPED
            assert!(ok == 0);
            let err = GetLastError();
            match (ok,err) {
                (0,winapi::ERROR_IO_PENDING) => {
                    self.state.set(ServerState::ConnectInProgress);
                    println!("< start_accept (ConnectInProgress)");
                    Ok(())
                },
                (0,winapi::ERROR_PIPE_CONNECTED) => {
                    self.state.set(ServerState::Connected);
                    println!("< start_accept (Connected)");
                    Ok(())
                },
                (_,_) =>
                    Err(WinError::last("ConnectNamedPipe"))
            }
        }
    }

    // Finish an asynchronous pipe connect, returning true or false
    // indicating if the pipe is connected.  If block is specified,
    // block until the pipe is connected (or error).  If block is false,
    // will return immediately.
    fn finish_accept(&mut self, block: bool) -> Result<bool,WinError> {
        println!("> finish_accept");

        // If we already connected (perhaps in start_connect), then
        // we're done
        if self.state.get() == ServerState::Connected {
            println!("< finish_accept (true)");
            return Ok(true);
        }

        // The only valid state is ConnectInProgress at this point
        assert!(self.state.get() == ServerState::ConnectInProgress);

        // If the IO operation is complete, we're connected; return
        // true.
        if self.io_completed() {
            self.state.set(ServerState::Connected);
            println!("< finish_accept (true)");
            return Ok(true);
        }

        unsafe {
            let mut ov = self.ov.borrow_mut();
            let mut dummy: u32 = 0;
            let ok = kernel32::GetOverlappedResult(self.handle.as_win(), ov.deref_mut(), &mut dummy, block as i32);
            if ok == 0 {
                let err = GetLastError();
                if err == winapi::ERROR_IO_INCOMPLETE {
                    println!("< finish_accept (false)");
                    return Ok(false);
                }
                return Err(WinError::last("GetOverlappedResult"));
            }
        }

        self.state.set(ServerState::Connected);
        println!("< finish_accept (true)");
        Ok(true)
    }

    // kick off an asynchronous read
    fn start_read(&mut self) -> Result<(),WinError> {
        println!("start_read");

        // If we already have a read in flight, we're done
        if self.state.get() == ServerState::ReadInProgress {
            return Ok(());
        }

        println!("state in start_read: {:?}", self.state.get());
        assert!(self.state.get() == ServerState::Connected);

        unsafe {
            let mut buf = self.read_buf.borrow_mut();
            let mut ov = self.ov.borrow_mut();
            reset_overlapped(ov.deref_mut());

            // if the buffer is full, add more space
            if buf.capacity() == buf.len() {
                let more =
                    if buf.capacity() == 0 { READ_BUFFER_SIZE }
                    else if buf.capacity() < READ_BUFFER_MAX_GROWTH { buf.capacity() }
                    else { READ_BUFFER_MAX_GROWTH };
                buf.reserve(more);
            }

            let buf_ptr = buf.deref_mut().as_mut_ptr() as winapi::LPVOID;
            let mut bytes_read: u32 = 0;
            let ok = kernel32::ReadFile(self.handle.as_win(),
                                        buf_ptr.offset(buf.len() as isize),
                                        (buf.capacity() - buf.len()) as u32,
                                        &mut bytes_read,
                                        //ptr::null_mut(),
                                        ov.deref_mut());
            if ok == winapi::TRUE {
                // the read completed synchronously, because windows
                let new_size = buf.len() + bytes_read as usize;
                buf.set_len(new_size);
                self.last_read_size.set(bytes_read);
                self.state.set(ServerState::ReadComplete);
            } else {
                if GetLastError() != winapi::ERROR_IO_PENDING {
                    return Err(WinError::last("ReadFile"));
                }
                self.state.set(ServerState::ReadInProgress);
            }
        }

        Ok(())
    }

    // Finish reading into self.read_buf. Returns true
    // if a read actually happened; false if it's still in progress.
    fn finish_read(&mut self, block: bool) -> Result<bool,WinError> {
        println!("finish_read (cur state {:?})", self.state.get());

        if self.state.get() == ServerState::ReadComplete {
            // or previous read start actually completed synchronously; just
            // report success or failure here
            self.state.set(ServerState::Connected);
            return Ok((self.last_read_size.get() != 0));
        }

        assert!(self.state.get() == ServerState::ReadInProgress);

        unsafe {
            let mut ov = self.ov.borrow_mut();
            let mut bytes_read: u32 = 0;
            let ok = kernel32::GetOverlappedResult(self.handle.as_win(), ov.deref_mut(), &mut bytes_read, block as i32);
            if ok == 0 {
                match GetLastError() {
                    winapi::ERROR_IO_INCOMPLETE =>
                        return Ok(false),
                    winapi::ERROR_BROKEN_PIPE => {
                        println!("finish_read GetOverlappedResult -> BROKEN_PIPE!");
                        //self.state.set(ServerState::Disconnected);
                        return Ok(false);
                    },
                    _ =>
                        return Err(WinError::last("GetOverlappedResult"))
                }
            }

            let mut buf = self.read_buf.borrow_mut();
            let new_size = buf.len() + bytes_read as usize;
            buf.set_len(new_size);

            println!("finish_read: read {} bytes -- total {}", bytes_read, buf.len());
            self.state.set(ServerState::Connected);
            Ok((bytes_read != 0))
        }
    }

    unsafe fn do_read(&mut self, block: bool) -> Result<OsIpcSelectionResult,WinError> {
        println!("do_read (block {})", block);

        if self.state.get() == ServerState::Disconnected {
            return Ok(OsIpcSelectionResult::ChannelClosed(self.handle.as_win() as i64));
        }

        // read until we get the expected number of bytes
        let mut do_block = block;
        let mut read_header: bool = false;
        const HEADER_SIZE: usize = 8*2;
        let mut bytes_to_read: usize = HEADER_SIZE; // this is the minimum number of bytes we need to read

        let mut data_bytes: usize = 0;
        let mut oob_bytes: usize = 0;

        while self.read_buf.borrow().len() < bytes_to_read {
            try!(self.start_read());
            if try!(self.finish_read(do_block)) == false {
                // If we're doing a nonblocking read and we didn't read anything, we're done;
                // if we started reading a message, then do blocking reads until we finish.
                if self.read_buf.borrow().len() == 0 {
                    assert!(!block);
                    return Ok(OsIpcSelectionResult::DataReceived(self.handle.as_win() as i64, vec![], vec![], vec![]));
                }

                do_block = true;
            }

            // if we're just reading the header for the first time
            if !read_header && self.read_buf.borrow().len() >= HEADER_SIZE {
                let buf = self.read_buf.borrow();
                let np = slice::from_raw_parts(buf.as_ptr() as *const usize, 2);
                data_bytes = np[0];
                oob_bytes = np[1];

                bytes_to_read = HEADER_SIZE + data_bytes + oob_bytes;
                read_header = true;
            }
        }

        // Sweet, we got a buffer
        let mut buf = self.read_buf.borrow_mut();
        assert!(buf.len() == HEADER_SIZE + data_bytes + oob_bytes);

        let buf_header = slice::from_raw_parts(buf.as_ptr().offset(0) as *const usize, 2);
        let buf_data = slice::from_raw_parts(buf.as_ptr().offset(HEADER_SIZE as isize), data_bytes);
        let buf_oob = slice::from_raw_parts(buf.as_ptr().offset((HEADER_SIZE + data_bytes) as isize), oob_bytes);

        let mut channels: Vec<OsOpaqueIpcChannel> = vec![];
        let mut shmems: Vec<OsIpcSharedMemory> = vec![];
        
        if oob_bytes > 0 {
            // deserialize
            let mut msg: OsIpcOutOfBandMessage = match bincode::serde::deserialize(&buf_oob) {
                Ok(m) => m,
                Err(err) => return Err(WinError(0xffffffffu32))
            };

            // play with handles!
            for ch_handle in &mut msg.channel_handles {
                channels.push(OsOpaqueIpcChannel::from_opaque(ch_handle));
            }

            // XXX fix shmems
        }

        // truncate the read buffer back to 0
        buf.truncate(0);

        Ok(OsIpcSelectionResult::DataReceived(self.handle.as_win() as i64, buf_data.to_vec(), channels, shmems))
    }

    fn recv(&mut self)
                -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),WinError> {
        println!("server recv");
        if try!(self.finish_accept(true)) == false {
            return Err(WinError::last("blocking accept returned false?"));
        }

        unsafe {
            match try!(self.do_read(true)) {
                OsIpcSelectionResult::DataReceived(_, a, b, c) => Ok((a, b, c)),
                OsIpcSelectionResult::ChannelClosed(_) => Err(WinError::last("Channel closed?")),
            }
        }
    }
}

#[derive(Debug)]
pub struct OsIpcReceiver {
    // the ID of this pipe
    pipe_id: Uuid,

    // servers
    servers: RefCell<Mutex<Vec<NamedPipeServer>>>,
}


unsafe impl Send for OsIpcReceiver { }
unsafe impl Sync for OsIpcReceiver { }

impl PartialEq for OsIpcReceiver {
    fn eq(&self, other: &OsIpcReceiver) -> bool {
        // XXX it should be enough to check
        self.pipe_id == other.pipe_id
        //self.servers == other.servers
    }
}

impl OsIpcReceiver {
    fn new() -> Result<OsIpcReceiver,WinError> {
        let pipe_id = make_pipe_id();
        OsIpcReceiver::from_id(&pipe_id)
    }

    fn sender(&mut self) -> Result<OsIpcSender,WinError> {
        OsIpcSender::connect_pipe_id(self.pipe_id)
    }

    fn from_id(pipe_id: &Uuid) -> Result<OsIpcReceiver,WinError> {
        unsafe {
            let mut server = try!(NamedPipeServer::from_id(&pipe_id));

            // first instance of this pipe_id, so keep w
            try!(server.start_accept());

            let rec = OsIpcReceiver {
                pipe_id: *pipe_id,
                servers: RefCell::new(Mutex::new(vec![server])),
            };

            Ok(rec)
        }
    }

    pub fn consume(&self) -> OsIpcReceiver {
        println!("consume is broken!");
        // XXX we need to dup all our handles over to the new one
        OsIpcReceiver::from_id(&self.pipe_id).unwrap()
    }

    pub fn what_the_fuck(&self, block: bool)
                         -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),WinError> {
        unsafe {
            // let's collect all the handles
            let mut server_borrow = self.servers.borrow_mut();
            let mut servers = server_borrow.lock().unwrap();
            let mut handles = servers.iter().map(|ref s| s.wait_handle()).collect::<Vec<HANDLE>>();

            // MAX_WAIT_HANDLES
            assert!(handles.len() <= 64);
            let timeout = if block { winapi::INFINITE } else { 0 };
            let rv = kernel32::WaitForMultipleObjects(handles.len() as u32,
                                                      handles.as_ptr(),
                                                      winapi::FALSE,
                                                      timeout);
            if rv >= 0 && rv < handles.len() as u32 {
                let ref mut server = servers[rv as usize];
                server.recv()
            } else if rv == winapi::WAIT_TIMEOUT {
                assert!(!block);
                Ok((vec![], vec![], vec![]))
            } else {
                assert!(rv == winapi::WAIT_FAILED);
                Err(WinError::last("WaitForMultipleObjects"))
            }
        }
    }

    pub fn recv(&self)
                -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),WinError> {
        println!("recv");
        self.what_the_fuck(true)
    }

    pub fn try_recv(&self)
                    -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),WinError> {
        println!("try_recv");
        self.what_the_fuck(false)
    }
}

#[derive(Debug, PartialEq)]
struct WinHandle {
    h: HANDLE
}

unsafe impl Send for WinHandle { }
unsafe impl Sync for WinHandle { }

impl Drop for WinHandle {
    fn drop(&mut self) {
        unsafe {
            if self.valid() {
                kernel32::CloseHandle(self.h);
            }
        }
    }
}

impl Default for WinHandle {
    fn default() -> WinHandle {
        WinHandle { h: INVALID_HANDLE_VALUE }
    }
}

impl WinHandle {
    fn new(h: HANDLE) -> WinHandle {
        WinHandle { h: h }
    }

    fn valid(&self) -> bool {
        self.h != INVALID_HANDLE_VALUE
    }

    fn as_win(&self) -> HANDLE {
        self.h
    }
}

#[derive(Debug)]
pub struct OsIpcSender {
    pipe_id: Uuid,
    handle: RefCell<Arc<WinHandle>>,
}

unsafe impl Send for OsIpcSender { }
unsafe impl Sync for OsIpcSender { }

impl PartialEq for OsIpcSender {
    fn eq(&self, other: &OsIpcSender) -> bool {
        self.pipe_id == other.pipe_id &&
        self.handle == other.handle
    }
}

impl Clone for OsIpcSender {
    fn clone(&self) -> OsIpcSender {
        println!("Sender CLONE!");
        OsIpcSender::connect_pipe_id(self.pipe_id).unwrap()
    }
}

impl OsIpcSender {
    fn connect_pipe_id(pipe_id: Uuid) -> Result<OsIpcSender,WinError> {
        let mut result = OsIpcSender {
            pipe_id: pipe_id,
            handle: RefCell::new(Arc::new(WinHandle::default())),
        };

        try!(result.connect_to_server());

        Ok(result)
    }

    pub fn connect(name: String) -> Result<OsIpcSender,WinError> {
        OsIpcSender::connect_pipe_id(Uuid::parse_str(&name).unwrap())
    }

    // Connect to a pipe server
    fn connect_to_server(&self) -> Result<(),WinError> {
        println!("> connect_to_server");
        unsafe {
            let pipe_name = make_pipe_name(&self.pipe_id);
            let handle =
                kernel32::CreateFileA(pipe_name.as_ptr(),
                                      winapi::GENERIC_WRITE,
                                      0,
                                      ptr::null_mut(), // lpSecurityAttributes
                                      winapi::OPEN_EXISTING,
                                      winapi::FILE_ATTRIBUTE_NORMAL,
                                      ptr::null_mut());
            if handle == INVALID_HANDLE_VALUE {
                return Err(WinError::last("CreateFileA"));
            }
            // XXX - if I write this as the below, it causes a segfault.
            // But only on the command line.  Debug this once we figure out wtf.
            //*self.handle.borrow_mut() = Arc::new(WinHandle::new(handle));
            // This way works:
            let k = Arc::new(WinHandle::new(handle));
            *self.handle.borrow_mut() = k;

            println!("< connect_to_server success (handle {:?})", handle);
        }

        Ok(())
    }

    pub fn send(&self,
                in_data: &[u8],
                ports: Vec<OsIpcChannel>,
                shared_memory_regions: Vec<OsIpcSharedMemory>)
                -> Result<(),WinError> {
        // XXX we have to make a copy of the data here because we're going
        // to use a thread to do the write.  This isn't ideal.
        let data = in_data.to_vec();
        let wh = self.handle.borrow().clone();

        thread::spawn(move || {
            unsafe {
                let channel_handles: Vec<OsIpcChannelHandle> = vec![];
                let shmem_sizes: Vec<u64> = vec![];
                let shmem_handles: Vec<intptr_t> = vec![];

                let mut header: Vec<usize> = vec![0; 2];
                let mut oob_data: Vec<u8> = vec![];

                if channel_handles.len() > 0 || shmem_handles.len() > 0 {
                    let msg = OsIpcOutOfBandMessage {
                        channel_handles: channel_handles,
                        shmem_source_pid: kernel32::GetCurrentProcessId(),
                        shmem_sizes: shmem_sizes,
                        shmem_handles: shmem_handles,
                    };

                    oob_data = bincode::serde::serialize(&msg, bincode::SizeLimit::Infinite).unwrap();
                }

                header[0] = data.len();
                header[1] = oob_data.len();

                unsafe fn write_buf(handle: HANDLE, bytes: &[u8]) -> Result<(),WinError> {
                    let mut ntowrite: u32 = bytes.len() as u32;
                    if ntowrite == 0 {
                        return Ok(());
                    }
                    let mut nwritten: u32 = 0;
                    let bytesptr = bytes.as_ptr() as *mut c_void;
                    while nwritten < ntowrite {
                        let mut nwrote: u32 = 0;
                        if kernel32::WriteFile(handle,
                                               bytesptr.offset(nwritten as isize),
                                               ntowrite,
                                               &mut nwrote,
                                               ptr::null_mut())
                            == winapi::FALSE
                        {
                            // this will println!
                            return Err(WinError::last("WriteFile"));
                        }
                        nwritten += nwrote;
                        ntowrite -= nwrote;
                        println!("Just wrote {} bytes, left {}/{} err {}", nwrote, nwritten, bytes.len(), GetLastError());
                    }
                    Ok(())
                }

                let handle = wh.as_win();
                let header_bytes = slice::from_raw_parts(header.as_ptr() as *const u8, 16);
                if write_buf(handle, &header_bytes).is_err() {
                    return;
                }
                if write_buf(handle, &data).is_err() {
                    return;
                }
                if write_buf(handle, &oob_data).is_err() {
                    return;
                }
            }
        });

        Ok(())
    }
}

pub struct OsIpcReceiverSet {
    // the set of receivers in this set
    receivers: Vec<OsIpcReceiver>,
    // the connection OVERLAPPED events
    receiver_connect_handles: Vec<HANDLE>,
}

pub enum OsIpcSelectionResult {
    DataReceived(i64, Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),
    ChannelClosed(i64),
}

impl OsIpcReceiverSet {
    pub fn new() -> Result<OsIpcReceiverSet,WinError> {
        Ok(OsIpcReceiverSet {
            receivers: vec![],
            receiver_connect_handles: vec![],
        })
    }

    pub fn add(&mut self, receiver: OsIpcReceiver) -> Result<i64,WinError> {
        //self.receiver_connect_handles.push(receiver.handle);
        //self.receivers.push(receiver);

        // XXX wtf does this return signify? The other impls just return the
        // fd/mach port as an i64, but we don't have a single one; so just
        // return the current len of receivers?
        Ok(self.receivers.len() as i64)
    }

    pub fn select(&mut self) -> Result<Vec<OsIpcSelectionResult>,WinError> {
        assert!(self.receivers.len() > 0, "selecting with no objects?");
        assert!(self.receivers.len() < winapi::MAXIMUM_WAIT_OBJECTS as usize, "trying to select() with too many handles!");

        unsafe {
            // the reciever_connect_handles array can only be added to, not removed from
            let index = kernel32::WaitForMultipleObjectsEx(self.receiver_connect_handles.len() as u32,
                                                           self.receiver_connect_handles.as_mut_ptr(),
                                                           winapi::FALSE,
                                                           winapi::INFINITE,
                                                           winapi::FALSE);

            if index as usize >= self.receiver_connect_handles.len() {
                return Err(WinError::last(&format!("WaitForMultipleObjectsEx returned {}", index)));
            }

            let receiver = &self.receivers[index as usize];
            /*
            match receiver.do_read(false) {
                Ok(r) => Ok(vec![r]),
                Err(err) => Err(err)
        }*/
            Ok(vec![])
        }
    }
}

impl OsIpcSelectionResult {
    pub fn unwrap(self) -> (i64, Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>) {
        match self {
            OsIpcSelectionResult::DataReceived(id, data, channels, shared_memory_regions) => {
                (id, data, channels, shared_memory_regions)
            }
            OsIpcSelectionResult::ChannelClosed(id) => {
                panic!("OsIpcSelectionResult::unwrap(): receiver ID {} was closed!", id)
            }
        }
    }
}

pub struct OsIpcSharedMemory {
    handle: HANDLE,
    ptr: *mut u8,
    length: usize,
}

unsafe impl Send for OsIpcSharedMemory {}
unsafe impl Sync for OsIpcSharedMemory {}

impl Drop for OsIpcSharedMemory {
    fn drop(&mut self) {
    }
}

impl Clone for OsIpcSharedMemory {
    fn clone(&self) -> OsIpcSharedMemory {
        OsIpcSharedMemory {
            handle: self.handle,
            ptr: self.ptr,
            length: self.length,
        }
    }
}

impl PartialEq for OsIpcSharedMemory {
    fn eq(&self, other: &OsIpcSharedMemory) -> bool {
        **self == **other
    }
}

impl Debug for OsIpcSharedMemory {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), fmt::Error> {
        (**self).fmt(formatter)
    }
}

impl Deref for OsIpcSharedMemory {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        if self.ptr.is_null() {
            panic!("attempted to access a consumed `OsIpcSharedMemory`")
        }
        unsafe {
            slice::from_raw_parts(self.ptr, self.length)
        }
    }
}

unsafe fn allocate_vm_pages(length: usize) -> *mut u8 {
    let address = 0;
    address as *mut u8
}

impl OsIpcSharedMemory {
    fn from_handle(handle: HANDLE, size: usize) -> OsIpcSharedMemory {
        OsIpcSharedMemory {
            handle: handle,
            length: size,
            ptr: ptr::null_mut(),
        }
    }

    unsafe fn from_raw_parts(ptr: *mut u8, length: usize) -> OsIpcSharedMemory {
        OsIpcSharedMemory {
            ptr: ptr,
            length: length,
            handle: INVALID_HANDLE_VALUE,
        }
    }

    pub fn from_byte(byte: u8, length: usize) -> OsIpcSharedMemory {
        unsafe {
            let address = allocate_vm_pages(length);
            ptr::write_bytes(address, byte, length);
            OsIpcSharedMemory::from_raw_parts(address, length)
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> OsIpcSharedMemory {
        unsafe {
            let address = allocate_vm_pages(bytes.len());
            ptr::copy_nonoverlapping(bytes.as_ptr(), address, bytes.len());
            OsIpcSharedMemory::from_raw_parts(address, bytes.len())
        }
    }
}

pub struct OsIpcOneShotServer {
    receiver: RefCell<Option<OsIpcReceiver>>,
}

impl OsIpcOneShotServer {
    pub fn new() -> Result<(OsIpcOneShotServer, String),WinError> {
        match OsIpcReceiver::new() {
            Ok(receiver) => {
                let pipe_id = receiver.pipe_id.clone();
                Ok((OsIpcOneShotServer {
                    receiver: RefCell::new(Some(receiver))
                }, pipe_id.to_string()))
            },
            Err(err) => { Err(err) }
        }
    }

    pub fn accept(&self) -> Result<(OsIpcReceiver,
                                    Vec<u8>,
                                    Vec<OsOpaqueIpcChannel>,
                                    Vec<OsIpcSharedMemory>),WinError> {
        let receiver = self.receiver.borrow_mut().take().unwrap();
        let (data, channels, shmems) = try!(receiver.recv());
        Ok((receiver, data, channels, shmems))
    }
}

pub enum OsIpcChannel {
    Sender(OsIpcSender),
    Receiver(OsIpcReceiver),
}

impl OsIpcChannel {
}

#[derive(PartialEq, Debug)]
pub struct OsOpaqueIpcChannel {
    is_sender: bool,
    pipe_id: Uuid,
}

impl OsOpaqueIpcChannel {
    fn from_opaque(hh: &OsIpcChannelHandle) -> OsOpaqueIpcChannel {
        OsOpaqueIpcChannel {
            is_sender: hh.sender,
            pipe_id: hh.pipe_id,
        }
    }

    pub fn to_receiver(&self) -> OsIpcReceiver {
        assert!(!self.is_sender);
        OsIpcReceiver::from_id(&self.pipe_id).unwrap()
    }

    pub fn to_sender(&self) -> OsIpcSender {
        assert!(self.is_sender);
        OsIpcSender::connect_pipe_id(self.pipe_id).unwrap()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct WinError(pub u32);

impl WinError {
    pub fn error_string(errnum: u32) -> String {
        // This value is calculated from the macro
        // MAKELANGID(LANG_SYSTEM_DEFAULT, SUBLANG_SYS_DEFAULT)
        let lang_id = 0x0800 as winapi::DWORD;
        let mut buf = [0 as winapi::WCHAR; 2048];

        unsafe {
            let res = kernel32::FormatMessageW(winapi::FORMAT_MESSAGE_FROM_SYSTEM |
                                               winapi::FORMAT_MESSAGE_IGNORE_INSERTS,
                                               ptr::null_mut(),
                                               errnum as winapi::DWORD,
                                               lang_id,
                                               buf.as_mut_ptr(),
                                               buf.len() as winapi::DWORD,
                                               ptr::null_mut()) as usize;
            if res == 0 {
                // Sometimes FormatMessageW can fail e.g. system doesn't like lang_id,
                let fm_err = kernel32::GetLastError();
                return format!("OS Error {} (FormatMessageW() returned error {})",
                               errnum, fm_err);
            }

            match String::from_utf16(&buf[..res]) {
                Ok(mut msg) => {
                    // Trim trailing CRLF inserted by FormatMessageW
                    let len = msg.trim_right().len();
                    msg.truncate(len);
                    msg
                },
                Err(..) => format!("OS Error {} (FormatMessageW() returned \
                                    invalid UTF-16)", errnum),
            }
        }
    }

    fn from_system(err: u32, f: &str) -> WinError {
        println!("WinError: {} ({}) from {}", WinError::error_string(err), err, f);
        WinError(err)
    }

    fn last(f: &str) -> WinError {
        unsafe {
            WinError::from_system(GetLastError(), f)
        }
    }

    #[allow(dead_code)]
    pub fn channel_is_closed(&self) -> bool {
        self.0 == winapi::ERROR_HANDLE_EOF
    }
}

impl From<WinError> for DeserializeError {
    fn from(mpsc_error: WinError) -> DeserializeError {
        DeserializeError::IoError(mpsc_error.into())
    }
}

impl From<WinError> for Error {
    fn from(mpsc_error: WinError) -> Error {
        //Error::new(ErrorKind::Other, format!("Win channel error ({} from {})", mpsc_error.0, mpsc_error.1))
        Error::new(ErrorKind::Other, format!("Win channel error ({})", mpsc_error.0))
    }
}
