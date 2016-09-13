// Copyright 2015 The Servo Project Developers. See the COPYRIGHT
// file at the top-level directory of this distribution.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use bincode::serde::DeserializeError;
use std::mem;
use std::cmp::{PartialEq};
use std::io::{Error, ErrorKind};
use std::fmt::{self, Debug, Formatter};
use std::ops::Deref;
use std::ptr;
use std::slice;
use std::cell::{Cell, RefCell};
use std::ops::DerefMut;
use std::ffi::CString;
use std::sync::{Arc, Mutex};
use std::marker::{Send, Sync};
use std::os::raw::c_void;

use libc::{c_char, intptr_t};

use uuid::Uuid;
use bincode;
use serde::ser::Serialize;

use winapi;
use winapi::{HANDLE, INVALID_HANDLE_VALUE};
use kernel32;
use kernel32::{GetLastError};
use user32;

const INVALID_PID: u32 = 0xffffffffu32;
const READ_BUFFER_SIZE: u32 = 8192;
const NMPWAIT_WAIT_FOREVER: u32 = 0xffffffffu32;
const NMPWAIT_NOWAIT: u32 = 0x1u32;

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

#[derive(Serialize, Deserialize, Debug)]
struct OsIpcMessage {
    data: Vec<u8>,
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

fn safe_close_handle_cell(handle: &Cell<HANDLE>) -> () {
    unsafe {
        if handle.get() != INVALID_HANDLE_VALUE {
            kernel32::CloseHandle(handle.get());
            handle.set(INVALID_HANDLE_VALUE);
        }
    }
}

// duplicate a given handle in the source process to this one, closing it in the source process
fn take_handle_from_process(handle: HANDLE, source_pid: u32) -> Result<HANDLE,WinError> {
    unsafe {
        let mut newh: HANDLE = INVALID_HANDLE_VALUE;
        let mut other_process: HANDLE = kernel32::OpenProcess(winapi::PROCESS_DUP_HANDLE, winapi::FALSE, source_pid);
        if other_process == INVALID_HANDLE_VALUE {
            return Err(WinError::last("OpenProcess"));
        }

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
fn dup_handle_for_process(handle: HANDLE, target_pid: u32) -> Result<HANDLE,WinError> {
    unsafe {
        let mut newh: HANDLE = INVALID_HANDLE_VALUE;
        let mut other_process: HANDLE = kernel32::OpenProcess(winapi::PROCESS_DUP_HANDLE, winapi::FALSE, target_pid);
        if other_process == INVALID_HANDLE_VALUE {
            return Err(WinError::last("OpenProcess"));
        }

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
        let ev = kernel32::CreateEventA(ptr::null_mut(), winapi::FALSE, winapi::FALSE, ptr::null_mut());
        assert!(ev != INVALID_HANDLE_VALUE);
        RefCell::new(winapi::OVERLAPPED {
            Internal: 0,
            InternalHigh: 0,
            Offset: 0,
            OffsetHigh: 0,
            hEvent: ev
        })
    }
}


#[derive(Debug)]
pub struct OsIpcReceiver {
    // the ID of this pipe
    pipe_id: Uuid,

    // the name of the pipe, constructed from the Uuid
    pipe_name: CString,

    // The handle to the current server end of a named pipe
    handle: HANDLE,
}


unsafe impl Send for OsIpcReceiver { }
unsafe impl Sync for OsIpcReceiver { }

impl PartialEq for OsIpcReceiver {
    fn eq(&self, other: &OsIpcReceiver) -> bool {
        self.pipe_id == other.pipe_id &&
        self.pipe_name == other.pipe_name &&
        self.handle == other.handle
    }
}

impl Drop for OsIpcReceiver {
    fn drop(&mut self) {
        unsafe {
            kernel32::CloseHandle(self.handle);
        }
    }
}

impl OsIpcReceiver {
    fn from_id(pipe_id: Uuid) -> Result<OsIpcReceiver,WinError> {
        unsafe {
            let pipe_name = make_pipe_name(&pipe_id);

            // create the pipe server
            let hserver =
                kernel32::CreateNamedPipeA(pipe_name.as_ptr(),
                                           winapi::PIPE_ACCESS_DUPLEX,
                                           winapi::PIPE_TYPE_BYTE | winapi::PIPE_READMODE_BYTE | winapi::PIPE_NOWAIT,
                                           winapi::PIPE_UNLIMITED_INSTANCES | winapi::PIPE_REJECT_REMOTE_CLIENTS,
                                           4096, 4096, // out/in buffer sizes
                                           0, // default timeout
                                           ptr::null_mut());
            if hserver == INVALID_HANDLE_VALUE {
                return Err(WinError::last("CreateNamedPipeA"));
            }

            let mut rec = OsIpcReceiver {
                handle: hserver,
                pipe_id: pipe_id,
                pipe_name: pipe_name,
            };

            Ok(rec)
        }
    }

    fn new() -> Result<OsIpcReceiver,WinError> {
        let pipe_id = make_pipe_id();
        OsIpcReceiver::from_id(pipe_id)
    }

    unsafe fn do_read(&self) -> Result<OsIpcSelectionResult,WinError> {
        println!("do_read");
        // optimistically allocate the read buffer
        let mut buf: Vec<u8> = Vec::with_capacity(READ_BUFFER_SIZE as usize);
        let mut channel_closed: bool = false;
        let mut bytes_read: u32 = 0;

        loop {
            let dest_ptr = buf.as_mut_ptr() as winapi::LPVOID;
            let mut ok = kernel32::ReadFile(self.handle,
                                            dest_ptr.offset(buf.len() as isize),
                                            (buf.capacity() - buf.len()) as u32,
                                            &mut bytes_read,
                                            ptr::null_mut());
            if ok == winapi::TRUE {
                let new_size = buf.len() + bytes_read as usize;
                buf.set_len(new_size);
                println!("ReadFile read {} bytes -- total {}", bytes_read, buf.len());

                // we could have read more, but we didn't; assume done
                if buf.len() < buf.capacity() {
                    break;
                }

                // extend and grow
                let len = buf.capacity();
                buf.reserve(len);
            } else {
                // Now handle real errors
                let mut err = GetLastError();

                // Was the pipe closed?
                if err == winapi::ERROR_HANDLE_EOF || err == winapi::ERROR_BROKEN_PIPE {
                    channel_closed = true;
                    break;
                }

                // Something actually failed for real
                return Err(WinError::from_system(err, "ReadFile"));
            }
        }

        // Hey, the read actually succeeded!

        // XXX we may want to avoid this shrink to fit since we're
        // just going to deserialize and throw this away soon anyway
        buf.shrink_to_fit();

        // if channel_closed:
        // return Ok(OsIpcSelectionResult::ChannelClosed(self.handle as i64));
        // We now have a complete message in buf! Amazing. \o/

        // deserialize!
        let mut msg: OsIpcMessage = match bincode::serde::deserialize(&buf) {
            Ok(m) => m,
            Err(err) => return Err(WinError(0xffffffffu32))
        };

        let mut channels: Vec<OsOpaqueIpcChannel> = vec![];
        let mut shmems: Vec<OsIpcSharedMemory> = vec![];
        
        // play with handles!
        for ch_handle in &mut msg.channel_handles {
            channels.push(OsOpaqueIpcChannel::from_opaque(ch_handle));
        }

        // XXX fix shmems

        Ok(OsIpcSelectionResult::DataReceived(self.handle as i64, msg.data, channels, shmems))
    }

    // This is called when we know we have a connection ready; we're going to
    // connect, read, and close all in one go.
    fn do_read_transaction(&self) -> Result<OsIpcSelectionResult, WinError>
    {
        //assert!(self.connection_ready());
        println!("do_read_transaction");
        unsafe {
            let mut ok = kernel32::ConnectNamedPipe(self.handle, ptr::null_mut());

            // if we're in do_read_transaction, we should already know we have
            // a connected client
            //assert!(ok == winapi::FALSE && kernel32::GetLastError() == winapi::ERROR_PIPE_CONNECTED);

            let result = self.do_read();

            // close!
            ok = kernel32::DisconnectNamedPipe(self.handle);
            if ok == winapi::FALSE {
                return Err(WinError::last("DisconnectNamedPipe"));
            }

            result
        }
    }

    // This function connects the server end of a named pipe, and starts it
    // listening for a connection using CreateFile, and returns th
    fn try_accept(&self) -> Result<bool,WinError> {
        unsafe {
            println!("try_accept");
            let ok = kernel32::ConnectNamedPipe(self.handle, ptr::null_mut());
            let err = kernel32::GetLastError();
            println!("ConnectNamedPipe: ok {}, err {}", ok, err);
            if ok == winapi::FALSE &&
                (err == winapi::ERROR_PIPE_CONNECTED || err == winapi::ERROR_NO_DATA) {
                return Ok(true);
            }

            if ok == winapi::TRUE || err == winapi::ERROR_PIPE_LISTENING {
                return Ok(false);
            }

            return Err(WinError::from_system(err, "ConnectNamedPipe"));
        }
    }

    fn wait_accept(&self) -> Result<(),WinError> {
        unsafe {
            println!("wait_accept");
            let mut mode: u32 = winapi::PIPE_WAIT;
            let mut ok: i32;

            ok = kernel32::SetNamedPipeHandleState(self.handle, &mut mode, ptr::null_mut(), ptr::null_mut());
            if ok == winapi::FALSE {
                return Err(WinError::last("SetNamedPipeHandleState"));
            }

            ok = kernel32::ConnectNamedPipe(self.handle, ptr::null_mut());
            if ok == winapi::FALSE {
                // XXX should we put the pipe state baack to NOWAIT, or is this
                // error going to be fatal?
                return Err(WinError::last("ConnectNamedPipe"));
            }

            mode = winapi::PIPE_NOWAIT;
            ok = kernel32::SetNamedPipeHandleState(self.handle, &mut mode, ptr::null_mut(), ptr::null_mut());
            if ok == winapi::FALSE {
                return Err(WinError::last("SetNamedPipeHandleState"));
            }

            Ok(())
        }
    }

    fn sender(&mut self) -> Result<OsIpcSender,WinError> {
        OsIpcSender::connect_pipe_id(self.pipe_id)
    }

    pub fn consume(&self) -> OsIpcReceiver {
        // we should probably close self.handle etc.
        // and create an entirely new pipe; just
        // OsIpcReceiver::from_id(self.pipe_id)
        OsIpcReceiver {
            handle: self.handle,
            pipe_id: self.pipe_id,
            pipe_name: self.pipe_name.clone(),
        }
    }

    pub fn recv(&self)
                -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),WinError> {
        unsafe {
            println!("recv");
            if let Err(error) = self.wait_accept() {
                return Err(error)
            }

            match self.do_read_transaction() {
                Ok(r) => match r {
                    OsIpcSelectionResult::DataReceived(_, a, b, c) => Ok((a, b, c)),
                    OsIpcSelectionResult::ChannelClosed(_) => Err(WinError::last("Channel closed?")),
                },
                Err(err) => Err(err)
            }
        }
    }

    pub fn try_recv(&self)
                    -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),WinError> {
        println!("try_recv");
        match self.try_accept() {
            // something connected? good, receive
            Ok(true) => self.recv(),
            // nothing connected? empty!
            Ok(false) => Ok((vec![], vec![], vec![])),
            // error? error!
            Err(error) => Err(error)
        }
    }
}

#[derive(Debug)]
pub struct OsIpcSender {
    pipe_id: Uuid,
    pipe_name: CString,
}

unsafe impl Send for OsIpcSender { }
unsafe impl Sync for OsIpcSender { }

impl PartialEq for OsIpcSender {
    fn eq(&self, other: &OsIpcSender) -> bool {
        self.pipe_id == other.pipe_id &&
        self.pipe_name == other.pipe_name
    }
}

impl Clone for OsIpcSender {
    fn clone(&self) -> OsIpcSender {
        OsIpcSender::connect_pipe_id(self.pipe_id).unwrap()
    }
}

impl OsIpcSender {
    fn connect_pipe_id(pipe_id: Uuid) -> Result<OsIpcSender,WinError> {
        Ok(OsIpcSender {
            pipe_id: pipe_id,
            pipe_name: make_pipe_name(&pipe_id),
        })
    }

    pub fn connect(name: String) -> Result<OsIpcSender,WinError> {
        OsIpcSender::connect_pipe_id(Uuid::parse_str(&name).unwrap())
    }

    pub fn send(&self,
                data: &[u8],
                ports: Vec<OsIpcChannel>,
                shared_memory_regions: Vec<OsIpcSharedMemory>)
                -> Result<(),WinError> {
        unsafe {
            let channel_handles: Vec<OsIpcChannelHandle> = vec![];
            let shmem_sizes: Vec<u64> = vec![];
            let shmem_handles: Vec<intptr_t> = vec![];
            let mut ok: i32 = 0;

            let msg = OsIpcMessage {
                data: data.to_vec(),
                channel_handles: channel_handles,
                shmem_source_pid: kernel32::GetCurrentProcessId(),
                shmem_sizes: shmem_sizes,
                shmem_handles: shmem_handles
            };

            let bytes = bincode::serde::serialize(&msg, bincode::SizeLimit::Infinite).unwrap();

            // 64k is the max size that is guaranteed to be able to be sent in a single transaction
            // ... but we're not using CallNamedPipe
            //assert!(bytes.len() < (64 * 1024));

            let h =
                kernel32::CreateFileA(self.pipe_name.as_ptr(),
                                      winapi::GENERIC_WRITE,
                                      0,
                                      ptr::null_mut(), // lpSecurityAttributes
                                      winapi::OPEN_EXISTING,
                                      winapi::FILE_ATTRIBUTE_NORMAL,
                                      ptr::null_mut());
            if h == INVALID_HANDLE_VALUE {
                return Err(WinError::last("CreateFileA"));
            }

            let mut mode: u32 = winapi::PIPE_WAIT;
            ok = kernel32::SetNamedPipeHandleState(h, &mut mode, ptr::null_mut(), ptr::null_mut());
            if ok == winapi::FALSE {
                return Err(WinError::last("SetNamedPipeHandleState"));
            }

            // XXX this is ridiculous, having to write a separate u32
            // just to represent to size of the message is *ugh*.  We can't
            // use message mode, because there's a 64k limit to message size
            // 

            let mut nwritten: u32 = 0;
            let mut ntowrite: u32 = bytes.len() as u32;
            let bytesptr = bytes.as_ptr() as *mut c_void;
            while nwritten < ntowrite {
                let mut nwrote: u32 = 0;
                if kernel32::WriteFile(h,
                                       bytesptr.offset(nwritten as isize),
                                       ntowrite,
                                       &mut nwrote,
                                       ptr::null_mut())
                    == winapi::FALSE
                {
                    return Err(WinError::last("WriteFile"));
                }
                nwritten += nwrote;
                ntowrite -= nwrote;
                println!("Just wrote {} bytes, left {}/{} err {}", nwrote, nwritten, bytes.len(), GetLastError());
            }

            // aaand disconnect
            kernel32::CloseHandle(h);
        }

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
        self.receiver_connect_handles.push(receiver.handle);
        self.receivers.push(receiver);

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
            match receiver.do_read_transaction() {
                Ok(r) => Ok(vec![r]),
                Err(err) => Err(err)
            }
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
        unsafe {
            let mut receiver = self.receiver.borrow_mut().take().unwrap();
            let (data, channels, shmems) = try!(receiver.recv());
            Ok((receiver, data, channels, shmems))
        }
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
        OsIpcReceiver::from_id(self.pipe_id).unwrap()
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
