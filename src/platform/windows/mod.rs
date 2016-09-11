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

pub fn channel() -> Result<(OsIpcSender, OsIpcReceiver),WinError> {
    let mut receiver = try!(OsIpcReceiver::new());
    let sender = try!(receiver.sender());
    Ok((sender, receiver))
}

#[derive(Serialize, Deserialize, Debug)]
struct OsIpcChannelHandle {
    // we always send the pipe_id
    pipe_id: Uuid,
    // If its a receiver, we also send along all of its existing
    // receive handles.  If this is None, then it's a sender.
    receiver: Option<Vec<intptr_t>>
}

#[derive(Serialize, Deserialize, Debug)]
struct OsIpcMessage {
    data: Vec<u8>,
    // channel handles -- array of handles,
    // stored as intptr_t so we can ser/de them
    channel_handles: Vec<OsIpcChannelHandle>,
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

// On Windows, each pipe is a single sender/receiver pair.  There is
// no way to receieve from multiple senders on a single receiver
// handle. So if we send a Sender to a client, we need to create a new
// anonymous pipe, which results in a new receiver.  This struct
// represents those handles.

struct OsIpcReceiverInternal {
    // A signalable event handle that will be triggered
    // whenever the handles vector is mutated.  Any
    // WaitForMultipleObjects that include this receiver's
    // handles must wait on this changed_event as well.
    // The set of connected receiver handles
    handles: Vec<HANDLE>,

    // If this is not INVALID_HANDLE_VALUE, there is an IOCP
    // that is waiting on IO on this receiver's handles.
    // Any modifications of the handles array should also add
    // the handles to the IOCP.
    active_iocp: HANDLE,
    
    // The process that this channel (receiver/sender) pair was
    // originally created on.  When we receive a handle on this
    // receiver, the source process handle is always this,
    // regardless of which process sent the message.  Receiving
    // a handle involves duplicating it to the current process
    // with the source process set to the given pid, and
    // the DUPLICATE_CLOSE_SOURCE flag.
    handle_exchange_process_id: u32,

    // The overlapped IO structs, one for each handle
    overlappeds: Vec<winapi::OVERLAPPED>,
}

impl Drop for OsIpcReceiverInternal {
    fn drop(&mut self) {
        unsafe {
            for i in 0..(self.handles.len()-1) {
                kernel32::CancelIoEx(self.handles[i], &mut self.overlappeds[i]);
                kernel32::CloseHandle(self.handles[i]);
                kernel32::CloseHandle(self.overlappeds[i].hEvent);
            }
        }
    }
}

impl Debug for OsIpcReceiverInternal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(OsIpcReceiverInternal)")
    }
}

impl PartialEq for OsIpcReceiverInternal {
    fn eq(&self, other: &OsIpcReceiverInternal) -> bool {
        self.handles == other.handles &&
        self.active_iocp == other.active_iocp &&
        self.handle_exchange_process_id == other.handle_exchange_process_id
    }
}

impl OsIpcReceiverInternal {
    fn new() -> OsIpcReceiverInternal {
        unsafe {
            OsIpcReceiverInternal {
                handles: vec![],
                active_iocp: INVALID_HANDLE_VALUE,
                overlappeds: vec![],
                handle_exchange_process_id: kernel32::GetCurrentProcessId(),
            }
        }
    }

    unsafe fn set_iocp(&mut self, iocp: HANDLE) -> Result<(),WinError> {
        if self.active_iocp == iocp {
            return Ok(());
        }

        let my_handles = self.handles.clone();
        for (index,handle) in my_handles.iter().enumerate() {
            // cancel any outstanding IO operations associated with this
            // OVERLAPPED structure
            kernel32::CancelIoEx(*handle, &mut self.overlappeds[index]);

            // associate the handle with the IOCP
            kernel32::CreateIoCompletionPort(*handle, iocp, *handle as u64, 0);

            // kick off an async read for later completion
            self.start_read(*handle);
        }

        self.active_iocp = iocp;
        Ok(())
    }

    fn find_handle(&self, handle: HANDLE) -> i32 {
        for (index,h) in self.handles.iter().enumerate() {
            if *h == handle {
                return index as i32;
            }
        }
        return -1;
    }

    unsafe fn complete_select(&mut self, ov: &winapi::OVERLAPPED_ENTRY, success: bool, win_err: u32) -> Result<OsIpcSelectionResult,WinError> {
        let handle = ov.lpCompletionKey as HANDLE;
        // XXX need to check for -1 result
        let index = self.find_handle(handle) as usize;
        
        // was the connection closed?
        if !success && win_err == winapi::ERROR_HANDLE_EOF {
            kernel32::CloseHandle(handle);
            self.handles.swap_remove(index);
            self.overlappeds.swap_remove(index);
            return Ok(OsIpcSelectionResult::ChannelClosed(handle as i64));
        }

        // we have a read that succeeded
        let result = self.complete_read(handle, index);

        // kick off another read for later completion
        self.start_read(handle);

        result
    }

    unsafe fn complete_read(&mut self, handle: HANDLE, index: usize) -> Result<OsIpcSelectionResult,WinError> {
        // optimistically allocate the read buffer
        let mut buf: Vec<u8> = vec![0; READ_BUFFER_SIZE as usize];
        let mut bytes_read: u32 = 0;

        loop {
            let mut ok = kernel32::ReadFile(handle,
                                            buf.as_mut_ptr() as winapi::LPVOID,
                                            buf.len() as u32,
                                            &mut bytes_read,
                                            &mut self.overlappeds[index]);
            let mut err = GetLastError();

            // Is the IO operation pending? If so wait for it to complete, since we know one is available
            if ok == winapi::FALSE && err == winapi::ERROR_IO_PENDING {
                ok = kernel32::GetOverlappedResult(handle, &mut self.overlappeds[index], &mut bytes_read, winapi::TRUE);
                err = GetLastError();
            }

            // Now handle real errors
            if ok == winapi::FALSE {
                // Was the pipe closed?
                if err == winapi::ERROR_HANDLE_EOF {
                    return Ok(OsIpcSelectionResult::ChannelClosed(handle as i64));
                }

                // Do we not have enough space to read the full message?
                if err == winapi::ERROR_MORE_DATA {
                    let mut message_size: u32 = 0;
                    let success = kernel32::PeekNamedPipe(handle, ptr::null_mut(), 0, ptr::null_mut(), ptr::null_mut(), &mut message_size);
                    assert!(success == winapi::TRUE, "PeekNamedPipe failed");

                    buf.resize(message_size as usize, 0);
                    continue; // try the read again
                }

                // Something actually failed for real
                return Err(WinError(err));
            }

            // Hey, the read actually succeeded!
            break;
        }

        // We now have a complete message in buf! Amazing. \o/

        // deserialize!
        let mut msg: OsIpcMessage = bincode::serde::deserialize(&buf).unwrap();

        let mut channels: Vec<OsOpaqueIpcChannel> = vec![];
        let mut shmems: Vec<OsIpcSharedMemory> = vec![];
        
        // play with handles!
        for ch_handle in &mut msg.channel_handles {
            match ch_handle.receiver {
                Some(ref handles) => {
                    let mut our_handles: Vec<HANDLE> = vec![];
                    for their_handle in handles {
                        our_handles.push(take_handle_from_process(*their_handle as HANDLE, self.handle_exchange_process_id).unwrap());
                    }
                    channels.push(OsOpaqueIpcChannel::from_receiver_handles(ch_handle.pipe_id, &our_handles, self.handle_exchange_process_id));
                },
                None => {
                    channels.push(OsOpaqueIpcChannel::from_sender(ch_handle.pipe_id, self.handle_exchange_process_id));
                }
            }
        }

        for (index,their_handle) in msg.shmem_handles.iter_mut().enumerate() {
            let our_handle = take_handle_from_process(*their_handle as HANDLE, self.handle_exchange_process_id).unwrap();
            shmems.push(OsIpcSharedMemory::from_handle(our_handle, msg.shmem_sizes[index] as usize));
        }

        Ok(OsIpcSelectionResult::DataReceived(handle as i64, msg.data, channels, shmems))
    }

    unsafe fn start_read(&mut self, handle: HANDLE) -> Result<(),WinError> {
        let index = self.find_handle(handle) as usize;
        for n in 1..10 {
            let ok = kernel32::ReadFile(handle,
                                        ptr::null_mut(), // read buffer -- NULL, we're not actually going to read
                                        0, // max number of bytes to read -- 0
                                        ptr::null_mut(), // out value of number of bytes actually read -- NULL with overlapped IO
                                        &mut self.overlappeds[index]);

            // grab the actual error code
            let err = GetLastError();

            // we expect ReadFile to return FALSE -- ideally to get ERROR_IO_PENDING, but also perhaps
            // ERROR_MORE_DATA if our async read turned into a sync one.  That should never happen
            // with a named pipe, but it's a possibility.
            if ok == winapi::FALSE {
                // the expected result -- async read was queued
                if err == winapi::ERROR_IO_PENDING {
                    return Ok(());
                }

                // If it's ERROR_MORE_DATA or EOF, then we have an actual read that needs to take place.
                // We don't handle it, instead we tell our IOCP to handle it.
                if err == winapi::ERROR_MORE_DATA || err == winapi::ERROR_HANDLE_EOF {
                    kernel32::PostQueuedCompletionStatus(self.active_iocp,
                                                         0, handle as u64, &mut self.overlappeds[index]);
                    return Ok(());
                }

                return Err(WinError(err));
            }

            // ReadFile succeeded with a read of 0.  The other end must have called Write with num bytes
            // 0.  What?  Keep looping.
        }

        panic!("start_read -- went through 10 loops of ReadFile() returning TRUE, what's going on?");
    }

    fn add_handle(&mut self, handle: HANDLE) -> () {
        // Create a completion event & OVERLAPPED structure to use for this
        unsafe {
            let completion_event = kernel32::CreateEventA(ptr::null_mut(), winapi::FALSE, winapi::FALSE, ptr::null_mut());
            assert!(completion_event != INVALID_HANDLE_VALUE);

            let mut overlapped = winapi::OVERLAPPED {
                Internal: 0,
                InternalHigh: 0,
                Offset: 0,
                OffsetHigh: 0,
                hEvent: completion_event
            };

            // add the handle and the overlapped struct to vectors
            self.handles.push(handle);
            self.overlappeds.push(overlapped);

            if self.active_iocp != INVALID_HANDLE_VALUE {
                // add it to the active iocp
                kernel32::CreateIoCompletionPort(handle, self.active_iocp, handle as u64, 0);
                // kick off a read
                self.start_read(handle);
            }
        }
    }
}

#[derive(PartialEq, Debug)]
pub struct OsIpcReceiver {
    internal: RefCell<Option<OsIpcReceiverInternal>>,
    pipe_id: Uuid,
}

unsafe impl Send for OsIpcReceiver { }
unsafe impl Sync for OsIpcReceiver { }

impl Drop for OsIpcReceiver {
    fn drop(&mut self) {
    }
}

impl OsIpcReceiver {
    fn new() -> Result<OsIpcReceiver,WinError> {
        unsafe {
            let pipe_id = make_pipe_id();
            let pipe_name = make_pipe_name(&pipe_id);

            // first create the pipe and get the read portion
            let hread =
                kernel32::CreateNamedPipeA(pipe_name.as_ptr(),
                                           winapi::PIPE_ACCESS_INBOUND | winapi::FILE_FLAG_OVERLAPPED,
                                           winapi::PIPE_TYPE_MESSAGE | winapi::PIPE_READMODE_MESSAGE,
                                           winapi::PIPE_UNLIMITED_INSTANCES,
                                           4096, 4096, // out/in buffer sizes
                                           0, // default timeout
                                           ptr::null_mut());
            if hread == INVALID_HANDLE_VALUE {
                return Err(WinError::last("CreateNamedPipeA"));
            }

            let mut internal = OsIpcReceiverInternal::new();
            internal.add_handle(hread);

            Ok(OsIpcReceiver {
                internal: RefCell::new(Some(internal)),
                pipe_id: pipe_id
            })
        }
    }

    fn from_handles(pipe_id: Uuid, handles: &Vec<HANDLE>, handle_exchange_pid: u32) -> OsIpcReceiver {
        let mut internal = OsIpcReceiverInternal::new();
        for handle in handles.iter() {
            internal.add_handle(*handle as HANDLE);
        }
        OsIpcReceiver {
            internal: RefCell::new(Some(internal)),
            pipe_id: pipe_id.clone()
        }
    }

    // This function connects the server end of a named pipe, and starts it
    // listening for a connection using CreateFile
    fn start_connect(&mut self, handle_index: usize) -> HANDLE {
        unsafe {
            let mut internal = self.internal.get_mut().as_mut().unwrap();
            assert!(handle_index < internal.handles.len());

            let rv = kernel32::ConnectNamedPipe(internal.handles[handle_index],
                                                &mut internal.overlappeds[handle_index]);
            assert!(rv == 0);
            assert!(GetLastError() == winapi::ERROR_IO_PENDING);

            internal.overlappeds[handle_index].hEvent
        }
    }

    fn sender(&mut self) -> Result<OsIpcSender,WinError> {
        // kick off the connect
        self.start_connect(0);

        // then just use OsIpcSender::connect to create the sender
        OsIpcSender::connect(self.pipe_id.to_string())
    }

    pub fn consume(&self) -> OsIpcReceiver {
        let inner = mem::replace(&mut *self.internal.borrow_mut(), None);

        OsIpcReceiver {
            internal: RefCell::new(inner),
            pipe_id: Uuid::nil(),
        }
    }

    fn take_internal(&self) -> OsIpcReceiverInternal {
        let inner = mem::replace(&mut *self.internal.borrow_mut(), None);
        inner.unwrap()
    }
    
    pub fn recv(&self)
                -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),WinError> {
        unsafe {
            let mut internal = self.internal.get_mut().as_mut().unwrap();
            match internal.complete_read(
        Err(WinError(winapi::ERROR_INVALID_OPERATION))
    }

    pub fn try_recv(&self)
                    -> Result<(Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),WinError> {
        Err(WinError(winapi::ERROR_INVALID_OPERATION))
    }
}

#[derive(PartialEq, Debug)]
pub struct OsIpcSender {
    pipe_id: Uuid,
    handle: Cell<HANDLE>,
    // The process that this channel (receiver/sender) pair was
    // originally created on.  When we send a handle using this
    // sender, we first need to duplicate the handle with the
    // destination being the process with this pid, and then
    // we send it.  The receiver will DuplicateHandle to itself
    // with its own process as the receiver, this same PID
    // as the sender, and will use DUPLICATE_CLOSE_SOURCE to
    // close the handle in the source.
    handle_exchange_process_id: u32,
}

unsafe impl Send for OsIpcSender { }
unsafe impl Sync for OsIpcSender { }

impl Clone for OsIpcSender {
    fn clone(&self) -> OsIpcSender {
        OsIpcSender::connect_inner(self.pipe_id.to_string(), self.handle_exchange_process_id).unwrap()
    }
}

impl OsIpcSender {
    // XXX should we lazy-connect on send?
    fn connect_inner(name: String, handle_exchange_pid: u32) -> Result<OsIpcSender,WinError> {
        unsafe {
            let pipe_uuid = Uuid::parse_str(&name).unwrap();
            let pipe_name = make_pipe_name(&pipe_uuid);
            let handle =
                kernel32::CreateFileA(pipe_name.as_ptr(),
                                      winapi::GENERIC_WRITE,
                                      0/*winapi::FILE_SHARE_WRITE | winapi::FILE_READ_ATTRIBUTES*/,
                                      ptr::null_mut(), // lpSecurityAttributes
                                      winapi::OPEN_EXISTING,
                                      winapi::FILE_ATTRIBUTE_NORMAL | winapi::FILE_FLAG_OVERLAPPED,
                                      0 as HANDLE);
            if handle == INVALID_HANDLE_VALUE {
                return Err(WinError::last("CreateFileA"));
            }

            // Grab the process so that when we send handles, we know what process to use as
            // the handle exchange process.
            let mut serverpid: u32 = 0;
            if handle_exchange_pid == INVALID_PID {
                if kernel32::GetNamedPipeServerProcessId(handle, &mut serverpid) == winapi::FALSE {
                    let err = WinError::last("GetNamedPipeServerProcessId");
                    kernel32::CloseHandle(handle);
                    return Err(err);
                }
            } else {
                serverpid = handle_exchange_pid;
            }

            Ok(OsIpcSender {
                pipe_id: pipe_uuid.clone(),
                handle: Cell::new(handle),
                handle_exchange_process_id: serverpid,
            })
        }
    }

    pub fn connect(name: String) -> Result<OsIpcSender,WinError> {
        OsIpcSender::connect_inner(name, INVALID_PID)
    }

    pub fn send(&self,
                data: &[u8],
                ports: Vec<OsIpcChannel>,
                shared_memory_regions: Vec<OsIpcSharedMemory>)
                -> Result<(),WinError> {
        let channel_handles: Vec<OsIpcChannelHandle> = vec![];
        let shmem_sizes: Vec<u64> = vec![];
        let shmem_handles: Vec<intptr_t> = vec![];
        
        let msg = OsIpcMessage {
            data: data.to_vec(),
            channel_handles: channel_handles,
            shmem_sizes: shmem_sizes,
            shmem_handles: shmem_handles
        };

        let data = bincode::serde::serialize(&msg, bincode::SizeLimit::Infinite).unwrap();
        unsafe {
            let mut wb: u32 = 0;
            let err = kernel32::WriteFile(self.handle.get(),
                                          data.as_ptr() as *const c_void,
                                          data.len() as u32,
                                          &mut wb, ptr::null_mut());
            assert!(err == winapi::TRUE);
            assert!(wb == data.len() as u32);
        }

        Ok(())
    }
}

pub struct OsIpcReceiverSet {
    // an IO completion port that all these handles
    // are associated with
    iocp: HANDLE,
    // the set of receivers in this set
    receivers: Vec<OsIpcReceiverInternal>,
}

pub enum OsIpcSelectionResult {
    DataReceived(i64, Vec<u8>, Vec<OsOpaqueIpcChannel>, Vec<OsIpcSharedMemory>),
    ChannelClosed(i64),
}

impl OsIpcReceiverSet {
    pub fn new() -> Result<OsIpcReceiverSet,WinError> {
        unsafe {
            let iocp = kernel32::CreateIoCompletionPort(INVALID_HANDLE_VALUE, ptr::null_mut(), 0, 0);
            Ok(OsIpcReceiverSet {
                iocp: iocp,
                receivers: vec![],
            })
        }
    }

    pub fn add(&mut self, receiver: OsIpcReceiver) -> Result<i64,WinError> {
        let mut internal = receiver.take_internal();
        unsafe {
            internal.set_iocp(self.iocp);
        }

        self.receivers.push(internal);

        // XXX wtf does this return signify? The other impls just return the
        // fd/mach port as an i64, but we don't have a single one; use the
        // changed event to do so.
        Ok(self.receivers.len() as i64)
    }

    pub fn select(&mut self) -> Result<Vec<OsIpcSelectionResult>,WinError> {
        assert!(self.receivers.len() > 0, "selecting with no objects?");

        unsafe {
            let mut ov = winapi::OVERLAPPED_ENTRY {
                lpCompletionKey: 0,
                lpOverlapped: ptr::null_mut(),
                Internal: 0,
                dwNumberOfBytesTransferred: 0
            };
            let mut ovcount: u32 = 0;
            // do an alertable wait, in case we need to interrupt
            let ok = kernel32::GetQueuedCompletionStatusEx(self.iocp, &mut ov, 1, &mut ovcount,
                                                           winapi::INFINITE, winapi::TRUE);
            let err = WinError::last("GetQueuedCompletionStatusEx");
            if ok == winapi::FALSE {
                return Err(err);
            }

            let mut results: Vec<OsIpcSelectionResult> = vec![];

            // ov.lpCompletionKey contains the handle that succeeded... let's find it
            for rs in &mut self.receivers {
                if rs.find_handle(ov.lpCompletionKey as HANDLE) != -1 {
                    match rs.complete_select(&ov, true, err.0) {
                        Ok(r) => results.push(r),
                        Err(err) => return Err(err),
                    };
                    break;
                }
            }

            Ok(results)
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
            {
                let event = receiver.start_connect(0);
                let rv = kernel32::WaitForSingleObject(event, winapi::INFINITE);
                if rv == winapi::WAIT_FAILED {
                    return Err(WinError::last("WaitForSingleObject"));
                }
                kernel32::ResetEvent(event);
            }

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
    // This handle could be either for a receiver or a sender.
    // The to_receiver/to_sender functions will turn it in to
    // the proper type, assuming the remote knows what to expect.
    receiver: RefCell<Option<OsIpcReceiver>>,
    sender: RefCell<Option<OsIpcSender>>,
}

impl Drop for OsOpaqueIpcChannel {
    fn drop(&mut self) {
        println!("Should have dropped OsOpaqueIpcChannel");
//        if self.receiver.is_some() {
//            self.receiver.unwrap().borrow_mut().
//        kernel32::CloseHandle(self.receiver.unwrap_or(INVALID_HANDLE_VALUE));
//        kernel32::CloseHandle(self.sender.unwrap_or(INVALID_HANDLE_VALUE));
    }
}

impl OsOpaqueIpcChannel {
    fn from_receiver_handles(pipe_id: Uuid, handles: &Vec<HANDLE>, handle_exchange_pid: u32) -> OsOpaqueIpcChannel {
        OsOpaqueIpcChannel {
            receiver: RefCell::new(Some(OsIpcReceiver::from_handles(pipe_id, handles, handle_exchange_pid))),
            sender: RefCell::new(None),
        }
    }

    fn from_sender(pipe_id: Uuid, handle_exchange_pid: u32) -> OsOpaqueIpcChannel {
        OsOpaqueIpcChannel {
            receiver: RefCell::new(None),
            sender: RefCell::new(Some(OsIpcSender::connect_inner(pipe_id.to_string(), handle_exchange_pid).unwrap())),
        }
    }

    pub fn to_receiver(&self) -> OsIpcReceiver {
        let receiver = mem::replace(&mut *self.receiver.borrow_mut(), None);
        receiver.unwrap()
    }

    pub fn to_sender(&self) -> OsIpcSender {
        let sender = mem::replace(&mut *self.sender.borrow_mut(), None);
        sender.unwrap()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct WinError(pub u32);

impl WinError {
    fn last(f: &str) -> WinError {
        unsafe {
            let err = GetLastError();
            println!("WinError: {} from {}", err, f);
            WinError(err)
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
