use std::{collections::HashMap, convert::TryFrom};

use maplit::hashmap;
use unicorn_engine::{unicorn_const, RegisterARM, RegisterX86, Unicorn};

#[derive(Clone, Copy, Debug)]
pub enum Mode {
    Mode32,
    Mode64,
}

#[allow(clippy::from_over_into)]
impl Into<unicorn_const::Mode> for Mode {
    fn into(self) -> unicorn_const::Mode {
        match self {
            Self::Mode32 => unicorn_const::Mode::MODE_32,
            Self::Mode64 => unicorn_const::Mode::MODE_64,
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<keystone::Mode> for Mode {
    fn into(self) -> keystone::Mode {
        match self {
            Self::Mode32 => keystone::Mode::MODE_32,
            Self::Mode64 => keystone::Mode::MODE_64,
        }
    }
}

impl TryFrom<unicorn_const::Mode> for Mode {
    type Error = &'static str;
    fn try_from(value: unicorn_const::Mode) -> Result<Self, Self::Error> {
        match value {
            unicorn_const::Mode::MODE_32 => Ok(Self::Mode32),
            unicorn_const::Mode::MODE_64 => Ok(Self::Mode64),
            _ => Err("unsupported mode"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Arch {
    X86, ARM
}

#[allow(clippy::from_over_into)]
impl Into<unicorn_const::Arch> for Arch {
    fn into(self) -> unicorn_const::Arch {
        match self {
            Self::X86 => unicorn_const::Arch::X86,
            Self::ARM => unicorn_const::Arch::ARM
        }
    }
}

#[allow(clippy::from_over_into)]
impl Into<keystone::Arch> for Arch {
    fn into(self) -> keystone::Arch {
        match self {
            Self::X86 => keystone::Arch::X86,
            Self::ARM => keystone::Arch::ARM
        }
    }
}

impl TryFrom<unicorn_const::Arch> for Arch {
    type Error = &'static str;
    fn try_from(value: unicorn_const::Arch) -> Result<Self, Self::Error> {
        match value {
            unicorn_const::Arch::X86 => Ok(Self::X86),
            unicorn_const::Arch::ARM => Ok(Self::ARM),
            _ => Err("unsupported arch"),
        }
    }
}

impl Arch {
    fn dump_registers(
        &self,
        emu: &Unicorn<'static, ()>,
        registers: HashMap<&'static str, i32>,
    ) -> HashMap<&'static str, u64> {
        let mut reg_dump = HashMap::new();
        for (reg_name, reg_num) in registers {
            if reg_name == "end" {
                continue;
            }
            let reg_val = emu.reg_read(reg_num).unwrap();
            reg_dump.insert(reg_name, reg_val);
        }
        reg_dump
    }

    /*
    fn dump_flags(
        &self,
        emu: &Unicorn<'static, ()>,
        flags_reg: i32,
        flags_bit_positions: HashMap<&'static str, i32>,
    ) -> HashMap<&'static str, bool> {
        let flags = emu.reg_read(flags_reg).unwrap();
        flags_bit_positions.into_iter().map(|(flag, bit_pos)| {
            (flag, (flags >> bit_pos) & 1 == 1)
        }).collect()
    }
    */
}

pub trait ArchMeta {
    fn cpu(&self) -> (Arch, Mode);
    fn sp_reg(&self) -> i32;
    fn fp_reg(&self) -> i32;
    fn flags_reg(&self) -> i32;
    fn word_size(&self) -> usize;

    fn sorted_reg_names(&self) -> Vec<&'static str>;
    fn register_map(&self) -> HashMap<&'static str, i32>;
    fn dump_registers(&self, emu: &Unicorn<'static, ()>) -> HashMap<&'static str, u64>;

    fn sorted_flags_names(&self) -> Vec<&'static str>;
    fn flags_bit_positions(&self) -> HashMap<&'static str, i32>;
}

#[derive(Clone, Copy, Debug)]
pub struct X32 {
    inner: Arch,
}
impl X32 {
    pub fn new(arch: Arch) -> Self {
        Self { inner: arch }
    }
}
impl ArchMeta for X32 {
    fn cpu(&self) -> (Arch, Mode) {
        (self.inner, Mode::Mode32)
    }

    fn sp_reg(&self) -> i32 {
        i32::from(RegisterX86::ESP)
    }
    fn fp_reg(&self) -> i32 {
        i32::from(RegisterX86::EBP)
    }
    fn flags_reg(&self) -> i32 {
        i32::from(RegisterX86::EFLAGS)
    }

    fn word_size(&self) -> usize {
        32 / 8
    }

    fn sorted_reg_names(&self) -> Vec<&'static str> {
        vec![
            "eax", "ebx", "ecx", "edx", "end", //
            "esi", "edi", "end", //
            "eip", "ebp", "esp", "end", //
            "flags", "end", //
            "cs", "ss", "ds", "es", "end", //
            "fs", "gs", "end", //
        ]
    }

    fn register_map(&self) -> HashMap<&'static str, i32> {
        // register to trace, display, etc.
        hashmap! {
            "eax"   => i32::from(RegisterX86::EAX),
            "ebx"   => i32::from(RegisterX86::EBX),
            "ecx"   => i32::from(RegisterX86::ECX),
            "edx"   => i32::from(RegisterX86::EDX),
            "esi"   => i32::from(RegisterX86::ESI),
            "edi"   => i32::from(RegisterX86::EDI),
            "eip"   => i32::from(RegisterX86::EIP),
            "ebp"   => i32::from(RegisterX86::EBP),
            "esp"   => i32::from(RegisterX86::ESP),
            "flags" => i32::from(RegisterX86::EFLAGS),
            "cs"    => i32::from(RegisterX86::CS),
            "ss"    => i32::from(RegisterX86::SS),
            "ds"    => i32::from(RegisterX86::DS),
            "es"    => i32::from(RegisterX86::ES),
            "fs"    => i32::from(RegisterX86::FS),
            "gs"    => i32::from(RegisterX86::GS),
        }
    }

    fn dump_registers(&self, emu: &Unicorn<'static, ()>) -> HashMap<&'static str, u64> {
        self.inner.dump_registers(emu, self.register_map())
    }

    fn sorted_flags_names(&self) -> Vec<&'static str> {
        vec!["cf", "zf", "of", "sf", "pf", "af", "df"]
    }
    fn flags_bit_positions(&self) -> HashMap<&'static str, i32> {
        hashmap! {
            "cf" => 0,
            "pf" => 2,
            "af" => 4,
            "zf" => 6,
            "sf" => 7,
            "df" => 10,
            "of" => 11,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct X64 {
    inner: Arch,
}
impl X64 {
    pub fn new(arch: Arch) -> X64 {
        Self { inner: arch }
    }
}
impl ArchMeta for X64 {
    fn cpu(&self) -> (Arch, Mode) {
        (self.inner, Mode::Mode64)
    }

    fn sp_reg(&self) -> i32 {
        i32::from(RegisterX86::RSP)
    }
    fn fp_reg(&self) -> i32 {
        i32::from(RegisterX86::RBP)
    }
    fn flags_reg(&self) -> i32 {
        i32::from(RegisterX86::EFLAGS)
    }

    fn word_size(&self) -> usize {
        64 / 8
    }

    fn sorted_reg_names(&self) -> Vec<&'static str> {
        vec![
            "rax", "rbx", "rcx", "rdx", "end", //
            "rsi", "rdi", "r8", "r9", "end", //
            "r10", "r11", "r12", "r13", "end", //
            "r14", "r15", "end", //
            "rip", "rbp", "rsp", "end", //
            "cs", "ss", "ds", "es", "end", //
            "fs", "gs", "end", "flags", "end", //
        ]
    }

    fn register_map(&self) -> HashMap<&'static str, i32> {
        // register to trace, display, etc.
        hashmap! {
            "rax"   => i32::from(RegisterX86::RAX),
            "rbx"   => i32::from(RegisterX86::RBX),
            "rcx"   => i32::from(RegisterX86::RCX),
            "rdx"   => i32::from(RegisterX86::RDX),
            "rsi"   => i32::from(RegisterX86::RSI),
            "rdi"   => i32::from(RegisterX86::RDI),
            "r8"    => i32::from(RegisterX86::R8),
            "r9"    => i32::from(RegisterX86::R9),
            "r10"   => i32::from(RegisterX86::R10),
            "r11"   => i32::from(RegisterX86::R11),
            "r12"   => i32::from(RegisterX86::R12),
            "r13"   => i32::from(RegisterX86::R13),
            "r14"   => i32::from(RegisterX86::R14),
            "r15"   => i32::from(RegisterX86::R15),
            "rip"   => i32::from(RegisterX86::RIP),
            "rbp"   => i32::from(RegisterX86::RBP),
            "rsp"   => i32::from(RegisterX86::RSP),
            "flags" => i32::from(RegisterX86::EFLAGS),
            "cs"    => i32::from(RegisterX86::CS),
            "ss"    => i32::from(RegisterX86::SS),
            "ds"    => i32::from(RegisterX86::DS),
            "es"    => i32::from(RegisterX86::ES),
            "fs"    => i32::from(RegisterX86::FS),
            "gs"    => i32::from(RegisterX86::GS),
        }
    }

    fn dump_registers(&self, emu: &Unicorn<'static, ()>) -> HashMap<&'static str, u64> {
        self.inner.dump_registers(emu, self.register_map())
    }

    fn sorted_flags_names(&self) -> Vec<&'static str> {
        vec!["cf", "zf", "of", "sf", "pf", "af", "df"]
    }
    fn flags_bit_positions(&self) -> HashMap<&'static str, i32> {
        hashmap! {
            "cf" => 0,
            "pf" => 2,
            "af" => 4,
            "zf" => 6,
            "sf" => 7,
            "df" => 10,
            "of" => 11,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ARM32 {
    inner: Arch,
}
impl ARM32 {
    pub fn new(arch: Arch) -> ARM32 {
        Self { inner: arch }
    }
}
impl ArchMeta for ARM32 {
    fn cpu(&self) -> (Arch, Mode) {
        (self.inner, Mode::Mode32)
    }

    fn sp_reg(&self) -> i32 {
        i32::from(RegisterARM::R13)
    }
    fn fp_reg(&self) -> i32 {
        i32::from(RegisterARM::R11)
    }
    fn flags_reg(&self) -> i32 {
        i32::from(RegisterARM::CPSR)
    }

    fn word_size(&self) -> usize {
        32 / 8
    }

    fn sorted_reg_names(&self) -> Vec<&'static str> {
        vec![
            "r0", "r1", "r2", "r3", "end", //
            "r4", "r5", "r6", "r7", "end", //
            "r8", "r9", "r10", "r11", "end", //
            "r12", "sp", "lr", "pc", "end", //
            "cpsr", "end", //
        ]
    }
    fn register_map(&self) -> HashMap<&'static str, i32> {
        // register to trace, display, etc.
        hashmap! {
            "r0"   => i32::from(RegisterARM::R0),
            "r1"   => i32::from(RegisterARM::R1),
            "r2"   => i32::from(RegisterARM::R2),
            "r3"   => i32::from(RegisterARM::R3),
            "r4"   => i32::from(RegisterARM::R4),
            "r5"   => i32::from(RegisterARM::R5),
            "r6"   => i32::from(RegisterARM::R6),
            "r7"   => i32::from(RegisterARM::R7),
            "r8"   => i32::from(RegisterARM::R8),
            "r9"   => i32::from(RegisterARM::R9),
            "r10"  => i32::from(RegisterARM::R10),
            "r11"  => i32::from(RegisterARM::R11),
            "r12"  => i32::from(RegisterARM::R12),
            "sp"   => i32::from(RegisterARM::R13),
            "lr"   => i32::from(RegisterARM::R14),
            "pc"   => i32::from(RegisterARM::R15),
            "cpsr" => i32::from(RegisterARM::CPSR),
        }
    }
    fn dump_registers(&self, emu: &Unicorn<'static, ()>) -> HashMap<&'static str, u64> {
        self.inner.dump_registers(emu, self.register_map())
    }

    fn sorted_flags_names(&self) -> Vec<&'static str> {
        vec!["N", "Z", "C", "V"]
    }
    fn flags_bit_positions(&self) -> HashMap<&'static str, i32> {
        hashmap! {
            "N" => 31,
            "Z" => 30,
            "C" => 29,
            "V" => 28,
        }
    }
}
