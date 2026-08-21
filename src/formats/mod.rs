pub mod elf;
pub mod macho;
pub mod pe;
mod util;

pub use elf::elf_parse_all;
pub use macho::macho_parse_all;
pub use pe::pe_parse_all;

use crate::analysis::disasm::Arch;

pub type ParseResult = (Vec<String>, Vec<String>, Option<(Vec<u8>, u64, Arch)>);
