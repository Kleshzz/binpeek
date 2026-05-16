pub mod elf;
pub mod macho;
pub mod pe;

pub use elf::elf_parse_all;
pub use macho::macho_parse_all;
pub use pe::pe_parse_all;
