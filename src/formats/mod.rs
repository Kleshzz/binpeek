pub mod elf;
pub mod pe;

pub use elf::{elf_parse_all, elf_text_section};
pub use pe::{pe_parse_all, pe_text_section};
