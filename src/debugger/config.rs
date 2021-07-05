use std::path::PathBuf;

pub struct Config {
    pub elf_file_path:  Option<PathBuf>,
    pub chip:           Option<String>,
    pub work_directory: Option<String>,
    pub probe_num:      usize,
}

impl Config {
    pub fn new(opt: super::Opt) -> Config {
        Config {
            elf_file_path: opt.elf_file_path,
            chip: opt.chip,
            work_directory: opt.work_directory,
            probe_num: 0,
        }
    }

    pub fn is_missing_config(&self) -> bool {
        self.elf_file_path.is_none() || self.chip.is_none() || self.work_directory.is_none()
    }

    pub fn missing_config_message(&self) -> String {
        if !self.is_missing_config() {
            return "No required configurations missing".to_owned();
        }

        let mut error = "Missing required configurations:".to_owned();
        if self.elf_file_path.is_none() {
            error = format!("{}\n\t{}", error, "elf file path");
        }
        if self.chip.is_none() {
            error = format!("{}\n\t{}", error, "chip");
        }
        if self.work_directory.is_none() {
            error = format!("{}\n\t{}", error, "work directory");
        }

        error
    }
}

