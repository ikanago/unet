use std::fs::File;

pub mod tap;

#[derive(Debug)]
pub enum DriverType {
    Tap{
        file: File,
    },
}
