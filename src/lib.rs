//! bitbeak — interactive terminal inspector and network testing workstation.

pub mod app;
pub mod bench;
pub mod capture;
pub mod cli;
pub mod codegen;
pub mod collections;
pub mod composer;
pub mod dissect;
pub mod frame;
pub mod framing;
pub mod fuzz;
pub mod http;
pub mod inspect;
pub mod pcap;
pub mod session;
pub mod tls_mitm;
pub mod tlsinfo;
pub mod transport;
pub mod ui;
pub mod workspace;

pub use app::run;
pub use cli::Args;
