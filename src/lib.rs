pub mod app;
pub mod controller;
pub mod domain;
pub mod error;
pub mod icon;
pub mod platform;
pub mod scan;
pub mod state;

pub const APP_NAME: &str = "Win Startup Manager";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
