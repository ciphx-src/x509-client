#![doc = include_str!("../README.md")]

pub use client::*;
pub use reqwest;
pub use result::*;

pub mod api;
mod client;
mod parse;
mod result;

pub mod provided;

#[cfg(test)]
pub mod tests;
