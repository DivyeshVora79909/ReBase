//! Isolated local calculation prototype, model tools and semantic primitives.

pub mod access;
pub mod algebra;
pub mod binding;
pub mod causal;
pub mod demo;
mod dependency;
pub mod effects;
pub mod fixtures;
pub mod identity;
pub mod index;
pub mod indexes;
pub mod inspector;
pub mod integrity;
pub mod json;
pub mod lifecycle;
pub mod local;
pub mod merge;
pub mod model;
pub mod models;
pub mod mutation;
pub mod native_codec;
pub mod native_slice;
pub mod plan;
pub mod query;
pub mod routes;
pub mod rpc;
pub mod security;
pub mod server;
pub mod staging;
pub mod time_range;
pub mod tree;
pub mod values;

#[cfg(test)]
mod parameter_tests;

#[cfg(test)]
mod publication_tests;

#[cfg(test)]
mod route_tests;
#[cfg(test)]
mod window_tests;

#[cfg(test)]
mod index_tests;

#[cfg(test)]
mod effect_tests;
