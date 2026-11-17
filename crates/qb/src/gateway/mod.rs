//! `qb gateway`: the model gateway. It runs as the owner of vendor credentials, serves the C4
//! contract (`/v1/model/*`, see `docs/api.md`) on its own unix socket, asks qbd where to run each
//! turn and reports back what happened.

pub mod upstream;
