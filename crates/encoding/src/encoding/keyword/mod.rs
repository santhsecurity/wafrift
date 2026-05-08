//! Keyword manipulation encoding strategies.

mod case;
mod comment;
mod space;
mod sql;

pub use case::{alternating_case, case_alternate, lowercase, random_case_alternate, uppercase};
pub use comment::{mysql_versioned_comment, sql_comment_insert};
pub use space::{
    space_to_comment, space_to_dash, space_to_hash, space_to_plus, space_to_random_blank,
    whitespace_insert,
};
pub use sql::{between_obfuscate, percentage_prefix, unmagic_quotes};
