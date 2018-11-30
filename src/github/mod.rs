pub mod error;
pub mod github_client;

pub use self::error::{Error, ErrorKind};
pub use self::github_client::{GithubAuthenticationMethod, GithubAPIClient};