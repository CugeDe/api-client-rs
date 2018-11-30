pub mod error;
pub mod insale_client;

pub use self::error::{Error, ErrorKind};
pub use self::insale_client::{InSaleAuthenticationMethod, InSaleAPIClient};