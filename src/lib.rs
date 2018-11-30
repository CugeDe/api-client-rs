extern crate base64;
extern crate bytes;
extern crate http;
extern crate hyper;
extern crate hyper_tls;

pub mod api_client;
pub mod github;
pub mod insale;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
