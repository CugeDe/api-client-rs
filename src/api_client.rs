use hyper;
use std::collections::HashMap;

pub trait APIClient<'a>
{
	type Error;

	fn endpoint(&self) -> &hyper::Uri;
	fn set_endpoint(&mut self, endpoint: &'static str) -> Result<(), Self::Error>;

	fn get(&mut self, HashMap<&str, String>, &str, HashMap<&str, String>, Option<&str>) -> Result<hyper::client::ResponseFuture, Self::Error>;
	fn post(&mut self, HashMap<&str, String>, &str, HashMap<&str, String>, Option<&str>, impl Into<hyper::Body>) -> Result<hyper::client::ResponseFuture, Self::Error>;
	fn put(&mut self, HashMap<&str, String>, &str, HashMap<&str, String>, Option<&str>, impl Into<hyper::Body>) -> Result<hyper::client::ResponseFuture, Self::Error>;
	fn head(&mut self, HashMap<&str, String>, &str, HashMap<&str, String>, Option<&str>) -> Result<hyper::client::ResponseFuture, Self::Error>;
	fn delete(&mut self, HashMap<&str, String>, &str, HashMap<&str, String>, Option<&str>, impl Into<hyper::Body>) -> Result<hyper::client::ResponseFuture, Self::Error>;
	fn option(&mut self, HashMap<&str, String>, &str, HashMap<&str, String>, Option<&str>) -> Result<hyper::client::ResponseFuture, Self::Error>;
	fn patch(&mut self, HashMap<&str, String>, &str, HashMap<&str, String>, Option<&str>, impl Into<hyper::Body>) -> Result<hyper::client::ResponseFuture, Self::Error>;
}