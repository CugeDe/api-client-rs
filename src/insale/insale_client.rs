use http::HttpTryFrom;
use hyper;
use hyper_tls;
use api_client::APIClient;
use insale::{Error, ErrorKind};
use std::collections::HashMap;
use std::error::Error as ErrorTrait;

pub const HTTPS_THREAD_COUNT: usize = 4usize;
pub const INSALE_API_ENDPOINT: &'static str = "http://api.prod.insale.fr/";

#[derive(Debug, Eq, PartialEq)]
pub enum InSaleAuthenticationMethod<'a>
{
	/// OAuth2TokenHeader Authentication adds one header to the request
	/// 'Authorization: Token OAUTH-TOKEN'
	/// 
	/// # Example
	/// `Authorization: Token oauth-token`
	OAuth2TokenHeader(&'a str),
}

impl<'a> InSaleAuthenticationMethod<'a>
{
	pub fn as_str(&self)
	-> &'static str
	{
		match *self {
			InSaleAuthenticationMethod::OAuth2TokenHeader(..) => "oauth2 token authentication (sent in a header)",
		}
	}

	#[allow(unreachable_patterns)]
	pub fn is_oauth2token_header(&self)
	-> bool
	{
		match *self {
			InSaleAuthenticationMethod::OAuth2TokenHeader(..) => true,
			_ => false
		}
	}
}

pub struct InSaleAPIClient<'a>
{
	authentication_method: Option<InSaleAuthenticationMethod<'a>>,
	endpoint: hyper::Uri,
	_client: hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>
}

impl<'a> InSaleAPIClient<'a>
{
	pub fn new()
	-> Self
	{
		// Clears the endpoint by removing any path, query parameter or fragment
		let uri: hyper::Uri = {
			let initial_uri = hyper::Uri::from_static(INSALE_API_ENDPOINT);
			let mut parts = initial_uri.into_parts();
			parts.path_and_query = Some(http::uri::PathAndQuery::from_static(""));

			hyper::Uri::from_parts(parts).unwrap()
		};

		// Creates the https connector
		let https = hyper_tls::HttpsConnector::new(HTTPS_THREAD_COUNT).unwrap();

		Self
		{
			authentication_method: None,
			endpoint: uri,
			_client: hyper::Client::builder().keep_alive(false).build(https)
		}
	}

	fn setup_oauth2_token_header_authentication(&mut self, _oauth2_token: &'a str) -> Result<(), Error>
	{
		if _oauth2_token.len() == 0 {
			Err(Error::new(ErrorKind::InvalidData, "oauth2 token is null"))
		}
		else {
			self.authentication_method = Some(InSaleAuthenticationMethod::OAuth2TokenHeader(_oauth2_token));
			Ok(())
		}
	}

	pub fn setup_authentication_method(&mut self, _authentication_method: Option<InSaleAuthenticationMethod<'a>>)
	-> Result<(), Error>
	{
		match _authentication_method {
			None => { self.authentication_method = None; Ok(()) },
			Some(InSaleAuthenticationMethod::OAuth2TokenHeader(_oauth2_credentials)) => { self.setup_oauth2_token_header_authentication(_oauth2_credentials) },
		}
	}

	pub fn authentication_method(&self)
	-> &Option<InSaleAuthenticationMethod<'a>>
	{
		&self.authentication_method
	}

	fn authenticate_request(&self, _builder: &mut hyper::http::request::Builder, _path: &str, mut _query: HashMap<&str, &'a str>, _fragment: Option<&str>)
	{
		let _fragment: String = match _fragment {
			Some(_fragment) => {
				"#".to_string() + _fragment
			},
			None => String::new()
		};

		match self.authentication_method.as_ref()
		{
			None => {},
			Some(&InSaleAuthenticationMethod::OAuth2TokenHeader(_token)) => {
				// Adds the Authorization header
				_builder.header("Authorization", "Token ".to_owned() + _token);
			}
		}

		// Builds the Url from self.endpoint, _path, _query parameters and _fragment
		let uri: hyper::Uri = self.endpoint().clone();
		let parts = uri.into_parts();

		let query: Vec<String> = _query.iter().map(|(key, value)| {
			let mut parameter: String = key.to_string();

			if value.len() > 0 {
				parameter = (parameter.to_owned() + "=") + value;
			}
			parameter
		}).collect();
		
		let _query: String = match query.len() {
			0 => { "".to_string() },
			_x => { "?".to_owned() + &query.as_slice().join(&"&") }
		};

		match hyper::Uri::builder()
			.scheme(parts.scheme.unwrap())
			.authority(parts.authority.unwrap())
			.path_and_query((_path.to_owned() + &_query).as_str())
			.build()
		{
			Ok(uri) => {
				_builder.uri(uri.to_string() + &_fragment);
			},
			Err(error) => unreachable!(error.description())
		};
	}
}

impl<'a> APIClient<'a> for InSaleAPIClient<'a>
{
	type Error = Error;

	fn endpoint(&self)
	-> &hyper::Uri
	{
		&self.endpoint
	}

	fn set_endpoint(&mut self, endpoint: &'static str)
	-> Result<(), Self::Error>
	{
		self.endpoint = {
			let initial_uri = match hyper::Uri::try_from(endpoint) {
				Ok(uri) => uri,
				Err(error) => return Err(Self::Error::new(ErrorKind::Other, error))
			};

			let mut parts = initial_uri.into_parts();
			parts.path_and_query = Some(http::uri::PathAndQuery::from_static(""));

			match hyper::Uri::from_parts(parts) {
				Ok(uri) => uri,
				Err(error) => return Err(Self::Error::new(ErrorKind::Other, error))
			}
		};

		Ok(())
	}


	fn get(&mut self, _headers: HashMap<&str, &str>, _path: &str, _query: HashMap<&str, &str>, _fragment: Option<&str>)
	-> Result<hyper::client::ResponseFuture, Self::Error>
	{
		let mut builder = hyper::Request::builder();

		builder.method("GET");
		self.authenticate_request(&mut builder, _path, _query, _fragment);

		// Prepares the body

		let request = match builder.body("".into()) {
			Ok(request) => request,
			Err(error) => { return Err(Error::new(ErrorKind::Other, error)) }
		};

		Ok(self._client.request(request))
	}

	fn post(&mut self, _headers: HashMap<&str, &str>, _path: &str, _query: HashMap<&str, &str>, _fragment: Option<&str>, _body: impl Into<hyper::Body>)
	-> Result<hyper::client::ResponseFuture, Self::Error>
	{
		let mut builder = hyper::Request::builder();

		builder.method("POST");
		self.authenticate_request(&mut builder, _path, _query, _fragment);

		let request = match builder.body(_body.into()) {
			Ok(request) => { request },
			Err(error) => { return Err(Error::new(ErrorKind::Other, error)) }
		};

		Ok(self._client.request(request))
	}

	fn put(&mut self, _headers: HashMap<&str, &str>, _path: &str, _query: HashMap<&str, &str>, _fragment: Option<&str>, _body: impl Into<hyper::Body>)
	-> Result<hyper::client::ResponseFuture, Self::Error>
	{
		let mut builder = hyper::Request::builder();

		builder.method("PUT");
		self.authenticate_request(&mut builder, _path, _query, _fragment);

		let request = match builder.body(_body.into()) {
			Ok(request) => request,
			Err(error) => { return Err(Error::new(ErrorKind::Other, error)) }
		};

		Ok(self._client.request(request))
	}

	fn head(&mut self, _headers: HashMap<&str, &str>, _path: &str, _query: HashMap<&str, &str>, _fragment: Option<&str>)
	-> Result<hyper::client::ResponseFuture, Self::Error>
	{
		let mut builder = hyper::Request::builder();

		builder.method("HEAD");
		self.authenticate_request(&mut builder, _path, _query, _fragment);

		// Prepares the body

		let request = match builder.body("".into()) {
			Ok(request) => request,
			Err(error) => { return Err(Error::new(ErrorKind::Other, error)) }
		};

		Ok(self._client.request(request))
	}

	fn delete(&mut self, _headers: HashMap<&str, &str>, _path: &str, _query: HashMap<&str, &str>, _fragment: Option<&str>, _body: impl Into<hyper::Body>)
	-> Result<hyper::client::ResponseFuture, Self::Error>
	{
		let mut builder = hyper::Request::builder();

		builder.method("DELETE");
		self.authenticate_request(&mut builder, _path, _query, _fragment);

		// Prepares the body

		let request = match builder.body(_body.into()) {
			Ok(request) => request,
			Err(error) => { return Err(Error::new(ErrorKind::Other, error)) }
		};

		Ok(self._client.request(request))
	}

	fn option(&mut self, _headers: HashMap<&str, &str>, _path: &str, _query: HashMap<&str, &str>, _fragment: Option<&str>)
	-> Result<hyper::client::ResponseFuture, Self::Error>
	{
		let mut builder = hyper::Request::builder();

		builder.method("OPTION");
		self.authenticate_request(&mut builder, _path, _query, _fragment);

		// Prepares the body

		let request = match builder.body("".into()) {
			Ok(request) => request,
			Err(error) => { return Err(Error::new(ErrorKind::Other, error)) }
		};

		Ok(self._client.request(request))
	}

	fn patch(&mut self, _headers: HashMap<&str, &str>, _path: &str, _query: HashMap<&str, &str>, _fragment: Option<&str>, _body: impl Into<hyper::Body>)
	-> Result<hyper::client::ResponseFuture, Self::Error>
	{
		let mut builder = hyper::Request::builder();

		builder.method("PATCH");
		self.authenticate_request(&mut builder, _path, _query, _fragment);

		// Prepares the body

		let request = match builder.body(_body.into()) {
			Ok(request) => request,
			Err(error) => { return Err(Error::new(ErrorKind::Other, error)) }
		};

		Ok(self._client.request(request))
	}
}

#[cfg(test)]
mod tests
{
	use api_client::APIClient;
	use hyper::rt::{self, Future, Stream};
	use hyper::service::service_fn_ok;
	use insale::{Error, ErrorKind};
	use insale::insale_client::INSALE_API_ENDPOINT;

	use super::{InSaleAuthenticationMethod, InSaleAPIClient};
	use std::collections::HashMap;
	use std::str;
	use std::sync::{Arc, Mutex};
	use std::thread;

	#[test]
	fn new_github_client()
	{
		let _client = InSaleAPIClient::new();
		assert_eq!(_client.endpoint().to_string(), String::from(INSALE_API_ENDPOINT));
	}

	#[test]
	fn set_endpoint()
	{
		let mut _client = InSaleAPIClient::new();

		assert!(_client.set_endpoint("http://localhost/").is_ok());
		assert_eq!(_client.endpoint().to_string(), String::from("http://localhost/"));

		assert!(_client.set_endpoint("http://localhost/first/second/third?p1=v1&p2=v2").is_ok());
		assert_eq!(_client.endpoint().to_string(), String::from("http://localhost/"));

		assert!(_client.set_endpoint("test:/localhost/").is_err());
	}

	#[test]
	fn get_authentication_method()
	{
		let mut _client = InSaleAPIClient::new();
		assert!(_client.authentication_method().is_none());

		let _ = _client.setup_authentication_method(Some(InSaleAuthenticationMethod::OAuth2TokenHeader("token")));
		assert!(_client.authentication_method().is_some());
		assert!(_client.authentication_method().as_ref().unwrap().is_oauth2token_header());

		let _ = _client.setup_authentication_method(None);
		assert!(_client.authentication_method().is_none());
	}

	fn setup_oauth2_token_header_authentication<'a>(_client: &mut InSaleAPIClient<'a>)
	{
		assert!(_client.setup_authentication_method(Some(InSaleAuthenticationMethod::OAuth2TokenHeader(""))).is_err());
		assert!(_client.setup_authentication_method(Some(InSaleAuthenticationMethod::OAuth2TokenHeader("token"))).is_ok());
	}

	#[test]
	fn setup_authentication_method()
	{
		let mut _client = InSaleAPIClient::new();
		assert!(_client.setup_authentication_method(None).is_ok());

		setup_oauth2_token_header_authentication(&mut _client);
	}

	fn start_test_server(port: u16)
	-> std::thread::JoinHandle<()>
	{
		thread::spawn(move || {
			let addr = ([127, 0, 0, 1], port).into();

			// A `Service` is needed for every connection, so this
			// creates one from our `hello_world` function.
			let new_svc = || {
			    // service_fn_ok converts our function into a `Service`
			    service_fn_ok(|_req| { hyper::Response::new(hyper::Body::from("Hello, World!"))})
			};

			let server = hyper::Server::bind(&addr)
			    .serve(new_svc);
			    

			// Run this server for... forever!
			hyper::rt::run(server.map_err(|e| eprintln!("server error: {}", e)));
		})
	}

	#[test]
	fn get()
	{
		let _thread_handle = start_test_server(4000);

		let mut _client = InSaleAPIClient::new();
		_client.set_endpoint("http://localhost:4000/").expect("failed to set http://localhost:4000/ as new endpoint");

		let _ = _client.setup_authentication_method(Some(InSaleAuthenticationMethod::OAuth2TokenHeader("token")));
		let future = _client.get(HashMap::new(), "/", HashMap::new(), Some("test")).unwrap();

		let responses: Arc<Mutex<Vec<Result<http::Response<String>, Error>>>> = Arc::new(Mutex::new(vec!()));
		let ok_responses = responses.clone();
		let err_responses = responses.clone();

		rt::run(rt::lazy(move || {
			// This is main future that the runtime will execute.
			//
			// The `lazy` is because we don't want any of this executing *right now*,
			// but rather once the runtime has started up all its resources.
			//
			// This is where we will setup our HTTP client requests.
			future
				.map(|res| {
					let (head, body) = res.into_parts();

					(head, body.concat2().wait())
				})
				.map(move |(head, chunk)| {
					let body = str::from_utf8(&chunk.unwrap()).expect("failed to convert body to str").to_string();

					ok_responses.lock().unwrap().push(Ok(http::Response::from_parts(head, body)));
				})
				.map_err(move |_err| {
					err_responses.lock().unwrap().push(Err(Error::new(ErrorKind::Other, _err)));
				})
		}));

		loop {
			let data = responses.lock().unwrap();
			if data.len() > 0 {
				if let Some(Ok(value)) = data.first() {
					assert_eq!(*value.body(), String::from("Hello, World!"));
					break;
				}
			}
		}

		// Drops the handle to force the closing of the thread when main thread leaves
		drop(_thread_handle);
	}

	#[test]
	fn post()
	{
		let _thread_handle = start_test_server(4001);

		let mut _client = InSaleAPIClient::new();
		_client.set_endpoint("http://localhost:4001/").expect("failed to set http://localhost:4001/ as new endpoint");

		let body = "";

		let _ = _client.setup_authentication_method(Some(InSaleAuthenticationMethod::OAuth2TokenHeader("token")));
		let future = _client.post(HashMap::new(), "/", HashMap::new(), Some("test"), body).unwrap();

		let responses: Arc<Mutex<Vec<Result<http::Response<String>, Error>>>> = Arc::new(Mutex::new(vec!()));
		let ok_responses = responses.clone();
		let err_responses = responses.clone();

		rt::run(rt::lazy(move || {
			// This is main future that the runtime will execute.
			//
			// The `lazy` is because we don't want any of this executing *right now*,
			// but rather once the runtime has started up all its resources.
			//
			// This is where we will setup our HTTP client requests.
			future
				.map(|res| {
					let (head, body) = res.into_parts();

					(head, body.concat2().wait())
				})
				.map(move |(head, chunk)| {
					let body = str::from_utf8(&chunk.unwrap()).expect("failed to convert body to str").to_string();

					ok_responses.lock().unwrap().push(Ok(http::Response::from_parts(head, body)));
				})
				.map_err(move |_err| {
					err_responses.lock().unwrap().push(Err(Error::new(ErrorKind::Other, _err)));
				})
		}));

		loop {
			let data = responses.lock().unwrap();
			if data.len() > 0 {
				if let Some(Ok(value)) = data.first() {
					assert_eq!(*value.body(), String::from("Hello, World!"));
					break;
				}
			}
		}

		// Drops the handle to force the closing of the thread when main thread leaves
		drop(_thread_handle);
	}

	#[test]
	fn put()
	{
		let _thread_handle = start_test_server(4002);

		let mut _client = InSaleAPIClient::new();
		_client.set_endpoint("http://localhost:4002/").expect("failed to set http://localhost:4002/ as new endpoint");

		let body = "";

		let _ = _client.setup_authentication_method(Some(InSaleAuthenticationMethod::OAuth2TokenHeader("token")));
		let future = _client.put(HashMap::new(), "/", HashMap::new(), Some("test"), body).unwrap();

		let responses: Arc<Mutex<Vec<Result<http::Response<String>, Error>>>> = Arc::new(Mutex::new(vec!()));
		let ok_responses = responses.clone();
		let err_responses = responses.clone();

		rt::run(rt::lazy(move || {
			// This is main future that the runtime will execute.
			//
			// The `lazy` is because we don't want any of this executing *right now*,
			// but rather once the runtime has started up all its resources.
			//
			// This is where we will setup our HTTP client requests.
			future
				.map(|res| {
					let (head, body) = res.into_parts();

					(head, body.concat2().wait())
				})
				.map(move |(head, chunk)| {
					let body = str::from_utf8(&chunk.unwrap()).expect("failed to convert body to str").to_string();

					ok_responses.lock().unwrap().push(Ok(http::Response::from_parts(head, body)));
				})
				.map_err(move |_err| {
					err_responses.lock().unwrap().push(Err(Error::new(ErrorKind::Other, _err)));
				})
		}));

		loop {
			let data = responses.lock().unwrap();
			if data.len() > 0 {
				if let Some(Ok(value)) = data.first() {
					assert_eq!(*value.body(), String::from("Hello, World!"));
					break;
				}
			}
		}

		// Drops the handle to force the closing of the thread when main thread leaves
		drop(_thread_handle);
	}

	#[test]
	fn head()
	{
		let _thread_handle = start_test_server(4003);

		let mut _client = InSaleAPIClient::new();
		_client.set_endpoint("http://localhost:4003/").expect("failed to set http://localhost:4003/ as new endpoint");

		let _ = _client.setup_authentication_method(Some(InSaleAuthenticationMethod::OAuth2TokenHeader("token")));
		let future = _client.head(HashMap::new(), "/", HashMap::new(), Some("test")).unwrap();

		let responses: Arc<Mutex<Vec<Result<http::Response<String>, Error>>>> = Arc::new(Mutex::new(vec!()));
		let ok_responses = responses.clone();
		let err_responses = responses.clone();

		rt::run(rt::lazy(move || {
			// This is main future that the runtime will execute.
			//
			// The `lazy` is because we don't want any of this executing *right now*,
			// but rather once the runtime has started up all its resources.
			//
			// This is where we will setup our HTTP client requests.
			future
				.map(|res| {
					let (head, body) = res.into_parts();

					(head, body.concat2().wait())
				})
				.map(move |(head, chunk)| {
					let body = str::from_utf8(&chunk.unwrap()).expect("failed to convert body to str").to_string();

					ok_responses.lock().unwrap().push(Ok(http::Response::from_parts(head, body)));
				})
				.map_err(move |_err| {
					err_responses.lock().unwrap().push(Err(Error::new(ErrorKind::Other, _err)));
				})
		}));

		loop {
			let data = responses.lock().unwrap();
			if data.len() > 0 {
				if let Some(Ok(value)) = data.first() {
					assert_eq!(*value.body(), String::from(""));
					break;
				}
			}
		}

		// Drops the handle to force the closing of the thread when main thread leaves
		drop(_thread_handle);
	}

	#[test]
	fn delete()
	{
		let _thread_handle = start_test_server(4004);

		let mut _client = InSaleAPIClient::new();
		_client.set_endpoint("http://localhost:4004/").expect("failed to set http://localhost:4004/ as new endpoint");

		let body = "";

		let _ = _client.setup_authentication_method(Some(InSaleAuthenticationMethod::OAuth2TokenHeader("token")));
		let future = _client.delete(HashMap::new(), "/", HashMap::new(), Some("test"), body).unwrap();

		let responses: Arc<Mutex<Vec<Result<http::Response<String>, Error>>>> = Arc::new(Mutex::new(vec!()));
		let ok_responses = responses.clone();
		let err_responses = responses.clone();

		rt::run(rt::lazy(move || {
			// This is main future that the runtime will execute.
			//
			// The `lazy` is because we don't want any of this executing *right now*,
			// but rather once the runtime has started up all its resources.
			//
			// This is where we will setup our HTTP client requests.
			future
				.map(|res| {
					let (head, body) = res.into_parts();

					(head, body.concat2().wait())
				})
				.map(move |(head, chunk)| {
					let body = str::from_utf8(&chunk.unwrap()).expect("failed to convert body to str").to_string();

					ok_responses.lock().unwrap().push(Ok(http::Response::from_parts(head, body)));
				})
				.map_err(move |_err| {
					err_responses.lock().unwrap().push(Err(Error::new(ErrorKind::Other, _err)));
				})
		}));

		loop {
			let data = responses.lock().unwrap();
			if data.len() > 0 {
				if let Some(Ok(value)) = data.first() {
					assert_eq!(*value.body(), String::from("Hello, World!"));
					break;
				}
			}
		}

		// Drops the handle to force the closing of the thread when main thread leaves
		drop(_thread_handle);
	}

	#[test]
	fn option()
	{
		let _thread_handle = start_test_server(4005);

		let mut _client = InSaleAPIClient::new();
		_client.set_endpoint("http://localhost:4005/").expect("failed to set http://localhost:4005/ as new endpoint");

		let _ = _client.setup_authentication_method(Some(InSaleAuthenticationMethod::OAuth2TokenHeader("token")));
		let future = _client.option(HashMap::new(), "/", HashMap::new(), Some("test")).unwrap();

		let responses: Arc<Mutex<Vec<Result<http::Response<String>, Error>>>> = Arc::new(Mutex::new(vec!()));
		let ok_responses = responses.clone();
		let err_responses = responses.clone();

		rt::run(rt::lazy(move || {
			// This is main future that the runtime will execute.
			//
			// The `lazy` is because we don't want any of this executing *right now*,
			// but rather once the runtime has started up all its resources.
			//
			// This is where we will setup our HTTP client requests.
			future
				.map(|res| {
					let (head, body) = res.into_parts();

					(head, body.concat2().wait())
				})
				.map(move |(head, chunk)| {
					let body = str::from_utf8(&chunk.unwrap()).expect("failed to convert body to str").to_string();

					ok_responses.lock().unwrap().push(Ok(http::Response::from_parts(head, body)));
				})
				.map_err(move |_err| {
					err_responses.lock().unwrap().push(Err(Error::new(ErrorKind::Other, _err)));
				})
		}));

		loop {
			let data = responses.lock().unwrap();
			if data.len() > 0 {
				if let Some(Ok(value)) = data.first() {
					assert_eq!(*value.body(), String::from("Hello, World!"));
					break;
				}
			}
		}

		// Drops the handle to force the closing of the thread when main thread leaves
		drop(_thread_handle);
	}

	#[test]
	fn patch()
	{
		let _thread_handle = start_test_server(4007);

		let mut _client = InSaleAPIClient::new();
		_client.set_endpoint("http://localhost:4007/").expect("failed to set http://localhost:4007/ as new endpoint");

		let body = "";

		let _ = _client.setup_authentication_method(Some(InSaleAuthenticationMethod::OAuth2TokenHeader("token")));
		let future = _client.patch(HashMap::new(), "/", HashMap::new(), Some("test"), body).unwrap();

		let responses: Arc<Mutex<Vec<Result<http::Response<String>, Error>>>> = Arc::new(Mutex::new(vec!()));
		let ok_responses = responses.clone();
		let err_responses = responses.clone();

		rt::run(rt::lazy(move || {
			// This is main future that the runtime will execute.
			//
			// The `lazy` is because we don't want any of this executing *right now*,
			// but rather once the runtime has started up all its resources.
			//
			// This is where we will setup our HTTP client requests.
			future
				.map(|res| {
					let (head, body) = res.into_parts();

					(head, body.concat2().wait())
				})
				.map(move |(head, chunk)| {
					let body = str::from_utf8(&chunk.unwrap()).expect("failed to convert body to str").to_string();

					ok_responses.lock().unwrap().push(Ok(http::Response::from_parts(head, body)));
				})
				.map_err(move |_err| {
					err_responses.lock().unwrap().push(Err(Error::new(ErrorKind::Other, _err)));
				})
		}));

		loop {
			let data = responses.lock().unwrap();
			if data.len() > 0 {
				if let Some(Ok(value)) = data.first() {
					assert_eq!(*value.body(), String::from("Hello, World!"));
					break;
				}
			}
		}

		// Drops the handle to force the closing of the thread when main thread leaves
		drop(_thread_handle);
	}
}