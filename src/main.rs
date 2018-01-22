//! An example [SOCKSv5] proxy server on top of futures
//!
//! [SOCKSv5]: https://www.ietf.org/rfc/rfc1928.txt
//!
//! This program is intended to showcase many aspects of the futures crate and
//! I/O integration, explaining how many of the features can interact with one
//! another and also provide a concrete example to see how easily pieces can
//! interoperate with one another.
//!
//! A SOCKS proxy is a relatively easy protocol to work with. Each TCP
//! connection made to a server does a quick handshake to determine where data
//! is going to be proxied to, another TCP socket is opened up to this
//! destination, and then bytes are shuffled back and forth between the two
//! sockets until EOF is reached.
//!
//! This server implementation is relatively straightforward, but
//! architecturally has a few interesting pieces:
//!
//! * The entire server only has one buffer to read/write data from. This global
//!   buffer is shared by all connections and each proxy pair simply reads
//!   through it. This is achieved by waiting for both ends of the proxy to be
//!   ready, and then the transfer is done.
//!
//! * Initiating a SOCKS proxy connection may involve a DNS lookup, which
//!   is done with the TRust-DNS futures-based resolver. This demonstrates the
//!   ease of integrating a third-party futures-based library into our futures
//!   chain.
//!
//! * The entire SOCKS handshake is implemented using the various combinators in
//!   the `futures` crate as well as the `tokio_core::io` module. The actual
//!   proxying of data, however, is implemented through a manual implementation
//!   of `Future`. This shows how it's easy to transition back and forth between
//!   the two, choosing whichever is the most appropriate for the situation at
//!   hand.
//!
//! You can try out this server with `cargo test` or just `cargo run` and
//! throwing connections at it yourself, and there should be plenty of comments
//! below to help walk you through the implementation as well!

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate futures;
#[macro_use]
extern crate tokio_core;
extern crate tokio_io;
extern crate trust_dns;
extern crate trust_dns_resolver;

use std::cell::RefCell;
use std::env;
use std::io::{self, Read, Write};
use std::net::{Shutdown};
use std::net::{SocketAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::rc::Rc;
use std::str;
use std::time::Duration;

use futures::future;
use futures::{Future, Stream, Poll, Async};
use tokio_io::io::{read_exact, write_all, Window};
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::reactor::{Core, Handle, Timeout};
use trust_dns::rr::{Name};
use trust_dns_resolver::ResolverFuture;
use trust_dns_resolver::config::*;

fn main() {
    drop(env_logger::init());

    // Take the first command line argument as an address to listen on, or fall
    // back to just some localhost default.
    let addr = env::args().nth(1).unwrap_or("127.0.0.1:8080".to_string());
    let addr = addr.parse::<SocketAddr>().unwrap();

    // Initialize the various data structures we're going to use in our server.
    // Here we create the event loop, the global buffer that all threads will
    // read/write into, and the bound TCP listener itself.
    let mut lp = Core::new().unwrap();
    let buffer = Rc::new(RefCell::new(vec![0; 64 * 1024]));
    let handle = lp.handle();
    let listener = TcpListener::bind(&addr, &handle).unwrap();

    // Use TRust-DNS's resolver with all defaults (including, using the system
    // DNS server) rather than trying to do DNS lookup ourselves

    // Unfortunately the ResolverFuture is not cloneable.. so we have to create one
    // for each client.  This is probably terribly inefficient.
    // let resolver = ResolverFuture::new(
    //     ResolverConfig::default(),
    //     ResolverOpts::default(),
    //     &handle.clone());

    // Construct a future representing our server. This future processes all
    // incoming connections and spawns a new task for each client which will do
    // the proxy work.
    //
    // This essentially means that for all incoming connections, those received
    // from `listener`, we'll create an instance of `Client` and convert it to a
    // future representing the completion of handling that client. This future
    // itself is then *spawned* onto the event loop to ensure that it can
    // progress concurrently with all other connections.
    println!("Listening for socks5 proxy connections on {}", addr);
    let clients = listener.incoming().map(move |(socket, addr)| {
        (Client {
            buffer: buffer.clone(),
            // if only this were cloneable...
            // dns: resolver.clone(),
            handle: handle.clone(),
        }.serve(socket), addr)
    });
    let handle = lp.handle();
    let server = clients.for_each(|(client, addr)| {
        handle.spawn(client.then(move |res| {
            match res {
                Ok((a, b)) => {
                    println!("proxied {}/{} bytes for {}", a, b, addr)
                }
                Err(e) => println!("error for {}: {}", addr, e),
            }
            future::ok(())
        }));
        Ok(())
    });

    // Now that we've got our server as a future ready to go, let's run it!
    //
    // This `run` method will return the resolution of the future itself, but
    // our `server` futures will resolve to `io::Result<()>`, so we just want to
    // assert that it didn't hit an error.
    lp.run(server).unwrap();
}

// Data used to when processing a client to perform various operations over its
// lifetime.
struct Client {
    buffer: Rc<RefCell<Vec<u8>>>,
    // dns: ResolverFuture,
    handle: Handle,
}

impl Client {
    /// This is the main entry point for starting a SOCKS proxy connection.
    ///
    /// This function is responsible for constructing the future which
    /// represents the final result of the proxied connection. In this case
    /// we're going to return an `IoFuture<T>`, an alias for
    /// `Future<Item=T, Error=io::Error>`, which indicates how many bytes were
    /// proxied on each half of the connection.
    ///
    /// The first part of the SOCKS protocol with a remote connection is for the
    /// server to read one byte, indicating the version of the protocol. The
    /// `read_exact` combinator is used here to entirely fill the specified
    /// buffer, and we can use it to conveniently read off one byte here.
    ///
    /// Once we've got the version byte, we then delegate to the below
    /// `serve_vX` methods depending on which version we found.
    fn serve(self, conn: TcpStream)
              -> Box<Future<Item=(u64, u64), Error=io::Error>> {
        Box::new(read_exact(conn, [0u8]).and_then(|(conn, buf)| {
            match buf[0] {
                v5::VERSION => self.serve_v5(conn),
                v4::VERSION => self.serve_v4(conn),

                // If we hit an unknown version, we return a "terminal future"
                // which represents that this future has immediately failed. In
                // this case the type of the future is `io::Error`, so we use a
                // helper function, `other`, to create an error quickly.
                _ => mybox(future::err(other("unknown version"))),
            }
        }))
    }

    /// Current SOCKSv4 is not implemented, but v5 below has more fun details!
    fn serve_v4(self, _conn: TcpStream)
                -> Box<Future<Item=(u64, u64), Error=io::Error>> {
        mybox(future::err(other("unimplemented")))
    }

    /// The meat of a SOCKSv5 handshake.
    ///
    /// This method will construct a future chain that will perform the entire
    /// suite of handshakes, and at the end if we've successfully gotten that
    /// far we'll initiate the proxying between the two sockets.
    ///
    /// As a side note, you'll notice a number of `.boxed()` annotations here to
    /// box up intermediate futures. From a library perspective, this is not
    /// necessary, but without them the compiler is pessimistically slow!
    /// Essentially, the `.boxed()` annotations here improve compile times, but
    /// are otherwise not necessary.
    fn serve_v5(self, conn: TcpStream)
                -> Box<Future<Item=(u64, u64), Error=io::Error>> {
        // First part of the SOCKSv5 protocol is to negotiate a number of
        // "methods". These methods can typically be used for various kinds of
        // proxy authentication and such, but for this server we only implement
        // the `METH_NO_AUTH` method, indicating that we only implement
        // connections that work with no authentication.
        //
        // First here we do the same thing as reading the version byte, we read
        // a byte indicating how many methods. Afterwards we then read all the
        // methods into a temporary buffer.
        //
        // Note that we use `and_then` here to chain computations after one
        // another, but it also serves to simply have fallible computations,
        // such as checking whether the list of methods contains `METH_NO_AUTH`.
        let num_methods = read_exact(conn, [0u8]);
        let authenticated = mybox(num_methods.and_then(|(conn, buf)| {
            read_exact(conn, vec![0u8; buf[0] as usize])
        }).and_then(|(conn, buf)| {
            if buf.contains(&v5::METH_NO_AUTH) {
                Ok(conn)
            } else {
                Err(other("no supported method given"))
            }
        }));

        // After we've concluded that one of the client's supported methods is
        // `METH_NO_AUTH`, we "ack" this to the client by sending back that
        // information. Here we make use of the `write_all` combinator which
        // works very similarly to the `read_exact` combinator.
        let part1 = mybox(authenticated.and_then(|conn| {
            write_all(conn, [v5::VERSION, v5::METH_NO_AUTH])
        }));

        // Next up, we get a selected protocol version back from the client, as
        // well as a command indicating what they'd like to do. We just verify
        // that the version is still v5, and then we only implement the
        // "connect" command so we ensure the proxy sends that.
        //
        // As above, we're using `and_then` not only for chaining "blocking
        // computations", but also to perform fallible computations.
        let ack = mybox(part1.and_then(|(conn, _)| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| {
                if buf[0] == v5::VERSION {
                    Ok(conn)
                } else {
                    Err(other("didn't confirm with v5 version"))
                }
            })
        }));
        let command = mybox(ack.and_then(|conn| {
            read_exact(conn, [0u8]).and_then(|(conn, buf)| {
                if buf[0] == v5::CMD_CONNECT {
                    Ok(conn)
                } else {
                    Err(other("unsupported command"))
                }
            })
        }));

        // After we've negotiated a command, there's one byte which is reserved
        // for future use, so we read it and discard it. The next part of the
        // protocol is to read off the address that we're going to proxy to.
        // This address can come in a number of forms, so we read off a byte
        // which indicates the address type (ATYP).
        //
        // Depending on the address type, we then delegate to different futures
        // to implement that particular address format.
        let resv = command.and_then(|c| read_exact(c, [0u8]).map(|c| c.0));
        let atyp = resv.and_then(|c| read_exact(c, [0u8]));
        let handle = self.handle.clone();
        let addr = mybox(atyp.and_then(move |(c, buf)| {
            match buf[0] {
                // For IPv4 addresses, we read the 4 bytes for the address as
                // well as 2 bytes for the port.
                v5::ATYP_IPV4 => {
                    mybox(read_exact(c, [0u8; 6]).map(|(c, buf)| {
                        let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                        let port = ((buf[4] as u16) << 8) | (buf[5] as u16);
                        let addr = SocketAddrV4::new(addr, port);
                        (c, SocketAddr::V4(addr))
                    }))
                }

                // For IPv6 addresses there's 16 bytes of an address plus two
                // bytes for a port, so we read that off and then keep going.
                v5::ATYP_IPV6 => {
                    mybox(read_exact(c, [0u8; 18]).map(|(conn, buf)| {
                        let a = ((buf[0] as u16) << 8) | (buf[1] as u16);
                        let b = ((buf[2] as u16) << 8) | (buf[3] as u16);
                        let c = ((buf[4] as u16) << 8) | (buf[5] as u16);
                        let d = ((buf[6] as u16) << 8) | (buf[7] as u16);
                        let e = ((buf[8] as u16) << 8) | (buf[9] as u16);
                        let f = ((buf[10] as u16) << 8) | (buf[11] as u16);
                        let g = ((buf[12] as u16) << 8) | (buf[13] as u16);
                        let h = ((buf[14] as u16) << 8) | (buf[15] as u16);
                        let addr = Ipv6Addr::new(a, b, c, d, e, f, g, h);
                        let port = ((buf[16] as u16) << 8) | (buf[17] as u16);
                        let addr = SocketAddrV6::new(addr, port, 0, 0);
                        (conn, SocketAddr::V6(addr))
                    }))
                }

                // The SOCKSv5 protocol not only supports proxying to specific
                // IP addresses, but also arbitrary hostnames. This allows
                // clients to perform hostname lookups within the context of the
                // proxy server rather than the client itself.
                //
                // Since the first publication of this code, several
                // futures-based DNS libraries appeared, and as a demonstration
                // of integrating third-party asynchronous code into our chain,
                // we will use one of them, TRust-DNS.
                //
                // The protocol here is to have the next byte indicate how many
                // bytes the hostname contains, followed by the hostname and two
                // bytes for the port. To read this data, we execute two
                // respective `read_exact` operations to fill up a buffer for
                // the hostname.
                //
                // Finally, to perform the "interesting" part, we process the
                // buffer and pass the retrieved hostname to a resolver future
                // if it wasn't already recognized as an IP address. TRust-DNS
                // handles all of the complexity from there out.
                v5::ATYP_DOMAIN => {
                    mybox(read_exact(c, [0u8]).and_then(|(conn, buf)| {
                        read_exact(conn, vec![0u8; buf[0] as usize + 2])
                    }).and_then(move |(conn, buf)| {
                        let (name, port) = match name_port(&buf) {
                            Ok(UrlHost::Name(name, port)) => (name, port),
                            Ok(UrlHost::Addr(addr)) => {
                                return mybox(future::ok((conn, addr)))
                            }
                            Err(e) => return mybox(future::err(e)),
                        };

                        debug!("dns lookup {}", name);

                        let dns = ResolverFuture::new(
                                ResolverConfig::default(),
                                ResolverOpts::default(),
                                &handle);

                        let lookup_future = dns.lookup_ip(&name.to_string());
                        let address_future =
                            lookup_future
                                .map_err(|e|
                                    other(&format!("dns error: {}", e)))
                                .and_then(move |ips| {
                                    let ip = ips.iter().next()
                                        .expect(
                                            &format!("lookup failed for: {}",
                                            &name));
                                    mybox(future::ok(ip))
                                });
                        mybox(address_future.map(move |addr|
                            (conn, SocketAddr::new(addr, port))))
                    }))
                }

                n => {
                    let msg = format!("unknown ATYP received: {}", n);
                    mybox(future::err(other(&msg)))
                }
            }
        }));

        // Now that we've got a socket address to connect to, let's actually
        // create a connection to that socket!
        //
        // To do this, we use our `handle` field, a handle to the event loop, to
        // issue a connection to the address we've figured out we're going to
        // connect to. Note that this `tcp_connect` method itself returns a
        // future resolving to a `TcpStream`, representing how long it takes to
        // initiate a TCP connection to the remote.
        //
        // We wait for the TCP connect to get fully resolved before progressing
        // to the next stage of the SOCKSv5 handshake, but we keep ahold of any
        // possible error in the connection phase to handle it in a moment.
        let handle = self.handle.clone();
        let connected = mybox(addr.and_then(move |(c, addr)| {
            debug!("proxying to {}", addr);
            TcpStream::connect(&addr, &handle).then(move |c2| Ok((c, c2, addr)))
        }));

        // Once we've gotten to this point, we're ready for the final part of
        // the SOCKSv5 handshake. We've got in our hands (c2) the client we're
        // going to proxy data to, so we write out relevant information to the
        // original client (c1) the "response packet" which is the final part of
        // this handshake.
        let handshake_finish = mybox(connected.and_then(|(c1, c2, addr)| {
            let mut resp = [0u8; 32];

            // VER - protocol version
            resp[0] = 5;

            // REP - "reply field" -- what happened with the actual connect.
            //
            // In theory this should reply back with a bunch more kinds of
            // errors if possible, but for now we just recognize a few concrete
            // errors.
            resp[1] = match c2 {
                Ok(..) => 0,
                Err(ref e) if e.kind() == io::ErrorKind::ConnectionRefused => 5,
                Err(..) => 1,
            };

            // RSV - reserved
            resp[2] = 0;

            // ATYP, BND.ADDR, and BND.PORT
            //
            // These three fields, when used with a "connect" command
            // (determined above), indicate the address that our proxy
            // connection was bound to remotely. There's a variable length
            // encoding of what's actually written depending on whether we're
            // using an IPv4 or IPv6 address, but otherwise it's pretty
            // standard.
            let addr = match c2.as_ref().map(|r| r.local_addr()) {
                Ok(Ok(addr)) => addr,
                Ok(Err(..)) |
                Err(..) => addr,
            };
            let pos = match addr {
                SocketAddr::V4(ref a) => {
                    resp[3] = 1;
                    resp[4..8].copy_from_slice(&a.ip().octets()[..]);
                    8
                }
                SocketAddr::V6(ref a) => {
                    resp[3] = 4;
                    let mut pos = 4;
                    for &segment in a.ip().segments().iter() {
                        resp[pos] = (segment >> 8) as u8;
                        resp[pos + 1] = segment as u8;
                        pos += 2;
                    }
                    pos
                }
            };
            resp[pos] = (addr.port() >> 8) as u8;
            resp[pos + 1] = addr.port() as u8;

            // Slice our 32-byte `resp` buffer to the actual size, as it's
            // variable depending on what address we just encoding. Once that's
            // done, write out the whole buffer to our client.
            //
            // The returned type of the future here will be `(TcpStream,
            // TcpStream)` representing the client half and the proxy half of
            // the connection.
            let mut w = Window::new(resp);
            w.set_end(pos + 2);
            write_all(c1, w).and_then(|(c1, _)| {
                c2.map(|c2| (c1, c2))
            })
        }));

        // Phew! If you've gotten this far, then we're now entirely done with
        // the entire SOCKSv5 handshake!
        //
        // In order to handle ill-behaved clients, however, we have an added
        // feature here where we'll time out any initial connect operations
        // which take too long.
        //
        // Here we create a timeout future, using the `Timeout::new` method,
        // which will create a future that will resolve to `()` in 10 seconds.
        // We then apply this timeout to the entire handshake all at once by
        // performing a `select` between the timeout and the handshake itself.
        let timeout = Timeout::new(Duration::new(10, 0), &self.handle).unwrap();
        let pair = mybox(handshake_finish.map(Ok).select(timeout.map(Err)).then(|res| {
            match res {
                // The handshake finished before the timeout fired, so we
                // drop the future representing the timeout, canceling the
                // timeout, and then return the pair of connections the
                // handshake resolved with.
                Ok((Ok(pair), _timeout)) => Ok(pair),

                // The timeout fired before the handshake finished. In this
                // case we drop the future representing the handshake, which
                // cleans up the associated connection and all other
                // resources.
                //
                // This automatically "cancels" any I/O associated with the
                // handshake: reads, writes, TCP connects, etc. All of those
                // I/O resources are owned by the future, so if we drop the
                // future they're all released!
                Ok((Err(()), _handshake)) => {
                    Err(other("timeout during handshake"))
                }

                // One of the futures (handshake or timeout) hit an error
                // along the way. We're not entirely sure which at this
                // point, but in any case that shouldn't happen, so we just
                // keep propagating along the error.
                Err((e, _other)) => Err(e),
            }
        }));

        // At this point we've *actually* finished the handshake. Not only have
        // we read/written all the relevant bytes, but we've also managed to
        // complete in under our allotted timeout.
        //
        // At this point the remainder of the SOCKSv5 proxy is shuttle data back
        // and for between the two connections. That is, data is read from `c1`
        // and written to `c2`, and vice versa.
        //
        // To accomplish this, we put both sockets into their own `Rc` and then
        // create two independent `Transfer` futures representing each half of
        // the connection. These two futures are `join`ed together to represent
        // the proxy operation happening.
        let buffer = self.buffer.clone();
        mybox(pair.and_then(|(c1, c2)| {
            let c1 = Rc::new(c1);
            let c2 = Rc::new(c2);

            let half1 = Transfer::new(c1.clone(), c2.clone(), buffer.clone());
            let half2 = Transfer::new(c2, c1, buffer);
            half1.join(half2)
        }))
    }
}

fn mybox<F: Future + 'static>(f: F) -> Box<Future<Item=F::Item, Error=F::Error>> {
    Box::new(f)
}

/// A future representing reading all data from one side of a proxy connection
/// and writing it to another.
///
/// This future, unlike the handshake performed above, is implemented via a
/// custom implementation of the `Future` trait rather than with combinators.
/// This is intended to show off how the combinators are not all that can be
/// done with futures, but rather more custom (or optimized) implementations can
/// be implemented with just a trait impl!
struct Transfer {
    // The two I/O objects we'll be reading.
    reader: Rc<TcpStream>,
    writer: Rc<TcpStream>,

    // The shared global buffer that all connections on our server are using.
    buf: Rc<RefCell<Vec<u8>>>,

    // If the reads are outpacing the writes, then an ephemeral buffer will
    // be stored within the Transfer object, keeping the bytes that were
    // last unable to be written.
    overrun: RefCell<Option<Vec<u8>>>,

    // The number of bytes we've written so far.
    amt: u64,
}

impl Transfer {
    fn new(reader: Rc<TcpStream>,
           writer: Rc<TcpStream>,
           buffer: Rc<RefCell<Vec<u8>>>) -> Transfer {
        Transfer {
            reader: reader,
            writer: writer,
            buf: buffer,
            overrun: RefCell::new(None),
            amt: 0,
        }
    }
}

// Here we implement the `Future` trait for `Transfer` directly. This does not
// use any combinators, and shows how you might implement it in custom
// situations if needed.
impl Future for Transfer {
    // Our future resolves to the number of bytes transferred, or an I/O error
    // that happens during the connection, if any.
    type Item = u64;
    type Error = io::Error;

    /// Attempts to drive this future to completion, checking if it's ready to
    /// be completed.
    ///
    /// This method is the core foundation of completing a future over time. It
    /// is intended to never block and return "quickly" to ensure that it
    /// doesn't block the event loop.
    ///
    /// Completion for our `Transfer` future is defined when one side hits EOF
    /// and we've written all remaining data to the other side of the
    /// connection. The behavior of `Future::poll` is in general not specified
    /// after a future resolves (e.g. in this case returns an error or how many
    /// bytes were transferred), so we don't need to maintain state beyond that
    /// point.
    fn poll(&mut self) -> Poll<u64, io::Error> {
        let mut buffer = self.buf.borrow_mut();

        // Here we loop over the two TCP halves, reading all data from one
        // connection and writing it to another. The crucial performance aspect
        // of this server, however, is that we wait until both the read half and
        // the write half are ready on the connection, allowing the buffer to
        // only be temporarily used in a small window for all connections.
        loop {
            let write_ready = self.writer.poll_write().is_ready();
            if !write_ready {
                return Ok(Async::NotReady)
            }

            let mut new_overrun = self.overrun.borrow_mut();
            if new_overrun.is_some() {

                // We have leftovers from the last time we read.
                // Flush those leftovers before doing anything else.
                *new_overrun = {
                    let buf = new_overrun.as_ref().unwrap();
                    let m = try!((&*self.writer).write(&buf));
                    if m < buf.len() {
                        // Still more leftovers...
                        let remain = buf[m as usize..].to_vec();
                        debug!("We have leftovers: {}", remain.len());
                        Some(remain)
                    } else {
                        // Finally cleaned our plate
                        debug!("Leftovers done");
                        None
                    }
                };

            } else {

                // We need to read more before continuing.
                let read_ready = self.reader.poll_read().is_ready();
                if !read_ready {
                    return Ok(Async::NotReady)
                }

                let n = try_nb!((&*self.reader).read(&mut buffer));
                if n == 0 {
                    // Source of the read has hit EOF.  Shut down both ends.
                    try!(self.writer.shutdown(Shutdown::Write));
                    return Ok(self.amt.into())
                }
                self.amt += n as u64;

                // Try writing with non-blocking IO
                let m = try_nb!((&*self.writer).write(&buffer[..n]));
                if m < n {
                    // We have leftovers, write them next time
                    let remain = buffer[m as usize..].to_vec();
                    debug!("We have leftovers: {}", remain.len());
                    *new_overrun = Some(remain);
                } else {
                    // Write completed
                    *new_overrun = None
                }
            }
        }
    }
}

fn other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

enum UrlHost {
    Name(Name, u16),
    Addr(SocketAddr),
}

// Extracts the name and port from addr_buf and returns them, converting
// the name to the form that the trust-dns client can use. If the original
// name can be parsed as an IP address, makes a SocketAddr from that
// address and the port and returns it; we skip DNS resolution in that
// case.
fn name_port(addr_buf: &[u8]) -> io::Result<UrlHost> {
    // The last two bytes of the buffer are the port, and the other parts of it
    // are the hostname.
    let hostname = &addr_buf[..addr_buf.len() - 2];
    let hostname = try!(str::from_utf8(hostname).map_err(|_e| {
        other("hostname buffer provided was not valid utf-8")
    }));
    let pos = addr_buf.len() - 2;
    let port = ((addr_buf[pos] as u16) << 8) | (addr_buf[pos + 1] as u16);

    if let Ok(ip) = hostname.parse() {
        return Ok(UrlHost::Addr(SocketAddr::new(ip, port)))
    }
    let name = try!(Name::parse(hostname, Some(&Name::root())).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, e.to_string())
    }));
    Ok(UrlHost::Name(name, port))
}

// Various constants associated with the SOCKS protocol

#[allow(dead_code)]
mod v5 {
    pub const VERSION: u8 = 5;

    pub const METH_NO_AUTH: u8 = 0;
    pub const METH_GSSAPI: u8 = 1;
    pub const METH_USER_PASS: u8 = 2;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
    pub const CMD_UDP_ASSOCIATE: u8 = 3;

    pub const ATYP_IPV4: u8 = 1;
    pub const ATYP_IPV6: u8 = 4;
    pub const ATYP_DOMAIN: u8 = 3;
}

#[allow(dead_code)]
mod v4 {
    pub const VERSION: u8 = 4;

    pub const CMD_CONNECT: u8 = 1;
    pub const CMD_BIND: u8 = 2;
}