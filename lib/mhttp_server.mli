type error
(** The type of errors. *)

val pp_error : error Fmt.t
(** Pretty-printer of {!error}s. *)

module Method = H2.Method
(** Request methods. *)

module Headers = H2.Headers
(** Header fields.

    Case-insensitive key-value pairs. *)

type stop
(** Type of switches to stop a HTTP server. *)

val stop : unit -> stop
(** [stop ()] creates a new switch to stop a HTTP server. *)

val switch : stop -> unit
(** [switch stop] turns off the HTTP server associated to the given [stop]. It
    call registered (by the HTTP server) finalizers and terminates. If the given
    switch is already off, it does nothing. *)

type flow = [ `Tcp of Mnet.TCP.flow | `Tls of Mnet_tls.t ]
(** The type of connection used to communicate with the client. *)

type request = {
    meth: Method.t
  ; target: string
  ; scheme: string
  ; headers: Headers.t
}
(** A request consisting of a method (see {!module:Method}), a {i target} (the
    path requested by the client), a scheme (whether the client used ["http"] or
    ["https"]) and a headers. *)

type body = [ `V1 of H1.Body.Writer.t | `V2 of H2.Body.Writer.t ]
type reqd = [ `V1 of H1.Reqd.t | `V2 of H2.Reqd.t ]

type error_handler =
  [ `V1 | `V2 ] -> ?request:request -> error -> (Headers.t -> body) -> unit

type handler = flow -> reqd -> unit

val clear :
     ?stop:stop
  -> ?config:H1.Config.t
  -> ?ready:unit Miou.Computation.t
  -> ?error_handler:error_handler
  -> ?upgrade:(Mnet.TCP.flow -> unit)
  -> handler:handler
  -> Mnet.TCP.state
  -> port:int
  -> unit

val with_tls :
     ?stop:stop
  -> ?config:
       [ `Both of H1.Config.t * H2.Config.t
       | `H2 of H2.Config.t
       | `HTTP_1_1 of H1.Config.t ]
  -> ?ready:unit Miou_sync.Computation.t
  -> ?error_handler:error_handler
  -> Tls.Config.server
  -> ?upgrade:(Mnet_tls.t -> unit)
  -> handler:handler
  -> Mnet.TCP.state
  -> port:int
  -> unit

val peer : secure:bool -> (Ipaddr.t * int) Logs.Tag.def
