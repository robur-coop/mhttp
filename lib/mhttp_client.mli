(** HTTP client with unikernels.

    [mhttp] is a HTTP client using the Miou scheduler and [mnet]/[mnet-tls] as
    the TCP/IP stack and the TLS implementation. It does a single HTTP request
    (though may follow redirects) to a remote URI. Both HTTP protocol 1.1 and
    2.0 are supported. Both clear HTTP and HTTP with TLS (via the pure
    implementation [ocaml-tls]) are supported. A connection must be established
    via the happy-eyeballs algorithm (see [mnet-happy-eyeballs]) with a specific
    domain-name resolver (see [ocaml-dns]/[mnet-dns]).

    The first entry point of [mhttp] is the {!val:request} function, which is
    used to make an HTTP request. *)

type error =
  [ `V1 of H1.Client_connection.error
  | `V2 of H2.Client_connection.error
  | `Protocol of string
  | `Msg of string
  | `Exn of exn ]
(** The type of errors. *)

val pp_error : error Fmt.t
(** Pretty-printer of {!error}s. *)

(** {2:crypto [mhttp] and cryptography}

    When an HTTP request is made, it may require cryptographic calculations,
    which in turn require a random number generator. [mhttp] exclusively uses
    [mirage-crypto] (an OCaml implementation of cryptographic primitives, some
    of which have been proven via the [fiat-crypto] project) for all these
    cryptographic calculations.

    It is therefore necessary to initialise this random number generator
    according to the scheduler used (here Miou), and it is the sole
    responsibility of the end user to do so (furthermore, a library such as
    [mhttp] should not initialise global elements but leave control of these
    elements to the end user).

    In the case of Miou, [mirage-crypto] and [mhttp], you should initialise your
    application in this way:

    {[
      module RNG = Mirage_crypto_rng.Fortuna
      let rng () = Mirage_crypto_rng_mkernel.initialize (module RNG)
      let rng = Mkernel.map rng Mkernel.[]

      let () =
        Mkernel.(run [ rng; ... ])
        @@ fun rng ... () ->
        let@ () = fun () -> Mirage_crypto_rng_mkernel.kill msg in
        Mhttp_client.request ...
    ]} *)

module Version = H1.Version
(** Protocol Version.

    Consists of [major.minor], in H2 this is [2.0]. *)

module Status = H2.Status
(** Response Status codes.

    A three-digit integer, the result of the request. *)

(** {2:headers Headers}

    The HTTP protocol requires that the request contain certain mandatory
    information in order to communicate correctly with a server. If this
    information is not present in the [~headers] passed to {!val:request},
    [mhttp] will add it. Here are the fields that [mhttp] can add:
    - [Host] or [:authority]
    - [User-Agent]
    - [Connection]
    - [Content-Length] or [Transfer-Encoding]

    The value of these fields depends on the arguments given to {!val:request}.

    [Host] or [:authority] allows you to specify which site you want to access.
    A server can offer several sites and requires you to specify which one you
    want to communicate with. [Host] is the required field for the [http/1.1]
    protocol and [:authority] is the required field for the [h2] protocol.

    [User-Agent] is an implementation identifier used to communicate with the
    server. It has the following format: [mhttp/%%VERSION%%].

    The {!val:request} function of [mhttp] does {b not} handle request pooling.
    This means that {!val:request} only makes a single request. In this sense,
    [mhttp] always adds the [Connection] field to specify that the current
    connection with the server should be closed ([close]) as soon as the
    response has been transmitted.

    Finally, depending on the content that the user wants to send to the server,
    it is necessary to specify either the size ([Content-Length]) if the user is
    using {!val:string}, or specify that the content will be sent as a stream if
    the user is using {!val:stream}.

    The user can specify their own fields using the [~headers] option. This is a
    list containing the fields and their values. Case (lowercase or uppercase)
    and order do not matter, and duplicates are allowed (but, as mentioned
    above, [mhttp] does not generate duplicates). *)

module Headers = H2.Headers
(** Header fields.

    Case-insensitive key-value pairs. *)

(* {2 Requests and responses} *)

module Method = H2.Method
(** Request methods. *)

module Cookie = Httpcats_core.Cookie

type request = { meth: Method.t; target: string; headers: Headers.t }
(** A request consisting of a method (see {!module:Method}), a {i target} (the
    path requested by the client) and a headers. *)

type response = {
    version: Version.t
  ; status: Status.t
  ; reason: string
  ; headers: Headers.t
}
(** A response, consisting of version, status, reason (HTTP 1.1 only), and
    headers. *)

(** {2:body The body of the request}

    [mhttp] allows you to transmit content via an HTTP request. This is
    particularly useful when transmitting a form using the POST method. [mhttp]
    expects two types of content:
    + a simple [string] (see {!val:string})
    + a {i stream} which is a [string Seq.t] (see {!val:stream})

    {3:stream The body as a stream.}

    If the user wishes to transfer a large amount of content, it is advisable to
    give [mhttp] a stream, i.e. a [string Seq.t], capable of producing parts of
    the content.

    {[
      let seq_of_filename filename =
        let ic = open_in_bin filename in
        let buf = Bytes.create 0x7ff in
        let rec go () =
          let len = input ic buf 0 (Bytes.length buf) in
          if len = 0 then
            let () = close_in ic in Seq.Nil
          else
            let str = Bytes.sub_string buf 0 len in
            Seq.Cons (str, go) in
        go

      let run () =
        let body = Mhttp_client.stream (seq_of_filename "form.txt") in
        Mhttp_client.request ~uri:"http://foo.bar" ~body ...
    ]}

    [mhttp] will add (if it does not already exist) information to the request
    stating that the content is being transferred in chunks (i.e. [mhttp] adds
    the header [Transfer-Encoding: Chunked]). For more information, please refer
    to the
    {{:https://en.wikipedia.org/wiki/Chunked_transfer_encoding}Wikipedia page}.

    The [Seq] module mentions two types of sequences:
    + {i persistent} sequences
    + {i ephemeral} sequences

    In the case of [mhttp] and possible redirects that may occur before reaching
    the final resource, there are cases where we would need to retransmit the
    content {b multiple times}. [htttpcats] therefore transforms all given
    streams into {i persistent} sequences using [Seq.memoize]. *)

(** A body, consisting to a basic string or a stream ([string Seq.t]). *)
type body = String of string | Stream of string Seq.t

val string : string -> body
(** [string str] is a {!type:body} from a string. *)

val stream : string Seq.t -> body
(** [stream seq] is a {!type:body} from a sequence of bytes. *)

(** {2:certificates [mhttp] and certificates}

    When communicating securely with a server, [ocaml-tls] attempts to validate
    the certificate presented by the server. The function used to validate the
    certificate is a value of type [X509.Authenticator.t].

    By default, [mhttp] will load your system's certificates using the
    [ca-certs-nss] library and will attempt to find a {i chain of trust} between
    these certificates and the one announced by the server. This means that, by
    default, [mhttp] does not accept {i self-signed} certificates or
    certificates that are not linked to certificates available on your system.
    However, there are several ways to make [ocaml-tls] more permissive in
    certificate validation.

    {3 Accept anything and be unsecure}

    In a case where we want to iterate fairly quickly without considering
    TLS-related issues, we could accept all certificates without performing any
    validation. Here's how to do it:

    {[
      let run () =
        let authenticator ?ip:_ ~host:_ _ = Ok None in
        Mhttp_client.request ~authenticator ~uri:"https://foo.bar" ...
    ]}

    However, we {b do not recommend} using such an [X509.Authenticator.t] in
    production, as a certificate issued by a third party (such as an attacker)
    would also be accepted.

    {3 Self-signed certificat.}

    If you have a certificate, you can obtain its {i fingerprint} and generate
    an {i authenticator} from it:

    {[
      $ openssl x509 -noout -fingerprint -sha1 -inform pem -in cert.pem | \
        cut -d'=' -f2 | \
        tr -d ':'
      8C452106C58135CA638C1BF2AF019BB00A8A44B3
    ]}

    {[
      let run () =
        let authenticator = X509.Authenticator.cert_fingerprint
          ~time:(fun () -> Some (Ptime_clock.now ()))
          ~hash:`SHA1
          "8C452106C58135CA638C1BF2AF019BB00A8A44B3" in
        Mhttp_client.request ~authenticator ~uri:"https://foo.bar" ...
    ]}

    If your server uses the [cert.pem] certificate, [mhttp] and [ocaml-tls] will
    verify that this is indeed the certificate being advertised (and an attacker
    cannot corrupt the communication). *)

(** {2:alpn [mhttp] and ALPN negotiation}

    There are two protocols for obtaining resources via HTTP: the [http/1.1]
    protocol and the [h2] protocol. [mhttp] manages both protocols and can
    perform what is known as ALPN negotiation to choose one of these two
    protocols. This negotiation {b only} takes place via TLS. Some servers only
    implement one of the two protocols (often [http/1.1]). However, [mhttp]
    always prioritises the [h2] protocol by default.

    The user can also {i force} the use of one of the two protocols by
    specifying a configuration for the [http/1.1] protocol (using [H1.Config.t]
    and [`HTTP_1_1]) or a configuration for the [h2] protocol (using
    [H2.Config.t] and [`H2]).

    If TLS is not involved in the communication, the [http/1.1] protocol will
    always be chosen. *)

(** {2:handler Response handler}

    [mhttp] expects a function [fn] that is capable of handling {b multiple}
    responses, with {i chunks} corresponding to the body of these responses. In
    the simplest case, the user only has to handle a single response, which is
    given to the function [fn] and must {i consume} the content of the response.
    Here is a practical example of how to obtain the response and its content:

    {[
    let fn _meta _req _resp buf chunk =
      match chunk with
      | Some str -> Buffer.add_string buf str; buf
      | None -> buf
    in
    let buf = Buffer.create 0x100 in
    let uri = "http://foo.bar" in
    let result = Mhttp_client.request ~follow_redirect:false ~fn ~uri buf in
    match result with
    | Ok (response, buf) ->
        let contents = Buffer.contents buf in
        Ok (response, contents)
    | Error _ as err -> err
    ]}

    The [fn] function has several arguments, such as:
    - [meta], which corresponds to information related to the protocols
      underlying HTTP (TCP/IP and TLS), see {!type:meta}.
    - [request], which is the request sent by [mhttp] (possibly containing new
      information described {{!section:headers}here}), see {!type:request}.
    - [response], which is the response given by the HTTP server, see
      {!type:response}.
    - [buf] or [acc], which is the accumulator given by the user. It can be a
      value of any types (['a]).
    - [chunk], which is a part of the response content that the user should save
      or process. If the value is [None], it means that the {b current} response
      no longer has any content.

    However, redirects may occur. As already explained (see {!section:body}), we
    need to forward the same content to the redirect. In this case, [fn] will be
    executed several times for all responses received throughout the redirects.

    Here is an example that aggregates all responses and their content in the
    form of a list in the case of one or more redirects:

    {[
    let fn _meta _req resp state chunk =
      match (state, chunk) with
      | `Body (_, []) -> assert false
      | `Body (chunks, resp :: resps), None ->
          let contents = String.concat "" (List.rev chunks) in
          let resp = (resp, contents) in
          `Responses (resp :: resps)
      | `Body (chunks, resps), Some str -> `Body (str :: chunks, resps)
      | `Responses resps, Some str ->
          let resps = (resp, "") :: resps in
          `Body ([ str ], resps)
      | `Responses resps, None ->
          let resps = (resp, "") :: resps in
          `Response resps
    in
    let uri = "http://foo.bar" in
    let result = Mhttp_client.request ~fn ~uri (`Response []) in
    match result with
    | Ok (_, `Responses resps) -> Ok resps
    | Ok (_, `Body _) -> assert false
    | Error _ as err -> err
    ]}

    It is also possible to simply filter the responses and only process the
    final response.

    {[
      let fn _meta _req resp buf chunk =
        if Mhttp_client.Status.is_redirection resp.status = false
        then match chunk with
          | Some str -> Buffer.add_string buf str; buf
          | None -> buf
        else buf in
      let uri = "http://foo.bar" in
      let buf = Buffer.create 0x100 in
      Mhttp_client.request ~fn ~uri buf ...
    ]} *)

type meta = (Ipaddr.t * int) * Tls.Core.epoch_data option
(** It may be interesting to know where the response comes from (the server's IP
    address and the configuration chosen during the TLS handshake). In this
    sense, all this information is condensed into the {i meta} type and given to
    the {{!section:handler}response handler}. *)

type 'a handler = meta -> request -> response -> 'a -> string option -> 'a
(** Type of response handlers (see {{!section:handler} this section} for more
    details). *)

(** {2:redirections [mhttp] and redirections}

    [mhttp] can handle redirects and bring the user directly to the final
    response. We recommend that you learn how [mhttp] {{!section:body} handles}
    the content of your request during a redirect, as well as how to
    {{!section:handler} handle} multiple responses within your {i handler}.

    By default, [mhttp] attempts a maximum of 5 redirects. This parameter can be
    changed with the [~max_redirect] option. The user can also prevent [mhttp]
    from following redirects (default behaviour) by specifying
    [~follow_redirect:false]. *)

(** {2:cookies [mhttp] and cookies}

    There are redirection patterns where the server attempts to save a cookie
    and redirect the user to another resource. In this case, it is necessary for
    [mhttp] to keep the cookies from the first response in order to send them
    back via the next request to the proposed redirection.

    The user can {i filter} these cookies throughout the redirects and thus keep
    some and delete others. The [~filter] argument allows you to specify what
    you want to keep and what you want to reject between the cookies currently
    used by [mhttp] and those that the server wants to add.

    By default, [mhttp] keeps the latest version of all cookies given by the
    server (whether they have expired or not). *)

type filter =
  (string * string) list -> Cookie.cookie list -> (string * string) list
(** Type of functions to filter cookies. *)

val request :
     ?config:[ `HTTP_1_1 of H1.Config.t | `H2 of H2.Config.t ]
  -> ?tls_config:Tls.Config.client
  -> ?authenticator:X509.Authenticator.t
  -> ?meth:H1.Method.t
  -> ?headers:(string * string) list
  -> ?body:body
  -> ?max_redirect:int
  -> ?follow_redirect:bool
  -> happy_eyeballs:Mnet_happy_eyeballs.t
  -> ?cookies:filter
  -> fn:'a handler
  -> uri:string
  -> 'a
  -> (response * 'a, error) result
(** [request] allows you to make an HTTP request and obtain the response.
    Several options are available, all of which are described above. Here is a
    summary of the options and the associated sections explaining their uses in
    detail:
    - [?config] is useful if you need to force a particular protocol with the
      server (see {!section:alpn}).
    - [?tls_config] allows you to specify a TLS configuration that takes
      precedence over anything [mhttp] can infer about this protocol (including
      which certificates we should accept or ALPN negotiation).
    - [?authenticator] allows you to specify how you would like to validate
      certificates during TLS communication (see {!section:certificates}).
    - [?meth] allows you to specify the HTTP method you would like to use (see
      {!module:Method}).
    - [?headers] allows you to specify the fields and their values that you want
      to send to the server (see {!section:headers}).
    - [?body] allows you to specify the content of your request (see
      {!section:body}).
    - [?max_redirect] & [?follow_redirect] specify how [mhttp] behaves with
      regard to redirection (see {!section:redirections}).
    - [?resolver] allows you to specify the domain name resolution mechanism
      (see {!section:dns})
    - [?cookies] allows the user to control which cookies must be kept during
      redirections (see {!section:cookies}).
    - [fn] & ['a] handles the responses received by the server (see
      {!section:handler}).
    - [uri] is the target of your request (for example, [https://foo.bar/]).

    It is {b mandatory} to initialise a random number generator (see
    {!section:crypto} before using [request] (which may involve cryptographic
    calculations). *)

(**/**)

type uri =
  bool * string * (string * string option) option * string * int option * string

val decode_uri : string -> (uri, [> `Msg of string ]) result

val resolve_location :
  uri:string -> location:string -> (string, [> `Msg of string ]) result
