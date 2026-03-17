open Mhttp

let peer ~secure =
  let scheme = if secure then "https" else "http" in
  let pp ppf (ipaddr, port) =
    Fmt.pf ppf "%s%a:%d" scheme Ipaddr.pp ipaddr port
  in
  Logs.Tag.def ~doc:"HTTP (unikernel) peer" "mhttp.peer" pp

let clear_peer = peer ~secure:false
let secure_peer = peer ~secure:true
let inhibit fn v = try fn v with _exn -> ()

module TCP_and_H1 = struct
  include TCP

  let shutdown flow = function `read -> () | value -> shutdown flow value
end

module H2_Server_connection = struct
  include H2.Server_connection

  let next_read_operation t =
    (next_read_operation t :> [ `Close | `Read | `Yield | `Upgrade ])

  let next_write_operation t =
    (next_write_operation t
      :> [ `Close of int
         | `Write of Bstr.t Faraday.iovec list
         | `Yield
         | `Upgrade ])
end

module A = Runtime.Make (TLS) (H1.Server_connection)
module B = Runtime.Make (TCP_and_H1) (H1.Server_connection)
module C = Runtime.Make (TLS) (H2_Server_connection)

type error =
  [ `V1 of H1.Server_connection.error
  | `V2 of H2.Server_connection.error
  | `Protocol of string ]

type stop = {
    mutex: Miou.Mutex.t
  ; condition: Miou.Condition.t
  ; flag: bool Atomic.t
}

let pp_error ppf = function
  | `V1 `Bad_request -> Fmt.string ppf "Bad HTTP/1.1 request"
  | `V1 `Bad_gateway -> Fmt.string ppf "Bad HTTP/1.1 gateway"
  | `V1 `Internal_server_error | `V2 `Internal_server_error ->
      Fmt.string ppf "Internal server error"
  | `V1 (`Exn exn) | `V2 (`Exn exn) ->
      Fmt.pf ppf "Unknown exception: %s" (Printexc.to_string exn)
  | `V2 `Bad_request -> Fmt.string ppf "Bad H2 request"
  | `Protocol msg -> Fmt.string ppf msg

module Method = H2.Method
module Headers = H2.Headers

type flow = [ `Tcp of Mnet.TCP.flow | `Tls of Mnet_tls.t ]

type request = {
    meth: Method.t
  ; target: string
  ; scheme: string
  ; headers: Headers.t
}

type body = [ `V1 of H1.Body.Writer.t | `V2 of H2.Body.Writer.t ]
type reqd = [ `V1 of H1.Reqd.t | `V2 of H2.Reqd.t ]

type error_handler =
  [ `V1 | `V2 ] -> ?request:request -> error -> (Headers.t -> body) -> unit

type handler = flow -> reqd -> unit

let request_from_h1 ~scheme { H1.Request.meth; target; headers; _ } =
  let headers = Headers.of_list (H1.Headers.to_list headers) in
  { meth; target; scheme; headers }

let request_from_h2 { H2.Request.meth; target; scheme; headers } =
  { meth; target; scheme; headers }

let http_1_1_server_connection ~config ~user's_error_handler ?upgrade
    ~user's_handler flow =
  let scheme = "http" in
  let read_buffer_size = config.H1.Config.read_buffer_size in
  let error_handler ?request err respond =
    let request = Option.map (request_from_h1 ~scheme) request in
    let err = `V1 err in
    let respond hdrs =
      let hdrs = H1.Headers.of_list (Headers.to_list hdrs) in
      let body = respond hdrs in
      `V1 body
    in
    user's_error_handler `V1 ?request err respond
  in
  let request_handler reqd = user's_handler (`Tcp flow) (`V1 reqd) in
  let conn =
    H1.Server_connection.create ~config ~error_handler request_handler
  in
  let tags =
    let (ipaddr, port), _ = Mnet.TCP.peers flow in
    let tags = Mnet.TCP.tags flow in
    Logs.Tag.add clear_peer (ipaddr, port) tags
  in
  let finally = inhibit Mnet.TCP.close in
  let res = Miou.Ownership.create ~finally flow in
  Miou.Ownership.own res;
  Miou.await_exn (B.run conn ~tags ~read_buffer_size ?upgrade flow);
  Miou.Ownership.release res

let https_1_1_server_connection ~config ~user's_error_handler ?upgrade
    ~user's_handler flow =
  let scheme = "https" in
  let read_buffer_size = config.H1.Config.read_buffer_size in
  let error_handler ?request err respond =
    let request = Option.map (request_from_h1 ~scheme) request in
    let err = `V1 err in
    let respond hdrs =
      let hdrs = H1.Headers.of_list (Headers.to_list hdrs) in
      let body = respond hdrs in
      `V1 body
    in
    user's_error_handler `V1 ?request err respond
  in
  let request_handler reqd = user's_handler (`Tls flow) (`V1 reqd) in
  let conn =
    H1.Server_connection.create ~config ~error_handler request_handler
  in
  let tags =
    let flow = Mnet_tls.file_descr flow in
    let (ipaddr, port), _ = Mnet.TCP.peers flow in
    let tags = Mnet.TCP.tags flow in
    Logs.Tag.add secure_peer (ipaddr, port) tags
  in
  let finally = inhibit Mnet_tls.close in
  let res = Miou.Ownership.create ~finally flow in
  Miou.Ownership.own res;
  Miou.await_exn (A.run conn ~tags ~read_buffer_size ?upgrade flow);
  Miou.Ownership.release res

let h2s_server_connection ~config ~user's_error_handler ?upgrade ~user's_handler
    flow =
  let read_buffer_size = config.H2.Config.read_buffer_size in
  let error_handler ?request err respond =
    let request = Option.map request_from_h2 request in
    let err = `V2 err in
    let respond hdrs = `V2 (respond hdrs) in
    user's_error_handler `V2 ?request err respond
  in
  let request_handler reqd = user's_handler (`Tls flow) (`V2 reqd) in
  let conn =
    H2.Server_connection.create ~config ~error_handler request_handler
  in
  let tags =
    let flow = Mnet_tls.file_descr flow in
    let (ipaddr, port), _ = Mnet.TCP.peers flow in
    let tags = Mnet.TCP.tags flow in
    Logs.Tag.add secure_peer (ipaddr, port) tags
  in
  let finally = inhibit Mnet_tls.close in
  let res = Miou.Ownership.create ~finally flow in
  Miou.Ownership.own res;
  Miou.await_exn (C.run conn ~tags ~read_buffer_size ?upgrade flow);
  Miou.Ownership.release res

let rec clean_up orphans =
  match Miou.care orphans with
  | None | Some None -> ()
  | Some (Some prm) -> begin
      match Miou.await prm with
      | Ok () -> clean_up orphans
      | Error exn ->
          Log.err (fun m ->
              m "unexpected exception: %s" (Printexc.to_string exn));
          clean_up orphans
    end

exception Stop

let rec wait ({ mutex; condition; flag } as stop) () =
  let value =
    Miou.Mutex.protect mutex @@ fun () ->
    while Atomic.get flag = false do
      Miou.Condition.wait condition mutex
    done;
    Atomic.get flag
  in
  if value then raise Stop else wait stop ()

let stop () =
  let mutex = Miou.Mutex.create () in
  let condition = Miou.Condition.create () in
  let flag = Atomic.make false in
  { mutex; condition; flag }

let switch { mutex; condition; flag } =
  Miou.Mutex.protect mutex @@ fun () ->
  Atomic.set flag true;
  Miou.Condition.broadcast condition

let accept_or_stop ?stop tcpv4 listen =
  match stop with
  | None -> Some (Mnet.TCP.accept tcpv4 listen)
  | Some s when Atomic.get s.flag -> None
  | Some s -> begin
      let accept = Miou.async @@ fun () -> Mnet.TCP.accept tcpv4 listen in
      let stop = Miou.async (wait s) in
      match Miou.await_first [ accept; stop ] with
      | Ok flow when Atomic.get s.flag -> Mnet.TCP.close flow; None
      | Ok flow -> Some flow
      | Error Stop -> None
      | Error _exn when Atomic.get s.flag -> None
      | Error exn ->
          Log.err (fun m ->
              m "unexpected exception: %S" (Printexc.to_string exn));
          raise exn
    end

let errf err =
  Fmt.str "<h1>500 Internal error</h1><p>Error: %a</p>" pp_error err

let default_error_handler version ?request:_ err respond =
  let str = errf err in
  let hdrs =
    match version with
    | `V1 ->
        [
          ("content-type", "text/html; charset=utf-8")
        ; ("content-length", string_of_int (String.length str))
        ; ("connection", "close")
        ]
    | `V2 ->
        [
          ("content-type", "text/html; charset=utf-8")
        ; ("content-length", string_of_int (String.length str))
        ]
  in
  let hdrs = H2.Headers.of_list hdrs in
  match respond hdrs with
  | `V1 body ->
      H1.Body.Writer.write_string body str;
      let fn () =
        if H1.Body.Writer.is_closed body = false then H1.Body.Writer.close body
      in
      H1.Body.Writer.flush body fn
  | `V2 body ->
      H2.Body.Writer.write_string body str;
      let fn = function
        | `Closed -> ()
        | `Written -> H2.Body.Writer.close body
      in
      H2.Body.Writer.flush body fn

let clear ?stop ?(config = H1.Config.default) ?ready
    ?error_handler:(user's_error_handler = default_error_handler) ?upgrade
    ~handler:user's_handler tcp ~port =
  let rec go orphans listen =
    match accept_or_stop ?stop tcp listen with
    | None ->
        Log.debug (fun m -> m "stop the server");
        (* TODO(dinosaure): unlisten? *)
        Runtime.terminate orphans
    | Some flow ->
        clean_up orphans;
        let _ =
          Miou.async ~orphans @@ fun () ->
          http_1_1_server_connection ~config ~user's_error_handler ?upgrade
            ~user's_handler flow
        in
        go orphans listen
  in
  let listen = Mnet.TCP.listen tcp port in
  Option.iter (fun c -> ignore (Miou.Computation.try_return c ())) ready;
  go (Miou.orphans ()) listen

let alpn tls =
  match Mnet_tls.epoch tls with
  | Some { Tls.Core.alpn_protocol= protocol; _ } -> protocol
  | None -> None

let with_tls ?stop ?(config = `Both (H1.Config.default, H2.Config.default))
    ?ready ?error_handler:(user's_error_handler = default_error_handler)
    tls_config ?upgrade ~handler:user's_handler tcp ~port =
  let rec go orphans listen =
    match accept_or_stop ?stop tcp listen with
    | None -> Runtime.terminate orphans
    | Some flow ->
        clean_up orphans;
        let fn () =
          try
            let tls_flow = Mnet_tls.server_of_fd tls_config flow in
            begin match (config, alpn tls_flow) with
            | `Both (_, h2), Some "h2" | `H2 h2, (Some "h2" | None) ->
                h2s_server_connection ~config:h2 ~user's_error_handler ?upgrade
                  ~user's_handler tls_flow
            | `Both (config, _), Some "http/1.1"
            | `HTTP_1_1 config, (Some "http/1.1" | None) ->
                https_1_1_server_connection ~config ~user's_error_handler
                  ?upgrade ~user's_handler tls_flow
            | `Both _, None ->
                failwith "No protocol specified during the ALPN negotiation"
            | _, Some protocol ->
                Fmt.failwith "Unrecognized protocol: %S" protocol
            end
          with exn ->
            Log.err (fun m ->
                m "Got a TLS error during the handshake: %s"
                  (Printexc.to_string exn));
            Mnet.TCP.close flow
        in
        let _ = Miou.async ~orphans fn in
        go orphans listen
  in
  let listen = Mnet.TCP.listen tcp port in
  Option.iter (fun c -> ignore (Miou.Computation.try_return c ())) ready;
  go (Miou.orphans ()) listen
