open Mhttp

let peer ~secure =
  let scheme = if secure then "https" else "http" in
  let pp ppf (ipaddr, port) =
    Fmt.pf ppf "%s%a:%d" scheme Ipaddr.pp ipaddr port
  in
  Logs.Tag.def ~doc:"HTTP (unikernel) peer" "mhttp.peer" pp

let clear_peer = peer ~secure:false

module TCP_and_H1 = struct
  include TCP

  let shutdown flow = function `read -> () | value -> shutdown flow value
end

module B = Runtime.Make (TCP_and_H1) (H1.Server_connection)

type error =
  [ `V1 of H1.Server_connection.error
  | `V2 of H2.Server_connection.error
  | `Protocol of string ]

type stop = Miou.Mutex.t * Miou.Condition.t * bool ref

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

type flow = [ `Tcp of Mnet.TCP.flow ]

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
  let finally () = Mnet.TCP.close flow in
  Fun.protect ~finally @@ fun () ->
  let tags =
    let (ipaddr, port), _ = Mnet.TCP.peers flow in
    let tags = Mnet.TCP.tags flow in
    Logs.Tag.add clear_peer (ipaddr, port) tags
  in
  Miou.await_exn (B.run conn ~tags ~read_buffer_size ?upgrade flow)

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

let rec wait ((m, c, v) as stop) () =
  let value =
    Miou.Mutex.protect m @@ fun () ->
    while not !v do
      Miou.Condition.wait c m
    done;
    !v
  in
  if value then raise Stop else wait stop ()

let stop () = (Miou.Mutex.create (), Miou.Condition.create (), ref false)

let switch (m, c, v) =
  Miou.Mutex.protect m @@ fun () ->
  v := true;
  Miou.Condition.broadcast c

let accept_or_stop ?stop tcpv4 listen =
  match stop with
  | None -> Some (Mnet.TCP.accept tcpv4 listen)
  | Some stop -> (
      let accept = Miou.async @@ fun () -> Mnet.TCP.accept tcpv4 listen in
      let stop = Miou.async (wait stop) in
      match Miou.await_first [ accept; stop ] with
      | Ok flow -> Some flow
      | Error Stop -> None
      | Error exn ->
          Log.err (fun m ->
              m "unexpected exception: %S" (Printexc.to_string exn));
          raise exn)

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
    ~handler:user's_handler tcpv4 ~port =
  let rec go orphans listen =
    match accept_or_stop ?stop tcpv4 listen with
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
  let listen = Mnet.TCP.listen tcpv4 port in
  Option.iter (fun c -> ignore (Miou.Computation.try_return c ())) ready;
  go (Miou.orphans ()) listen
