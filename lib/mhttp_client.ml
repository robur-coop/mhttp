open Mhttp

let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let open_error_msg = function
  | Ok v -> Ok v
  | Error (`Msg msg) -> Error (`Msg msg)

module Client = struct
  module H1_Client_connection = struct
    include H1.Client_connection

    let yield_reader _ = assert false

    let next_read_operation t =
      (next_read_operation t :> [ `Close | `Read | `Yield | `Upgrade ])

    let next_write_operation t =
      (next_write_operation t
        :> [ `Close of int
           | `Write of Bigstringaf.t Faraday.iovec list
           | `Yield
           | `Upgrade ])
  end

  module H2_Client_connection = struct
    include H2.Client_connection

    let next_read_operation t =
      (next_read_operation t :> [ `Close | `Read | `Yield | `Upgrade ])

    let next_write_operation t =
      (next_write_operation t
        :> [ `Close of int
           | `Write of Bigstringaf.t Faraday.iovec list
           | `Yield
           | `Upgrade ])
  end

  module A = Runtime.Make (TLS) (H1_Client_connection)
  module B = Runtime.Make (TCP) (H1_Client_connection)
  module C = Runtime.Make (TLS) (H2_Client_connection)
  module D = Runtime.Make (TCP) (H2_Client_connection)

  type response = [ `V1 of H1.Response.t | `V2 of H2.Response.t ]

  type error =
    [ `V1 of H1.Client_connection.error
    | `V2 of H2.Client_connection.error
    | `Protocol of string
    | `Exn of exn ]

  let pp_error ppf = function
    | `V1 (`Malformed_response msg) ->
        Fmt.pf ppf "Malformed HTTP/1.1 response: %s" msg
    | `V1 (`Invalid_response_body_length _resp) ->
        Fmt.pf ppf "Invalid response body length"
    | `V1 (`Exn exn) | `V2 (`Exn exn) ->
        Fmt.pf ppf "Got an unexpected exception: %S" (Printexc.to_string exn)
    | `V2 (`Malformed_response msg) ->
        Fmt.pf ppf "Malformed H2 response: %s" msg
    | `V2 (`Invalid_response_body_length _resp) ->
        Fmt.pf ppf "Invalid response body length"
    | `V2 (`Protocol_error (err, msg)) ->
        Fmt.pf ppf "Protocol error %a: %s" H2.Error_code.pp_hum err msg
    | `Protocol msg -> Fmt.string ppf msg
    | `Exn exn -> Fmt.pf ppf "%S" (Printexc.to_string exn)

  type ('conn, 'resp, 'body) version =
    | V1 : (H1.Client_connection.t, H1.Response.t, H1.Body.Writer.t) version
    | V2 : (H2.Client_connection.t, H2.Response.t, H2.Body.Writer.t) version

  exception Error of error

  let empty = Printexc.get_callstack 0

  type 'acc process =
    | Process : {
          version: ('conn, 'resp, 'body) version
        ; acc: 'acc ref
        ; response: 'resp Miou.Computation.t
        ; body: 'body
        ; conn: 'conn
        ; process: unit Miou.t
      }
        -> 'acc process

  let http_1_1_response_handler ~fn acc =
    let acc = ref acc in
    let response = Miou.Computation.create () in
    let response_handler resp body =
      let rec on_eof () = H1.Body.Reader.close body
      and on_read bstr ~off ~len =
        let str = Bigstringaf.substring bstr ~off ~len in
        acc := fn (`V1 resp) !acc str;
        H1.Body.Reader.schedule_read body ~on_read ~on_eof
      in
      H1.Body.Reader.schedule_read body ~on_read ~on_eof;
      ignore (Miou.Computation.try_return response resp)
    in
    (response_handler, response, acc)

  let http_1_1_error_handler response err =
    let err = `V1 err in
    let _set = Miou.Computation.try_cancel response (Error err, empty) in
    Log.err (fun m -> m "%a" pp_error err)

  let h2_response_handler conn ~fn response acc =
    let acc = ref acc in
    let response_handler resp body =
      let rec on_eof () =
        H2.Body.Reader.close body;
        H2.Client_connection.shutdown conn
      and on_read bstr ~off ~len =
        let str = Bigstringaf.substring bstr ~off ~len in
        acc := fn (`V2 resp) !acc str;
        H2.Body.Reader.schedule_read body ~on_read ~on_eof
      in
      H2.Body.Reader.schedule_read body ~on_read ~on_eof;
      ignore (Miou.Computation.try_return response resp)
    in
    (response_handler, acc)

  let h2_error_handler conn response err =
    let err = `V2 err in
    let _set = Miou.Computation.try_cancel response (Error err, empty) in
    H2.Client_connection.shutdown (Lazy.force conn);
    Log.err (fun m -> m "%a" pp_error err)

  let pp_request ppf (flow, request) =
    match (flow, request) with
    | `Tls _, `V1 _ -> Fmt.string ppf "http/1.1 + tls"
    | `Tcp _, `V1 _ -> Fmt.string ppf "http/1.1"
    | `Tls _, `V2 _ -> Fmt.string ppf "h2 + tls"
    | `Tcp _, `V2 _ -> Fmt.string ppf "h2"

  let run ~fn acc config flow request =
    Log.debug (fun m -> m "start a new %a request" pp_request (flow, request));
    match (flow, config, request) with
    | `Tls flow, `V1 config, `V1 request ->
        let read_buffer_size = config.H1.Config.read_buffer_size in
        let response_handler, response, acc =
          http_1_1_response_handler ~fn acc
        in
        let error_handler = http_1_1_error_handler response in
        let body, conn =
          H1.Client_connection.request ~config request ~error_handler
            ~response_handler
        in
        let prm = A.run conn ~read_buffer_size flow in
        Process { version= V1; acc; response; body; conn; process= prm }
    | `Tcp flow, `V1 config, `V1 request ->
        let read_buffer_size = config.H1.Config.read_buffer_size in
        let response_handler, response, acc =
          http_1_1_response_handler ~fn acc
        in
        let error_handler = http_1_1_error_handler response in
        let body, conn =
          H1.Client_connection.request ~config request ~error_handler
            ~response_handler
        in
        let prm = B.run conn ~read_buffer_size flow in
        Process { version= V1; acc; response; body; conn; process= prm }
    | `Tls flow, `V2 config, `V2 request ->
        let read_buffer_size = config.H2.Config.read_buffer_size in
        let response = Miou.Computation.create () in
        (* NOTE(dinosaure): With regard to [h2], there are two levels of error:
         one at the protocol level and one at the request level. [httpcats] is
         currently designed to make only one request, even with [h2]. Thus, if
         an error occurs at the request level, it means that the connection must
         be "shutdown" — see [h2_error_handler].

         Here we use the “lazy”/“rec” trick to have the instance of our [conn]
         connection in our [error_handler] at both levels. *)
        let rec error_handler = fun err -> h2_error_handler conn response err
        and conn =
          lazy (H2.Client_connection.create ~config ~error_handler ())
        in
        let conn = Lazy.force conn in
        let response_handler, acc = h2_response_handler conn ~fn response acc in
        let body =
          H2.Client_connection.request conn ~error_handler ~response_handler
            request
        in
        let prm = C.run conn ~read_buffer_size flow in
        Process { version= V2; acc; response; body; conn; process= prm }
    | `Tcp flow, `V2 config, `V2 request ->
        let read_buffer_size = config.H2.Config.read_buffer_size in
        let response = Miou.Computation.create () in
        let rec error_handler = fun err -> h2_error_handler conn response err
        and conn =
          lazy (H2.Client_connection.create ~config ~error_handler ())
        in
        let conn = Lazy.force conn in
        let response_handler, acc = h2_response_handler conn ~fn response acc in
        let body =
          H2.Client_connection.request conn ~error_handler ~response_handler
            request
        in
        let prm = D.run conn ~read_buffer_size flow in
        Process { version= V2; acc; response; body; conn; process= prm }
    | _ -> invalid_arg "Mhttp_client.run"
end

let open_client_error = function
  | Ok _ as v -> v
  | Error #Client.error as err -> err

let decode_host_port str =
  match String.split_on_char ':' str with
  | [] -> Error (`Msg "Empty host part")
  | [ host ] -> Ok (host, None)
  | [ host; "" ] -> Ok (host, None)
  | hd :: tl -> (
      let port, host =
        match List.rev (hd :: tl) with
        | hd :: tl -> (hd, String.concat ":" (List.rev tl))
        | _ -> assert false
      in
      try Ok (host, Some (int_of_string port))
      with _ -> Error (`Msg "Couln't decode port"))

let decode_user_pass up =
  match String.split_on_char ':' up with
  | [ user; pass ] -> Ok (user, Some pass)
  | [ user ] -> Ok (user, None)
  | _ -> assert false

type uri =
  bool * string * (string * string option) option * string * int option * string

let decode_uri uri =
  (* proto :// user : pass @ host : port / path *)
  let ( >>= ) = Result.bind in
  match String.split_on_char '/' uri with
  | proto :: "" :: user_pass_host_port :: path ->
      (if String.equal proto "http:" then Ok ("http", false)
       else if String.equal proto "https:" then Ok ("https", true)
       else Error (`Msg "Unknown protocol"))
      >>= fun (scheme, is_tls) ->
      (match String.split_on_char '@' user_pass_host_port with
        | [ host_port ] -> Ok (None, host_port)
        | [ user_pass; host_port ] ->
            decode_user_pass user_pass >>= fun up -> Ok (Some up, host_port)
        | _ -> Error (`Msg "Couldn't decode URI"))
      >>= fun (user_pass, host_port) ->
      decode_host_port host_port >>= fun (host, port) ->
      Ok (is_tls, scheme, user_pass, host, port, "/" ^ String.concat "/" path)
  | [ user_pass_host_port ] ->
      (match String.split_on_char '@' user_pass_host_port with
        | [ host_port ] -> Ok (None, host_port)
        | [ user_pass; host_port ] ->
            decode_user_pass user_pass >>= fun up -> Ok (Some up, host_port)
        | _ -> Error (`Msg "Couldn't decode URI"))
      >>= fun (user_pass, host_port) ->
      decode_host_port host_port >>= fun (host, port) ->
      Ok (false, "", user_pass, host, port, "/")
  | user_pass_host_port :: path ->
      (match String.split_on_char '@' user_pass_host_port with
        | [ host_port ] -> Ok (None, host_port)
        | [ user_pass; host_port ] ->
            decode_user_pass user_pass >>= fun up -> Ok (Some up, host_port)
        | _ -> Error (`Msg "Couldn't decode URI"))
      >>= fun (user_pass, host_port) ->
      decode_host_port host_port >>= fun (host, port) ->
      Ok (false, "", user_pass, host, port, "/" ^ String.concat "/" path)
  | _ -> Error (`Msg "Could't decode URI on top")

let resolve_location ~uri ~location =
  Log.debug (fun m -> m "resolve location: uri:%S, location:%S" uri location);
  match String.split_on_char '/' location with
  | "http:" :: "" :: _ -> Ok location
  | "https:" :: "" :: _ -> Ok location
  | "" :: "" :: _ -> begin
      match String.split_on_char '/' uri with
      | schema :: "" :: user_pass_host_port :: _ ->
          Ok (String.concat "/" [ schema; ""; user_pass_host_port ^ location ])
      | _ -> error_msgf "Expected an absolute uri, got: %S" uri
    end
  | _ -> error_msgf "Unknown location (relative path): %S" location

let add_authentication ?(meth = `Basic) ~add headers user_pass =
  match (user_pass, meth) with
  | None, _ -> headers
  | Some (user, Some pass), `Basic ->
      let data = Base64.encode_string (user ^ ":" ^ pass) in
      let str = "Basic " ^ data in
      add headers "authorization" str
  | Some (user, None), `Basic ->
      let data = Base64.encode_string user in
      let str = "Basic " ^ data in
      add headers "authorization" str

(* User facing API *)

module Version = Httpcats_core.Version
module Status = Httpcats_core.Status
module Headers = Httpcats_core.Headers
module Method = Httpcats_core.Method
module Cookie = Httpcats_core.Cookie

type request = Httpcats_core.request = {
    meth: Method.t
  ; target: string
  ; headers: Headers.t
}

type response = Httpcats_core.response = {
    version: Version.t
  ; status: Status.t
  ; reason: string
  ; headers: Headers.t
}

type error = Httpcats_core.error
type body = Httpcats_core.body = String of string | Stream of string Seq.t
type meta = Httpcats_core.meta
type 'a handler = 'a Httpcats_core.handler

type config = {
    meth: H2.Method.t
  ; headers: (string * string) list
  ; body: body option
  ; scheme: string
  ; user_pass: (string * string option) option
  ; host: string
  ; path: string
  ; ipaddr: Ipaddr.t
  ; port: int
  ; epoch: Tls.Core.epoch_data option
}

let pp_error ppf = function
  | `Msg msg -> Fmt.string ppf msg
  | #Client.error as err -> Client.pp_error ppf err

let user_agent = "mhttp/%%VERSION_NUM%%"

let prep_http_1_1_headers cfg body =
  let hdr = H1.Headers.of_list cfg.headers in
  let add = H1.Headers.add_unless_exists in
  let hdr = add hdr "user-agent" user_agent in
  let hdr = add hdr "host" cfg.host in
  let hdr =
    match body with
    | Some (Some len) ->
        let hdr = add hdr "connection" "close" in
        add hdr "content-length" (string_of_int len)
    | Some None -> add hdr "transfer-encoding" "chunked"
    | None ->
        let hdr = add hdr "connection" "close" in
        add hdr "content-length" "0"
  in
  add_authentication ~add hdr cfg.user_pass

let prep_h2_headers cfg body =
  (* please note, that h2 (at least in version 0.10.0) encodes the headers
     in reverse order ; and for http/2 compatibility we need to retain the
     :authority pseudo-header first (after method/scheme/... that are encoded
     specially *)
  (* also note that "host" is no longer a thing, but :authority is -- so if
     we find a host header, we'll rephrase that as authority. *)
  let fn (k, v) = (String.lowercase_ascii k, v) in
  let hdr = List.rev_map fn cfg.headers in
  let hdr = H2.Headers.of_rev_list hdr in
  let hdr, authority =
    match (H2.Headers.get hdr "host", H2.Headers.get hdr ":authority") with
    | None, None -> (hdr, cfg.host)
    | Some h, None -> (H2.Headers.remove hdr "host", h)
    | None, Some a -> (H2.Headers.remove hdr ":authority", a)
    | Some h, Some a ->
        if String.equal h a then
          let hdr = H2.Headers.remove hdr ":authority" in
          let hdr = H2.Headers.remove hdr "host" in
          (hdr, h)
        else (H2.Headers.remove hdr ":authority", a)
  in
  let add hdr = H2.Headers.add_unless_exists hdr ?sensitive:None in
  let hdr = H2.Headers.add_list H2.Headers.empty (H2.Headers.to_rev_list hdr) in
  let hdr =
    match body with
    | Some (Some len) -> add hdr "content-length" (string_of_int len)
    | Some None -> add hdr "transfer-encoding" "chunked"
    | None -> add hdr "content-length" "0"
  in
  let hdr = add hdr ":authority" authority in
  let hdr = add hdr "user-agent" user_agent in
  let hdr = add_authentication ~add hdr cfg.user_pass in
  let hdr = H2.Headers.to_list hdr in
  let hdr = List.sort (fun (a, _) (b, _) -> String.compare a b) hdr in
  H2.Headers.of_list hdr

let resp_from_h1 response =
  {
    version= response.H1.Response.version
  ; status= (response.H1.Response.status :> H2.Status.t)
  ; reason= response.H1.Response.reason
  ; headers=
      H2.Headers.of_list (H1.Headers.to_list response.H1.Response.headers)
  }

let req_from_h1 req =
  {
    meth= req.H1.Request.meth
  ; target= req.H1.Request.target
  ; headers= H2.Headers.of_list (H1.Headers.to_list req.H1.Request.headers)
  }

let resp_from_h2 response =
  {
    version= { major= 2; minor= 0 }
  ; status= response.H2.Response.status
  ; reason= H2.Status.to_string response.H2.Response.status
  ; headers= response.H2.Response.headers
  }

let req_from_h2 req =
  {
    meth= req.H2.Request.meth
  ; target= req.H2.Request.target
  ; headers= req.H2.Request.headers
  }

let connect ?port ?tls_config ~happy_eyeballs host =
  let port =
    match (port, tls_config) with
    | None, None -> 80
    | None, Some _ -> 443
    | Some port, _ -> port
  in
  Log.debug (fun m -> m "try to connect to %s (with happy-eyeballs)" host);
  match
    (Mnet_happy_eyeballs.connect happy_eyeballs host [ port ], tls_config)
  with
  | Ok ((ipaddr, port), file_descr), None ->
      Ok (`Tcp file_descr, ipaddr, port, None)
  | Ok ((ipaddr, port), file_descr), Some tls_config ->
      let tls = Mnet_tls.client_of_fd tls_config file_descr in
      let epoch = Mnet_tls.epoch tls in
      Ok (`Tls tls, ipaddr, port, epoch)
  | (Error (`Msg _) as err), _ -> err

let http_1_1_writer body seq () =
  let rec next seq =
    match Seq.uncons seq with
    | None -> H1.Body.Writer.close body
    | Some (str, seq) ->
        H1.Body.Writer.write_string body str;
        H1.Body.Writer.flush body (fun () -> next seq)
  in
  next seq

let[@warning "-8"] single_http_1_1_request ?(config = H1.Config.default) flow
    cfg ~fn:fn0 acc =
  let contents_length =
    match cfg.body with
    | Some (String str) -> Some (Some (String.length str))
    | Some (Stream _) -> Some None
    | None -> None
  in
  let headers = prep_http_1_1_headers cfg contents_length in
  let meth = cfg.meth and path = cfg.path in
  let request = H1.Request.create ~headers meth path in
  let meta = ((cfg.ipaddr, cfg.port), cfg.epoch) in
  let fn (`V1 resp : Client.response) acc str =
    fn0 meta (req_from_h1 request) (resp_from_h1 resp) acc (Some str)
  in
  let finally () =
    Log.debug (fun m -> m "close the underlying socket");
    match flow with
    | `Tls flow -> Mnet_tls.close flow
    | `Tcp flow -> Mnet.TCP.close flow
  in
  Fun.protect ~finally @@ fun () ->
  let (Client.Process { version= V1; acc; response; body; process; _ }) =
    Client.run ~fn acc (`V1 config) flow (`V1 request)
  in
  let seq =
    match cfg.body with
    | Some (String str) -> Seq.return str
    | Some (Stream seq) -> seq
    | None -> Seq.empty
  in
  let sender = Miou.async (http_1_1_writer body seq) in
  let on_error exn =
    Log.debug (fun m -> m "cancel http/1.1 tasks");
    Miou.cancel process;
    Miou.cancel sender;
    match exn with Client.Error err -> err | exn -> `Exn exn
  in
  let ( let* ) = Result.bind in
  let resp = Miou.Computation.await response in
  let* resp = Result.map_error (Fun.compose on_error fst) resp in
  let* () = Result.map_error on_error (Miou.await sender) in
  let* () = Result.map_error on_error (Miou.await process) in
  let req = req_from_h1 request in
  let resp = resp_from_h1 resp in
  Ok (resp, fn0 meta req resp !acc None)

let h2_writer body seq () =
  let rec next seq reason =
    match reason with
    | `Closed -> H2.Body.Writer.close body
    | `Written -> begin
        match Seq.uncons seq with
        | None -> H2.Body.Writer.close body
        | Some (str, seq) ->
            H2.Body.Writer.write_string body str;
            H2.Body.Writer.flush body (fun reason -> next seq reason)
      end
  in
  next seq `Written

let[@warning "-8"] single_h2_request ?(config = H2.Config.default) flow cfg
    ~fn:fn0 acc =
  let contents_length =
    match cfg.body with
    | Some (String str) -> Some (Some (String.length str))
    | Some (Stream _) -> Some None
    | None -> None
  in
  let headers = prep_h2_headers cfg contents_length in
  let scheme = cfg.scheme and meth = cfg.meth and path = cfg.path in
  let request = H2.Request.create ~scheme ~headers meth path in
  let meta = ((cfg.ipaddr, cfg.port), cfg.epoch) in
  let fn (`V2 response : Client.response) acc str =
    fn0 meta (req_from_h2 request) (resp_from_h2 response) acc (Some str)
  in
  let (Client.Process { version= V2; acc; response; body; process; _ }) =
    Client.run ~fn acc (`V2 config) flow (`V2 request)
  in
  let seq =
    match cfg.body with
    | Some (String str) -> Seq.return str
    | Some (Stream seq) -> seq
    | None -> Seq.empty
  in
  let sender = Miou.async (h2_writer body seq) in
  let on_error exn =
    Log.debug (fun m -> m "cancel h2 tasks");
    Miou.cancel process;
    Miou.cancel sender;
    match exn with Client.Error err -> err | exn -> `Exn exn
  in
  let ( let* ) = Result.bind in
  let resp = Miou.Computation.await response in
  let* resp = Result.map_error (Fun.compose on_error fst) resp in
  let* () = Result.map_error on_error (Miou.await sender) in
  let* () = Result.map_error on_error (Miou.await process) in
  let req = req_from_h2 request in
  let resp = resp_from_h2 resp in
  Ok (resp, fn0 meta req resp !acc None)

let alpn_protocol = function
  | `Tcp _ -> None
  | `Tls tls -> (
      match Mnet_tls.epoch tls with
      | Some { Tls.Core.alpn_protocol= Some "h2"; _ } -> Some `H2
      | Some { Tls.Core.alpn_protocol= Some "http/1.1"; _ } -> Some `HTTP_1_1
      | Some { Tls.Core.alpn_protocol= None; _ } -> None
      | Some { Tls.Core.alpn_protocol= Some _; _ } -> None
      | None -> None)

type tls_config =
  [ `Custom of Tls.Config.client | `Default of Tls.Config.client ]

type config_for_a_request = {
    happy_eyeballs: Mnet_happy_eyeballs.t
  ; http_config: [ `HTTP_1_1 of H1.Config.t | `H2 of H2.Config.t ] option
  ; tls_config: (tls_config, error) result
  ; meth: H2.Method.t
  ; headers: (string * string) list
  ; body: body option
  ; uri: string
  ; cookies: (string * string) list
}

let single_request cfg ~fn acc =
  let ( let* ) = Result.bind in
  let ( let+ ) x f = Result.map f x in
  let* tls, scheme, user_pass, host, port, path = decode_uri cfg.uri in
  let* tls_config =
    if tls then
      let+ tls_config = cfg.tls_config in
      let host =
        let* domain_name = Domain_name.of_string host in
        Domain_name.host domain_name
      in
      match (tls_config, host) with
      | `Custom cfg, _ -> Some cfg
      | `Default cfg, Ok host -> Some (Tls.Config.peer cfg host)
      | `Default cfg, _ -> Some cfg
    else Ok None
  in
  let* flow, ipaddr, port, epoch =
    let happy_eyeballs = cfg.happy_eyeballs in
    connect ?port ?tls_config ~happy_eyeballs host |> open_error_msg
  in
  Log.debug (fun m -> m "connected to %s" cfg.uri);
  let to_cookie (k, v) = ("Cookie", Fmt.str "%s=%s" k v) in
  let cookies = List.map to_cookie cfg.cookies in
  let headers = cfg.headers @ cookies in
  let cfg' =
    {
      meth= cfg.meth
    ; headers
    ; body= cfg.body
    ; scheme
    ; user_pass
    ; host
    ; path
    ; ipaddr
    ; port
    ; epoch
    }
  in
  begin match (alpn_protocol flow, cfg.http_config) with
  | (Some `HTTP_1_1 | None), Some (`HTTP_1_1 config) ->
      single_http_1_1_request ~config flow cfg' ~fn acc
  | (Some `HTTP_1_1 | None), None -> single_http_1_1_request flow cfg' ~fn acc
  | Some `H2, Some (`H2 config) -> single_h2_request ~config flow cfg' ~fn acc
  | None, Some (`H2 _) ->
      Log.warn (fun m ->
          m "no ALPN protocol (choose http/1.1) where user forces h2");
      single_http_1_1_request flow cfg' ~fn acc
  | Some `H2, None -> single_h2_request flow cfg' ~fn acc
  | Some `H2, Some (`HTTP_1_1 _) ->
      Log.warn (fun m -> m "ALPN protocol is h2 where user forces http/1.1");
      single_h2_request flow cfg' ~fn acc
  | Some `HTTP_1_1, Some (`H2 _) ->
      Log.warn (fun m -> m "ALPN protocol is http/1.1 where user forces h2");
      single_http_1_1_request flow cfg' ~fn acc
  end
  |> open_client_error

let string str = String str
let stream seq = Stream seq

(* NOTE(dinosaure): we must [memoize] (and ensure that the given [seq] is used
   only one time) the body if we follow redirections where we will try, for each
   redirections, to send the body. *)
let memoize = function
  | String _ as body -> body
  | Stream seq -> Stream (Seq.memoize seq)

(* NOTE(dinosaure): Cookie part, the goal is to keep a [db]
   ([(string * string) list]) along the redirection if the server wants to
   implement a POST-to-GET service. *)

let cookies_from_headers headers =
  let parse str =
    match String.split_on_char '=' str with
    | [ key; value ] -> Some (key, value)
    | _ -> None
  in
  let rec go acc = function
    | [] -> List.rev acc
    | (key, value) :: headers -> (
        match String.lowercase_ascii key with
        | "cookie" ->
            let acc =
              match parse value with
              | Some (key, value) -> (key, value) :: acc
              | None -> acc
            in
            go acc headers
        | _ -> go acc headers)
  in
  go [] headers

let headers_without_cookies headers =
  let rec go acc = function
    | [] -> List.rev acc
    | (key, value) :: rest -> (
        match String.lowercase_ascii key with
        | "cookie" -> go acc rest
        | _ -> go ((key, value) :: acc) rest)
  in
  go [] headers

let get_cookies_from_response (resp : response) =
  let headers = Headers.to_list resp.headers in
  let rec go acc = function
    | [] -> acc
    | (key, value) :: headers -> (
        match String.lowercase_ascii key with
        | "set-cookie" ->
            let acc =
              match Cookie.parse value with
              | Some cookie -> cookie :: acc
              | None -> acc
            in
            go acc headers
        | _ -> go acc headers)
  in
  go [] headers

let accept_all_cookies db cookies =
  let db' = List.map (fun { Cookie.key; value; _ } -> (key, value)) cookies in
  let rec go db' = function
    | [] -> db'
    | (key, value) :: rest ->
        (* NOTE(dinosaure): we add only pre-existing cookies which are not set by the server. *)
        if List.mem_assoc key db' then go db' rest
        else go ((key, value) :: db') rest
  in
  go db' db

(* NOTE(dinosaure): depending on the redirection, we possibly need to change the method used.
   Specially for 302 and 302 status codes. *)

let meth_from_redirection meth (resp : response) =
  match (meth, resp.status) with
  | _, (`See_other | `Found) -> `GET
  | meth, _ -> meth

type filter =
  (string * string) list -> Cookie.cookie list -> (string * string) list

let request ?config:http_config ?tls_config ?authenticator ?(meth = `GET)
    ?(headers = []) ?body ?(max_redirect = 5) ?(follow_redirect = true)
    ~happy_eyeballs ?cookies:(filter = accept_all_cookies) ~fn ~uri acc =
  let tls_config =
    match tls_config with
    | Some cfg -> Ok (`Custom cfg)
    | None ->
        let alpn_protocols =
          match http_config with
          | None -> [ "h2"; "http/1.1" ]
          | Some (`H2 _) -> [ "h2" ]
          | Some (`HTTP_1_1 _) -> [ "http/1.1" ]
        and authenticator =
          match authenticator with
          | None -> Ca_certs_nss.authenticator ()
          | Some authenticator -> Ok authenticator
        in
        Result.map
          begin fun authenticator ->
            Tls.Config.client ~alpn_protocols ~authenticator () |> Result.get_ok
            |> fun default -> `Default default
          end
          authenticator
  in
  let cfg =
    {
      happy_eyeballs
    ; http_config
    ; tls_config
    ; meth
    ; headers= headers_without_cookies headers
    ; body= Option.map memoize body
    ; uri
    ; cookies= cookies_from_headers headers
    }
  in
  if not follow_redirect then single_request cfg ~fn acc
  else
    let ( let* ) = Result.bind in
    let rec go count cfg =
      if count = 0 then Error (`Msg "Redirect limit exceeded")
      else
        match single_request cfg ~fn acc with
        | Error _ as err -> err
        | Ok (resp, result) ->
            let cookies = filter cfg.cookies (get_cookies_from_response resp) in
            if Status.is_redirection resp.status then
              match Headers.get resp.headers "location" with
              | Some location ->
                  let meth = meth_from_redirection cfg.meth resp in
                  let* uri = resolve_location ~uri ~location in
                  go (pred count) { cfg with meth; uri; cookies }
              | None -> Ok (resp, result)
            else Ok (resp, result)
    in
    go max_redirect cfg
