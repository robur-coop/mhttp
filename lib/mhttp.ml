let src = Logs.Src.create "mhttp"

module Log = (val Logs.src_log src : Logs.LOG)

external reraise : exn -> 'a = "%reraise"

module TCP = struct
  type t = Mnet.TCP.flow

  let read = Mnet.TCP.read

  let write flow ?(off = 0) ?len str =
    (* NOTE(dinosaure): There is an important subtlety here that needs to be
       understood between httpcats and mhttp/mnet/utcp. Currently, mnet/utcp is
       not blocking when writing. This means that [str] is probably kept in the
       utcp state (cached) and will actually be sent during a tick.

       On the other hand, httpcats.runtime uses and reuses the same buffer for
       writing. In other words, the [str] given to this function will always be
       physically the same. httpcats.runtime assumes that once [Flow.write] is
       complete, it can reuse and write to this buffer, but this is not the
       case with mnet/utcp where, as we said, it is probably cached to be
       written later.

       So here we are trying to protect ourselves from a data race by copying
       the given [str] so that when httpcats.runtime wants to write over it, it
       does not rewrite into the cached segment. *)
    let default = String.length str - off in
    let len = Option.value ~default len in
    let tmp = Bytes.create len in
    Bytes.blit_string str 0 tmp 0 len;
    Mnet.TCP.write flow ~off:0 ~len (Bytes.unsafe_to_string tmp)

  let close = Mnet.TCP.close
  let shutdown = Mnet.TCP.shutdown
end

module TLS = struct
  include Mnet_tls

  let write fd ?off ?len str =
    try write fd ?off ?len str with
    | Mnet_tls.Closed_by_peer -> reraise Runtime.Flow.Closed_by_peer
    | exn -> reraise exn
end
