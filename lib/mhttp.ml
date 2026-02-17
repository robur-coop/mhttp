let src = Logs.Src.create "mhttp"

module Log = (val Logs.src_log src : Logs.LOG)

external reraise : exn -> 'a = "%reraise"

module TCP = struct
  type t = Mnet.TCP.flow

  let read = Mnet.TCP.read
  let write = Mnet.TCP.write
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
