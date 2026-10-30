let schema_relative () =
  let uri = "https://user:pass@builds.robur.coop/old-path"
  and location = "//builds.osau.re/new-path" in
  Alcotest.(check (result string reject)) "schema relative resolve_location"
    (Ok "https://builds.osau.re/new-path")
  @@ Mhttp_client.resolve_location ~uri ~location

let relative () =
  let uri = "https://user:pass@builds.robur.coop/job/mollymawk/build/latest"
  and location = "/job/mollymawk/build/7aba1606-06e6-4e66-9d3b-8410f0183a49" in
  Alcotest.(check (result string reject)) "relative resolve_location"
    (Ok ("https://user:pass@builds.robur.coop" ^ location))
  @@ Mhttp_client.resolve_location ~uri ~location

let resolve_location_tests =
  [
  "Schema-relative", `Quick, schema_relative;
  "Relative", `Quick, relative;
]

let tests = [ "resolve_location", resolve_location_tests ]

let () =
  Alcotest.run "resolve location" tests
