rule runtime_exec_marker {
  strings:
    $exec = "Runtime.getRuntime().exec"
  condition:
    $exec
}

rule suspicious_payload_url {
  strings:
    $url = "https://payload.example.invalid/bootstrap"
  condition:
    $url
}

rule synthetic_c2_domain {
  strings:
    $domain = "c2.jarspect.example.invalid"
  condition:
    $domain
}
