// Production YARA-X rules.
//
// Design goals:
// - High-precision: avoid generic primitives that appear in benign mods.
// - Prefer family-/campaign-specific strings and require multiple corroborating tokens.
// - Severity is derived from meta.severity by Jarspect at runtime.

rule minecraft_makslibraries_mcmod_info {
  meta:
    severity = "high"
    description = "Forge mcmod.info payload associated with Maks Libraries malware-labeled samples"

  strings:
    $modid = "\"modid\": \"makslibraries\"" ascii nocase
    $name  = "\"name\": \"maks libraries\"" ascii nocase

  condition:
    $modid and $name
}

rule minecraft_pussylib_pussygo_class {
  meta:
    severity = "high"
    description = "Pussylib payload marker (seen in malware-labeled Minecraft jars)"

  strings:
    $cls = "pussylib/pussygo" ascii nocase

  condition:
    $cls
}

rule minecraft_loaderclient_staging_helper {
  meta:
    severity = "high"
    description = "Staging helper that combines jar/resource staging with HTTP client primitives"

  strings:
    $cls = "me/mclauncher/StagingHelper" ascii
    $jar = "java/util/jar/JarInputStream" ascii
    $http = "java/net/http/HttpRequest" ascii

  condition:
    $cls and $jar and $http
}

rule minecraft_krypton_loader_stub {
  meta:
    severity = "high"
    description = "Obfuscated Fabric ModInitializer loader stub with URLClassLoader and embedded Config payload (seen in Krypton* stealer-labeled jars)"

  strings:
    $fabric = "net/fabricmc/api/ModInitializer" ascii
    $urlcl  = "java/net/URLClassLoader" ascii
    $config = "a/a/a/Config" ascii
    $utf16  = "UTF_16BE" ascii
    $err    = "Error in hash" ascii

  condition:
    all of them
}

rule minecraft_maxcoffe_socket_loader_stub {
  meta:
    severity = "high"
    description = "Obfuscated Fabric example-mod-derived stub that combines Socket I/O, jar staging, and defineClass (seen in MaksRAT-labeled jars)"

  strings:
    $cls     = "MaxCoffe/Coffe" ascii
    $socket  = "java/net/Socket" ascii
    $jar     = "java/util/jar/JarInputStream" ascii
    $define  = "defineClass" ascii
    $urlcl   = "java/net/URLClassLoader" ascii
    $err     = "Error in hash" ascii
    $nothing = "nothing_to_see_here" ascii
    $obf     = "rotipxshzohhkhlt/ejlqrhoxjhblcfpd" ascii

  condition:
    all of them
}

rule minecraft_eth_rpc_endpoint_list {
  meta:
    severity = "high"
    description = "Hardcoded Ethereum JSON-RPC endpoint list in staged loader helper (seen in fractureiser-tagged jars)"

  strings:
    $cls = "com/github/RPCHelper" ascii
    $rpc_urls = "RPC_URLS" ascii

    $eth1 = "rpc.flashbots.net" ascii
    $eth2 = "rpc.mevblocker.io" ascii
    $eth3 = "eth.llamarpc.com" ascii
    $eth4 = "1rpc.io/eth" ascii
    $eth5 = "api.zan.top/eth-mainnet" ascii
    $eth6 = "eth.meowrpc.com" ascii
    $eth7 = "eth-mainnet.public.blastapi.io" ascii
    $eth8 = "eth-mainnet.nodereal.io" ascii
    $eth9 = "ethereum-rpc.publicnode.com" ascii
    $ethA = "gateway.tenderly.co" ascii

  condition:
    $cls and $rpc_urls and 6 of ($eth*)
}
