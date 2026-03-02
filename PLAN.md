# Jarspect Full Overhaul Plan

> **Goal:** Transform Jarspect from a demo-only scanner (that scores real malware 0/100) into a
> production-grade Minecraft mod security scanner capable of detecting real threats like
> fractureiser, BleedingPipe, trojanized mod downloaders, and credential-stealing RATs.
>
> **Sources:** GPT-5.2 Pro extended thinking analysis, Perplexity deep research on Java bytecode
> malware, fractureiser technical documentation (trigram-mrp/fractureiser), Check Point Research
> (Stargazers Ghost Network), Bitdefender lab reports, BleepingComputer BleedingPipe analysis,
> PussyRAT Fabric trojan writeup, jNeedle/NekoShield scanner references, JVM specification for
> class file format.

---

## Table of Contents

1. [Diagnosis: Why Real Malware Scores 0/100](#1-diagnosis-why-real-malware-scores-0100)
2. [Real-World Java/JAR Malware Techniques](#2-real-world-javajar-malware-techniques)
3. [Detection Techniques for Compiled Bytecode](#3-detection-techniques-for-compiled-bytecode)
4. [Production YARA Rules](#4-production-yara-rules)
5. [Minecraft-Mod-Specific Red Flags](#5-minecraft-mod-specific-red-flags)
6. [Scoring Model](#6-scoring-model)
7. [Implementation Phases](#7-implementation-phases)
8. [Architecture Changes](#8-architecture-changes)

---

## 1. Diagnosis: Why Real Malware Scores 0/100

### 1.1 Current repo map (as of now)

Current project is a Rust (Axum) HTTP server with a static web UI.

Top-level layout (key paths):

```
jarspect/
├── Cargo.toml
├── src/main.rs                         # entire backend (routes + analysis + scoring)
├── data/signatures/signatures.json     # demo-only signatures today
├── data/signatures/rules.yar           # demo-only YARA rules today
├── web/index.html
├── web/app.js
├── web/styles.css
├── demo/                               # synthetic sample builder + sample jar
└── .local-data/                        # runtime storage (uploads + scan JSON)
    ├── uploads/{upload_id}.jar
    └── scans/{scan_id}.json
```

Backend currently:
- reads jar entries via `zip::ZipArchive`
- scans lossy UTF-8 text for regex patterns + simple signatures
- scans raw bytes with YARA-X
- synthesizes behavior prediction
- builds verdict with a small weighted score and tier mapping

### 1.2 Current upload -> scan -> verdict pipeline (as implemented)

Flow:

1. `POST /upload` stores `.jar` bytes under `.local-data/uploads/{uuid}.jar`
2. `POST /scan`:
   - unzip to entries
   - `run_static_analysis()`:
     - 4 hardcoded regexes (exec/runtime, url, base64, reflection)
     - JSON signatures (token/regex) from `data/signatures/signatures.json`
     - YARA-X scan per entry from `data/signatures/rules.yar`
   - `infer_behavior()` uses indicator IDs to add synthetic behavior indicators
   - optional `score_author()` adds reputation indicator
   - `build_verdict()` scores indicators and returns `risk_score` 0-100 + tier string
3. Persists full response JSON under `.local-data/scans/{scan_id}.json`

Current scoring mechanics (important for why scores look wrong):
- Indicators are deduped by `indicator.id` and only the max severity per ID counts
- Severity points are: critical=28, high=10, med=3, low=1
- Tier mapping is: 85+=CRITICAL, 65+=HIGH, 40+=MEDIUM, else LOW
- "CLEAN" tier is not implemented (0 score always maps to LOW)

### Current fatal flaws

### Current fatal flaws

1. **Signatures only match the demo sample.** All 6 signatures in `signatures.json` are either
   fictional domains (`payload.example.invalid`, `c2.jarspect.example.invalid`) or exact
   plain-text API strings (`Runtime.getRuntime().exec`) that only appear in Java source code,
   not in compiled `.class` bytecode.

2. **YARA rules only match the demo sample.** All 3 rules in `rules.yar` match synthetic strings
   that exist nowhere in real malware.

3. **Regex patterns scan lossy UTF-8 of binary `.class` files.** The scanner converts all files
   (including compiled bytecode) to `String::from_utf8_lossy()` and runs text regexes. In `.class`
   files, API references exist as structured constant pool entries with length prefixes and type
   tags — not as grep-able plain text. The lossy conversion inserts replacement characters that
   break regex matches.

4. **Behavior inference is completely synthetic.** `infer_behavior()` checks indicator ID
   substrings and hardcodes fake URLs (`payload.example.invalid`) and fake file paths
   (`mods/cache.bin`). If static analysis finds nothing, behavior finds nothing.

5. **Scoring caps too low.** Even if everything fired, dedup-by-ID means the theoretical maximum
   without reputation data is ~47-57 points → MEDIUM at best. The CLEAN tier documented in the
   README doesn't exist in code.

6. **No constant pool parsing.** The scanner has zero understanding of the Java class file format.
   It cannot extract the structured string data where real malware indicators live.

7. **No byte-array string reconstruction.** Real malware (fractureiser Stage 0) builds strings
   via `new String(new byte[]{...})` to avoid literal strings in the constant pool. The scanner
   has no way to recover these.

### The core insight

Real Java malware lives in **compiled bytecode** where:
- API references (`java/lang/Runtime`, `exec`, `java/net/URLClassLoader`) exist as
  `CONSTANT_Utf8` entries in the class file constant pool
- Method calls are encoded as `CONSTANT_Methodref` → `CONSTANT_Class` → `CONSTANT_NameAndType`
  → `CONSTANT_Utf8` chains
- Obfuscated malware hides strings via byte-array construction, Base64 encoding, XOR loops,
  and reflection chains

A scanner that doesn't parse `.class` files is blind to all of this.

---

## 2. Real-World Java/JAR Malware Techniques

### 2.1 How Malicious Code Gets Executed in Minecraft Mod Loaders

**Where attackers hook execution:**

1. **Static initializers (`<clinit>`)** — The earliest reliable trigger. As soon as a class is
   loaded, the JVM runs `<clinit>` once. Fractureiser Stage 0 injected a new static method into
   a mod's main class and added a call to it inside the class's static initializer.

2. **Loader entrypoints / mod init lifecycle:**
   - Fabric/Quilt: classes implementing `net.fabricmc.api.ModInitializer`
   - Forge: class annotated with `net.minecraftforge.fml.common.Mod`
   - Bukkit/Spigot: main class extends `org.bukkit.plugin.java.JavaPlugin`
   - BungeeCord: main class extends `net.md_5.bungee.api.plugin.Plugin`

   Fractureiser Stage 3 explicitly scanned JARs for these signals before infecting them.

3. **Mixin config plugins** — `IMixinConfigPlugin` implementations run very early (before many
   normal mod entrypoints). Can inject into sensitive targets.

4. **Java agents / instrumentation** — If a JAR's MANIFEST.MF declares `Premain-Class` or
   `Agent-Class`, it can use `Instrumentation.addTransformer` to rewrite classes at load time.
   Rare in legit mods; treat as high suspicion.

### 2.2 Real Technique Families (with Concrete APIs)

#### A) Downloading payloads (stagers/droppers)

Common APIs abused:
- `java.net.URL`
- `java.net.URLConnection` / `java.net.HttpURLConnection`
- `java.net.http.HttpClient` (Java 11+)
- `java.io.InputStream` / `java.nio.channels.ReadableByteChannel`
- `java.nio.file.Files` (`write`, `copy`, `newOutputStream`)
- `java.io.FileOutputStream`

**Real-world:** Fractureiser Stage 0 loaded remote code from a hardcoded URL, then Stage 1/2
fetched further payloads. Stargazers Ghost Network used trojanized mods to download additional
stages (Java stealer → .NET stealer).

#### B) Executing OS commands / spawning processes

Common APIs:
- `java.lang.Runtime` → `getRuntime()` + `exec(...)`
- `java.lang.ProcessBuilder` → `start()`
- `java.lang.Process` (pipes, `waitFor`, etc.)

**Real-world:** Fractureiser Stage 3 had OS-command execution. Trojanized RAT-style mods use
process spawning for persistence helpers, registry edits, downloading tools.

#### C) Dynamic code loading (the most important "mod malware" primitive)

**High-signal APIs:**
- `java.net.URLClassLoader`
- `java.lang.ClassLoader#defineClass`
- `java.lang.Class#forName`
- `java.lang.reflect.Constructor#newInstance`
- `java.lang.reflect.Method#invoke`
- `java.lang.invoke.MethodHandles$Lookup#defineClass` (newer)

**Fractureiser Stage 0 specifically used a reflection chain to:**
1. Create a `URLClassLoader`
2. Load a class named `Utility` from the network
3. Call a `run` method with a per-infection identifier string

Even if strings are obfuscated, the reflection chain itself is very detectable in bytecode.

#### D) Self-replication / "infect other mods" behavior

**Minecraft-mod-ecosystem signature.** Common APIs:
- `java.nio.file.Files` (walk filesystem, read/write)
- `java.util.zip.ZipInputStream` / `ZipOutputStream`
- `java.util.jar.JarFile` / `JarOutputStream`
- `java.security` / `META-INF/*` manipulation (signature stripping)

**Fractureiser Stage 3:** Scanned the filesystem for JARs matching mod/plugin patterns and
injected Stage 0 into them. Could disable Java code signing by removing signature-related
files under `META-INF/` (`.RSA`, `.SF`).

#### E) Persistence mechanisms (cross-platform)

**Windows (most common):**
- Registry Run key via `reg.exe`: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- Startup folder drop

**Linux:**
- systemd unit file drop: `/etc/systemd/system` or `~/.config/systemd/user`

**Fractureiser Stage 1:** Attempted persistence via systemd unit placement AND Windows registry
Run key / Startup folder.

#### F) Credential/token theft (Minecraft-specific)

APIs: `java.nio.file.Files.readAllBytes`, JSON parsing, regex
Targets: `.minecraft` launcher profiles, Discord tokens, browser cookies, MSA tokens, crypto wallets

**PussyRAT:** Used reflection to access `MinecraftClient.getSession()` for token hijacking.
**Fractureiser Stage 3:** Full credential stealer — MSA tokens from multiple launchers, Discord
tokens, browser cookies/passwords, crypto wallets, clipboard hijacking.

#### G) JNI / native payload drop + load

Very high signal in mod jars. APIs:
- `java.lang.System#load` / `System#loadLibrary`
- `native` methods in class file access flags
- Embedded `.dll` / `.so` resources

**Fractureiser Stage 3:** Included native `hook.dll` used via JNI for clipboard and credential access.

### 2.3 How These Techniques Look in Compiled `.class` Files

#### Constant pool representation

Every `.class` starts:
- offset `0x00`: magic `CA FE BA BE`
- offset `0x04`: `minor_version` (u2)
- offset `0x06`: `major_version` (u2)
- offset `0x08`: `constant_pool_count` (u2)
- offset `0x0A`: `constant_pool[]` (variable-length)

A `CONSTANT_Utf8` entry (tag `0x01`):
```
u1 tag = 0x01
u2 length (big-endian)
u1 bytes[length] (modified UTF-8)
```

Example: `java/lang/Runtime` appears as raw bytes:
```
01 00 11 6A 61 76 61 2F 6C 61 6E 67 2F 52 75 6E 74 69 6D 65
^  ^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
tag len   "java/lang/Runtime" (17 bytes)
```

YARA string matching works because ASCII substrings appear contiguously in the Utf8 payload.

#### Method/field references driven by Utf8 constants

A call to `Runtime.exec(String)` requires these Utf8 constants:
- `java/lang/Runtime`
- `exec`
- `(Ljava/lang/String;)Ljava/lang/Process;`

Even if code is obfuscated, if it directly invokes Runtime.exec (not purely reflective), these
descriptors will exist.

#### What breaks naive string scanning: byte-array-built strings

Fractureiser Stage 0 avoided literal strings via `new String(new byte[]{...})`:
```java
Class.forName(new String(new byte[]{
    // "java.net.URLClassLoader"
    106, 97, 118, 97, 46, 110, 101, 116, 46, 85, 82, 76, 67, 108, 97, 115, 115,
    76, 111, 97, 100, 101, 114
}))
```

In bytecode: lots of `bipush`/`sipush` + `bastore` + `String.<init>([B)V`.
The actual string will NOT exist in the constant pool. This is why scanners that only extract
constant pool strings score such malware as "0/100".

### 2.4 Obfuscation Techniques in Mod Malware

#### A) String encryption/encoding
- `java/util/Base64` + `decode` + `new String(...)`
- `javax/crypto/Cipher` + `javax/crypto/spec/SecretKeySpec`
- XOR loops (`ixor` opcode `0x82`)
- Allatori string encryption (encodes strings, adds runtime decoder)
- Fractureiser Stage 2 was obfuscated with demo Allatori

#### B) Reflection chains (hiding dangerous API usage)
Constant pool strings:
- `java/lang/Class`, `forName`
- `java/lang/reflect/Method`, `invoke`
- `java/lang/reflect/Constructor`, `newInstance`
- `getDeclaredMethod`, `getMethod`, `setAccessible`

#### C) Control-flow obfuscation
- High density of `tableswitch` / `lookupswitch`
- Opaque predicates (`if_icmp*` chains that always fold)
- Exception-driven flow: frequent `athrow`, weird try/catch structure

#### D) Custom classloaders / in-memory execution
- Classes extending `java/lang/ClassLoader`
- Calls to `defineClass`
- Huge static byte arrays (encrypted payloads)
- High entropy resources

---

## 3. Detection Techniques for Compiled Bytecode

This scanner must be **bytecode-native**, not source-native.

### 3.1 Parse `.class` properly (offsets and structures that matter)

Build (or integrate) a classfile parser that provides:

1. Constant pool table (all CP entries, not just Utf8)
2. Per-method `Code` attribute:
   - `max_stack`, `max_locals`
   - `code_length`
   - raw bytecode bytes
   - exception table
   - nested attributes (LineNumberTable, StackMapTable, etc.)

Why: most useful detection requires resolving an `invoke*` operand (a constant-pool index) into:
- owner class internal name (`java/lang/Runtime`)
- method name (`exec`)
- descriptor (`(Ljava/lang/String;)Ljava/lang/Process;`)

### 3.2 Constant pool extraction (and the missing piece: reconstruction)

#### A) Baseline extraction

Extract and deduplicate:
- all `CONSTANT_Utf8` entries
- all `CONSTANT_String` literal entries

Store both raw + normalized variants:
- `java/lang/Runtime` and `java.lang.Runtime`
- case-normalized for domain/path checks where appropriate

#### B) Byte-array-to-string reconstruction (critical for Fractureiser Stage 0)

Goal: recover strings constructed with `new String(new byte[]{...})`.

You do NOT need a full decompiler. You need a tiny partial evaluator for a specific pattern.

Heuristic bytecode shape (CP indices vary, opcodes do not):
- create byte array:
  - push length (`iconst_*`, `bipush`, `sipush`)
  - `newarray T_BYTE` (`0xBC 0x08`)
- repeated initialization:
  - `dup`
  - push index
  - push value
  - `bastore` (`0x54`)
- instantiate String:
  - `new java/lang/String`
  - `dup`
  - (array ref on stack)
  - `invokespecial java/lang/String.<init>([B)V`

When you see `String.<init>([B)V`, walk backwards within the same basic block to recover the
constant byte array if it was constructed in-line.

Output: decoded ASCII/UTF-8 strings added to the extracted string set, tagged as "reconstructed".

This is often the difference between scoring Stage-0 loaders as 0/100 vs catching them.

#### C) Other common string-hiding encodings

You do not need to fully decrypt everything, but you should detect the presence of:
- Base64 decode chains: `java/util/Base64` + `decode`
- Crypto decode chains: `javax/crypto/Cipher`, `SecretKeySpec`, `MessageDigest`
- XOR decode loops (look for `ixor` / int ops + `i2b` patterns)

Even without decryption, these are high-confidence obfuscation indicators that should increase
score when combined with network/dynamic-load/exec signals.

### 3.3 Bytecode instruction matching (resolve invoke sequences)

Do NOT rely on raw opcode hex matching with fixed offsets. Constant pool indices change across
builds and obfuscation.

Instead:
1. Disassemble `Code` bytes into an instruction stream
2. For each invoke instruction (`invokevirtual`, `invokestatic`, `invokespecial`,
   `invokeinterface`, `invokedynamic`):
   - resolve the CP reference into `(owner, name, desc)`
3. Run matchers on these resolved tuples

#### A) Process execution detectors (high signal when paired with network/file IO)

Match any of:
- `java/lang/Runtime.getRuntime:()Ljava/lang/Runtime;`
- `java/lang/Runtime.exec:(...)Ljava/lang/Process;` (multiple overloads)
- `java/lang/ProcessBuilder.<init>:(...)V`
- `java/lang/ProcessBuilder.start:()Ljava/lang/Process;`

Escalate severity if command strings include:
- `cmd.exe`, `powershell`, `/bin/sh`, `/bin/bash`
- `reg add`, `schtasks`, `systemctl`, `crontab`
- `curl`, `wget`, `bitsadmin`

#### B) Remote code loading detectors (critical)

Match any of:
- `java/net/URLClassLoader`
- `java/lang/ClassLoader#defineClass`
- `java/lang/reflect/Method.invoke`
- `java/lang/Class.forName`

Escalate if combined with:
- `java/net/URL` construction/open
- `HttpURLConnection` / `java/net/http/HttpClient`
- `Files.write/copy`
- jar-in-jar extraction + load

Fractureiser Stage 0 is exactly: construct classloader → load remote class → invoke method.

#### C) Self-replication / JAR modification detectors (very high signal in mods)

Match combinations like:
- `java/util/zip/ZipInputStream.getNextEntry`
- `java/util/zip/ZipOutputStream.putNextEntry`
- `java/util/jar/JarFile` / `JarOutputStream`
- directory traversal (`Files.walk`, `File.listFiles`)

Escalate if paired with:
- strings containing `mods`, `.minecraft`, `plugins`, `versions`, `libraries`
- writing `.class` entries or rewriting JARs

#### D) Persistence detectors

Look for constant pool strings and/or behavior referencing:
- Windows Run key path: `Software\\Microsoft\\Windows\\CurrentVersion\\Run`
- Linux systemd paths: `/etc/systemd/system`, `~/.config/systemd/user`
- Startup folder paths

Also look for process-spawn usage of `reg`, `systemctl`, `schtasks`, etc.

#### E) Unsafe deserialization sink detectors (BleedingPipe-style risk)

Flag as vulnerability/exploit-risk (not necessarily malware) if:
- `java/io/ObjectInputStream.<init>(Ljava/io/InputStream;)V`
- followed by `java/io/ObjectInputStream.readObject:()Ljava/lang/Object;`

Escalate if the same class also references sockets or networking streams.

### 3.4 Entropy analysis (useful, but avoid false positives)

Entropy alone is noisy. Use it as a multiplier when paired with suspicious decode/load behavior.

Compute Shannon entropy on:
- each archive entry raw bytes (resources, embedded binaries)
- each `CONSTANT_Utf8` string bytes
- optionally each method Code byte array

Use cases:
- embedded `.dll`/`.so` or `.bin` with entropy > ~7.2 bits/byte
- huge static byte arrays (many `bastore`/`iastore`)
- string pools full of high-entropy gibberish + presence of decryptors

Do not convict on entropy alone.

### 3.6 Advanced Implementation Tips (from research)

1. **Scan per-entry, not per-jar bytes**: Inflate every `.class`, config, and nested jar entry and scan those bytes individually. This is critical because YARA over the whole JAR won't reliably hit compressed entries.
2. **Build a "resolved invoke" stream**: Minimal method parser + constant pool resolver is enough. You don’t need a full decompiler—just `invoke*` → Methodref → `(owner, name, desc)`.
3. **Report evidence with offsets**: Include class name, method name, and constant pool offset in results to make findings credible and testable.

### 5.6 Deep Structural Anomalies

- **Package Namespace Sanity**: Legit mods usually follow `com.<author>.<mod>`. Flag weird short packages (`a/a/a.class`) or packages unrelated to the mod vendor.
- **ServiceLoader Abuse**: Check for `java/util/ServiceLoader` usage to auto-load hidden implementations.
- **Opaque Predicates**: High density of `tableswitch` / `lookupswitch` or exception-driven flow (`athrow` chains).
...
---

## 4. Production YARA Rules

### Operational note

YARA will not reliably see inside deflated ZIP members if you scan the `.jar` as a single blob.
The correct approach:
1. unzip jar
2. run YARA on each `.class` and selected resources (manifest, json/toml/yml, embedded binaries)

Treat YARA hits as *signals* feeding the risk score, not as a final verdict.

### 4.1 Refined Production YARA Rulepack (Bytecode-Aware)

These rules are optimized for scanning inflated `.class` entries, targeting the Constant Pool structure.

```yara
rule JAVA_Runtime_exec_ConstantPool
{
  meta:
    id = "JAVA-EXEC-001"
    family = "generic"
    description = "Detects Runtime.getRuntime().exec() indicators in Java .class constant pool"
    severity = "high"
  strings:
    // Constant pool UTF-8 format: 0x01 + u2 length + bytes
    // "java/lang/Runtime" length = 17 (0x0011)
    $cp_runtime = { 01 00 11 6A 61 76 61 2F 6C 61 6E 67 2F 52 75 6E 74 69 6D 65 }
    // "getRuntime" length = 10 (0x000A)
    $cp_getRuntime = { 01 00 0A 67 65 74 52 75 6E 74 69 6D 65 }
    // "exec" length = 4 (0x0004)
    $cp_exec = { 01 00 04 65 78 65 63 }
  condition:
    uint32be(0) == 0xCAFEBABE and ( $cp_runtime and $cp_getRuntime and $cp_exec )
}

rule JAVA_ProcessBuilder_start_ConstantPool
{
  meta:
    id = "JAVA-EXEC-002"
    family = "generic"
    description = "Detects ProcessBuilder.start() indicators in Java .class constant pool"
    severity = "medium"
  strings:
    // "java/lang/ProcessBuilder" length = 24 (0x0018)
    $cp_pb = { 01 00 18 6A 61 76 61 2F 6C 61 6E 67 2F 50 72 6F 63 65 73 73 42 75 69 6C 64 65 72 }
    // "start" length = 5 (0x0005)
    $cp_start = { 01 00 05 73 74 61 72 74 }
  condition:
    uint32be(0) == 0xCAFEBABE and ( $cp_pb and $cp_start )
}

rule JAVA_URLClassLoader_RemoteURL
{
  meta:
    id = "JAVA-LOAD-001"
    family = "generic"
    description = "Detects URLClassLoader usage combined with HTTP(S) URL indicators"
    severity = "high"
  strings:
    // "java/net/URLClassLoader" length = 23 (0x0017)
    $cp_ucl = { 01 00 17 6A 61 76 61 2F 6E 65 74 2F 55 52 4C 43 6C 61 73 73 4C 6F 61 64 65 72 }
    $http  = "http://" ascii nocase
    $https = "https://" ascii nocase
  condition:
    uint32be(0) == 0xCAFEBABE and $cp_ucl and ($http or $https)
}

rule JAVA_Unsafe_Deserialization_ObjectInputStream
{
  meta:
    id = "JAVA-DESER-001"
    description = "Detects ObjectInputStream.readObject usage (unsafe deserialization indicator)"
    severity = "medium"
  strings:
    // "java/io/ObjectInputStream" length = 25 (0x0019)
    $cp_ois = { 01 00 19 6A 61 76 61 2F 69 6F 2F 4F 62 6A 65 63 74 49 6E 70 75 74 53 74 72 65 61 6D }
    // "readObject" length = 10 (0x000A)
    $cp_readObject = { 01 00 0A 72 65 61 64 4F 62 6A 65 63 74 }
  condition:
    uint32be(0) == 0xCAFEBABE and $cp_ois and $cp_readObject
}

rule Fractureiser_Stage0_Heuristic
{
  meta:
    id = "FRACT-001"
    family = "fractureiser"
    description = "Heuristic for Fractureiser Stage 0 style loader patterns"
    severity = "critical"
  strings:
    $ucl = "java/net/URLClassLoader" ascii
    $utility = "Utility" ascii
    $run = "run" ascii
    $jls = "java/lang/String" ascii
    $byte_arr_desc = "([B)" ascii
    $http = "http" ascii nocase
  condition:
    uint32be(0) == 0xCAFEBABE and $ucl and $http and ($utility and $run) and ($jls and $byte_arr_desc)
}

rule Java_Shell_Command_Indicators
{
  meta:
    id = "JAVA-CMD-001"
    description = "Detects embedded shell command strings in class constants"
    severity = "high"
  strings:
    $cmd1 = "cmd.exe" ascii nocase
    $cmd2 = "powershell" ascii nocase
    $sh1 = "/bin/sh" ascii
    $sh2 = "/bin/bash" ascii
  condition:
    uint32be(0) == 0xCAFEBABE and (1 of ($cmd*) or 1 of ($sh*))
}

rule Credential_Theft_Indicators
{
  meta:
    id = "STEAL-001"
    description = "Detects common credential/token theft path indicators"
    severity = "critical"
  strings:
    $d1 = "Discord\\Local Storage\\leveldb" ascii nocase
    $b1 = "User Data\\Default\\Login Data" ascii nocase
    $f1 = "Firefox\\Profiles" ascii nocase
    $m1 = "IdentityCache" ascii nocase
  condition:
    1 of them
}

rule Persistence_Indicators
{
  meta:
    id = "PERSIST-001"
    description = "Detects common persistence indicators"
    severity = "high"
  strings:
    $r1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase
    $s1 = "/etc/systemd/system" ascii
    $c1 = "/etc/cron.d" ascii
  condition:
    1 of them
}
```

### 4.2 Additional YARA rules from the Pro query blueprint (Deprecated/Legacy)

The rules below are kept for reference but should be replaced by the rules in 4.1.

```yara
import "math"
...
rule JAVA_ClassFile_Header
{
  meta:
    description = "Java .class file magic"
  condition:
    uint32be(0) == 0xCAFEBABE
}

rule JAVA_ProcessExec_SuspiciousShell
{
  meta:
    description = "Runtime.exec / ProcessBuilder combined with common shell / admin tool strings"
    severity = "high"
  strings:
    $rt  = "java/lang/Runtime"
    $gr  = "getRuntime"
    $exec = "exec"
    $pb  = "java/lang/ProcessBuilder"
    $start = "start"

    // common shell/persistence tooling markers
    $cmd = "cmd.exe" nocase
    $ps  = "powershell" nocase
    $sh  = "/bin/sh"
    $bash = "/bin/bash"
    $reg = "CurrentVersion\\Run" nocase
    $systemctl = "systemctl" nocase
    $schtasks = "schtasks" nocase
    $curl = "curl " nocase
    $wget = "wget " nocase

  condition:
    uint32be(0) == 0xCAFEBABE and
    (
      (all of ($rt, $gr, $exec) and 1 of ($cmd, $ps, $sh, $bash, $reg, $systemctl, $schtasks, $curl, $wget))
      or
      ($pb and $start and 1 of ($cmd, $ps, $sh, $bash, $reg, $systemctl, $schtasks, $curl, $wget))
    )
}

rule JAVA_URLClassLoader_RemoteCodeLoad
{
  meta:
    description = "URLClassLoader + HTTP(S) indicators + dynamic loading keywords"
    severity = "critical"
  strings:
    $ucl = "java/net/URLClassLoader"
    $url = "java/net/URL"
    $http = "http" nocase
    $https = "https" nocase

    $loadClass = "loadClass"
    $defineClass = "defineClass"

    $forName = "java/lang/Class"
    $forName2 = "forName"
    $reflectM = "java/lang/reflect/Method"
    $invoke = "invoke"

  condition:
    uint32be(0) == 0xCAFEBABE and
    (
      // direct URLClassLoader usage
      ($ucl and $url and 1 of ($http, $https) and 1 of ($loadClass, $defineClass))
      or
      // reflection chain often used to hide loader creation
      ($forName and $forName2 and $reflectM and $invoke and 1 of ($http, $https))
    )
}

rule JAVA_UnsafeDeserialization_ObjectInputStream_ReadObject
{
  meta:
    description = "Unsafe deserialization sink: ObjectInputStream.readObject (BleedingPipe-style risk)"
    severity = "high"
    kind = "vuln-risk"
  strings:
    $ois = "java/io/ObjectInputStream"
    $init = "<init>"
    $readObject = "readObject"
    $socket = "java/net/Socket"
    $getIS = "getInputStream"
  condition:
    uint32be(0) == 0xCAFEBABE and
    $ois and $readObject and
    // escalate if socket appears too (very rough static correlation)
    ( $socket or $getIS )
}

rule JAVA_JNI_NativeLoad_Suspicious
{
  meta:
    description = "System.load/loadLibrary + native library extensions"
    severity = "high"
  strings:
    $sys = "java/lang/System"
    $load = "loadLibrary"
    $load2 = "load"
    $dll = ".dll" nocase
    $so  = ".so" nocase
    $dylib = ".dylib" nocase
  condition:
    uint32be(0) == 0xCAFEBABE and
    $sys and ( $load or $load2 ) and 1 of ($dll, $so, $dylib)
}

rule MC_Fractureiser_Stage1_Indicators
{
  meta:
    description = "Known Fractureiser Stage 1/2/3 indicator strings (when present as literals)"
    severity = "critical"
    family = "fractureiser"
  strings:
    $nekoRun = "neko.run"
    $refFile = ".ref"
    $cfPages = "files-8ie.pages.dev"
    $c2ip1 = "85.217.144.130"
    $stage2w = "libWebGL64.jar"
    $stage2l = "lib.jar"
    $systemd1 = "/etc/systemd/system"
    $systemd2 = ".config/systemd/user"
    $runKey = "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    $devNeko = "dev/neko/nekoclient"
    $hookDll = "hook.dll"
  condition:
    uint32be(0) == 0xCAFEBABE and
    2 of ($nekoRun, $refFile, $cfPages, $c2ip1, $stage2w, $stage2l, $systemd1, $systemd2, $runKey, $devNeko, $hookDll)
}

rule MC_Fractureiser_Stage0_ImplantShape
{
  meta:
    description = "Heuristic for Fractureiser-like Stage 0 implant: GUID-ish method name + <clinit> + reflection chain + URL usage"
    severity = "high"
    family = "fractureiser-ish"
  strings:
    $clinit = "<clinit>"
    $url = "java/net/URL"
    $class = "java/lang/Class"
    $forName = "forName"
    $reflectC = "java/lang/reflect/Constructor"
    $reflectM = "java/lang/reflect/Method"
    $invoke = "invoke"

    // method name pattern: _ + 32 hex chars
    $mname = /_[0-9a-f]{32}/
  condition:
    uint32be(0) == 0xCAFEBABE and
    $clinit and $mname and
    $url and $class and $forName and
    1 of ($reflectC, $reflectM) and $invoke
}

rule MC_TrojanizedMod_SessionTheft_Heuristic
{
  meta:
    description = "Minecraft session access strings seen in trojanized mod malware reports"
    severity = "medium"
  strings:
    $mcClient = "net/minecraft/client/MinecraftClient"
    $getSession = "getSession"
    $reflect = "java/lang/reflect"
  condition:
    uint32be(0) == 0xCAFEBABE and
    $mcClient and $getSession and $reflect
}

rule JAVA_Obfuscator_Allatori_Marker
{
  meta:
    description = "Possible Allatori marker strings (informational; not malware by itself)"
    severity = "info"
  strings:
    $allatori = "Allatori" nocase
    $smardec = "Smardec" nocase
  condition:
    uint32be(0) == 0xCAFEBABE and 1 of ($allatori, $smardec)
}
```

### 4.2 Additional YARA rules captured from GPT-5.2 tool output

These are included verbatim as additional starting points. They need tuning for false positives
and for fractureiser Stage 0 (which often avoids literal strings).

```yara
rule JAVA_Class_RuntimeExec { meta: description = "Detects Java .class bytecode invoking Runtime.exec" author = "ChatGPT" date = "2026-02-28" confidence = "high" strings: $magic = { CA FE BA BE } $s1 = "java/lang/Runtime" ascii $s2 = "getRuntime" ascii $s3 = "exec" ascii $s4 = "(Ljava/lang/String;)" ascii $s5 = "(Ljava/lang/String;[Ljava/lang/String;)" ascii $s6 = "([Ljava/lang/String;)" ascii condition: uint32be(0) == 0xCAFEBABE and $magic in (0..8) and $s1 and $s2 and $s3 }
rule JAVA_Class_ProcessBuilder { meta: description = "Detects Java .class bytecode using ProcessBuilder" author = "ChatGPT" date = "2026-02-28" confidence = "high" strings: $magic = { CA FE BA BE } $s1 = "java/lang/ProcessBuilder" ascii $s2 = "start" ascii $s3 = "command" ascii $s4 = "redirectErrorStream" ascii $s5 = "inheritIO" ascii $s6 = "java/util/List" ascii condition: uint32be(0) == 0xCAFEBABE and $magic in (0..8) and $s1 and $s2 }
rule JAVA_Class_URLClassLoader_DynamicLoad { meta: description = "Detects Java .class bytecode using URLClassLoader / dynamic class loading" author = "ChatGPT" date = "2026-02-28" confidence = "high" strings: $magic = { CA FE BA BE } $s1 = "java/net/URLClassLoader" ascii $s2 = "newInstance" ascii $s3 = "loadClass" ascii $s4 = "defineClass" ascii $s5 = "java/lang/ClassLoader" ascii $s6 = "getResource" ascii condition: uint32be(0) == 0xCAFEBABE and $magic in (0..8) and ( $s1 or $s5 ) and ( $s2 or $s3 or $s4 ) }
rule JAVA_Class_ObjectInputStream_ReadObject { meta: description = "Detects Java .class bytecode performing Java deserialization via ObjectInputStream.readObject" author = "ChatGPT" date = "2026-02-28" confidence = "high" strings: $magic = { CA FE BA BE } $s1 = "java/io/ObjectInputStream" ascii $s2 = "readObject" ascii $s3 = "readUnshared" ascii $s4 = "java/io/Serializable" ascii $s5 = "java/io/ObjectStreamClass" ascii $s6 = "resolveClass" ascii condition: uint32be(0) == 0xCAFEBABE and $magic in (0..8) and $s1 and ( $s2 or $s3 ) }
rule JAVA_Class_Fractureiser_Stage0_Indicators { meta: description = "Detects suspected fractureiser stage0 indicators in Java .class bytecode" author = "ChatGPT" date = "2026-02-28" confidence = "medium" strings: $magic = { CA FE BA BE } $k1 = "fractureiser" ascii nocase $k2 = "stage0" ascii nocase $k3 = "Stage0" ascii $k4 = "bootstrap" ascii nocase $k5 = "download" ascii nocase $k6 = "payload" ascii nocase condition: uint32be(0) == 0xCAFEBABE and $magic in (0..8) and ( ($k1 and ($k2 or $k3)) or ( $k1 and 2 of ($k4,$k5,$k6) ) ) }
rule JAVA_Class_DevNeko_Packages { meta: description = "Detects suspicious dev/neko package namespace in Java .class bytecode" author = "ChatGPT" date = "2026-02-28" confidence = "medium" strings: $magic = { CA FE BA BE } $p1 = "dev/neko/" ascii $p2 = "dev\\neko\\" ascii $p3 = "dev.neko." ascii $p4 = "neko" ascii nocase condition: uint32be(0) == 0xCAFEBABE and $magic in (0..8) and ( $p1 or $p2 or $p3 ) and $p4 }
rule JAVA_Class_Allatori_Obfuscator { meta: description = "Detects Allatori obfuscator artifacts in Java .class bytecode" author = "ChatGPT" date = "2026-02-28" confidence = "medium" strings: $magic = { CA FE BA BE } $a1 = "Allatori" ascii $a2 = "allatori" ascii nocase $a3 = "com/allatori/" ascii nocase $a4 = "Allatori Obfuscator" ascii $a5 = "allatori-annotations" ascii nocase condition: uint32be(0) == 0xCAFEBABE and $magic in (0..8) and ( 2 of ($a1,$a2,$a3,$a4,$a5) ) }
rule JAVA_Class_Embedded_Shell_Commands { meta: description = "Detects embedded shell command indicators in Java .class bytecode" author = "ChatGPT" date = "2026-02-28" confidence = "high" strings: $magic = { CA FE BA BE } $sh1 = "/bin/sh" ascii $sh2 = "/bin/bash" ascii $sh3 = "sh -c" ascii $w1 = "cmd.exe" ascii nocase $w2 = "/c " ascii $ps1 = "powershell" ascii nocase $ps2 = "-ExecutionPolicy" ascii nocase $ps3 = "Invoke-Expression" ascii nocase $ps4 = "IEX" ascii condition: uint32be(0) == 0xCAFEBABE and $magic in (0..8) and ( 2 of ($sh1,$sh2,$sh3,$w1,$w2,$ps1,$ps2,$ps3,$ps4) ) }
rule JAVA_Class_Credential_Theft_Paths { meta: description = "Detects common credential theft file path indicators in Java .class bytecode" author = "ChatGPT" date = "2026-02-28" confidence = "medium" strings: $magic = { CA FE BA BE } $u1 = "/.ssh/id_rsa" ascii $u2 = "/.ssh/id_ed25519" ascii $u3 = "/.ssh/known_hosts" ascii $u4 = "/etc/passwd" ascii $u5 = "/etc/shadow" ascii $b1 = "Login Data" ascii $b2 = "Local State" ascii $b3 = "Cookies" ascii $b4 = "key4.db" ascii $b5 = "logins.json" ascii $w1 = "AppData\\Local\\Google\\Chrome\\User Data" ascii nocase $w2 = "AppData\\Roaming\\Mozilla\\Firefox\\Profiles" ascii nocase $w3 = "Microsoft\\Edge\\User Data" ascii nocase condition: uint32be(0) == 0xCAFEBABE and $magic in (0..8) and ( 2 of ($u1,$u2,$u3,$u4,$u5,$b1,$b2,$b3,$b4,$b5,$w1,$w2,$w3) ) }
rule JAVA_Class_Windows_Registry_Persistence { meta: description = "Detects Windows registry persistence indicators in Java .class bytecode" author = "ChatGPT" date = "2026-02-28" confidence = "high" strings: $magic = { CA FE BA BE } $r1 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase $r2 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii nocase $r3 = "CurrentVersion\\RunOnce" ascii nocase $r4 = "reg add" ascii nocase $r5 = "reg.exe" ascii nocase $r6 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" ascii nocase $r7 = "RunServices" ascii nocase $r8 = "schtasks" ascii nocase $r9 = "Task Scheduler" ascii nocase condition: uint32be(0) == 0xCAFEBABE and $magic in (0..8) and ( 2 of ($r1,$r2,$r3,$r4,$r5,$r6,$r7,$r8,$r9) ) }
```

---

## 5. Minecraft-Mod-Specific Red Flags

### 5.1 Metadata presence + validity (cheap, high ROI)

Fabric/Quilt:
- `fabric.mod.json` exists and parses as JSON
- entrypoint classes exist in the JAR

Forge:
- `META-INF/mods.toml` exists and parses
- plausible `modId`, version, loader constraints

Bukkit/Spigot:
- `plugin.yml` exists; `main:` class exists

BungeeCord:
- `bungee.yml` exists; main exists

Score up when:
- no mod metadata exists but JAR contains many `.class` files that reference mod APIs
- metadata exists but references missing classes

### 5.2 Classes outside expected namespaces

Heuristic:
- derive dominant package prefix frequency
- flag unrelated high-risk packages (e.g., `dev/neko/nekoclient` inside a mod otherwise under
  `com/someauthor/modname`)

### 5.3 Mixin abuse patterns

Legit mods use Mixins constantly. Avoid flagging on presence alone.

Implementable checks:
1. Parse mixin config JSON(s)
2. Collect targets
3. Flag if target includes:
   - `java/` or `javax/` (JRE hooking)
   - loader internals
4. If `IMixinConfigPlugin` exists, flag if it includes network + file write + reflection patterns

### 5.4 Suspicious manifest entries

In `META-INF/MANIFEST.MF`, score up if any exist:
- `Premain-Class:`
- `Agent-Class:`
- `Can-Redefine-Classes:`
- `Can-Retransform-Classes:`
- `Boot-Class-Path:`

These are legitimate in agents/profilers but uncommon in mods.

### 5.5 Jar-in-jar embedding (nested jars)

Fabric supports nested jars, so this is not malware by itself.

Checks:
- enumerate embedded `*.jar` entries (common under `META-INF/jars/`)
- recursively scan inner jars
- flag if inner jar has no metadata but contains loader/exec/network primitives or looks like a payload

---

## 6. Scoring Model

### 6.1 Scoring principles

- Do not score primitives alone (reflection/network are common in mods)
- Score combinations (download + dynamic load + exec + persistence + jar rewrite)
- Include explainability: the score must be attributable to indicators with concrete evidence
- Prefer diminishing returns for repeated similar hits

### 6.2 Practical 0-100 capability scoring (from Pro query blueprint)

Base capability weights (example):
- Remote code load (URLClassLoader/defineClass/invoke chain): +35
- Process execution (Runtime.exec / ProcessBuilder): +25
- Persistence attempt (Run key / systemd / Startup): +25
- JAR rewriting / self-replication indicators: +35
- JNI native load + embedded `.dll/.so`: +20
- Unsafe deserialization sink: +20 (tag as vulnerability risk)

Confidence / IoC weights:
- Known family IoCs (fractureiser indicators): +60 (cap at 100)
- Implant shape (`_[0-9a-f]{32}` + `<clinit>` + reflection chain): +25
- Obfuscation-only signals: cap at +10 when alone

Synergy bonuses:
- download + exec: +20
- download + dynamic load: +25
- persistence + any of above: +20
- jar rewrite + any of above: +25

Severity bands:
- 0: CLEAN (only when 0 indicators)
- 1-19: LOW
- 20-49: MEDIUM
- 50-79: HIGH
- 80-100: CRITICAL

### 6.3 Alternative scoring model captured from GPT-5.2 output

This model returns a raw score that can be normalized to 0-100.

```json
{ "severity_points": { "critical": 60, "high": 35, "medium": 20, "low": 10, "info": 2 }, "category_multipliers": { "execution": 1.6, "network": 1.2, "obfuscation": 1.15, "credential_theft": 1.8, "persistence": 1.4, "known_malware": 2.2, "dynamic_loading": 1.3, "deserialization": 1.5, "mod_integrity": 1.25 }, "combo_bonuses": [ { "categories": ["known_malware", "execution"], "bonus": 40 }, { "categories": ["execution", "network"], "bonus": 18 }, { "categories": ["credential_theft", "network"], "bonus": 28 }, { "categories": ["persistence", "execution"], "bonus": 22 }, { "categories": ["obfuscation", "dynamic_loading"], "bonus": 16 }, { "categories": ["deserialization", "execution"], "bonus": 26 }, { "categories": ["mod_integrity", "dynamic_loading"], "bonus": 12 }, { "categories": ["known_malware", "persistence"], "bonus": 24 } ], "tier_thresholds": { "CLEAN": "0-19", "LOW": "20-49", "MEDIUM": "50-89", "HIGH": "90-139", "CRITICAL": "140+" }, "dedup_strategy": "Deduplicate at the indicator level using a normalized key per finding (category + canonicalized IOC/symbol/pattern + normalized location). Within each category, apply diminishing returns after the first N unique indicators (e.g., full value for first 3, 50% for next 3, 25% thereafter) to avoid score inflation from many near-duplicate string hits typical of signature/heuristic engines. Cap each category’s contribution (e.g., max 2.5x the highest single indicator in that category). For vendor-style results (e.g., multiple engines flagging the same family/label), collapse to one 'known_malware' hit and increase confidence via a small consensus bump (e.g., +5 to +15 based on #malicious vs #suspicious) rather than counting each engine separately, mirroring how multi-engine reports present counts without implying linear additive severity." }
```

### 6.5 Refined Production Scoring Model (Numeric-Only)

Based on latest research (Research Report 5), the following numeric weights and multipliers should be implemented for the production engine.

#### 1) Severity → Base Points
- **info**: 1
- **low**: 4
- **medium**: 10
- **high**: 18
- **critical**: 28

#### 2) Category Multipliers
- **execution**: 1.8
- **network**: 1.4
- **obfuscation**: 1.2
- **credential_theft**: 2.0
- **persistence**: 1.6
- **known_malware**: 2.2
- **dynamic_loading**: 1.5
- **deserialization**: 1.4
- **mod_integrity**: 1.1

#### 3) Combo Bonuses (Additive)
Apply once per pair if both categories are present, max **+35** total bonus.
- **execution + network**: +12
- **dynamic_loading + network**: +10
- **credential_theft + network**: +18
- **obfuscation + execution**: +8
- **persistence + network**: +8
- **known_malware + execution**: +15
- **known_malware + credential_theft**: +15

#### 4) 0–100 Normalized Thresholds
Mapping of raw weighted sum to 0-100 scale (Normalization factor: 120).
- **CLEAN**: 0–9
- **LOW**: 10–24
- **MEDIUM**: 25–49
- **HIGH**: 50–74
- **CRITICAL**: 75–100

#### 5) Corroboration Bonuses (Dedup)
For same indicator (fingerprint) from multiple layers:
- Keep `max(points)` across layers (not sum).
- Corroboration bonus per fingerprint:
  - 1 layer: +0
  - 2 layers: +2
  - 3+ layers: +4
- Cap total corroboration bonuses at **+20**.

#### 6) False-Positive Controls (Discount Multipliers)
- **network-only**: ×0.35
- **dynamic_loading-only**: ×0.45
- **obfuscation-only**: ×0.55
- **deserialization-only**: ×0.60
- **Allowlisted endpoint**: ×0.25 (network only)
- **Private/Local IP**: ×0.40 (network only)
- **Allowlisted package**: ×0.15

#### 7) Hard Numeric Gates for Tiers
- To reach **HIGH (50+)**: Must have ≥1 of {execution, credential_theft, persistence, known_malware} OR combos total ≥12.
- To reach **CRITICAL (75+)**: Must have `known_malware` present OR (`execution` AND `network`) OR (`credential_theft` AND `network`).

---

## 7. Implementation Phases
...
NOTE: This document is a plan only. No implementation changes are made as part of writing it.

### Phase 0: Freeze demo-only assets

- Keep demo signatures/rules for the synthetic sample
- Add production rulepacks separately (avoid mixing demo IOCs with real detections)

### Phase 1: Classfile parsing + constant pool extraction

Deliverables:
- Detect `.class` entries reliably (`CAFEBABE`)
- Parse constant pool
- Extract:
  - CP UTF-8 strings
  - string literals (CONSTANT_String)
  - resolved method refs (owner/name/descriptor)

### Phase 2: Invoke-resolution matchers (capability detectors)

Implement bytecode disassembly sufficient to:
- scan each method Code
- resolve invoke instructions to method refs

Add detectors for:
- execution (Runtime/ProcessBuilder)
- network download APIs
- dynamic loading (URLClassLoader/defineClass)
- reflection chains
- jar rewriting/self-replication
- persistence
- unsafe deserialization
- JNI load

### Phase 3: Byte-array string reconstruction

Implement partial evaluator for:
- `new String(new byte[]{...})`

Use reconstructed strings to:
- recover hidden URLs/class names/method names
- enrich evidence output

### Phase 4: JAR-structure + mod metadata checks

- Parse MANIFEST.MF
- Parse mod metadata files (`fabric.mod.json`, `mods.toml`, `plugin.yml`, etc.)
- Cross-check entrypoint classes exist
- Detect jar-in-jar and recursively scan

### Phase 5: YARA overhaul

- Replace demo-only rules with production rulesets
- Run YARA on extracted `.class` + resources (not on jar blob)
- Map YARA rule severity from rule metadata or rule naming conventions

### Phase 6: Scoring engine overhaul

- Add CLEAN tier
- Move to capability+synergy scoring
- Dedup across layers
- Apply diminishing returns

### Phase 7: Behavior inference overhaul

- Remove hardcoded fake evidence
- Derive predicted URLs, file writes, commands, persistence from extracted evidence

### Phase 8: Frontend fixes

- Normalize severity labels consistently (`med` vs `medium` mismatch)
- Display CLEAN tier
- Render behavior evidence from actual extracted values

### Phase 9: Verification and regression tests

Constraints:
- Tests must not use mocks

Add fixtures:
- minimal compiled `.class` samples for each detector (exec, urlclassloader, ois.readObject, etc.)
- jar-in-jar fixture
- metadata mismatch fixture

Regression goal:
- A known real malware sample (or a safe extracted subset of indicators) must score HIGH/CRITICAL

---

## 8. Architecture Changes

### 8.1 Backend modularization (recommended)

Current state: everything is in `src/main.rs`.

Proposed modules (names flexible):
- `analysis/jar.rs` (archive reading, entry classification)
- `analysis/classfile.rs` (constant pool + method parsing)
- `analysis/bytecode.rs` (instruction scanning, invoke resolution)
- `analysis/detectors/*` (capability detectors)
- `analysis/yara.rs` (rule loading, scan per entry, severity mapping)
- `analysis/scoring.rs` (risk score + tier)
- `analysis/explain.rs` (evidence extraction and formatting)

### 8.2 Indicator schema upgrades

Add fields for explainability:
- `class_name` (internal name)
- `method_name`
- `bytecode_pc` (instruction offset)
- `evidence_kind` (method_ref, string_literal, reconstructed_string, yara_rule, metadata)

### 8.3 Behavior output schema upgrades

Add:
- `predicted_commands: Vec<String>`
- `predicted_registry_keys: Vec<String>`

### 8.4 Known repo issues to fix during overhaul (from codebase exploration)

- Verdict tiering: CLEAN tier is unreachable in backend (score 0 → LOW today)
- Behavior inference uses fake URL/path evidence
- Regex patterns only match first occurrence per file (`regex.find`, not `find_iter`)
- Frontend `normalizeSeverity` does not recognize backend `med`
- Body size limits mismatch (axum 100MB vs app 50MB)
- README says port 8000 but code binds 18000 by default
- YARA matches are all labeled `high` severity today (should read rule metadata)

---

## Appendix A: Fractureiser Indicators (non-exhaustive)

From public technical analysis:
- injected method name pattern: `_[0-9a-f]{32}` and call inserted into `<clinit>`
- Stage 0 remote loader: `java/net/URLClassLoader` + reflection chain + `Utility.run`
- mutex-ish property: `neko.run`
- marker file: `.ref`
- known infra (historical): `85.217.144.130`, `107.189.3.101`, `files-8ie.pages.dev`
- stage filenames: `dl.jar`, `lib.jar`, `libWebGL64.jar`, `client.jar`
- packages: `dev/neko/nekoclient`, `dev/neko/nekoinjector`
- embedded native: `hook.dll`
- persistence paths: Windows Run key, Startup folder; Linux systemd unit paths

## Appendix B: External references

- Fractureiser technical doc: https://raw.githubusercontent.com/trigram-mrp/fractureiser/main/docs/tech.md
- Check Point (Stargazers): https://research.checkpoint.com/2025/minecraft-mod-malware-stargazers/
- Bitdefender lab report: https://www.bitdefender.com/en-us/blog/labs/infected-minecraft-mods-lead-to-multi-stage-multi-platform-infostealer-malware
- PussyRAT writeup: https://raw.githubusercontent.com/dbissell6/DFIR/main/Rev%2BPwn/Real_Malware/PussyRAT.md
- Allatori string encryption: https://allatori.com/features/string-encryption.html
- CurseForge detection tool notice: https://support.curseforge.com/en/support/solutions/articles/9000228509-june-2023-infected-mods-detection-tool/
- BleedingPipe (BleepingComputer): https://www.bleepingcomputer.com/news/security/hackers-exploit-bleedingpipe-rce-to-target-minecraft-servers-players/
