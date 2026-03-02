# Jarspect Demo Voiceover (ElevenLabs TTS)

## Settings
- **Voice:** Pick a calm, confident male or female voice (e.g. "Adam", "Rachel", or "Antoni")
- **Stability:** 0.50
- **Clarity + Similarity Enhancement:** 0.75
- **Style:** 0 (neutral -- no dramatic flair)
- **Speed:** Slightly slow

## Script

Jarspect. A bytecode-native security scanner that catches malicious Minecraft mods before they compromise your system.

In June 2023, a malware campaign called fractureiser infected dozens of mods on CurseForge and Bukkit. It spread through three stages. Stage zero hid a URL inside a byte array -- literally `new String(new byte[]{106, 97, 118, 97, 46, 110, 101, 116...})` -- so the string `java.net.URLClassLoader` never appeared in the constant pool. Then it used a reflection chain to load a remote class and call its `run` method. Stages one through three added Windows registry persistence, Linux systemd units, credential theft for Discord tokens, browser passwords, crypto wallets, and self-replication into every other mod on the system.

Traditional scanners run text regex over compiled class files and score this zero out of a hundred. The strings aren't there to grep for. They're hidden in bytecode instructions.

That's the problem Jarspect solves. Here's how.

When you upload a jar, Jarspect recursively extracts every archive entry, including jars nested inside jars. Each class file is parsed at the binary level using the `cafebabe` constant pool format. Every UTF-8 entry, every string literal, every method reference is extracted. Then an invoke resolver walks each method's bytecode and maps `invokevirtual`, `invokestatic`, `invokespecial`, and `invokeinterface` instructions back to their owner class, method name, and descriptor.

For obfuscated strings like the ones fractureiser used, a byte-array reconstruction engine detects the `newarray`, `bipush`, `bastore`, `String init` opcode pattern and reassembles the hidden value. The string `java.net.URLClassLoader` gets recovered even though it was never in the constant pool.

Eight capability detectors then run against this evidence. Process execution. Network I/O. Dynamic class loading. Filesystem and jar modification. Persistence. Unsafe deserialization -- that's the BleedingPipe attack vector. Native JNI loading. And credential theft. Each detector uses class-scoped correlation: a network call alone might be low severity, but the same call in a class that also builds a URLClassLoader and invokes a reflected method escalates to critical.

YARA rules scan each inflated entry individually -- not the compressed jar blob -- with severity pulled from rule metadata. The scoring engine deduplicates across all layers, applies diminishing returns for repeated signals, and adds synergy bonuses when dangerous combinations appear. Download plus execute. Persistence plus network. Credential theft plus exfiltration.

Finally, the behavior predictor extracts actual URLs, shell commands, file paths, and persistence indicators from the evidence -- not synthetic placeholders, but the real values found in the bytecode.

Let me show you a live scan.

I'm uploading a jar that contains process execution APIs, network calls, dynamic class loading, and credential theft paths. The pipeline runs in seconds. The verdict comes back critical. The indicator list shows exactly which class files triggered which detectors, the method names, the program counter offsets, and the extracted evidence strings. Every finding is traceable back to a specific location in the bytecode.

Jarspect is seven thousand lines of Rust. Sixty tests. Zero mocks. A single binary. No AI, no heuristic guessing -- just bytecode parsing, evidence extraction, and deterministic scoring grounded in how real malware actually works.

Built for the Microsoft AI Dev Days Hackathon twenty twenty-six. Thank you for watching.
