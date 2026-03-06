# Jarspect Demo Voiceover (ElevenLabs TTS)

## Settings
- **Voice:** Pick a calm, confident male or female voice (e.g. "Adam", "Rachel", or "Antoni")
- **Stability:** 0.50
- **Clarity + Similarity Enhancement:** 0.75
- **Style:** 0 (neutral -- no dramatic flair)
- **Speed:** Slightly slow

## Script

Jarspect. An AI-powered, bytecode-native security scanner that catches malicious Minecraft mods before they compromise your system.

In June 2023, a malware campaign called fractureiser infected dozens of mods on CurseForge and Bukkit. Stage zero hid a URL inside a byte array -- literally `new String(new byte[]{106, 97, 118, 97...})` -- so the string `java.net.URLClassLoader` never appeared in the constant pool. It used a reflection chain to load a remote class. Later stages added Windows registry persistence, Linux systemd units, credential theft for Discord tokens, browser passwords, crypto wallets, and self-replication into every other mod on the system.

Traditional scanners run text regex over compiled class files and score this zero out of a hundred. The strings aren't there to grep for. They're hidden in bytecode instructions. And rule-based scoring can't tell the difference between a rendering mod that calls `Runtime.exec` for GPU probing and a RAT that calls it to run shell commands.

That's the problem Jarspect solves. Here's how.

Jarspect runs a three-layer pipeline. Layer one checks the file's SHA-256 hash against MalwareBazaar -- abuse.ch's threat intelligence database. If it's known malware, the verdict is immediate: MALICIOUS, confidence one point zero, with the malware family name attached.

If the hash is unknown, layer two kicks in. Jarspect recursively extracts every archive entry, including jars nested inside jars. Each class file is parsed at the binary level. Every constant-pool entry, every string literal, every method reference is extracted. An invoke resolver walks each method's bytecode and maps invokevirtual, invokestatic, invokespecial, and invokeinterface instructions back to their owner class, method name, and descriptor. For obfuscated strings like the ones fractureiser used, a byte-array reconstruction engine detects the newarray, bipush, bastore, String init opcode pattern and reassembles the hidden value.

Eight capability detectors then run against this evidence. Process execution. Network IO. Dynamic class loading. Filesystem and jar modification. Persistence. Unsafe deserialization -- that's the BleedingPipe attack vector. Native JNI loading. And credential theft. Each detector uses class-scoped correlation: a network call alone might be low severity, but the same call in a class that also builds a URLClassLoader and invokes a reflected method escalates to high.

YARA rules scan each inflated entry individually -- not the compressed jar blob. The production rulepack includes six high-precision rules targeting real malware families: Krypton stealer, MaxCoffe, MaksRAT, PussyRAT, fractureiser-tagged loaders, and staging helpers. Each rule requires multiple corroborating strings -- no single-string matches.

Layer three sends the full capability profile to Azure OpenAI. The AI analyzes it in context -- it understands that Sodium calling glxinfo is legitimate GPU detection, not process execution abuse. It returns a verdict: CLEAN, SUSPICIOUS, or MALICIOUS, with a confidence score, a risk rating, a prose explanation, and per-capability rationale.

But the AI doesn't get the final word on everything. A static override layer sits on top: if a production YARA rule fires at high severity, or if a malware-specific compound detector like a base64 stager or Discord webhook exfiltration triggers at high severity, the verdict is locked to MALICIOUS -- no matter what the AI says. This prevents the AI from downgrading obvious malware.

The results speak for themselves. We benchmarked Jarspect against seventy real malware samples from MalwareBazaar -- Krypton stealers, MaksRAT loaders, PussyRAT, fractureiser variants -- all with Minecraft mod metadata, all scanned with hash matching disabled so the detection layers had to earn the verdict. Seventy out of seventy: MALICIOUS. Then we scanned the fifty most-downloaded mods from Modrinth -- Sodium, Fabric API, Iris, Lithium, all the names you'd recognize. Fifty out of fifty: CLEAN. Zero false positives.

Let me show you a live scan.

I'm uploading a jar through the web UI. The pipeline runs in seconds. The verdict comes back with the AI's assessment, the detection method, the confidence score, and every capability finding traced back to specific class files and bytecode locations. Every finding is explainable.

Jarspect is built in Rust. Over seventy tests, zero mocks. A single binary that serves the API and the web UI on the same port. Built for the Microsoft AI Dev Days Hackathon twenty twenty-six. Thank you for watching.
