def heuristic_flags(content):
    flags = []
    if "eval(" in content or "exec(" in content:
        flags.append("⚠️ Usage of eval or exec (dynamic code execution)")
    if "base64" in content:
        flags.append("⚠️ Possible encoding or obfuscation (base64)")
    if "os.system" in content:
        flags.append("⚠️ System command execution (os.system)")
    if "subprocess" in content:
        flags.append("⚠️ External process execution (subprocess)")
    return flags
