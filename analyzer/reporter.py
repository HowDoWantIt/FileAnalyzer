def analyze_pe(filepath):
    """
    Analyzes a PE (Portable Executable) file (.exe, .dll) and returns key attributes.
    """
    try:
        import pefile

        pe = pefile.PE(filepath)

        return {
            "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
            "sections": [s.Name.decode(errors='ignore').rstrip('\x00') for s in pe.sections]
        }

    except Exception as e:
        return {"error": str(e)}
