import os

def get_file_size(path):
    """Returns the size of a file in bytes."""
    return os.path.getsize(path)

def is_large_file(path, threshold=10 * 1024 * 1024):
    """Checks whether the file is larger than a given threshold (default 10 MB)."""
    return get_file_size(path) > threshold

def analyze_pe(filepath):
    """
    Analyzes a PE (Portable Executable) file like .exe or .dll.
    Returns a dictionary with extracted information.
    """
    try:
        import pefile

        pe = pefile.PE(filepath)

        entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        image_base = hex(pe.OPTIONAL_HEADER.ImageBase)
        section_names = [s.Name.decode(errors='ignore').rstrip('\x00') for s in pe.sections]
        number_of_sections = len(section_names)

        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode(errors='ignore')
                funcs = [imp.name.decode(errors='ignore') if imp.name else "ordinal" for imp in entry.imports]
                imports.append({"dll": dll_name, "functions": funcs})

        has_resources = hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE')

        return {
            "entry_point": entry_point,
            "image_base": image_base,
            "file_size_bytes": get_file_size(filepath),
            "is_large_file": is_large_file(filepath),
            "number_of_sections": number_of_sections,
            "sections": section_names,
            "has_resources": has_resources,
            "imports": imports,
        }

    except Exception as e:
        return {"error": str(e)}
