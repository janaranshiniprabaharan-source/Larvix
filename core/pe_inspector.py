"""
PE inspection wrapper. Returns dict with:
  - is_pe: bool
  - imports: list of "dll:func"
  - suspicious_apis: list of matches
  - sections_entropy: dict section_name -> entropy
"""
def inspect_pe(path):
    info = {"is_pe": False, "imports": [], "suspicious_apis": [], "sections_entropy": {}}
    try:
        import pefile
    except Exception:
        return info

    try:
        pe = pefile.PE(path)
    except Exception:
        return info

    info["is_pe"] = True
    try:
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode(errors='ignore') if isinstance(entry.dll, (bytes, bytearray)) else str(entry.dll)
                for imp in entry.imports:
                    name = imp.name.decode(errors='ignore') if imp.name else ''
                    full = f"{dll}:{name}"
                    info["imports"].append(full)
    except Exception:
        pass

    # sections entropy
    try:
        from .entropy import shannon_entropy
        for s in pe.sections:
            name = s.Name.decode(errors='ignore').rstrip('\x00')
            try:
                data = s.get_data()
                ent = shannon_entropy(data)
            except Exception:
                ent = 0.0
            info["sections_entropy"][name] = ent
    except Exception:
        pass

    # Suspicious API matching will be evaluated in heuristics using imports list
    return info
