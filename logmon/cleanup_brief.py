__all__ = (
    'cleanup_brief',
)

def cleanup_brief(brief: str) -> str:
    # If brief has multiple lines then join them into one,
    # but only up to 120 "characters" (arbitrarily chosen),
    # but at least one non-empty line.
    buf: list[str] = []
    brief_len = 0
    for line in brief.splitlines():
        line = line.strip().replace('\r', '')
        if line:
            line_len = len(line)
            if brief_len == 0:
                brief_len = line_len
                buf.append(line)
            elif brief_len + line_len <= 120:
                brief_len += line_len
                buf.append(line)
            else:
                break

    return ' '.join(buf)
