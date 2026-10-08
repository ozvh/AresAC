/** Refuse C0 controls and DEL; only a free-text note may contain line feeds. */
export function hasForbiddenControl(value: string, allowLineFeed = false): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if ((code < 32 || code === 127) && !(allowLineFeed && code === 10)) return true;
  }
  return false;
}
