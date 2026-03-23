import * as os from 'os';
import * as path from 'path';

/**
 * Build a process environment suitable for spawning bd and its dependencies.
 *
 * VS Code launched from a GUI (macOS Dock, Linux desktop shortcut, etc.) inherits
 * a limited system PATH rather than the full interactive-shell PATH. When the
 * extension then spawns `bd` with `shell:false`, `bd` in turn can't find tools it
 * depends on (e.g., `dolt`) because they live in directories like
 * `/opt/homebrew/bin` or `~/.local/bin` that are absent from the GUI PATH.
 *
 * This function returns a copy of `process.env` with `additionalPaths` prepended
 * to `PATH`, so both `bd` and any tools it calls are discoverable.
 *
 * Tilde (`~`) at the start of a path is expanded to the current user's home
 * directory. Null bytes and empty entries are filtered out. The existing PATH is
 * always preserved at the end.
 *
 * @param additionalPaths - Directories to prepend to PATH (order is preserved)
 * @returns A NodeJS.ProcessEnv with the augmented PATH
 */
export function buildSpawnEnv(additionalPaths: string[]): NodeJS.ProcessEnv {
  const expanded = additionalPaths
    .map(p => p.replace(/\0/g, ''))                                       // strip null bytes
    .map(p => (p === '~' || p.startsWith('~/') || p.startsWith('~\\'))   // expand leading ~
              ? os.homedir() + p.slice(1)
              : p)
    .filter(p => p.trim().length > 0);                                    // drop empty entries

  if (expanded.length === 0) {
    return { ...process.env };
  }

  const separator = path.delimiter; // ':' on POSIX, ';' on Windows
  const existingPath = process.env.PATH ?? '';
  const newPath = [...expanded, existingPath].filter(Boolean).join(separator);

  return { ...process.env, PATH: newPath };
}
