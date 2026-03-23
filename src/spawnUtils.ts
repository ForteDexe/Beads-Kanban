import * as os from 'os';
import * as path from 'path';

/**
 * Map `process.platform` to the key used by VS Code's `terminal.integrated.env.*`
 * configuration namespace.  The three possible values VS Code recognises are
 * `'linux'`, `'osx'`, and `'windows'`.
 */
export function getVSCodePlatformName(): 'linux' | 'osx' | 'windows' {
  if (process.platform === 'darwin') { return 'osx'; }
  if (process.platform === 'win32')  { return 'windows'; }
  return 'linux';
}

/**
 * Resolve VS Code variable substitution references of the form `${env:VARNAME}`
 * inside a string value.  This is the same syntax VS Code uses in
 * `terminal.integrated.env.*` settings.
 *
 * Unknown variable names resolve to an empty string (matching VS Code behaviour).
 *
 * @param value - Raw string potentially containing `${env:VARNAME}` tokens
 * @param env   - Environment to look up variable values in (defaults to process.env)
 * @returns The string with all `${env:VARNAME}` tokens replaced
 */
export function resolveEnvVarRefs(value: string, env: NodeJS.ProcessEnv = process.env): string {
  return value.replace(/\$\{env:([^}]+)\}/g, (_, name: string) => env[name] ?? '');
}

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
    .map(p => {
      if (p === '~') { return os.homedir(); }
      if (p.startsWith('~/') || p.startsWith('~\\')) {
        return path.join(os.homedir(), p.slice(2));
      }
      return p;
    })
    .filter(p => p.trim().length > 0);                                    // drop empty entries

  if (expanded.length === 0) {
    return { ...process.env };
  }

  const separator = path.delimiter; // ':' on POSIX, ';' on Windows
  const existingPath = process.env.PATH ?? '';
  const newPath = [...expanded, existingPath].filter(Boolean).join(separator);

  return { ...process.env, PATH: newPath };
}
