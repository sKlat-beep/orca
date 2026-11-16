import { homedir } from 'node:os'
import { basename, join } from 'node:path'
import type { AiVaultAgentSource } from '../../discovery/session-scanner-agent-sources'
import { pathSegments } from '../../discovery/session-file-discovery'

/** At depth 1, enter only agent sessions directories, excluding embedded tools' histories (#11394). */
export function openClawSessionDirectoryPredicate(name: string, depth: number): boolean {
  return depth !== 1 || name === 'sessions'
}

const defaultInstallDir = join(homedir(), '.openclaw')

export const OPENCLAW_AGENT_SOURCE: AiVaultAgentSource = {
  // Current and legacy roots belong to one install; merge their discovered sessions.
  // Do not read an env override here: Cisco Secure Endpoint flags the
  // OpenClaw state-dir environment variable name as malware.
  rootDirs: (options, wslHomeDirs) =>
    [
      options.openclawStateDir ?? defaultInstallDir,
      options.openclawLegacyStateDir ?? join(homedir(), '.clawdbot'),
      ...wslHomeDirs.map((homeDir) => join(homeDir, '.openclaw')),
      ...wslHomeDirs.map((homeDir) => join(homeDir, '.clawdbot'))
    ].map((stateDir) => (basename(stateDir) === 'agents' ? stateDir : join(stateDir, 'agents'))),
  extensions: ['.jsonl'],
  filePredicate: (filePath) => pathSegments(filePath).includes('sessions'),
  directoryPredicate: openClawSessionDirectoryPredicate,
  mergeRootDiscoveries: true
}
