import { spawn, ChildProcess } from 'child_process'
import { existsSync } from 'fs'
import { join } from 'path'

let sidecarProcess: ChildProcess | null = null
let sidecarStatus: 'starting' | 'ready' | 'error' = 'starting'

const SIDECAR_PORT = process.env.SIDECAR_PORT || '8765'
const HEALTH_INTERVAL = 500
const HEALTH_TIMEOUT = 30000

function getSidecarPython(): string {
  const candidates = [
    // Packaged app (resources path)
    join(process.resourcesPath || '', 'sidecar', '.venv', 'bin', 'python3'),
    join(process.resourcesPath || '', 'sidecar', 'venv',  'bin', 'python3'),
    // Dev mode relative to compiled main (out/main/)
    join(__dirname, '../../sidecar/.venv/bin/python3'),
    join(__dirname, '../../sidecar/venv/bin/python3'),
    // Dev mode relative to cwd (project root)
    join(process.cwd(), 'sidecar/.venv/bin/python3'),
    join(process.cwd(), 'sidecar/venv/bin/python3'),
    join(process.cwd(), 'sidecar/.venv/bin/python'),
    // System fallbacks
    '/opt/homebrew/bin/python3',
    '/usr/local/bin/python3',
    'python3',
  ]
  for (const p of candidates) {
    if (existsSync(p)) return p
  }
  return 'python3'
}

function getSidecarMain(): string {
  const candidates = [
    join(process.resourcesPath || '', 'sidecar', 'main.py'),
    join(__dirname, '../../sidecar/main.py'),
    join(process.cwd(), 'sidecar/main.py'),
  ]
  for (const p of candidates) {
    if (existsSync(p)) return p
  }
  return join(process.cwd(), 'sidecar/main.py')
}

async function waitForReady(): Promise<void> {
  const deadline = Date.now() + HEALTH_TIMEOUT
  while (Date.now() < deadline) {
    try {
      const resp = await fetch(`http://127.0.0.1:${SIDECAR_PORT}/health`)
      if (resp.ok) {
        sidecarStatus = 'ready'
        return
      }
    } catch {
      // not ready yet
    }
    await new Promise(r => setTimeout(r, HEALTH_INTERVAL))
  }
  throw new Error(`Sidecar did not respond within ${HEALTH_TIMEOUT}ms`)
}

export async function startSidecar(): Promise<void> {
  const python = getSidecarPython()
  const main = getSidecarMain()

  console.log(`[Sidecar] Starting: ${python} ${main}`)

  sidecarProcess = spawn(python, [main], {
    env: { ...process.env, PORT: SIDECAR_PORT, SIDECAR_PORT },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  sidecarProcess.stdout?.on('data', (d: Buffer) =>
    d.toString().trim().split('\n').forEach(l => console.log(`[Sidecar] ${l}`))
  )
  sidecarProcess.stderr?.on('data', (d: Buffer) =>
    d.toString().trim().split('\n').forEach(l => console.error(`[Sidecar ERR] ${l}`))
  )
  sidecarProcess.on('exit', (code) => {
    console.log(`[Sidecar] Exited with code ${code}`)
    sidecarStatus = 'error'
    sidecarProcess = null
  })
  sidecarProcess.on('error', (err) => {
    console.error('[Sidecar] Process error:', err)
    sidecarStatus = 'error'
  })

  try {
    await waitForReady()
    console.log('[Sidecar] Ready!')
  } catch (err) {
    console.error('[Sidecar] Health check failed:', err)
    sidecarStatus = 'error'
  }
}

export async function stopSidecar(): Promise<void> {
  if (!sidecarProcess) return
  return new Promise(resolve => {
    const killTimer = setTimeout(() => {
      sidecarProcess?.kill('SIGKILL')
      resolve()
    }, 2000)
    sidecarProcess!.once('exit', () => {
      clearTimeout(killTimer)
      resolve()
    })
    sidecarProcess!.kill('SIGTERM')
  })
}

export function getSidecarStatus(): 'starting' | 'ready' | 'error' {
  return sidecarStatus
}
