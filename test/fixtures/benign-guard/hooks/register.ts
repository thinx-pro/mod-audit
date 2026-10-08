import type { Register } from 'claude-code'

// Note: $.http.fetch in a comment must not count.
/* neither should $.process.run() here */
export const register: Register = on => {
  on('tool.call', { tool: 'Edit' }, ($, e, next) =>
    /\.secret$/.test(e.file_path) ? { deny: 'protected' } : next(e),
  )
  on('session.start', async ($, e, next) => {
    $.ui.status('guard on')
    return next(e)
  })
}
