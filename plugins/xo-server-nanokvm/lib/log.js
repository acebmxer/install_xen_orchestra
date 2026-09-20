'use strict'

// A minimal, dependency-free logger. xo-server runs under systemd, which
// captures stdout/stderr into the journal the same as any other log line
// it prints, so a small prefix is all that's needed to find this plugin's
// output in `journalctl -u xo-server`.

const PREFIX = '[xo-server-nanokvm]'

exports.info = (message, extra) => console.log(PREFIX, message, extra ?? '')
exports.warn = (message, extra) => console.warn(PREFIX, message, extra ?? '')
exports.error = (message, extra) => console.error(PREFIX, message, extra ?? '')
