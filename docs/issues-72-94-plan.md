Working note: order for fixing issues #72-#94. Not user documentation.

One commit per issue, handed over before the next one starts.
Stop for a dev -> main PR at the end of each batch marked PR.

Batch 1 - security (PR after this batch)
  #87  template build key left in /tmp, public half shipped in templates
  #92  secrets on command lines, in debug trace and in the log file
  #91  pool master host key: --deploy pins unchecked keys, --proxy checks none
  #89  running-task check: backslash in password breaks login, check skipped

Batch 2 - install lifecycle / data loss (PR after this batch)
  #74  GIT_BRANCH tag: --rebuild deletes the install, --update can't update   (needs a decision: support tags or reject them)
  #72  --uninstall never stops xo-server
  #86  uninstall "purge Redis data" leaves Redis unable to start
  #73  --restore unusable when SERVICE_USER is not root
  #85  one run with sudo breaks self-update
  #78  certificate renewal advice leaves XO with no certificate      (needs a decision: regenerate in --reconfigure or change the advice)
  #79  --adjust-memory lost on update/rebuild/reconfigure/restore    (needs a decision: carry the flag over or a systemd drop-in)

Batch 3 - template builder (PR after this batch, together with batch 4 if both are done)
  #80  --build-templates ignores --dry-run and --non-interactive    (needs a decision: refuse --non-interactive or add template names on the command line)
  #81  API path never verifies the image checksum
  #82  API path mixes pool, SR and network across pools
  #83  picker never shows "already on this pool"                     (needs a decision: make it work or drop the README promise)

Batch 4 - host-power-manager plugin
  #75  CPU metric always throws; two ticks can both press the button
  #77  duplicate rules leak timers, failed power-off ignores cooldown, unsafe values
  #76  power button pressed on a booting/rebooting/maintenance host   (needs decisions: the issue lists several possible guards)

Batch 5 - menu, helpers, docs, CI (final PR)
  #84  menu: config edit drops ticked items, quoted editor, value flags
  #88  proxy helper waits 10 minutes on key login
  #90  --deploy: SSH key comment with ": " breaks cloud-init
  #93  docs that don't match the code (four items)
  #94  plugin sync skips new-file-only changes; CI needs jq installed
       (also add curl and nodejs to ci.yml's apt line: the #92 tests skip
       without them, and ubuntu-latest only happens to have both)

Status (an issue is listed here once its fix is on dev; each one goes into
the dev -> main PR notes as a "Fixes #N" line, which closes it on merge)
  #87  fixed - build key removed from authorized_keys in all three prep
       scripts; picker keeps earlier EXIT traps. Not yet tested on a real build.
  #92  fixed - token via curl -K pipe and private xo-cli config, password to
       the xo-cli login by env, XO_DEBUG off in secret-handling functions,
       proxy token kept out of --log-file. Left as is (decided): xo-cli
       proxy.register still takes the proxy token as an argument. Also fixed
       the #87 test's `! grep` lines, which bats never fails on.
       Not yet tested on a live --proxy run or a live template build.

Fixes lines for the next PR:
  Fixes #87
  Fixes #92

Delete this file once all of the above has landed on main.
