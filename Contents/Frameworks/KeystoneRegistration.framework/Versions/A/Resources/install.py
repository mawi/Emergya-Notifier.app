#!/usr/bin/python
# Copyright 2008 Google Inc.  All rights reserved.

"""This script will install Keystone in the correct context
(system-wide or per-user).  It can also uninstall Keystone.  is run by
KeystoneRegistration.framework.

Example command lines for testing:
Install:    install.py --install=/tmp/Keystone.tbz --root=/Users/fred
Uninstall:  install.py --nuke --root=/Users/fred

Example real command lines, for user and root install and uninstall:
  install.py --install Keystone.tbz
  install.py --nuke
  sudo install.py --install Keystone.tbz
  sudo install.py --nuke

For a system-wide Keystone, the install root is "/".  Run with --help
for a list of options.  Use --no-processes to NOT start background
processes (e.g. launchd item).

Errors can happen if:
 - we don't have write permission to install in the given root
 - pieces of our install are missing

On error, we print an message on stdout and our exit status is
non-zero.  On success, we print nothing and exit with a status of 0.
"""

import os
import re
import sys
import pwd
import stat
import glob
import fcntl
import getopt
import signal
import shutil
import platform
from posix import umask

popen_returns_proc = None
popen_returns_files = None

# We need to work in python 2.3 (OSX 10.4), 2.5 (10.5), and 2.6 (10.6)
if (sys.version_info[0] == 2) and (sys.version_info[1] <= 5):

  # Can't unconditionally import this or we'll get warnings in py2.6
  from popen2 import Popen4

  def popen_returns_proc(args):
    """popen() type call that returns a proc."""
    return Popen4(args)

  def popen_returns_files(args):
    """popen() type call that returns a tuple of file descriptors.

    Args:
      args: a tuple of commands to run (e.g. ['/bin/ls'])
    Returns:
      A file descriptor tuple (stdin, stdout, stderr), like os.popen3.
    """
    return os.popen3(args)

else:

  # Can't unconditionally import this; doesn't exist in py2.3
  import subprocess

  def popen_returns_proc(args):
    """popen() type call that returns a proc."""
    return subprocess.Popen(args, shell=False, close_fds=True)

  def popen_returns_files(args):
    """popen() tyle call that returns a tuple of file descriptors.

    Args:
      args: a tuple of commands to run (e.g. ['/bin/ls'])
    Returns:
      A file descriptor tuple (stdin, stdout, stderr), like os.popen3.
    """
    p = subprocess.Popen(args, shell=False,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,
                         close_fds=True)
    return (None, p.stdout, p.stderr)



# Allow us to force the installer to think we're on Tiger (10.4)
gForceTiger = False

# Allow us to adjust the agent launch interval (for testing).
# In seconds.  Time is 1 hour minus a jitter factor.
gAgentStartInterval = 3523

# Name of our "lockdown" ticket.  If you change this name be sure to
# change it in other places in the code (grep is your friend)
LOCKDOWN_TICKET = 'com.google.Keystone.Lockdown'

class Failure(Exception):
  """Generic exception for Keystone install failure."""

  def __init__(self, package, root, error):
    self.package = package
    self.root = root
    self.error = error

  def __str__(self):
    return 'File %s, root %s, Error %s' % (self.package, self.root,
                                           self.error)


def CheckOnePath(file, statmode):
  """Sanity check a file or directory as requested.  On failure throw
  an exception."""
  if os.path.exists(file):
    st = os.stat(file)
    if (st.st_mode & statmode) != 0:
      return
  raise Failure(file, "None", "Bad access for " + file)


# -------------------------------------------------------------------------

class KeystoneInstall(object):

  """Worker object which does the heavy lifting of install or uninstall.
  By default it assumes 10.5 (Leopard).

  Attributes:
   keystone: owning Keystone object
   uid: the relevant uid for our install/uninstall.
     0 is System Keystone; else a UID.
   root: root directory for install.  On System this would be "/";
     else would be a user home directory (unless testing, in which case
     the root can be anywhere).
   myBundleVersion: a cached value of the Keystone bundle version in "package".

   Conventions:
   All functions which return directory paths end in '/'
     """

  def __init__(self, keystone, uid, root):
    self.keystone = keystone
    self.uid = uid
    self.root = root
    if not self.root.endswith('/'):
      self.root = self.root + '/'
    self.myBundleVersion = None

  def KeystoneDir(self):
    """Return the subdirectory where Keystone.bundle is or will be.
    Does not sanity check the directory."""
    return self.root + 'Library/Google/GoogleSoftwareUpdate/'

  def KeystoneBundle(self):
    """Return the location of Keystone.bundle."""
    return self.KeystoneDir() + 'GoogleSoftwareUpdate.bundle/'

  def GetKsadmin(self):
    """Return a path to ksadmin which will exist only AFTER Keystone is
    installed.  Return None if it doesn't exist."""
    ksadmin = self.KeystoneBundle() + 'Contents/MacOS/ksadmin'
    if not os.path.exists(ksadmin):
      return None
    return ksadmin

  def InstalledKeystoneBundleVersion(self):
    """Return the version of an installed Keystone bundle, or None if
    not installed.  Specifically, it returns the CFBundleVersion as a
    string (e.g. "0.1.0.0").  Invariant: we require a 4-digit version
    when building Keystone.bundle."""
    plist = self.KeystoneBundle() + 'Contents/Info.plist'
    if not os.path.exists(plist):
      return None
    cmds = [ '/usr/bin/defaults', 'read',
             self.KeystoneBundle() + 'Contents/Info',
             'CFBundleVersion' ]
    (stdin_ignored, stdoutfile, stderrfile) = popen_returns_files(cmds)
    stdout = stdoutfile.read().strip()
    return stdout

  def MyKeystoneBundleVersion(self):
    """Return the version of our Keystone bundle which we might want to install.
    Specifically, it returns the CFBundleVersion as a string (e.g. "0.1.0.0").
    Invariant: we require a 4-digit version when building Keystone.bundle."""
    if self.myBundleVersion == None:
      cmds = ['/usr/bin/tar', '-Oxjf',
              self.keystone.package,
              'GoogleSoftwareUpdate.bundle/Contents/Info.plist']
      (stdin_ignored, stdoutfile, stderrfile) = popen_returns_files(cmds)
      stdout = stdoutfile.read()
      # walking by index instead of implicit iterator so we can easily
      # "get next"
      linelist = stdout.splitlines()
      for i in range(len(linelist)):
        if linelist[i].find('<key>CFBundleVersion</key>') != -1:
          version = linelist[i+1].strip()
          version = version.strip('<string>').strip('</string>')
          self.myBundleVersion = version
          break
    return self.myBundleVersion

  def IsVersionGreaterThanVersion(self, myversion, insversion):
    """Return True if myversion is greater than insversion"""
    if ((insversion == None) or (myversion == None)):
      return True
    else:
      myversion = myversion.split('.')
      insversion = insversion.split('.')
    if len(myversion) != len(insversion):
      return True
    for my, ins in zip(myversion, insversion):
      if int(my) > int(ins):
        return True
      elif int(my) < int(ins):
        return False
    # If we get here, it's a complete match, so no.
    return False

  def IsMyVersionGreaterThanInstalledVersion(self):
    """Return True if my Keystone version is greater than the installed version.
    Else return False.  Like above, assumes a 4-digit version."""
    myversion = self.MyKeystoneBundleVersion()
    insversion = self.InstalledKeystoneBundleVersion()
    return self.IsVersionGreaterThanVersion(myversion, insversion)

  def KeystoneResources(self):
    """Return the subdirectory where Keystone.bundle's resources should be.
    Does not sanity check the directory."""
    return self.KeystoneBundle() + 'Contents/Resources/'

  def KeystoneAgentPath(self):
    """Returns a path to KeystoneAgent.app. Does not sanity check the
    directory."""
    return (self.KeystoneDir() + 'GoogleSoftwareUpdate.bundle/Contents/'
            + 'Resources/GoogleSoftwareUpdateAgent.app')

  def MakeDirectories(self, doLaunchdPlists):
    """Make directories for our package if needed.  Note conditional on
    doLaunchdPlists."""
    dirs = [ self.KeystoneDir() ]
    if doLaunchdPlists:
      dirs.append(self.LaunchAgentConfigDir())
      if self.IsSystemKeystone():
        dirs.append(self.LaunchDaemonConfigDir())
    umask(022)
    for d in dirs:
      p = popen_returns_proc(['/bin/mkdir', '-p', d])
      result = p.wait()
      if os.WEXITSTATUS(result) != 0:
        raise Failure(self.keystone.package, self.root, 'mkdir -p')

  def InstallPackage(self):
    "Extract self.keystone.package into self.root."
    d = self.KeystoneDir()
    cmds = ['/usr/bin/tar', 'xjf', self.keystone.package, '--no-same-owner',
            '--directory', d]
    p = popen_returns_proc(cmds)
    result = p.wait()
    # runoutput = p.fromchild.read()
    if os.WEXITSTATUS(result) != 0:
      raise Failure(self.keystone.package, self.root, 'extract command')

  def DeleteDirectoryAndContents(self, d):
    """Delete |dir| and all it's contents with rm -rf."""
    d = self.KeystoneBundle()
    CheckOnePath(self.root, stat.S_IWUSR)
    cmds = ['/bin/rm', '-rf', d]
    p = popen_returns_proc(cmds)
    p.wait()

  # TODO: add a unit test for this
  def UninstallPackage(self):
    """Remove our package (opposite of ExtractPackage()) Note we
    delete the bundle, NOT the $ROOT/Library/Google/GoogleSoftwareUpdate
    directory, so that all tickets aren't blown away on
    upgrade/install.  DO uninstall our own ticket."""
    cmds = [self.GetKsadmin(), '--delete', '--productid',
            'com.google.Keystone']
    if self.GetKsadmin():
      if (self.uid != 0) and (os.geteuid() == 0):
        # We are promoting; be sure to delete the ticket as the right user.
        self.RunCommandAsUID(cmds, -1, self.uid)
      else:
        p = popen_returns_proc(cmds)
        p.wait() # rtn ignored
    self.DeleteDirectoryAndContents(self.KeystoneBundle())

  def DeleteCache(self):
    """Deletes any cached download files."""
    cachedirs = glob.glob(self.root + 'Library/Caches/com.google.Keystone.*')
    for dir in cachedirs:
      shutil.rmtree(dir, True)

  def FullUninstallOfDirectories(self):
    """*DOES* uninstall as much as possible (including ticket files)."""
    self.DeleteDirectoryAndContents(self.KeystoneDir())
    ksdir = self.KeystoneDir()
    CheckOnePath(self.root, stat.S_IWUSR)
    cmds = ['/bin/rm', '-rf', ksdir]
    p = popen_returns_proc(cmds)
    p.wait()

  def GetKeystoneTicketURL(self):
    """Return the URL for Keystone's ticket, possibly from a defaults file."""
    cmds = [ '/usr/bin/defaults', 'read',
             'com.google.KeystoneInstall', 'URL' ]
    (stdin_ignored, stdoutfile, stderrfile) = popen_returns_files(cmds)
    stdout = stdoutfile.read().strip()
    if len(stdout) > 0:
      return stdout
    else:
      return 'https://tools.google.com/service/update2'

  def MakeTicketForKeystone(self):
    """Install a ticket for Keystone itself."""
    ksadmin = self.GetKsadmin()
    if ksadmin == None:
      raise Failure(self.keystone.package, self.root,
                    "Can't use ksadmin if not installed")
    # may not exist yet...
    p = popen_returns_proc(['/bin/mkdir', '-p', self.KeystoneDir() + 'TicketStore'])
    p.wait()
    # Finally, register.
    url = self.GetKeystoneTicketURL()
    cmds = [ksadmin,
            # store is specified explicitly so unit tests work
            '--store', self.KeystoneDir() + 'TicketStore/Keystone.ticketstore',
            '--register',
            '--productid', 'com.google.Keystone',
            '--version', self.InstalledKeystoneBundleVersion(),
            '--xcpath', ksadmin,
            '--url', url,
            '--preserve-tttoken']
    p = popen_returns_proc(cmds)
    p.wait() # rtn ignored

  def LockdownKeystone(self):
    """Prevent Keystone from ever self-uninstalling.

    This is necessary for a System Keystone used for Trusted Tester support.
    We do this by installing (and never uninstalling) a system ticket.
    """
    ksadmin = self.GetKsadmin()
    if ksadmin == None:
      raise Failure(self.keystone.package, self.root,
                    "Can't use ksadmin if not installed")
    url = self.GetKeystoneTicketURL()
    cmds = [ksadmin,
            # store is specified explicitly so unit tests work
            '--store', self.KeystoneDir() + 'TicketStore/Keystone.ticketstore',
            '--register',
            '--productid', LOCKDOWN_TICKET,
            '--version', '1.0',
            '--xcpath', '/',
            '--url', url]
    p = popen_returns_proc(cmds)
    p.wait() # rtn ignored

  def LaunchAgentConfigDir(self):
    """Return the destination directory where launch agents should go."""
    return self.root + '/Library/LaunchAgents/'

  def LaunchDaemonConfigDir(self):
    """Return the destination directory where launch daemons should go.
    Only used on a root install."""
    return self.root + '/Library/LaunchDaemons/'

  def InstalledPlistsForRootInstall(self):
    """Return a list of plists which are supposed to be installed
    (destination paths) if we are a root install.  If we are not a root install,
    return an empty list.  Does NOT check they actually exist.  Called by
    both the 10.4 and 10.5 versions of self.InstalledPlists()"""
    plists = []
    if self.IsSystemKeystone():
      plists.append(self.LaunchDaemonConfigDir() +
                    'com.google.keystone.daemon.plist')
    return plists

  def InstalledPlists(self):
    """Return a list of plists which are supposed to be installed
    (destination paths).  Does NOT check they actually exist.
    10.5 version."""
    plists = [ self.LaunchAgentConfigDir() + 'com.google.keystone.agent.plist' ]
    plists.extend(self.InstalledPlistsForRootInstall())
    return plists

  def Plists(self):
    """Return an array of all launchd plists we care about.  These are
    not full paths.  These values are used as a SOURCE pathname (not
    fully qualified) for plists to install.  On 10.4, return only the
    daemon, and use the 10.4 daemon script."""
    # trim all except the last path component
    plists = map(lambda x: x.split('/')[-1], self.InstalledPlists())
    # On 10.4 use the always-running launchd config for the daemon
    if not self.keystone.IsLeopardOrLater():
      plists = map(lambda x: x.replace('.daemon.', '.daemon4.'), plists)
    return plists

  def RunCommand(self, cmds, rtn):
    """Run a command with args.  If rtn is not -1 and it doesn't match
    the proc return code, throw an exception.  Throws away output."""
    p = popen_returns_proc(cmds)
    result = p.wait()
    if (rtn != -1) and (os.WEXITSTATUS(result) != rtn):
      raise Failure(self.keystone.package, self.root,
                                    'Command failed.  cmd=' +
                                    str(cmds) + ' rtn=' +
                                    str(result))

  def StartProcessesForCurrentContext(self):
    """Start running processes (e.g. launchd item).
    If root, we start the daemon, then start the agent as the console user.
    If not, we just start the agent (as ourself)."""
    for plist in self.InstalledPlists():
      if not os.path.exists(plist):
        raise Failure(self.keystone.package, self.root, "didn't find plist")
    self.ChangeProcessRunState(True, 0)

  def StopProcessesForCurrentContext(self):
    """Stop some running processes; opposite of
    StartProcessesForCurrentContext().  If root, we stop the daemon as
    ourself, then stop the agent as the console user.  If not root, we
    just stop the agent (as ourself).  Ignores agents running in other
    contexts."""
    # We don't care if this works (e.g. uninstall before an install),
    # so -1 on rtn.
    self.ChangeProcessRunState(False, -1)

  def DoCommandOnAgentProcess(self, cmd, pid):
    """Stop one agent process specified by |pid| with |cmd|
    (e.g.'load', 'unload').
    10.5 version; agent is launchd job."""
    file = self.LaunchAgentConfigDir() + 'com.google.keystone.agent.plist'
    if os.path.exists(file):
      cmds = ['/bin/launchctl', 'bsexec', str(pid),
              '/bin/launchctl', cmd, '-S', 'Aqua', file]
      self.RunCommand(cmds, -1)

  def StopAllAgentProcesses(self):
    """Stop the agent running in any context (e.g. multi-user login).
    Not a good idea on upgrade, since we can't easily restart them."""
    if self.IsSystemKeystone():
      (stdin_ignored, stdoutfile, stderrfile) = popen_returns_files(['/bin/ps', 'auxwww'])
      stdout = stdoutfile.read()
      for s in stdout.splitlines():
        if s.endswith(' /Library/Google/GoogleSoftwareUpdate/' +
                      'GoogleSoftwareUpdate.bundle/Contents/' +
                      'Resources/GoogleSoftwareUpdateAgent.app/' +
                      'Contents/MacOS/GoogleSoftwareUpdateAgent'):
          words = s.split()
          pid = words[1]
          self.DoCommandOnAgentProcess('unload', pid)

  def InstallPlists(self):
    """Install plist files needed to running processes."""
    for plist, dest in zip(self.Plists(), self.InstalledPlists()):
      rsdir = self.KeystoneResources()
      rsdirfile = rsdir + plist
      try:
        f = open(rsdirfile, 'r')
      except IOError:
        raise Failure(file, self.root, "Bad access for " + rsdirfile)
      data = f.read()
      f.close()
      # This line is key.  We can't have a tilde in a launchd script;
      # we need an absolute path.  So we replace a known token, like this:
      #    cat src.plist | 's/INSTALL_ROOT/self.root/g' > dest.plist
      data = data.replace('${INSTALL_ROOT}', self.root)
      # Make sure launchd can distinguish between user and system Agents.
      # This is a no-op for the daemon.
      installType = 'user'
      if self.IsSystemKeystone():
        installType = 'root'
      data = data.replace('${INSTALL_TYPE}', installType)
      # Allow start interval to be configured.
      data = data.replace('${START_INTERVAL}', str(gAgentStartInterval))
      try:
        f = open(dest, 'w')
        f.write(data)
        f.close()
      except IOError:
        raise Failure(file, self.root, "Bad access for " + dest)

  def UninstallPlists(self):
    """Remove plists needed to run processes."""
    for plist in self.InstalledPlists():
      if os.path.exists(plist):
        os.unlink(plist)

  def DeleteReceipts(self):
    """Remove pkg receipts to help "clean out" an install."""
    if self.IsSystemKeystone():
      self.RunCommand(['/bin/rm', '-rf', '/Library/Receipts/Keystone.pkg'], -1)
      self.RunCommand(['/bin/rm', '-rf',
                       '/Library/Receipts/UninstallKeystone.pkg'], -1)

  def ChangeProcessRunState(self, doload, rtn):
    """Load or unload the correct processes if root or non-root.  If
    |doload| is True, load things (e.g. 'launchctl load').  Else,
    unload things (e.g. 'launchctl unload').  See
    StartProcessesForCurrentContext() and
    StopProcessesForCurrentContext() for more details.  For both 10.4
    and 10.5."""
    if self.IsSystemKeystone():
      self.ChangeDaemonRunState(doload, rtn)
      self.ChangeAgentRunStateRootInstall(doload, rtn)
    else:
      self.ChangeAgentRunStateUserInstall(doload, rtn)

  def ChangeDaemonRunState(self, doload, rtn):
    """For both 10.4 and 10.5."""
    if doload:
      cmd = 'load'
    else:
      cmd = 'unload'
    file = self.LaunchDaemonConfigDir() + 'com.google.keystone.daemon.plist'
    if os.path.exists(file):
      self.RunCommand(['/bin/launchctl', cmd, file], rtn)

  def RunCommandAsUID(self, cmdLine, rtn, uid):
    """Like self.RunCommand(), but do it as user id |uid|."""
    pid = os.fork()
    if pid == 0:
      os.setuid(uid)
      self.RunCommand(cmdLine, rtn)
      sys.exit(0)
    else:
      os.waitpid(pid, 0)

  def ChangeAgentRunStateRootInstallLeopard(self, doload, rtn):
    """Change the run state of the agent for a root (system) install.
    10.5 version."""
    procToLookFor = (' /System/Library/CoreServices/Finder.app/' +
                     'Contents/MacOS/Finder')
    if doload:
      cmd = 'load'
    else:
      cmd = 'unload'
    # # launchd agent as user
    # self.RunCommandAsUID(['/bin/launchctl', cmd, '-S', 'Aqua',
    #                       (self.LaunchAgentConfigDir() +
    #                       'com.google.keystone.agent.plist') ],
    #                      rtn,
    #                      self.keystone.LocalUserUID())
    (stdin_ignored, stdoutfile, stderrfile) = popen_returns_files(['/bin/ps', 'auxwww'])
    stdout = stdoutfile.read()
    for s in stdout.splitlines():
      if ((s.find(procToLookFor) >= 0) and
          (s.split()[0] == self.keystone.LocalUsername())):
        pid = s.split()[1]
        # Must be root to bsexec.
        # Must bsexec to (pid) to get in local user's context.
        # Must become local user to have right process owner.
        # Must unset SUDO_COMMAND to keep launchctl happy.
        # Order is important.
        file = self.LaunchAgentConfigDir() + 'com.google.keystone.agent.plist'
        if os.path.exists(file):
          cmds = ['/bin/launchctl', 'bsexec', str(pid),
                  '/usr/bin/sudo', '-u', self.keystone.LocalUsername(),
                  '/bin/bash', '-c',
                  'unset SUDO_COMMAND ; /bin/launchctl ' + cmd + ' -S Aqua ' +
                  '"' + file + '"']
          self.RunCommand(cmds, rtn)
        return

  def ChangeAgentRunStateRootInstallTiger(self, doload, rtn):
    """10.4 version.  System-wide login item."""
    self.ChangeLoginItemRunState(doload, '/Library/Preferences/loginwindow')

  def ChangeAgentRunStateRootInstall(self, doload, rtn):
    """On 10.5, we also uninstall the 10.4 way in case we upgraded OSs."""
    self.ChangeAgentRunStateRootInstallLeopard(doload, rtn)
    if not doload:
      self.ChangeAgentRunStateRootInstallTiger(doload, rtn)

  def ChangeAgentRunStateUserInstallLeopard(self, doload, rtn):
    """Change the run state of the agent for a user install.  10.5
    version."""
    if doload:
      cmd = 'load'
    else:
      cmd = 'unload'
    file = self.LaunchAgentConfigDir() + 'com.google.keystone.agent.plist'
    fullCommandLine = ['/bin/launchctl', cmd, '-S', 'Aqua', file]
    if os.path.exists(file):
      if (not doload) and (os.geteuid() == 0):
        # We get here on promote (install as root, so euid==0, but we need
        # to uninstall the user Keystone).
        self.RunCommandAsUID(fullCommandLine, rtn, self.keystone.LocalUserUID())
      else:
        self.RunCommand(fullCommandLine, rtn)

  def ChangeAgentRunStateUserInstallTiger(self, doload, rtn):
    """10.4 version; login item."""
    self.ChangeLoginItemRunState(doload, 'loginwindow')

  def ChangeAgentRunStateUserInstall(self, doload, rtn):
    """On 10.5, we also uninstall the 10.4 way in case we upgraded OSs."""
    self.ChangeAgentRunStateUserInstallLeopard(doload, rtn)
    if not doload:
      self.ChangeAgentRunStateUserInstallTiger(doload, rtn)

  def AddAndStartLoginItem(self, domain):
    """Add the agent to as a login item to the specified |domain|.  Used
    for both root and user.  Since the 10.5 equivilent, 'launchctl
    load', will run the process now, we do the same thing.
    Intended for 10.4.  Added to the 10.5 base class to keep consistency
    with RemoveAndKillLoginItem()."""
    try:
      self.RunCommand(['/usr/bin/defaults', 'write', domain,
                       'AutoLaunchedApplicationDictionary',  '-array-add',
                       ('{Hide = 1; Path = \"' +
                        self.KeystoneAgentPath() + '\"; }')], 0)
    except Failure:
      # An empty AutoLaunchedApplicationDictionary is an empty string,
      # not an empty array, in which case -array-add chokes.  There is
      # no easy way to do a typeof(AutoLaunchedApplicationDictionary)
      # for a plist.  Our solution is to catch the error and try a
      # different way.
      self.RunCommand(['/usr/bin/defaults', 'write', domain,
                       'AutoLaunchedApplicationDictionary',  '-array',
                       ('{Hide = 1; Path = \"' +
                        self.KeystoneAgentPath() + '\"; }')], 0)
    if self.IsSystemKeystone():
      self.RunCommand(['/usr/bin/sudo', '-u',
                       str(self.keystone.LocalUsername()),
                       '/usr/bin/open', self.KeystoneAgentPath()], 0)
    else:
      self.RunCommand(['/usr/bin/open', self.KeystoneAgentPath()], 0)

  def RemoveAndKillLoginItem(self, domain):
    """Remove a login item in the specified |domain|.  Used for both
    root and user.  Since the 10.5 equivilent, 'launchctl unload',
    will kill the process, we do the same thing.  Intended for 10.4,
    but possibly used on 10.5 to cleanup."""
    aladir = 'AutoLaunchedApplicationDictionary'
    (stdin_ignored, stdoutfile, stderrfile) = popen_returns_files(['/usr/bin/defaults',
                                                         'read',
                                                         domain,
                                                         aladir])
    stdout = stdoutfile.read()
    if len(stdout.strip()) == 0:
      stdout = '()'

    # One line per loginitem to help us match
    stdout = re.compile('[\n]+').sub('', stdout)
    # handles case where we are the only item
    stdout = stdout.replace('(', '(\n')
    stdout = stdout.replace('}', '}\n')
    for line in stdout.splitlines():
      if line.find('/Library/Google/GoogleSoftwareUpdate/' +
                   'GoogleSoftwareUpdate.bundle/Contents/' +
                   'Resources/GoogleSoftwareUpdateAgent.app') != -1:
        stdout = stdout.replace(line, '')
    stdout = stdout.replace('\n', '')
    # help make sure it's a well-formed list
    stdout = stdout.replace('(,', '(')

    try:
      self.RunCommand(['/usr/bin/defaults', 'write', domain,
                       'AutoLaunchedApplicationDictionary', stdout], 0)
    except Failure, inst:
      # if we messed up the parse, log and move on.
      print inst

    # Now kill it
    lun = self.keystone.LocalUsername()
    (stdin_ignored, stdoutfile, stderrfile) = popen_returns_files(['/bin/ps',
                                                                   'auxwww',
                                                                   '-U',
                                                                   lun])
    for s in stdoutfile.readlines():
      pn1 = ('/Library/Google/GoogleSoftwareUpdate/' +
             'GoogleSoftwareUpdate.bundle/Contents/' +
             'Resources/GoogleSoftwareUpdateAgent.app/' +
             'Contents/MacOS/GoogleSoftwareUpdateAgent')
      if s.find(pn1) != -1 and s.find('-oneShot') == -1:
        words = s.split()
        pid = words[1]
        os.kill(int(pid), signal.SIGTERM)

  def ChangeLoginItemRunState(self, doload, domain):
    """Change (add or remove) the login item for |domain| based on the
      value of |doload|.  Also start or kill the relevant item (in the
      current context) to mirror 10.5 launchctl behavior.  Although
      this is mainly for 10.4, it is also used on 10.5 to help cleanup
      (e.g. after an upgrade to 10.5)."""
    if doload:
      self.AddAndStartLoginItem(domain)
    else:
      self.RemoveAndKillLoginItem(domain)

  def FixupProducts(self):
    """Attempt to repair any products might have broken tickets."""
    # Google Talk Plugin 1.0.15.1351 can have its existence checker
    # pointing to a deleted directory.  Fix up the xc so it'll update
    # next time.
    if not self.IsSystemKeystone():
      # Don't bother if we can't change sytem tickets.
      return
    # See if there's a talk plugin ticket.
    cmds = [self.GetKsadmin(), '--productid', 'com.google.talkplugin', '-p']
    (stdin_ignored, stdoutfile, stderrfile) = popen_returns_files(cmds)
    stdout = stdoutfile.read()
    if stdout.find('1.0.15.1351') == -1:
      # Don't bother if we don't find the right version.
      return
    # Fix the ticket by reregistering it.
    # We can only get here if 1.0.15.1351 is the current version, so it's
    # safe to use that version.
    xcpath = '/Library/Internet Plug-Ins/googletalkbrowserplugin.plugin'
    cmds = [self.GetKsadmin(), '--register',
            '--productid', 'com.google.talkplugin',
            '--xcpath', xcpath,
            '--version', '1.0.15.1351',
            '--url', 'https://tools.google.com/service/update2']
    self.RunCommand(cmds, -1)

  def IsSystemKeystone(self):
    """Are we doing work for system keystone?"""
    return self.uid == 0

# -------------------------------------------------------------------------

class KeystoneInstallTiger(KeystoneInstall):

  """Like KeystoneInstall, but overrides a few methods to support 10.4
  (Tiger)."""

  def __init__(self, keystone, uid, root):
    KeystoneInstall.__init__(self, keystone, uid, root)
    pass

  def InstalledPlists(self):
    """Return a list of plists which are supposed to be installed
    (destination paths).  Does NOT check they actually exist.
    10.4 override (no agent)."""
    plists = []
    plists.extend(self.InstalledPlistsForRootInstall())
    return plists

  def ChangeAgentRunStateRootInstall(self, doload, rtn):
    """Only do Tiger version."""
    self.ChangeAgentRunStateRootInstallTiger(doload, rtn)

  def ChangeAgentRunStateUserInstall(self, doload, rtn):
    """Only do Tiger version."""
    self.ChangeAgentRunStateUserInstallTiger(doload, rtn)

# -------------------------------------------------------------------------

class Keystone(object):

  """Top-level interface for Keystone install and uninstall.

  Attributes:
    package: name of the package to install (e.g. Keystone.tbz)
    root: root directory for install (e.g. "/", "/Users/frankie")
    doLaunchdPlists: boolean stating if we should install plist files
    doProcLaunch: boolean stating if we should launch/stop processes
    doForce: if True, force an install no matter what versions may say.
      Don't reference directly; use MyKeystoneBundleVersion().
    allInstallers: a list of all installers.  Used when uninstalling,
      stopping, or removing stuff.  If root, includes both,
      with the root installer first.
      Else only includes the user installer.
    currentInstaller: if a root install, the root installer.
      Else the user installer.
   """

  def __init__(self, package, systemRoot, userRoot, doLaunchdPlists,
               doProcLaunch, doForce):
    self.package = package
    self.doLaunchdPlists = doLaunchdPlists
    self.doProcLaunch = doProcLaunch
    self.doForce = doForce
    if userRoot == None:
      userRoot = self.RootForUID(self.LocalUserUID())
    if self.IsTiger():
      self.rootInstaller = KeystoneInstallTiger(self, 0, systemRoot)
      self.userInstaller = KeystoneInstallTiger(self, self.LocalUserUID(),
                                                userRoot)
    else:
      self.rootInstaller = KeystoneInstall(self, 0, systemRoot)
      self.userInstaller = KeystoneInstall(self, self.LocalUserUID(), userRoot)
    if self.IsRootInstall():
      self.allInstallers = [ self.rootInstaller, self.userInstaller ]
    else:
      self.allInstallers = [ self.userInstaller ]
    self.currentInstaller = self.allInstallers[0]

  def IsLeopardOrLater(self):
    """Ouch!  platform.mac_ver() returns
    ('10.5.1', ('', '', ''), 'i386')       10.5, python2.4 or python2.5
    ('', ('', '', ''), '')                 10.4, python2.3
    <unknown on 10.4, python2.4>
    Return True if we're on 10.5; else return False."""
    global gForceTiger
    if gForceTiger:
      return False
    (vers, dontcare1, dontcare2) = platform.mac_ver()
    splits = vers.split('.')
    if (len(splits) == 3) and (splits[1] >= '5'):
      return True
    return False

  def IsTiger(self):
    """Return the boolean opposite of IsLeopardOrLater()."""
    if self.IsLeopardOrLater():
      return False
    else:
      return True

  def IsRootInstall(self):
    """Return True if this is a root install.  On root install we do
    some special things (e.g. we have a daemon)."""
    uid = os.geteuid()
    if uid == 0:
      return True
    else:
      return False

  def LocalUserUID(self):
    """Return the UID of the local (non-root) user who initiated this
    install/uninstall.  If we can't figure it out, default to the user
    on conosle.  We don't want to default to console user in case a
    FUS happens in the middle of install or uninstall."""
    uid = os.geteuid()
    if uid != 0:
      return uid
    else:
      return os.stat('/dev/console')[stat.ST_UID]

  def LocalUsername(self):
    """Return the username of the local user."""
    uid = self.LocalUserUID()
    p = pwd.getpwuid(uid)
    return p[0]

  def RootForUID(self, uid):
    """For the given UID, return the install root for Keystone (where
    is is, or where it should be, installed)."""
    if uid == 0:
      return '/'
    else:
      return pwd.getpwuid(uid)[5]

  def ShouldInstall(self):
    """Return True if we should on install.  Possible reasons for
    punting (returning False):
    1) This is a System Keystone install and the installed System
    Keystone has a smaller version.
    2) This is a User Keystone and there is a System Keystone
    installed (of any version).
    3) This is a User Keystone and the installed User Keystone has a
    smaller version.
    4) We are told to force an install (--force cmd line option)
    """
    if self.doForce:
      return True
    if self.IsRootInstall():
      if self.rootInstaller.IsMyVersionGreaterThanInstalledVersion():
        return True
      else:
        return False
    else:
      # User install; check for any root presence
      if self.rootInstaller.InstalledKeystoneBundleVersion() != None:
        return False
      # There is no root install so just compare with existing user install
      elif self.userInstaller.IsMyVersionGreaterThanInstalledVersion():
        return True
      else:
        return False

  def Install(self, lockdown):
    """Public install interface.

      lockdown: if True, install a special ticket to lock down Keystone
        and prevent uninstall.  This will happen even if an install
        of Keystone itself is not needed.
    """
    CheckOnePath(self.package, stat.S_IRUSR)
    if self.ShouldInstall():
      self.Uninstall()
      self.currentInstaller.MakeDirectories(self.doLaunchdPlists)
      self.currentInstaller.InstallPackage()
      self.currentInstaller.MakeTicketForKeystone()
      if self.doLaunchdPlists:
        # Uninstall will also Stop/UninstallPlists if desired
        self.currentInstaller.InstallPlists()
        if self.doProcLaunch:
          self.currentInstaller.StartProcessesForCurrentContext()
    # possibly lockdown even if we don't need to install
    if lockdown:
      self.currentInstaller.LockdownKeystone()

  def Nuke(self):
    """Public nuke interface.  Likely never called explicitly
    other than testing."""
    self.Uninstall()
    for i in self.allInstallers:
      i.FullUninstallOfDirectories()  # DOES nuke all tickets
      i.StopAllAgentProcesses()
      i.DeleteReceipts()

  def Uninstall(self):
    """Prepare this machine for an install.  Although similar, it is
    NOT as comprehensive as a nuke.  Stops and removes
    components with all relevate installers (e.g. if root, do both; if
    user, do only user.)"""
    for i in self.allInstallers:
      if self.doProcLaunch:
        i.StopProcessesForCurrentContext()
      if self.doLaunchdPlists:
        i.UninstallPlists()
      i.UninstallPackage()  # does not delete all tickets; only our own
      i.DeleteCache()

  def FixupProducts(self):
    """Attempt to repair any products might have broken tickets."""
    for i in self.allInstallers:
      i.FixupProducts()

# -------------------------------------------------------------------------

def PrintUse():
  print 'Use: '
  print ' [--install PKG]    Install keystone using PKG as the source.'
  print ' [--root ROOT]      Use ROOT as the dest for an install.  Optional.'
  print ' [--nuke]           Nuke Keystone and tickets.'
  print ' [--uninstall]      Like nuke but do NOT delete the ticket store.'
  print '                    Only supported for a user install.'
  print ' [--no-launchd]     Do NOT touch Keystone launchd plists or jobs,'
  print '                     for both install and uninstall.  For testing.'
  print ' [--no-launchdjobs] Do NOT touch jobs, but do do launchd plist files,'
  print '                     for both install and uninstall.  For testing.'
  print ' [--force]          Force an install no matter what.  For testing.'
  print ' [--forcetiger]     Pretend we are on Tiger (MacOSX 10.4).  For testing.'
  print ' [--lockdown]       Prevent Keystone from ever uninstalling itself.'
  print ' [--interval N]     Change agent plist to wake up every N sec '
  print ' [--help]           This message'


def main():
  os.environ.clear()
  os.environ['PATH'] = '/bin:/sbin:/usr/bin:/usr/sbin:/usr/libexec'

  # Make sure AuthorizationExecuteWithPrivileges() is happy
  if os.getuid() and os.geteuid() == 0:
    os.setuid(os.geteuid())

  try:
    opts, args = getopt.getopt(sys.argv[1:], "i:r:XunNhfI:",
                               ["install=", "root=", "nuke", "uninstall",
                                "no-launchd", "no-launchdjobs", "help",
                                "force", "forcetiger", "lockdown", "interval="])
  except getopt.GetoptError:
    print 'Bad options.'
    PrintUse()
    sys.exit(1)

  systemRoot = '/'
  userRoot = None
  package = None
  nuke = False
  uninstall = False
  doLaunchdPlists = True
  doProcLaunch = True
  doForce = False
  lockdown = False  # If true, prevent uninstall by adding a "lockdown" ticket

  for opt, val in opts:
    if opt in ('-i', '--install'):
      package = val
    if opt in ('-r', '--root'):
      userRoot = val
    if opt in ('-X', '--nuke'):
      nuke = True
    if opt in ('-u', '--uninstall'):
      uninstall = True
    if opt in ('-n', '--no-launchd'):
      doLaunchdPlists = False
    if opt in ('-N', '--no-launchdjobs'):
      doProcLaunch = False
    if opt in ('-f', '--force'):
      doForce = True
    if opt in ('-T', '--forcetiger'):
      global gForceTiger
      gForceTiger = True
    if opt in ('--lockdown',):
      lockdown = True
    if opt in ('-I', '--interval'):
      global gAgentStartInterval
      gAgentStartInterval = int(val)
    if opt in ('-h', '--help'):
      PrintUse()
      sys.exit(0)

  if (package == None) and (not nuke) and (not uninstall):
    print 'Must specify package name or nuke'
    PrintUse()
    sys.exit(1)
  try:
    (vers, dontcare1, dontcare2) = platform.mac_ver()
    splits = vers.split('.')
    if (len(splits) == 3) and (int(splits[1]) < 4):
      print 'Requires MacOS10.4 or later'
      sys.exit(1)
  except:
    # 10.3 throws an exception for platform.mac_ver()
    print 'Requires MacOS10.4 or later'
    sys.exit(1)

  # lock file to make sure only one of these runs at a time
  lockfilename = '/tmp/.keystone_install_lock'

  # Make sure that root and user can share the same lockfile
  oldmask = os.umask(0000)
  # os.O_EXLOCK is 32, but isn't defined on 10.4 (python2.3)
  lockfile = os.open(lockfilename, os.O_CREAT | os.O_RDWR | 32, 0666)
  # restore umask for other files we create
  os.umask(oldmask)

  exitcode = 0
  try:
    k = Keystone(package, systemRoot, userRoot,
                 doLaunchdPlists, doProcLaunch, doForce)
    if uninstall:
      k.Uninstall()
    elif nuke:
      k.Nuke()
    else:
      k.Install(lockdown)
      k.FixupProducts()
  except Failure, inst:
    print inst
    exitcode = 1

  os.close(lockfile)
  # lock file left around on purpose (or locking not happy)

  sys.exit(exitcode)

if __name__ == "__main__":
  main()
