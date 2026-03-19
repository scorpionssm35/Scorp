#include "KernelCheatDetector.h"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <numeric>
#include <execution>
#include <intrin.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include "LogUtils.h"
#include "dllmain.h"
#include "DetectionAggregator.h"

#pragma comment(lib, "Psapi.lib")

#define SAFE_EXECUTE(expr) \
    try { expr; } \
    catch (...) { \
        Log("[LOGEN] Exception in: " #expr); \
    }

double CalculateDetectionConfidence(KernelCheatDetector::CheatPattern pattern) {
    switch (pattern) {
    case KernelCheatDetector::PATTERN_DMA_BURST:
    case KernelCheatDetector::PATTERN_KERNEL_DELAY:
        return 0.95; // Высокая уверенность
    case KernelCheatDetector::PATTERN_SUB_HUMAN:
        return 0.85;
    case KernelCheatDetector::PATTERN_READ_COMPUTE_WRITE:
        return 0.75;
    case KernelCheatDetector::PATTERN_REGULAR_READ:
        return 0.65;
    default:
        return 0.5;
    }
}
static const std::vector<std::string> EXCLUDED_PROCESSES = {
    "textinputhost.exe",
    "svchost.exe",
    "explorer.exe",
    "taskhostw.exe",
    "runtimebroker.exe",
    "dwm.exe",
    "ctfmon.exe",
    "conhost.exe",
    "winlogon.exe",
    "csrss.exe",
    "services.exe",
    "lsass.exe",
    "wininit.exe",
    "smss.exe",
    "system",
    "system idle process",
    "taskmgr.exe",
    "cmd.exe",
    "powershell.exe",
    "searchui.exe",
    "searchindexer.exe",
    "sihost.exe",
    "fontdrvhost.exe",
    "wlanext.exe",
    "dasHost.exe",
    "dllhost.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "applicationframehost.exe",
    "backgroundtaskhost.exe",
    "calculator.exe",
    "camera.exe",
    "microsoft.photos.exe",
    "microsoftedge.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "notepad.exe",
    "phoneexperiencehost.exe",
    "searchhost.exe",
    "securityhealthsystray.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "video.ui.exe",
    "widgets.exe",
    "windows.internal.shellexperience.exe",
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "chrome.exe",
    "firefox.exe",
    "opera.exe",
    "browser.exe",
    "steam.exe",
    "steamwebhelper.exe",
    "origin.exe",
    "epicgameslauncher.exe",
    "battlenet.exe",
    "uplay.exe",
    "galaxyclient.exe",
    "discord.exe",
    "teams.exe",
    "zoom.exe",
    "skype.exe",
    "whatsapp.exe",
    "telegram.exe",
    "viber.exe",
    "slack.exe",
    "spotify.exe",
    "vlc.exe",
    "winamp.exe",
    "itunes.exe",
    "devenv.exe",
    "code.exe",
    "clion.exe",
    "pycharm.exe",
    "webstorm.exe",
    "rider.exe",
    "datagrip.exe",
    "androidstudio.exe",
    "xamarin.exe",
    "matlab.exe",
    "solidworks.exe",
    "autocad.exe",
    "photoshop.exe",
    "illustrator.exe",
    "premiere.exe",
    "aftereffects.exe",
    "lightroom.exe",
    "inkscape.exe",
    "gimp.exe",
    "blender.exe",
    "maya.exe",
    "3dsmax.exe",
    "zbrush.exe",
    "substancepainter.exe",
    "quixelmixer.exe",
    "worldmachine.exe",
    "speedtree.exe",
    "houdini.exe",
    "cinema4d.exe",
    "unity.exe",
    "unrealengine.exe",
    "godot.exe",
    "gamemaker.exe",
    "construct.exe",
    "rpgmaker.exe",
    "cryengine.exe",
    "frostbite.exe",
    "source2.exe",
    "idtech.exe",
    "creationkit.exe",
    "nwscript.exe",
    "lua.exe",
    "python.exe",
    "pythonw.exe",
    "ruby.exe",
    "perl.exe",
    "php.exe",
    "node.exe",
    "npm.exe",
    "yarn.exe",
    "java.exe",
    "javaw.exe",
    "kotlin.exe",
    "scala.exe",
    "groovy.exe",
    "clojure.exe",
    "erlang.exe",
    "elixir.exe",
    "haskell.exe",
    "ocaml.exe",
    "fsharp.exe",
    "vb.exe",
    "csc.exe",
    "msbuild.exe",
    "cmake.exe",
    "make.exe",
    "gcc.exe",
    "g++.exe",
    "cl.exe",
    "link.exe",
    "rc.exe",
    "mt.exe",
    "lib.exe",
    "dumpbin.exe",
    "editbin.exe",
    "nmake.exe",
    "jom.exe",
    "qmake.exe",
    "moc.exe",
    "uic.exe",
    "rcc.exe",
    "windeployqt.exe",
    "android.exe",
    "adb.exe",
    "fastboot.exe",
    "emulator.exe",
    "genymotion.exe",
    "bluestacks.exe",
    "nox.exe",
    "ldplayer.exe",
    "memu.exe",
    "virtualbox.exe",
    "vmware.exe",
    "vboxmanage.exe",
    "vboxsds.exe",
    "vboxsvc.exe",
    "vboxtray.exe",
    "vmware-tray.exe",
    "vmware-user.exe",
    "vmware-vmx.exe",
    "prl_tools.exe",
    "prl_cc.exe",
    "prl_disp.exe",
    "docker.exe",
    "dockerd.exe",
    "containerd.exe",
    "kubectl.exe",
    "minikube.exe",
    "helm.exe",
    "terraform.exe",
    "vagrant.exe",
    "packer.exe",
    "ansible.exe",
    "chef.exe",
    "puppet.exe",
    "salt.exe",
    "git.exe",
    "git-bash.exe",
    "git-cmd.exe",
    "git-gui.exe",
    "svn.exe",
    "hg.exe",
    "bzr.exe",
    "cvs.exe",
    "tortoisegit.exe",
    "tortoisesvn.exe",
    "sourcetree.exe",
    "githubdesktop.exe",
    "gitkraken.exe",
    "fork.exe",
    "smartgit.exe",
    "beyondcompare.exe",
    "winmerge.exe",
    "meld.exe",
    "kdiff3.exe",
    "ultracompare.exe",
    "examdiff.exe",
    "diffmerge.exe",
    "p4merge.exe",
    "araxis.exe",
    "compareit.exe",
    "guiffy.exe",
    "diffoscope.exe",
    "vim.exe",
    "gvim.exe",
    "emacs.exe",
    "nano.exe",
    "notepad++.exe",
    "sublime_text.exe",
    "atom.exe",
    "vscode.exe",
    "brackets.exe",
    "textmate.exe",
    "gedit.exe",
    "kate.exe",
    "leafpad.exe",
    "mousepad.exe",
    "pluma.exe",
    "xed.exe",
    "bluefish.exe",
    "komodo.exe",
    "geany.exe",
    "jedit.exe",
    "pspad.exe",
    "conemu.exe",
    "cmder.exe",
    "mobaxterm.exe",
    "putty.exe",
    "kitty.exe",
    "winscp.exe",
    "filezilla.exe",
    "cyberduck.exe",
    "transmit.exe",
    "forklift.exe",
    "totalcommander.exe",
    "freecommander.exe",
    "doublecommander.exe",
    "midnightcommander.exe",
    "far.exe",
    "q-dir.exe",
    "xyplorer.exe",
    "directoryopus.exe",
    "explorer++.exe",
    "onecommander.exe",
    "mucommander.exe",
    "windirstat.exe",
    "wiztree.exe",
    "treesize.exe",
    "spacesniffer.exe",
    "jdsk.exe",
    "diskanalyzer.exe",
    "filelight.exe",
    "baobab.exe",
    "duplicatecleaner.exe",
    "auslogicsduplicate.exe",
    "alldup.exe",
    "visipics.exe",
    "imagedupeless.exe",
    "dupeguru.exe",
    "czkawka.exe",
    "fslint.exe",
    "rmlint.exe",
    "fdupes.exe",
    "jdupes.exe",
    "rdfind.exe",
    "duff.exe",
    "fclones.exe",
    "hashdeep.exe",
    "md5deep.exe",
    "sha256deep.exe",
    "hashcheck.exe",
    "hashcalc.exe",
    "hashtab.exe",
    "md5checker.exe",
    "rapidcrc.exe",
    "chkhash.exe",
    "exactfile.exe",
    "checksumcontrol.exe",
    "hashmyfiles.exe",
    "veracrypt.exe",
    "truecrypt.exe",
    "cryptomator.exe",
    "axcrypt.exe",
    "gpg4win.exe",
    "kleopatra.exe",
    "gnupg.exe",
    "openpgp.exe",
    "pgp.exe",
    "encfs.exe",
    "ecryptfs.exe",
    "fscrypt.exe",
    "bitlocker.exe",
    "veracryptformat.exe",
    "7z.exe",
    "winrar.exe",
    "winzip.exe",
    "bandizip.exe",
    "peazip.exe",
    "zipgenius.exe",
    "izarc.exe",
    "ha.exe",
    "ark.exe",
    "file-roller.exe",
    "xarchiver.exe",
    "engrampa.exe",
    "squeeze.exe",
    "extractnow.exe",
    "universalextractor.exe",
    "uniextract.exe",
    "innounp.exe",
    "innoextract.exe",
    "nsis.exe",
    "msiexec.exe",
    "installshield.exe",
    "wise.exe",
    "installaware.exe",
    "advancedinstaller.exe",
    "setupfactory.exe",
    "installbuilder.exe",
    "izpack.exe",
    "packages.exe",
    "pkg.exe",
    "dpkg.exe",
    "rpm.exe",
    "yum.exe",
    "apt.exe",
    "apt-get.exe",
    "pacman.exe",
    "zypper.exe",
    "emerge.exe",
    "portage.exe",
    "nix.exe",
    "guix.exe",
    "chocolatey.exe",
    "scoop.exe",
    "winget.exe",
    "npm.exe",
    "yarn.exe",
    "pip.exe",
    "conda.exe",
    "maven.exe",
    "gradle.exe",
    "ant.exe",
    "make.exe",
    "ninja.exe",
    "bazel.exe",
    "buck.exe",
    "pants.exe",
    "please.exe",
    "soong.exe",
    "gn.exe",
    "gyp.exe",
    "cmake.exe",
    "qmake.exe",
    "premake.exe",
    "meson.exe",
    "scons.exe",
    "waf.exe",
    "autoconf.exe",
    "automake.exe",
    "libtool.exe",
    "pkg-config.exe",
    "configure.exe",
    "makefile.exe",
    "build.bat",
    "build.sh",
    "compile.bat",
    "compile.sh",
    "run.bat",
    "run.sh",
    "start.bat",
    "start.sh",
    "launch.bat",
    "launch.sh",
    "execute.bat",
    "execute.sh",
    "install.bat",
    "install.sh",
    "setup.bat",
    "setup.sh",
    "config.bat",
    "config.sh",
    "init.bat",
    "init.sh",
    "update.bat",
    "update.sh",
    "upgrade.bat",
    "upgrade.sh",
    "patch.bat",
    "patch.sh",
    "fix.bat",
    "fix.sh",
    "repair.bat",
    "repair.sh",
    "clean.bat",
    "clean.sh",
    "reset.bat",
    "reset.sh",
    "restore.bat",
    "restore.sh",
    "backup.bat",
    "backup.sh",
    "sync.bat",
    "sync.sh",
    "deploy.bat",
    "deploy.sh",
    "publish.bat",
    "publish.sh",
    "release.bat",
    "release.sh",
    "package.bat",
    "package.sh",
    "distribute.bat",
    "distribute.sh",
    "upload.bat",
    "upload.sh",
    "download.bat",
    "download.sh",
    "transfer.bat",
    "transfer.sh",
    "copy.bat",
    "copy.sh",
    "move.bat",
    "move.sh",
    "rename.bat",
    "rename.sh",
    "delete.bat",
    "delete.sh",
    "remove.bat",
    "remove.sh",
    "uninstall.bat",
    "uninstall.sh",
    "wipe.bat",
    "wipe.sh",
    "format.bat",
    "format.sh",
    "partition.bat",
    "partition.sh",
    "mount.bat",
    "mount.sh",
    "unmount.bat",
    "unmount.sh",
    "eject.bat",
    "eject.sh",
    "lock.bat",
    "lock.sh",
    "unlock.bat",
    "unlock.sh",
    "encrypt.bat",
    "encrypt.sh",
    "decrypt.bat",
    "decrypt.sh",
    "sign.bat",
    "sign.sh",
    "verify.bat",
    "verify.sh",
    "hash.bat",
    "hash.sh",
    "checksum.bat",
    "checksum.sh",
    "scan.bat",
    "scan.sh",
    "check.bat",
    "check.sh",
    "test.bat",
    "test.sh",
    "debug.bat",
    "debug.sh",
    "profile.bat",
    "profile.sh",
    "monitor.bat",
    "monitor.sh",
    "log.bat",
    "log.sh",
    "trace.bat",
    "trace.sh",
    "audit.bat",
    "audit.sh",
    "inspect.bat",
    "inspect.sh",
    "analyze.bat",
    "analyze.sh",
    "optimize.bat",
    "optimize.sh",
    "tune.bat",
    "tune.sh",
    "adjust.bat",
    "adjust.sh",
    "configure.bat",
    "configure.sh",
    "customize.bat",
    "customize.sh",
    "personalize.bat",
    "personalize.sh",
    "modify.bat",
    "modify.sh",
    "edit.bat",
    "edit.sh",
    "change.bat",
    "change.sh",
    "update.bat",
    "update.sh",
    "upgrade.bat",
    "upgrade.sh",
    "downgrade.bat",
    "downgrade.sh",
    "rollback.bat",
    "rollback.sh",
    "revert.bat",
    "revert.sh",
    "undo.bat",
    "undo.sh",
    "redo.bat",
    "redo.sh",
    "repeat.bat",
    "repeat.sh",
    "loop.bat",
    "loop.sh",
    "cycle.bat",
    "cycle.sh",
    "rotate.bat",
    "rotate.sh",
    "alternate.bat",
    "alternate.sh",
    "switch.bat",
    "switch.sh",
    "toggle.bat",
    "toggle.sh",
    "flip.bat",
    "flip.sh",
    "invert.bat",
    "invert.sh",
    "reverse.bat",
    "reverse.sh",
    "mirror.bat",
    "mirror.sh",
    "duplicate.bat",
    "duplicate.sh",
    "clone.bat",
    "clone.sh",
    "copy.bat",
    "copy.sh",
    "paste.bat",
    "paste.sh",
    "cut.bat",
    "cut.sh",
    "clear.bat",
    "clear.sh",
    "reset.bat",
    "reset.sh",
    "refresh.bat",
    "refresh.sh",
    "reload.bat",
    "reload.sh",
    "restart.bat",
    "restart.sh",
    "reboot.bat",
    "reboot.sh",
    "shutdown.bat",
    "shutdown.sh",
    "hibernate.bat",
    "hibernate.sh",
    "sleep.bat",
    "sleep.sh",
    "wake.bat",
    "wake.sh",
    "lock.bat",
    "lock.sh",
    "unlock.bat",
    "unlock.sh",
    "login.bat",
    "login.sh",
    "logout.bat",
    "logout.sh",
    "switchuser.bat",
    "switchuser.sh",
    "changepassword.bat",
    "changepassword.sh",
    "resetpassword.bat",
    "resetpassword.sh",
    "recoveraccount.bat",
    "recoveraccount.sh",
    "verifyidentity.bat",
    "verifyidentity.sh",
    "authenticate.bat",
    "authenticate.sh",
    "authorize.bat",
    "authorize.sh",
    "validate.bat",
    "validate.sh",
    "confirm.bat",
    "confirm.sh",
    "approve.bat",
    "approve.sh",
    "reject.bat",
    "reject.sh",
    "deny.bat",
    "deny.sh",
    "block.bat",
    "block.sh",
    "allow.bat",
    "allow.sh",
    "permit.bat",
    "permit.sh",
    "forbid.bat",
    "forbid.sh",
    "ban.bat",
    "ban.sh",
    "unban.bat",
    "unban.sh",
    "mute.bat",
    "mute.sh",
    "unmute.bat",
    "unmute.sh",
    "deafen.bat",
    "deafen.sh",
    "undeafen.bat",
    "undeafen.sh",
    "kick.bat",
    "kick.sh",
    "ban.bat",
    "ban.sh",
    "timeout.bat",
    "timeout.sh",
    "warn.bat",
    "warn.sh",
    "notice.bat",
    "notice.sh",
    "alert.bat",
    "alert.sh",
    "notify.bat",
    "notify.sh",
    "inform.bat",
    "inform.sh",
    "announce.bat",
    "announce.sh",
    "broadcast.bat",
    "broadcast.sh",
    "publish.bat",
    "publish.sh",
    "share.bat",
    "share.sh",
    "send.bat",
    "send.sh",
    "receive.bat",
    "receive.sh",
    "transmit.bat",
    "transmit.sh",
    "communicate.bat",
    "communicate.sh",
    "connect.bat",
    "connect.sh",
    "disconnect.bat",
    "disconnect.sh",
    "join.bat",
    "join.sh",
    "leave.bat",
    "leave.sh",
    "enter.bat",
    "enter.sh",
    "exit.bat",
    "exit.sh",
    "start.bat",
    "start.sh",
    "stop.bat",
    "stop.sh",
    "pause.bat",
    "pause.sh",
    "resume.bat",
    "resume.sh",
    "continue.bat",
    "continue.sh",
    "break.bat",
    "break.sh",
    "interrupt.bat",
    "interrupt.sh",
    "terminate.bat",
    "terminate.sh",
    "kill.bat",
    "kill.sh",
    "destroy.bat",
    "destroy.sh",
    "remove.bat",
    "remove.sh",
    "delete.bat",
    "delete.sh",
    "erase.bat",
    "erase.sh",
    "wipe.bat",
    "wipe.sh",
    "clean.bat",
    "clean.sh",
    "clear.bat",
    "clear.sh",
    "reset.bat",
    "reset.sh",
    "format.bat",
    "format.sh",
    "initialize.bat",
    "initialize.sh",
    "setup.bat",
    "setup.sh",
    "configure.bat",
    "configure.sh",
    "install.bat",
    "install.sh",
    "uninstall.bat",
    "uninstall.sh",
    "upgrade.bat",
    "upgrade.sh",
    "downgrade.bat",
    "downgrade.sh",
    "update.bat",
    "update.sh",
    "patch.bat",
    "patch.sh",
    "fix.bat",
    "fix.sh",
    "repair.bat",
    "repair.sh",
    "restore.bat",
    "restore.sh",
    "recover.bat",
    "recover.sh",
    "backup.bat",
    "backup.sh",
    "sync.bat",
    "sync.sh",
    "clone.bat",
    "clone.sh",
    "copy.bat",
    "copy.sh",
    "move.bat",
    "move.sh",
    "rename.bat",
    "rename.sh",
    "delete.bat",
    "delete.sh",
    "create.bat",
    "create.sh",
    "generate.bat",
    "generate.sh",
    "build.bat",
    "build.sh",
    "compile.bat",
    "compile.sh",
    "assemble.bat",
    "assemble.sh",
    "link.bat",
    "link.sh",
    "package.bat",
    "package.sh",
    "deploy.bat",
    "deploy.sh",
    "publish.bat",
    "publish.sh",
    "release.bat",
    "release.sh",
    "distribute.bat",
    "distribute.sh",
    "upload.bat",
    "upload.sh",
    "download.bat",
    "download.sh",
    "transfer.bat",
    "transfer.sh",
    "share.bat",
    "share.sh",
    "send.bat",
    "send.sh",
    "receive.bat",
    "receive.sh",
    "sync.bat",
    "sync.sh",
    "backup.bat",
    "backup.sh",
    "restore.bat",
    "restore.sh",
    "clone.bat",
    "clone.sh",
    "mirror.bat",
    "mirror.sh",
    "duplicate.bat",
    "duplicate.sh",
    "copy.bat",
    "copy.sh",
    "paste.bat",
    "paste.sh",
    "cut.bat",
    "cut.sh",
    "clear.bat",
    "clear.sh",
    "reset.bat",
    "reset.sh",
    "refresh.bat",
    "refresh.sh",
    "reload.bat",
    "reload.sh",
    "restart.bat",
    "restart.sh",
    "reboot.bat",
    "reboot.sh",
    "shutdown.bat",
    "shutdown.sh",
    "hibernate.bat",
    "hibernate.sh",
    "sleep.bat",
    "sleep.sh",
    "wake.bat",
    "wake.sh",
    "lock.bat",
    "lock.sh",
    "unlock.bat",
    "unlock.sh",
    "login.bat",
    "login.sh",
    "logout.bat",
    "logout.sh",
    "switchuser.bat",
    "switchuser.sh",
    "changepassword.bat",
    "changepassword.sh",
    "resetpassword.bat",
    "resetpassword.sh",
    "recoveraccount.bat",
    "recoveraccount.sh",
    "verifyidentity.bat",
    "verifyidentity.sh",
    "authenticate.bat",
    "authenticate.sh",
    "authorize.bat",
    "authorize.sh",
    "validate.bat",
    "validate.sh",
    "confirm.bat",
    "confirm.sh",
    "approve.bat",
    "approve.sh",
    "reject.bat",
    "reject.sh",
    "deny.bat",
    "deny.sh",
    "block.bat",
    "block.sh",
    "allow.bat",
    "allow.sh",
    "permit.bat",
    "permit.sh",
    "forbid.bat",
    "forbid.sh",
    "ban.bat",
    "ban.sh",
    "unban.bat",
    "unban.sh",
    "mute.bat",
    "mute.sh",
    "unmute.bat",
    "unmute.sh",
    "deafen.bat",
    "deafen.sh",
    "undeafen.bat",
    "undeafen.sh",
    "kick.bat",
    "kick.sh",
    "ban.bat",
    "ban.sh",
    "timeout.bat",
    "timeout.sh",
    "warn.bat",
    "warn.sh",
    "notice.bat",
    "notice.sh",
    "alert.bat",
    "alert.sh",
    "notify.bat",
    "notify.sh",
    "inform.bat",
    "inform.sh",
    "announce.bat",
    "announce.sh",
    "broadcast.bat",
    "broadcast.sh",
    "publish.bat",
    "publish.sh",
    "share.bat",
    "share.sh",
    "send.bat",
    "send.sh",
    "receive.bat",
    "receive.sh",
    "transmit.bat",
    "transmit.sh",
    "communicate.bat",
    "communicate.sh",
    "connect.bat",
    "connect.sh",
    "disconnect.bat",
    "disconnect.sh",
    "join.bat",
    "join.sh",
    "leave.bat",
    "leave.sh",
    "enter.bat",
    "enter.sh",
    "exit.bat",
    "exit.sh",
    "start.bat",
    "start.sh",
    "stop.bat",
    "stop.sh",
    "pause.bat",
    "pause.sh",
    "resume.bat",
    "resume.sh",
    "continue.bat",
    "continue.sh",
    "break.bat",
    "break.sh",
    "interrupt.bat",
    "interrupt.sh",
    "terminate.bat",
    "terminate.sh",
    "kill.bat",
    "kill.sh",
    "destroy.bat",
    "destroy.sh",
    "remove.bat",
    "remove.sh",
    "delete.bat",
    "delete.sh",
    "erase.bat",
    "erase.sh",
    "wipe.bat",
    "wipe.sh",
    "clean.bat",
    "clean.sh",
    "clear.bat",
    "clear.sh",
    "reset.bat",
    "reset.sh",
    "format.bat",
    "format.sh",
    "initialize.bat",
    "initialize.sh",
    "setup.bat",
    "setup.sh",
    "configure.bat",
    "configure.sh",
    "install.bat",
    "install.sh",
    "uninstall.bat",
    "uninstall.sh",
    "upgrade.bat",
    "upgrade.sh",
    "downgrade.bat",
    "downgrade.sh",
    "update.bat",
    "update.sh",
    "patch.bat",
    "patch.sh",
    "fix.bat",
    "fix.sh",
    "repair.bat",
    "repair.sh",
    "restore.bat",
    "restore.sh",
    "recover.bat",
    "recover.sh",
    "backup.bat",
    "backup.sh",
    "sync.bat",
    "sync.sh",
    "clone.bat",
    "clone.sh",
    "copy.bat",
    "copy.sh",
    "move.bat",
    "move.sh",
    "rename.bat",
    "rename.sh",
    "delete.bat",
    "delete.sh",
    "create.bat",
    "create.sh",
    "generate.bat",
    "generate.sh",
    "build.bat",
    "build.sh",
    "compile.bat",
    "compile.sh",
    "assemble.bat",
    "assemble.sh",
    "link.bat",
    "link.sh",
    "package.bat",
    "package.sh",
    "deploy.bat",
    "deploy.sh",
    "publish.bat",
    "publish.sh",
    "release.bat",
    "release.sh",
    "distribute.bat",
    "distribute.sh",
    "upload.bat",
    "upload.sh",
    "download.bat",
    "download.sh",
    "transfer.bat",
    "transfer.sh",
    "share.bat",
    "share.sh",
    "send.bat",
    "send.sh",
    "receive.bat",
    "receive.sh",
    "sync.bat",
    "sync.sh",
    "backup.bat",
    "backup.sh",
    "restore.bat",
    "restore.sh",
    "clone.bat",
    "clone.sh",
    "mirror.bat",
    "mirror.sh",
    "duplicate.bat",
    "duplicate.sh",
    "copy.bat",
    "copy.sh",
    "paste.bat",
    "paste.sh",
    "cut.bat",
    "cut.sh",
    "clear.bat",
    "clear.sh",
    "reset.bat",
    "reset.sh",
    "refresh.bat",
    "refresh.sh",
    "reload.bat",
    "reload.sh",
    "restart.bat",
    "restart.sh",
    "reboot.bat",
    "reboot.sh",
    "shutdown.bat",
    "shutdown.sh",
    "hibernate.bat",
    "hibernate.sh",
    "sleep.bat",
    "sleep.sh",
    "wake.bat",
    "wake.sh",
    "lock.bat",
    "lock.sh",
    "unlock.bat",
    "unlock.sh",
    "login.bat",
    "login.sh",
    "logout.bat",
    "logout.sh",
    "switchuser.bat",
    "switchuser.sh",
    "changepassword.bat",
    "changepassword.sh",
    "resetpassword.bat",
    "resetpassword.sh",
    "recoveraccount.bat",
    "recoveraccount.sh",
    "verifyidentity.bat",
    "verifyidentity.sh",
    "authenticate.bat",
    "authenticate.sh",
    "authorize.bat",
    "authorize.sh",
    "validate.bat",
    "validate.sh",
    "confirm.bat",
    "confirm.sh",
    "approve.bat",
    "approve.sh",
    "reject.bat",
    "reject.sh",
    "deny.bat",
    "deny.sh",
    "block.bat",
    "block.sh",
    "allow.bat",
    "allow.sh",
    "permit.bat",
    "permit.sh",
    "forbid.bat",
    "forbid.sh",
    "ban.bat",
    "ban.sh",
    "unban.bat",
    "unban.sh",
    "mute.bat",
    "mute.sh",
    "unmute.bat",
    "unmute.sh",
    "deafen.bat",
    "deafen.sh",
    "undeafen.bat",
    "undeafen.sh",
    "kick.bat",
    "kick.sh",
    "ban.bat",
    "ban.sh",
    "timeout.bat",
    "timeout.sh",
    "warn.bat",
    "warn.sh",
    "notice.bat",
    "notice.sh",
    "alert.bat",
    "alert.sh",
    "notify.bat",
    "notify.sh",
    "inform.bat",
    "inform.sh",
    "announce.bat",
    "announce.sh",
    "broadcast.bat",
    "broadcast.sh",
    "publish.bat",
    "publish.sh",
    "share.bat",
    "share.sh",
    "send.bat",
    "send.sh",
    "receive.bat",
    "receive.sh",
    "transmit.bat",
    "transmit.sh",
    "communicate.bat",
    "communicate.sh",
    "connect.bat",
    "connect.sh",
    "disconnect.bat",
    "disconnect.sh",
    "join.bat",
    "join.sh",
    "leave.bat",
    "leave.sh",
    "enter.bat",
    "enter.sh",
    "exit.bat",
    "exit.sh",
    "start.bat",
    "start.sh",
    "stop.bat",
    "stop.sh",
    "pause.bat",
    "pause.sh",
    "resume.bat",
    "resume.sh",
    "continue.bat",
    "continue.sh",
    "break.bat",
    "break.sh",
    "interrupt.bat",
    "interrupt.sh",
    "terminate.bat",
    "terminate.sh",
    "kill.bat",
    "kill.sh",
    "destroy.bat",
    "destroy.sh",
    "remove.bat",
    "remove.sh",
    "delete.bat",
    "delete.sh",
    "erase.bat",
    "erase.sh",
    "wipe.bat",
    "wipe.sh",
    "clean.bat",
    "clean.sh",
    "clear.bat",
    "clear.sh",
    "reset.bat",
    "reset.sh",
    "format.bat",
    "format.sh",
    "initialize.bat",
    "initialize.sh",
    "setup.bat",
    "setup.sh",
    "configure.bat",
    "configure.sh",
    "install.bat",
    "install.sh",
    "uninstall.bat",
    "uninstall.sh",
    "upgrade.bat",
    "upgrade.sh",
    "downgrade.bat",
    "downgrade.sh",
    "update.bat",
    "update.sh",
    "patch.bat",
    "patch.sh",
    "fix.bat",
    "fix.sh",
    "repair.bat",
    "repair.sh",
    "restore.bat",
    "restore.sh",
    "recover.bat",
    "recover.sh",
    "backup.bat",
    "backup.sh",
    "sync.bat",
    "sync.sh",
    "clone.bat",
    "clone.sh",
    "copy.bat",
    "copy.sh",
    "move.bat",
    "move.sh",
    "rename.bat",
    "rename.sh",
    "delete.bat",
    "delete.sh"
};

KernelCheatDetector::KernelCheatDetector(const std::string& targetGameProcess, bool onlyMonitorGameProcess)
    : m_targetGameProcess(targetGameProcess)
    , m_onlyMonitorGameProcess(onlyMonitorGameProcess) {

    // Приводим к нижнему регистру для сравнений
    std::transform(m_targetGameProcess.begin(), m_targetGameProcess.end(),
        m_targetGameProcess.begin(), ::tolower);

    m_highResTimer = QueryPerformanceFrequency(&m_frequency) != 0;
    if (!m_highResTimer) {
        Log("[VEH] KERNEL WARNING: No high-resolution timer available");
    }
    ResetStatistics();

   // LogFormat("[VEH] KernelCheatDetector initialized. Target: %s, OnlyMonitorGame: %d", m_targetGameProcess.c_str(), m_onlyMonitorGameProcess);
}

KernelCheatDetector::~KernelCheatDetector() {
}

void KernelCheatDetector::SetTargetGameProcess(const std::string& processName) {
    m_targetGameProcess = processName;
    std::transform(m_targetGameProcess.begin(), m_targetGameProcess.end(),
        m_targetGameProcess.begin(), ::tolower);
}

void KernelCheatDetector::SetOnlyMonitorGameProcess(bool enable) {
    m_onlyMonitorGameProcess = enable;
}

std::string KernelCheatDetector::GetProcessNameById(DWORD pid) {
    if (pid == 0 || pid == 4) return ""; // System processes

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return "";

    char processName[MAX_PATH] = { 0 };
    DWORD size = MAX_PATH;
    std::string result;

    if (QueryFullProcessImageNameA(hProcess, 0, processName, &size)) {
        result = processName;
    }

    CloseHandle(hProcess);
    return result;
}

bool KernelCheatDetector::IsProcessExcluded(const std::string& processName) {
    if (processName.empty()) return true;

    std::string lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    // Извлекаем только имя файла из пути
    size_t lastSlash = lowerName.find_last_of("\\/");
    if (lastSlash != std::string::npos) {
        lowerName = lowerName.substr(lastSlash + 1);
    }

    // Проверяем исключения
    for (const auto& excl : EXCLUDED_PROCESSES) {
        if (lowerName == excl) {
            return true;
        }
    }

    return false;
}

bool KernelCheatDetector::IsTargetGameProcess(DWORD pid) {
    std::string processPath = GetProcessNameById(pid);
    if (processPath.empty()) return false;

    return IsTargetGameProcess(processPath);
}

bool KernelCheatDetector::IsTargetGameProcess(const std::string& processName) {
    if (processName.empty()) return false;

    std::string lowerName = processName;
    std::transform(lowerName.begin(), lowerName.end(), lowerName.begin(), ::tolower);

    // Проверяем по имени файла
    size_t lastSlash = lowerName.find_last_of("\\/");
    std::string fileName = (lastSlash != std::string::npos) ?
        lowerName.substr(lastSlash + 1) : lowerName;

    // Проверяем, содержит ли имя файла целевой игровой процесс
    if (m_targetGameProcess.empty()) {
        return false;
    }

    return fileName.find(m_targetGameProcess) != std::string::npos;
}

bool KernelCheatDetector::ShouldMonitorProcess(DWORD pid) {

    if (!m_onlyMonitorGameProcess) {
        std::string processPath = GetProcessNameById(pid);
        return !IsProcessExcluded(processPath);
    }

    // Проверяем исключения
    std::string processPath = GetProcessNameById(pid);
    if (processPath.empty()) return false;

    if (IsProcessExcluded(processPath)) {
        return false;
    }

    // Мониторим только игровой процесс
    return IsTargetGameProcess(processPath);
}

uint64_t KernelCheatDetector::GetCurrentTimeMicroseconds() {
    if (m_highResTimer) {
        LARGE_INTEGER counter;
        if (QueryPerformanceCounter(&counter)) {
            return (counter.QuadPart * 1000000) / m_frequency.QuadPart;
        }
    }
    return GetTickCount64() * 1000;
}

void KernelCheatDetector::RecordTiming(const std::string& operation, double durationMicroseconds) {
    try {
        DWORD currentPid = GetCurrentProcessId();

        // Проверяем, нужно ли мониторить этот процесс
        if (!ShouldMonitorProcess(currentPid)) {
            return; // Не логируем для неигровых процессов
        }

        std::lock_guard<std::mutex> lock(m_timingMutex);

        TimingRecord record;
        record.timestamp = GetCurrentTimeMicroseconds();
        record.duration = durationMicroseconds;
        record.operation = operation;
        record.processId = currentPid;

        m_recentTimings.push_back(record);
        if (m_recentTimings.size() > MAX_RECORDS) {
            m_recentTimings.pop_front();
        }

        UpdateStatistics(operation, durationMicroseconds);
    }
    catch (...) {
        Log("[LOGEN] Exception in RecordTiming");
    }
}

void KernelCheatDetector::RecordFrameTiming(double frameTimeMicroseconds) {
    try {
        RecordTiming("FRAME_RENDER", frameTimeMicroseconds);
    }
    catch (...) {
        Log("[LOGEN] Exception in RecordFrameTiming");
    }
}
void KernelCheatDetector::CleanupOldOperationStats(uint64_t currentTimeMs) {
    try {
        // Если время не передано, получаем текущее
        if (currentTimeMs == 0) {
            currentTimeMs = GetCurrentTimeMicroseconds() / 1000; // конвертируем в мс
        }

        // Удаляем записи, которые не обновлялись последние 5 минут (300000 мс)
        uint64_t cutoffTime = currentTimeMs - 300000;
        uint64_t cutoffMicro = cutoffTime * 1000; // конвертируем в микросекунды для сравнения с lastUpdateTime

        std::lock_guard<std::mutex> lock(m_statsMutex);

        size_t beforeSize = m_operationStats.size();
        auto it = m_operationStats.begin();

        while (it != m_operationStats.end()) {
            // Удаляем, если:
            // 1. Нет данных (recentTimings пуст) ИЛИ
            // 2. Данные устарели (не обновлялись больше 5 минут)
            if (it->second.recentTimings.empty() ||
                it->second.lastUpdateTime < cutoffMicro) {

                // Логируем удаление в дебаг-режиме
#ifdef _DEBUG
                LogFormat("[LOGEN] KernelDetector: removing stale stats for '%s' (last update: %llu, cutoff: %llu)",
                    it->first.c_str(), it->second.lastUpdateTime, cutoffMicro);
#endif

                it = m_operationStats.erase(it);
            }
            else {
                ++it;
            }
        }

        // Логируем результат очистки (только если что-то удалили)
        size_t removedCount = beforeSize - m_operationStats.size();
        if (removedCount > 0) {
            LogFormat("[LOGEN] KernelDetector: cleaned up %zu old operation stats (remaining: %zu)", removedCount, m_operationStats.size());
        }
    }
    catch (const std::exception& e) {
        Log("[LOGEN] Exception in CleanupOldOperationStats: " + std::string(e.what()));
    }
    catch (...) {
        Log("[LOGEN] Unknown exception in CleanupOldOperationStats");
    }
}
void KernelCheatDetector::UpdateStatistics(const std::string& operation, double duration) {
    try {
        std::lock_guard<std::mutex> lock(m_statsMutex);

        auto& stats = m_operationStats[operation];
        stats.recentTimings.push_back(duration);

        // НОВАЯ СТРОКА - обновляем время последнего обновления
        stats.lastUpdateTime = GetCurrentTimeMicroseconds();

        if (stats.recentTimings.size() > STATS_WINDOW) {
            stats.recentTimings.pop_front();
        }

        if (!stats.recentTimings.empty()) {
            double sum = std::accumulate(stats.recentTimings.begin(),
                stats.recentTimings.end(), 0.0);
            stats.mean = sum / stats.recentTimings.size();

            auto minmax = std::minmax_element(stats.recentTimings.begin(),
                stats.recentTimings.end());
            stats.min = *minmax.first;
            stats.max = *minmax.second;

            stats.stddev = CalculateStdDev(stats.recentTimings, stats.mean);
            stats.count++;
        }
    }
    catch (...) {
        Log("[LOGEN] Exception in UpdateStatistics");
    }
}

double KernelCheatDetector::CalculateStdDev(const std::deque<double>& values, double mean) {
    try {
        if (values.size() < 2) return 0.0;
        double sumSquaredDiff = 0.0;
        for (double val : values) {
            double diff = val - mean;
            sumSquaredDiff += diff * diff;
        }
        return std::sqrt(sumSquaredDiff / values.size());
    }
    catch (...) {
        return 0.0;
    }
}

double KernelCheatDetector::CalculateCorrelation(const std::deque<double>& x, const std::deque<double>& y) {
    try {
        if (x.size() != y.size() || x.size() < 2) return 0.0;
        size_t n = x.size();
        double mean_x = std::accumulate(x.begin(), x.end(), 0.0) / n;
        double mean_y = std::accumulate(y.begin(), y.end(), 0.0) / n;
        double numerator = 0.0, denom_x = 0.0, denom_y = 0.0;
        for (size_t i = 0; i < n; ++i) {
            double dx = x[i] - mean_x;
            double dy = y[i] - mean_y;
            numerator += dx * dy;
            denom_x += dx * dx;
            denom_y += dy * dy;
        }
        if (denom_x == 0.0 || denom_y == 0.0) return 0.0;
        return numerator / std::sqrt(denom_x * denom_y);
    }
    catch (...) {
        return 0.0;
    }
}

bool KernelCheatDetector::CheckPatternConsistency(const std::deque<double>& timings) {
    try {
        if (timings.size() < 10) return false;
        double mean = std::accumulate(timings.begin(), timings.end(), 0.0) / timings.size();
        double stddev = CalculateStdDev(timings, mean);
        double cv = (mean > 0) ? (stddev / mean) : 0.0;
        return cv < 0.05;
    }
    catch (...) {
        return false;
    }
}

bool KernelCheatDetector::CheckHumanReactionTime(double duration) {
    return duration < HUMAN_REACTION_MIN;
}

bool KernelCheatDetector::DetectESPCheat() {
    try {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        auto it = m_operationStats.find("MEMORY_READ_ENTITY");
        if (it == m_operationStats.end()) return false;
        const auto& stats = it->second;
        if (stats.recentTimings.size() < 20) return false;

        bool isRegular = CheckPatternConsistency(stats.recentTimings);
        auto frameIt = m_operationStats.find("FRAME_RENDER");
        if (frameIt != m_operationStats.end()) {
            double correlation = CalculateCorrelation(stats.recentTimings, frameIt->second.recentTimings);
            if (isRegular && correlation > CORRELATION_THRESHOLD) {
                Log("[VEH] KERNEL ESP DETECTED: Correlation=" + std::to_string(correlation) + " Regularity=yes");
                StartSightImgDetection("[VEH] KERNEL ESP DETECTED: Correlation=" + std::to_string(correlation) + " Regularity=yes");
                return true;
            }
        }
        return false;
    }
    catch (...) {
        return false;
    }
}

bool KernelCheatDetector::DetectAimbotCheat() {
    try {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        auto readIt = m_operationStats.find("MEMORY_READ_POSITION");
        auto writeIt = m_operationStats.find("MEMORY_WRITE_ANGLES");
        if (readIt == m_operationStats.end() || writeIt == m_operationStats.end()) return false;
        const auto& readStats = readIt->second;
        const auto& writeStats = writeIt->second;
        if (readStats.recentTimings.size() < 10 || writeStats.recentTimings.size() < 10) return false;

        double totalTime = readStats.mean + writeStats.mean;
        if (totalTime > 10000.0) return false;

        double correlation = CalculateCorrelation(readStats.recentTimings, writeStats.recentTimings);
        if (correlation > 0.6 && totalTime < 5000.0) {
            Log("[VEH] KERNEL AIMBOT DETECTED: Total time=" + std::to_string(totalTime) + "μs Correlation=" + std::to_string(correlation));
            StartSightImgDetection("[VEH] KERNEL AIMBOT DETECTED: Total time=" + std::to_string(totalTime) + "μs Correlation=" + std::to_string(correlation));
            return true;
        }
        return false;
    }
    catch (...) {
        return false;
    }
}

bool KernelCheatDetector::DetectTriggerbotCheat() {
    try {
        auto it = m_operationStats.find("TRIGGER_CHECK");
        if (it == m_operationStats.end()) return false;
        const auto& stats = it->second;
        if (stats.recentTimings.empty()) return false;

        double avgTime = stats.mean;
        if (avgTime < 1000.0) {
            bool isTooRegular = CheckPatternConsistency(stats.recentTimings);
            if (isTooRegular) {
                Log("[VEH] KERNEL TRIGGERBOT DETECTED: Avg time=" + std::to_string(avgTime) + "μs");
                StartSightImgDetection("[VEH] KERNEL TRIGGERBOT DETECTED: Avg time=" + std::to_string(avgTime) + "μs");
                return true;
            }
        }
        return false;
    }
    catch (...) {
        return false;
    }
}

bool KernelCheatDetector::DetectDMACheat() {
    try {
        std::vector<std::string> memoryOps = { "MEMORY_READ_ENTITY", "MEMORY_READ_POSITION", "MEMORY_READ_HEALTH" };
        for (const auto& op : memoryOps) {
            auto it = m_operationStats.find(op);
            if (it == m_operationStats.end()) continue;
            const auto& stats = it->second;
            if (stats.recentTimings.size() < 30) continue;

            uint64_t now = GetCurrentTimeMicroseconds();
            int burstCount = 0;
            for (const auto& timing : m_recentTimings) {
                if (timing.operation == op && (now - timing.timestamp) < 100000) burstCount++;
            }

            double cv = (stats.mean > 0) ? (stats.stddev / stats.mean) : 0.0;
            if (burstCount > 50 && cv < 0.02) {
                Log("[VEH] KERNEL DMA SUSPECTED: Op=" + op + " Burst=" + std::to_string(burstCount) + " CV=" + std::to_string(cv));
                StartSightImgDetection("[VEH] KERNEL DMA SUSPECTED: Op=" + op + " Burst=" + std::to_string(burstCount) + " CV=" + std::to_string(cv));
                return true;
            }
        }
        return false;
    }
    catch (...) {
        return false;
    }
}

KernelCheatDetector::CheatPattern KernelCheatDetector::AnalyzePatterns() {
    try {
        // Проверяем, находимся ли в игровом процессе
        DWORD currentPid = GetCurrentProcessId();
        if (!ShouldMonitorProcess(currentPid)) {
            return PATTERN_NONE;
        }

        if (DetectTriggerbotCheat()) return PATTERN_SUB_HUMAN;
        if (DetectAimbotCheat()) return PATTERN_READ_COMPUTE_WRITE;
        if (DetectESPCheat()) return PATTERN_REGULAR_READ;
        if (DetectDMACheat()) return PATTERN_DMA_BURST;

        std::lock_guard<std::mutex> lock(m_statsMutex);
        for (const auto& item : m_operationStats) {
            const auto& stats = item.second;
            if (stats.recentTimings.size() < 10) continue;
            if (stats.mean >= SUSPICIOUS_DELAY_MIN && stats.mean <= SUSPICIOUS_DELAY_MAX) {
                if (CheckPatternConsistency(stats.recentTimings)) {
                    return PATTERN_KERNEL_DELAY;
                }
            }
        }
    }
    catch (...) {
        Log("[LOGEN] Exception in AnalyzePatterns");
    }
    return PATTERN_NONE;
}

void KernelCheatDetector::ResetStatistics() {
    try {
        std::lock_guard<std::mutex> lock1(m_timingMutex);
        std::lock_guard<std::mutex> lock2(m_statsMutex);
        m_recentTimings.clear();
        m_operationStats.clear();
    }
    catch (...) {
        Log("[LOGEN] Exception in ResetStatistics");
    }
}

bool KernelCheatDetector::DetectKernelDriverCheat() {
    try {
        std::vector<std::pair<std::string, double>> kernelOps;
        {
            std::lock_guard<std::mutex> lock(m_statsMutex);
            for (const auto& item : m_operationStats) {
                if (item.second.mean >= SUSPICIOUS_DELAY_MIN && item.second.mean <= SUSPICIOUS_DELAY_MAX) {
                    kernelOps.emplace_back(item.first, item.second.mean);
                }
            }
        }

        if (!kernelOps.empty()) {
            int regularDelays = 0;
            for (const auto& op : kernelOps) {
                auto it = m_operationStats.find(op.first);
                if (it != m_operationStats.end() && CheckPatternConsistency(it->second.recentTimings)) {
                    regularDelays++;
                }
            }

            if (regularDelays >= 2) {
                std::vector<std::string> opNames;
                for (const auto& op : kernelOps) opNames.push_back(op.first);
                for (size_t i = 0; i < opNames.size(); i++) {
                    for (size_t j = i + 1; j < opNames.size(); j++) {
                        auto it1 = m_operationStats.find(opNames[i]);
                        auto it2 = m_operationStats.find(opNames[j]);
                        if (it1 != m_operationStats.end() && it2 != m_operationStats.end()) {
                            double corr = CalculateCorrelation(it1->second.recentTimings, it2->second.recentTimings);
                            if (corr > 0.8) {
                                Log("[VEH] KERNEL DRIVER SUSPECTED: Sync delays between " + opNames[i] + " and " + opNames[j] + " Corr=" + std::to_string(corr));
                                StartSightImgDetection("[VEH] KERNEL DRIVER SUSPECTED: Sync delays between " + opNames[i] + " and " + opNames[j] + " Corr=" + std::to_string(corr));
                                return true;
                            }
                        }
                    }
                }
            }
        }
        return false;
    }
    catch (...) {
        return false;
    }
}

bool KernelCheatDetector::DetectTimingCheat() {
    try {
        std::lock_guard<std::mutex> lock(m_statsMutex);
        for (const auto& item : m_operationStats) {
            const auto& stats = item.second;
            if (stats.recentTimings.size() < 30) continue;

            std::vector<double> sortedTimes(stats.recentTimings.begin(), stats.recentTimings.end());
            std::sort(sortedTimes.begin(), sortedTimes.end());
            size_t q25_idx = sortedTimes.size() * 0.25;
            size_t q75_idx = sortedTimes.size() * 0.75;
            if (q25_idx >= sortedTimes.size() || q75_idx >= sortedTimes.size()) continue;

            double q25 = sortedTimes[q25_idx];
            double q75 = sortedTimes[q75_idx];
            double iqr = q75 - q25;

            if (iqr > 0 && (stats.stddev / iqr) < 0.1) {
                double cv = (stats.mean > 0) ? (stats.stddev / stats.mean) : 0.0;
                if (cv < 0.02) {
                    Log("[VEH] KERNEL TIMING ATTACK SUSPECTED: " + item.first + " CV=" + std::to_string(cv));
                    StartSightImgDetection("[VEH] KERNEL TIMING ATTACK SUSPECTED: " + item.first + " CV=" + std::to_string(cv));
                    return true;
                }
            }
        }
        return false;
    }
    catch (...) {
        return false;
    }
}

bool KernelCheatDetector::DetectMemoryPatternCheat() {
    try {
        std::lock_guard<std::mutex> lock(m_timingMutex);
        if (m_recentTimings.size() < 50) return false;

        std::vector<std::string> sequence;
        for (const auto& record : m_recentTimings) {
            if (sequence.size() < 10) sequence.push_back(record.operation);
        }

        auto CheckPattern = [&](const std::vector<std::string>& pattern) -> bool {
            if (sequence.size() < pattern.size()) return false;
            for (size_t i = 0; i <= sequence.size() - pattern.size(); i++) {
                bool match = true;
                for (size_t j = 0; j < pattern.size(); j++) {
                    if (sequence[i + j].find(pattern[j]) == std::string::npos) {
                        match = false;
                        break;
                    }
                }
                if (match) return true;
            }
            return false;
            };

        if (CheckPattern({ "MEMORY_READ_POSITION", "MEMORY_READ_POSITION", "MEMORY_READ_POSITION" })) {
            Log("[VEH] KERNEL ESP PATTERN DETECTED: Regular position reads");
            StartSightImgDetection("[VEH] KERNEL ESP PATTERN DETECTED: Regular position reads");
            return true;
        }

        for (size_t i = 0; i < m_recentTimings.size() - 1; i++) {
            if (m_recentTimings[i].operation.find("READ_POSITION") != std::string::npos &&
                m_recentTimings[i + 1].operation.find("WRITE_ANGLES") != std::string::npos) {
                double timeBetween = m_recentTimings[i + 1].timestamp - m_recentTimings[i].timestamp;
                if (timeBetween < 1000.0) {
                    Log("[VEH] KERNEL AIMBOT PATTERN: Read->Write in " + std::to_string(timeBetween) + "μs");
                    StartSightImgDetection("[VEH] KERNEL AIMBOT PATTERN: Read->Write in " + std::to_string(timeBetween) + "μs");
                    return true;
                }
            }
        }

        return false;
    }
    catch (...) {
        return false;
    }
}

void KernelCheatDetector::AnalyzeAdvancedPatterns() {
    try {
        DWORD currentPid = GetCurrentProcessId();
        if (!ShouldMonitorProcess(currentPid)) {
            return;
        }

        bool espDetected = DetectESPCheat();
        bool aimbotDetected = DetectAimbotCheat();
        bool triggerDetected = DetectTriggerbotCheat();
        bool dmaDetected = DetectDMACheat();
        bool kernelDetected = DetectKernelDriverCheat();
        bool timingDetected = DetectTimingCheat();
        bool patternDetected = DetectMemoryPatternCheat();

        int cheatScore = 0;
        CheatPattern detectedPattern = PATTERN_NONE;

        if (espDetected) {
            cheatScore += 30;
            detectedPattern = PATTERN_REGULAR_READ;
        }
        if (aimbotDetected) {
            cheatScore += 40;
            detectedPattern = PATTERN_READ_COMPUTE_WRITE;
        }
        if (triggerDetected) {
            cheatScore += 50;
            detectedPattern = PATTERN_SUB_HUMAN;
        }
        if (dmaDetected) {
            cheatScore += 60;
            detectedPattern = PATTERN_DMA_BURST;
        }
        if (kernelDetected) {
            cheatScore += 70;
            detectedPattern = PATTERN_KERNEL_DELAY;
        }
        if (timingDetected) cheatScore += 20;
        if (patternDetected) cheatScore += 30;

        // Добавляем в агрегатор при любом обнаружении
        if (cheatScore > 0 && detectedPattern != PATTERN_NONE) {
            g_totalDetections++;

            char processName[MAX_PATH] = { 0 };
            GetModuleBaseNameA(GetCurrentProcess(), NULL, processName, MAX_PATH);
            std::string exeName = processName;

            double confidence = CalculateDetectionConfidence(detectedPattern);
            g_detectionAggregator.AddDetection(detectedPattern, currentPid, exeName, confidence);
        }

        if (cheatScore > 50) {
            Log("[VEH] KERNEL HIGH CHEAT PROBABILITY: Score " + std::to_string(cheatScore) + "/300");
            StartSightImgDetection("[VEH] KERNEL HIGH CHEAT PROBABILITY: Score " + std::to_string(cheatScore) + "/300");

            if (cheatScore > 100) {
                Log("[VEH] KERNEL CHEAT CONFIRMED - Score threshold exceeded");
                StartSightImgDetection("[VEH] KERNEL CHEAT CONFIRMED - Score threshold exceeded");
            }
        }
    }
    catch (...) {
        Log("[LOGEN] Exception in AnalyzeAdvancedPatterns");
    }
}

KernelCheatDetector::CheatPattern KernelCheatDetector::AnalyzePatternsForProcess(DWORD pid) {
    try {
        // Проверяем, нужно ли анализировать этот процесс
        if (!ShouldMonitorProcess(pid)) {
            return PATTERN_NONE;
        }

        // Используем стандартный анализ, так как тайминги уже фильтруются по процессу
        return AnalyzePatterns();
    }
    catch (...) {
        Log("[LOGEN] Exception in AnalyzePatternsForProcess");
        return PATTERN_NONE;
    }
}