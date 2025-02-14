#!/usr/bin/env -S python -u

'''
Copyright 2009, The Android Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

# Script to highlight adb logcat output for console
# Originally written by Jeff Sharkey, http://jsharkey.org/
# Piping detection and popen() added by other Android team members
# Package filtering and output improvements by Jake Wharton, http://jakewharton.com

import argparse
import os
import signal
import sys
import re
import textwrap
import subprocess
from datetime import datetime
from subprocess import PIPE

__version__ = '3.1.1'

LOG_LEVELS = 'VDIWEF'
LOG_LEVELS_MAP = dict([(LOG_LEVELS[i], i) for i in range(len(LOG_LEVELS))])
BUFFER = ['radio', 'events', 'main', 'system', 'crash', 'all', 'default', 'kernel', 'security']
formatter = lambda prog: argparse.HelpFormatter(prog,max_help_position=60)
parser = argparse.ArgumentParser(formatter_class=formatter,description='Advanced ADB logcat filter')
#parser = argparse.ArgumentParser(description='Filter logcat by package name')
parser.add_argument('package', nargs='*', help='Application package name(s)')
parser.add_argument('-w', '--tag-width', metavar='N', dest='tag_width', type=int, default=20, help='Width of log tag')
parser.add_argument('-l', '--min-level', dest='min_level', type=str, choices=LOG_LEVELS, default='V', help='Minimum log level to be displayed')
parser.add_argument('--color-gc', dest='color_gc', action='store_true', help='Color garbage collection')
parser.add_argument('--always-display-tags', dest='always_tags', action='store_true', help='Always display the tag name')
parser.add_argument('--current', dest='current_app', action='store_true',help='Filter logcat by current running app')
parser.add_argument('-s', '--serial', dest='device_serial', help='Device serial number (adb -s option)')
parser.add_argument('-d', '--device', dest='use_device', action='store_true', help='Use first device for log input (adb -d option)')
parser.add_argument('-e', '--emulator', dest='use_emulator', action='store_true', help='Use first emulator for log input (adb -e option)')
parser.add_argument('-c', '--clear', dest='clear_logcat', action='store_true', help='Clear the entire log before running')
parser.add_argument('-t', '--tag', dest='tag', metavar='TAG', action='append', type=str, help='Filter output by specified tag(s)')
parser.add_argument('--ignore-tag', dest='ignored_tag', metavar='TAG', action='append', type=str, help='Filter output by ignoring specified tag(s)')
parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__, help='Print the version number and exit')
parser.add_argument('-a', '--all', dest='all', action='store_true', default=False, help='Print all log messages')
parser.add_argument('-r', '--regex', dest='regex', type=str, action='append', help='Print REGEX matches')
parser.add_argument('--ignore-regex', dest='ignore_regex', metavar='REGEX', type=str, action='append', help='Don\'t print REGEX matches')
parser.add_argument('--time', dest='time', action='store_true', default=False, help='Show timestamps')
parser.add_argument('--exclude-level', choices=LOG_LEVELS, dest='exclude_level', type=str, help='Exclude specific log level(s)')
parser.add_argument('--include-level', choices=LOG_LEVELS, dest='include_level', type=str, default='VDIWEF', help='Show specific log level(s)')
parser.add_argument('--buffer', dest='buffer', choices=BUFFER, type=str, default='all', help='Select alternative logcat buffers')
parser.add_argument('--tid', dest='tid', action='store_true', help='Show thread IDs (TID)')

args = parser.parse_args()

if args.min_level:
  min_level = LOG_LEVELS_MAP[args.min_level.upper()]
if args.exclude_level:
  exc_level = "".join(dict.fromkeys(re.sub('[^VDIWEF]', '', args.exclude_level.upper())))
  min_level = LOG_LEVELS_MAP["V"]
if args.include_level:
  inc_level = "".join(dict.fromkeys(re.sub('[^VDIWEF]', '', args.include_level.upper())))
  min_level = LOG_LEVELS_MAP["V"]

package = args.package

base_adb_command = ['adb']
if args.device_serial:
  base_adb_command.extend(['-s', args.device_serial])
if args.use_device:
  base_adb_command.append('-d')
if args.use_emulator:
  base_adb_command.append('-e')

if args.current_app:
  system_dump_command = base_adb_command + ["shell", "dumpsys", "activity", "activities"]
  system_dump = subprocess.Popen(system_dump_command, stdout=PIPE, stderr=PIPE).communicate()[0]
  pattern_match = b"visibleRequested=true"
  running_package_name = None
  for line in system_dump.splitlines():
    if pattern_match in line:
      running_package_name = line
  #print(running_package_name)
  running_package_name = re.search(".*Task.*(A|I)[= ][^:]*.([^ ^}]*)", str(running_package_name)).group(2)
  #print(running_package_name)
  package.append(running_package_name)

if len(package) == 0:
  args.all = True

# Store the names of packages for which to match all processes.
catchall_package = list(filter(lambda package: package.find(":") == -1, package))
# Store the name of processes to match exactly.
named_processes = list(filter(lambda package: package.find(":") != -1, package))
# Convert default process names from <package>: (cli notation) to <package> (android notation) in the exact names match group.
named_processes = map(lambda package: package if package.find(":") != len(package) - 1 else package[:-1], named_processes)

tag_width = args.tag_width

header_size = tag_width + 1 + 3 + 1 # space, level, space
header_size += 1 + 1 + 5 + 1 + 1 # space, colored space, 5 digit tid, colored space, space
if args.time == True:
  header_size += 6 + 1 + 12 + 1 # time, space

stdout_isatty = sys.stdout.isatty()

width = -1
try:
  # Get the current terminal width
  #import fcntl, termios, struct
  #h, width = struct.unpack('hh', fcntl.ioctl(0, termios.TIOCGWINSZ, struct.pack('hh', 0, 0)))
  width, h = os.get_terminal_size()
except:
  pass

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

RESET = '\033[0m'

def termcolor(fg=None, bg=None):
  codes = []
  if fg is not None: codes.append('3%d' % fg)
  if bg is not None: codes.append('10%d' % bg)
  return '\033[%sm' % ';'.join(codes) if codes else ''

def colorize(message, fg=None, bg=None):
  return termcolor(fg, bg) + message + RESET if stdout_isatty else message

def indent_wrap(message):
  if width == -1:
    return message
  message = message.replace('\t', '    ')
  wrap_area = width - header_size
  messagebuf = ''
  lines = textwrap.wrap(message, wrap_area)
  messagebuf += textwrap.dedent(lines[0])
  for line in lines[1:]:
  #for line in lines:
    messagebuf += '\n'
    messagebuf += ' ' * header_size + textwrap.dedent(line)
  return messagebuf

def indent_wrap_proc(message):
  if width == -1:
    return message
  message = message.replace('\t', '    ')
  wrap_area = width - header_size
  messagebuf = ''
  if len(message) > wrap_area:
    messagebuf += '\n'.join(map(lambda x : x.rjust(width), textwrap.wrap(message, width)))
  else:
    messagebuf += ' ' * header_size + textwrap.dedent(message)
  return messagebuf

LAST_USED = [RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN]
KNOWN_TAGS = {
  'dalvikvm': WHITE,
  'Process': WHITE,
  'ActivityManager': WHITE,
  'ActivityThread': WHITE,
  'AndroidRuntime': CYAN,
  'jdwp': WHITE,
  'StrictMode': WHITE,
  'DEBUG': YELLOW,
}

def allocate_color(tag):
  # this will allocate a unique format for the given tag
  # since we dont have very many colors, we always keep track of the LRU
  if tag not in KNOWN_TAGS:
    KNOWN_TAGS[tag] = LAST_USED[0]
  color = KNOWN_TAGS[tag]
  if color in LAST_USED:
    LAST_USED.remove(color)
    LAST_USED.append(color)
  return color

RULES = {
  # StrictMode policy violation; ~duration=319 ms: android.os.StrictMode$StrictModeDiskWriteViolation: policy=31 violation=1
  re.compile(r'^(StrictMode policy violation)(; ~duration=)(\d+ ms)')
    : r'%s\1%s\2%s\3%s' % (termcolor(RED), RESET, termcolor(YELLOW), RESET),
}

# Only enable GC coloring if the user opted-in
if args.color_gc:
  # GC_CONCURRENT freed 3617K, 29% free 20525K/28648K, paused 4ms+5ms, total 85ms
  key = re.compile(r'^(GC_(?:CONCURRENT|FOR_M?ALLOC|EXTERNAL_ALLOC|EXPLICIT) )(freed <?\d+.)(, \d+\% free \d+./\d+., )(paused \d+ms(?:\+\d+ms)?)')
  val = r'\1%s\2%s\3%s\4%s' % (termcolor(GREEN), RESET, termcolor(YELLOW), RESET)

  RULES[key] = val

TAGTYPES = {
  'V': colorize(' V ', fg=WHITE, bg=BLACK),
  'D': colorize(' D ', fg=WHITE, bg=BLUE),
  'I': colorize(' I ', fg=BLACK, bg=GREEN),
  'W': colorize(' W ', fg=BLACK, bg=YELLOW),
  'E': colorize(' E ', fg=WHITE, bg=RED),
  'F': colorize(' F ', fg=WHITE, bg=RED),
}

PID_LINE = re.compile(r'^.*\w+\s+(\w+)\s+\w+\s+\w+\s+\w+\s+\w+\s+\w+\s+\w\s([\w|\.|\/]+)$')
PID_START = re.compile(r'^.*: Start proc ([a-zA-Z0-9._:]+) for ([a-z]+ [^:]+): pid=(\d+) uid=(\d+) gids=(.*)$')
PID_START_5_1 = re.compile(r'^.*: Start proc (\d+):([a-zA-Z0-9._:]+)/([a-z0-9]+) for (.*) .*/(.*)\}$')
PID_START_DALVIK = re.compile(r'^.*E/dalvikvm\(\s*(\d+)\): >>>>> ([a-zA-Z0-9._:]+) \[ userId:0 \| appId:(\d+) \]$')
PID_KILL  = re.compile(r'^.*Killing (\d+):([a-zA-Z0-9._:]+).*$')
PID_LEAVE = re.compile(r'^.*No longer want ([a-zA-Z0-9._:]+) \(pid (\d+)\): .*$')
PID_DEATH = re.compile(r'^.*Process ([a-zA-Z0-9._:]+) \(pid (\d+)\) has died.?$')
#LOG_LINE  = re.compile(r'^.*[0-9-]+ ([0-9:.]+) ([A-Z])/(.+?)\( *(\d+)\): (.*?)$')
LOG_LINE_PREFIX = r'^(\d+-\d+\s+\d+:\d+:\d+\.\d+)\s+(\d+)\s+(\d+)\s+?'
LOG_LINE  = re.compile(LOG_LINE_PREFIX + r'([A-Z])\s+(.+?): (.*?)$')
BUG_LINE  = re.compile(r'.*nativeGetEnabledTags.*')
BACKTRACE_LINE = re.compile(r'^.*#(.*?)pc\s(.*?)$')
UID_KILL  = re.compile(r'^.*libprocessgroup.*uid (\d+).*pid (\d+).* (\d+ms)$')

adb_command = base_adb_command[:]
adb_command.append('logcat')
adb_command.extend(['-v', 'threadtime'])
if args.regex:
  regexx = []
  for item in args.regex:
    regexx.extend(item.split())
  regexx = "|".join(regexx)
  adb_command.extend(['--regex', regexx])
adb_command.extend(['--buffer', args.buffer])

# Clear log before starting logcat
if args.clear_logcat:
  adb_clear_command = list(adb_command)
  adb_clear_command.append('-c')
  adb_clear = subprocess.Popen(adb_clear_command)

  while adb_clear.poll() is None:
    pass

# This is a ducktype of the subprocess.Popen object
class FakeStdinProcess():
  def __init__(self):
    self.stdout = sys.stdin
  def poll(self):
    return None

if sys.stdin.isatty():
  adb = subprocess.Popen(adb_command, stdin=PIPE, stdout=PIPE, stderr=PIPE)
else:
  adb = FakeStdinProcess()
pids = set()
last_tag = None
last_tid = None
app_pid = None
tid_color_dict = {}

def match_packages(token):
  if len(package) == 0:
    return True
  if token in named_processes:
    return True
  index = token.find(':')
  return (token in catchall_package) if index == -1 else (token[:index] in catchall_package)

def parse_death_activity_mgr(tag, message):
  if tag == 'ActivityManager':
    #return None, None
    kill = PID_KILL.match(message)
    if kill:
      pid = kill.group(1)
      package_line = kill.group(2)
      if match_packages(package_line) and pid in pids:
        return pid, package_line
    leave = PID_LEAVE.match(message)
    if leave:
      pid = leave.group(2)
      package_line = leave.group(1)
      if match_packages(package_line) and pid in pids:
        return pid, package_line
    death = PID_DEATH.match(message)
    if death:
      pid = death.group(2)
      package_line = death.group(1)
      if match_packages(package_line) and pid in pids:
        return pid, package_line
  return None, None

def parse_death_libprocess_grp(tag, message):
  if tag == 'libprocessgroup':
    #return None, None
    kill = UID_KILL.match(message)
    if kill:
      uid = kill.group(1)
      pid = kill.group(2)
      time = kill.group(3)
  return None, None, None

def parse_start_proc(line):
  start = PID_START_5_1.match(line)
  if start is not None:
    line_pid, line_package, line_uid, type, target = start.groups()
    return line_package, target, line_pid, line_uid, type
  start = PID_START.match(line)
  if start is not None:
    line_package, target, line_pid, line_uid, line_gids = start.groups()
    return line_package, target, line_pid, line_uid, line_gids
  start = PID_START_DALVIK.match(line)
  if start is not None:
    line_pid, line_package, line_uid = start.groups()
    return line_package, '', line_pid, line_uid, ''
  return None

def tag_in_tags_regex(tag, tags):
  return any(re.match(r'^' + t + r'$', tag) for t in map(str.strip, tags))

ps_command = base_adb_command + ['shell', 'ps']
ps_pid = subprocess.Popen(ps_command, stdin=PIPE, stdout=PIPE, stderr=PIPE)

# suppresses tracebacks on script termination
def interuppt_handler(signum, frame):
  sys.exit(-2)
signal.signal(signal.SIGINT, interuppt_handler)

while True:
  try:
    line = ps_pid.stdout.readline().decode('utf-8', 'replace').strip()
  except (KeyboardInterrupt, SystemExit):
    break
  if len(line) == 0:
    break

  pid_match = PID_LINE.match(line)
  if pid_match is not None:
    pid = pid_match.group(1)
    proc = pid_match.group(2)
    if proc in catchall_package:
      seen_pids = True
      pids.add(pid)

while adb.poll() is None:
  try:
    #exclude_pattern = r'\s+([i])\s+'
    line = adb.stdout.readline().decode('utf-8', 'replace').strip()
  except (KeyboardInterrupt, SystemExit):
    break
  if len(line) == 0:
    break

  bug_line = BUG_LINE.match(line)
  if bug_line is not None:
    continue

  log_line = LOG_LINE.match(line)
  if log_line is None:
    continue

  time, owner, tid, level, tag, message = log_line.groups()
  tag = tag.strip()
  start = parse_start_proc(line)
  if start:
    line_package, target, line_pid, line_uid, line_gids = start
    if match_packages(line_package):
      pids.add(line_pid)

      app_pid = line_pid

      proc_header_left = ' PROCESS CREATED!'
      proc_header_right = '%s :TYPE' % (line_gids)
      proc_header_left_length = len(proc_header_left)
      proc_header_right_length = len(proc_header_right)
      proc_header_mid_length = header_size - proc_header_left_length - proc_header_right_length
      proc_body_left = '%s' % (line_package)
      proc_body_left_length = len(proc_body_left)
      proc_body_right = '%s' % (target)
      proc_footer_left = ' PID: %s' % (line_pid)
      proc_footer_left_length = len(proc_footer_left)
      proc_footer_right = '%s :USER ' % (line_uid)
      proc_footer_right_length = len(proc_footer_right)
      proc_footer_mid_length = header_size - proc_footer_left_length - proc_footer_right_length
      linebuf  = '\n'
      linebuf += colorize('%s' % proc_header_left, fg=BLACK, bg=WHITE)
      linebuf += colorize(' ' * (proc_header_mid_length - 2), bg=WHITE)
      linebuf += colorize('%s' % (line_gids.upper()), fg=RED, bg=WHITE)
      linebuf += colorize(' :TYPE ', fg=BLACK, bg=WHITE)
      #linebuf += '\n'
      linebuf += ' '
      linebuf += indent_wrap(proc_body_left)
      linebuf += '\n'
      linebuf += colorize(' PID: ', fg=BLACK, bg=WHITE)
      linebuf += colorize('%s' % line_pid, fg=RED, bg=WHITE)
      linebuf += colorize(' ' * (proc_footer_mid_length - 1), bg=WHITE)
      linebuf += colorize('%s' % line_uid, fg=RED, bg=WHITE)
      linebuf += colorize(' :USER ', fg=BLACK, bg=WHITE)
      linebuf += ' '
      linebuf += indent_wrap(proc_body_right)
      linebuf += '\n'
      print(linebuf)
      # Ensure next log gets a tag/tid printed
      last_tag = None 
      last_tid = None
      tid_color_dict = {}

  dead_pid, dead_pname = parse_death_activity_mgr(tag, message)
  if dead_pid:
    pids.remove(dead_pid)
    dead_header = ' PROCESS ENDED:'
    dead_header_length = len(dead_header)
    dead_footer = 'PID: %s ' % (dead_pid)
    dead_footer_length = len(dead_footer)
    linebuf  = '\n'
    #linebuf += colorize(' ' * (header_size - 1), bg=RED)
    linebuf += colorize(' PROCESS ENDED!', fg=WHITE, bg=RED)
    linebuf += colorize(' ' * (header_size - dead_header_length - dead_footer_length - 1), bg=RED)
    linebuf += colorize('%s' % (dead_footer), fg=WHITE, bg=RED)
    #linebuf += '\n'
    linebuf += ' '
    linebuf += indent_wrap('%s' % (dead_pname))
    linebuf += '\n'
    #linebuf += colorize('%s' % (dead_footer), fg=WHITE, bg=RED)
    #linebuf += colorize(' ' * (header_size - dead_footer_length - 1), bg=RED)
    #linebuf += '\n'
    print(linebuf)
    # Ensure next log gets a tag/tid printed
    last_tag = None 
    last_tid = None
    tid_color_dict = {}

  # Make sure the backtrace is printed after a native crash
  if tag == 'DEBUG':
    bt_line = BACKTRACE_LINE.match(message.lstrip())
    if bt_line is not None:
      message = message.lstrip()
      owner = app_pid

  if not args.all and owner not in pids:
    continue
  if level in LOG_LEVELS_MAP and LOG_LEVELS_MAP[level] <= min_level:
    continue
  if args.ignored_tag and tag_in_tags_regex(tag, args.ignored_tag):
    continue
  if args.tag and not tag_in_tags_regex(tag, args.tag):
    continue
  
  linebuf = ''

  
  if args.tid:
    tid_space_dict = {1:5,2:4,3:3,4:2,5:1} # assuming 5 digits
    # [1:RED, 2:GREEN, 3:YELLOW, 4:BLUE, 5:MAGENTA, 6:CYAN]
    tid_fg = {1:BLACK, 2:BLACK, 3:BLACK, 4:WHITE, 5:WHITE, 6:BLACK}
    last_tid = tid
    tid_length = len(tid)
    color = allocate_color(tid)
    linebuf += colorize(' %s ' % (tid), fg=tid_fg[color], bg=color)
    linebuf += ' ' * tid_space_dict[tid_length]
    linebuf += ' '

  if tag_width > 0:
    # right-align tag title and allocate color if needed
    if tag != last_tag or args.always_tags:
      last_tag = tag
      color = allocate_color(tag)
      tag = tag[-tag_width:].rjust(tag_width)
      linebuf += colorize(tag, fg=color)
    else:
      linebuf += ' ' * tag_width
    linebuf += ' '

  # write out level colored edge
  if level in TAGTYPES:
    linebuf += TAGTYPES[level]
  else:
    linebuf += ' ' + level + ' '
  linebuf += ' '

  if args.time == True:
    time = datetime.strptime(time, '%m-%d %H:%M:%S.%f')
    linebuf = datetime.strftime(time, '%d-%b %H:%M:%S.%f')[:-3] + ' ' + linebuf

  # format tag message using rules
  for matcher in RULES:
    replace = RULES[matcher]
    message = matcher.sub(replace, message)

  linebuf += indent_wrap(message)

  if args.exclude_level:
    if level in exc_level:
      continue
    else:
      print(linebuf)
  if args.include_level:
    if level in inc_level:
      print(linebuf)
    else:
      continue

  #print(linebuf)
  