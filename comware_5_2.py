#!/usr/bin/python
#coding: utf-8 -*-

#
# (c) 2014, Patrick Galbraith <patg@patg.net>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import re
import paramiko
import os
from collections import OrderedDict


cmd_line_mode = "_cmdline-mode on\n"
cmd_quit = "quit\n"
cmd_disable_paging = "screen-length disable\n"
cmd_yes = "Y\n"
cmd_no = "N\n"
cmd_line_mode_resp = "%s512900\n" % cmd_yes
cmd_summary = "summary\n"
cmd_save = "save\n"
cmd_system_view = "system-view\n"
cmd_current_config = "display current-configuration\n"
cmd_reboot = "reboot\n"
cmd_display_vlan_all = "display vlan all\n"

verify_save_current_conf = \
    'Current configuration will be lost, save current configuration'
verify_filename = 'Please input the file name'
verify_filename_unchanged = 'To leave existing filename unchanged'
verify_config_file_saved = 'Configuration is saved to device successfully'
verify_reboot = 'This command will reboot the device'

top_level_prompt = "<HP>"
sys_prompt = '[HP]'


class Comware_5_2(object):
    def __init__(self,
                 module,
                 host,
                 username,
                 password,
                 timeout,
                 port=22,
                 private_key_file=None):
        self.module = module
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.private_key_file = private_key_file
        self.timeout = timeout
        self._failed = False
        self._changed = False
        self._message = ""
        self._developer_mode_set = False
        self._system_view = False
        self._top_level_view = False
        self._paging_disabled = False

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if self.private_key_file is not None:
            self.keyfile = os.path.expanduser("~/.ssh/known_hosts")
            key_filename = os.path.expanduser(self.private_key_file)
        else:
            key_filename = None

        # TODO: get ansible constants working
        #C.HOST_KEY_CHECKING:
        if True:
            ssh.load_system_host_keys()

        allow_agent = True
        if self.password is not None:
            allow_agent = False

        try:
            ssh.connect(self.host,
                        username=self.username,
                        password=self.password,
                        key_filename=key_filename,
                        allow_agent=allow_agent,
                        look_for_keys=False,
                        timeout=self.timeout)
        # TODO: more specific error-handling (?)
        except Exception, e:
            message = "%s %s" % (e.__class__, e)
            self.fail(message)

        self._top_level_view = True

        self.ssh = ssh
        try:
            self.channel = ssh.invoke_shell()
        except Exception, e:
            message = "%s %s" % (e.__class__, e)
            self.fail(message)

        self.channel.settimeout(self.timeout)

    def get_failed(self):
        return self._failed

    def get_changed(self):
        return self._changed

    def get_message(self):
        return self._message

    def set_failed(self, state):
        self._failed = state

    def set_changed(self, state):
        self._changed = state

    def set_message(self, message):
        self._message = message

    def append_message(self, message):
        self._message += message

    def fail(self, message=''):
        self.set_failed(True)
        self.set_message(message)
        self.module.fail_json(msg=self.get_message())

    def _developer_mode(self):
        error_message = "ERROR: Unable to switch to developer mode"
        self._send_command(cmd_line_mode, error_message)
        error_message = "ERROR: Unable to send dev mode password"
        self._send_command(cmd_line_mode_resp, error_message)
        self._developer_mode_set = True

    def _send_command(self, command, msg=""):
        try:
            self.channel.send(command)
        except Exception, e:
            msg = msg + "%s %s" % (e.__class__, e)
            self.fail(msg)

    def _exec_command(self, command, msg=""):
        try:
            self.channel.send(command)
        except Exception, e:
            msg = msg + "%s %s" % (e.__class__, e)
            self.fail(msg)

        output_list = self._get_output_list()
        for line in output_list:
            m = re.match('^\s\%\s(.*)$', line)
            if m and m.group(1):
                message = msg + ". Switch ERROR: command %s failed with %s" %\
                    (command, m.group(1))
                self.fail(message)

    def save(self):
        cmd_confirm = cmd_no
        if self.module.params.get('save') is True:
            cmd_confirm = cmd_yes

        cmd_file_name = "\n"
        if self.module.params.get('startup_cfg'):
            cmd_file_name = "flash:/" + self.module.params.get('startup_cfg') \
                            + cmd_file_name
        self._send_command(cmd_save, "ERROR: unable to save config")
        self._send_command(cmd_confirm, "ERROR: unable to save config")
        self._send_command(cmd_file_name, "ERROR: unable to save %s"
                           % cmd_file_name)
        self._developer_mode_set = True

    def _quit(self):
        self._send_command(cmd_quit, "ERROR: unable to quit level")

    def _ensure_top_level_view(self):
        if self._is_system_view() is True:
            self._quit()
            self._top_level_view = True
            self._system_view = False

    # this has to be done. Life is miserable if the switch is waiting
    # for a space-bar to be hit.
    def _disable_paging(self):
        self._send_command(cmd_disable_paging,
                           "ERROR: unable to disable paging")
        self._paging_disabled = True

    def _get_output(self, start='', end=""):
        output_buf = ""
        append_flag = False
        expect_end = False
        while True:
            read_buf = self.channel.recv(1024)
            read_buf = read_buf.replace("\r", "")

            if start in read_buf:
                expect_end = True
                append_flag = True

            if append_flag:
                output_buf += read_buf

            if end == "":
                end = '(' + top_level_prompt + '|' +\
                      re.escape(sys_prompt) + ')'
            if re.match('.*\n' + end + '$', read_buf, re.DOTALL) \
               and expect_end:
                break
            if re.match('.*\n[\[<].*[\]>]$', read_buf, re.DOTALL) \
               and expect_end:
                break
        return output_buf

    def _get_output_list(self, start='', keep_prompt=False):
        output_buf = self._get_output(start)

        output_list = output_buf.split('\n')
        list_length = len(output_list)
        if not keep_prompt:
            list_length -= 1

        return output_list[0:list_length]

    def _get_summary(self):
        summary_start = "Select menu option:             Summary"
        self._ensure_top_level_view()
        self._send_command(cmd_summary, "ERROR: unable to get switch summary")
        summary_buf = self._get_output(summary_start, top_level_prompt)
        summary_dict = self._get_summary_dict(summary_buf)
        return summary_dict

    # get a clean dictionary representation of summary output for facts
    def _get_summary_dict(self, summary_buf=''):
        summary_dict = {}
        summary_list = summary_buf.split('\n')
        line_count = 0
        for item in summary_list:
            m = re.search('^([\s\w]+):\s*(\w.*)$', item)
            if m:
                key = m.group(1)
                value = m.group(2)
                key = key.replace(' ', '_')
                summary_dict[key] = value
            m = re.search('HP .* Software', item)
            if m:
                summary_dict['software_version'] = summary_list[line_count + 1]
                summary_dict['software_copyright'] = \
                    summary_list[line_count + 2]
                summary_dict['uptime'] = summary_list[line_count + 3]
                summary_dict['model'] = summary_list[line_count + 4]
                summary_dict['memory_dram'] = summary_list[line_count + 6]
                summary_dict['memory_flash'] = summary_list[line_count + 7]
                summary_dict['memory_register'] = summary_list[line_count + 8]
                summary_dict['hardware_version'] = \
                    summary_list[line_count + 10]
                summary_dict['cpld_version'] = summary_list[line_count + 11]
                summary_dict['bootrom_version'] = summary_list[line_count + 12]
                summary_dict['subslot_0'] = summary_list[line_count + 13]
                break

            line_count += 1

        return summary_dict

    def _run_current_config(self):
        self._set_system_view()
        self._send_command(cmd_current_config,
                           "ERROR: unable to get switch current config")

    # get a clean dictionary representation of current config output for facts
    # TODO: work into a dict with specific parsing phrases. No easy way
    # to do this!
    def _get_current_config(self):
        self._run_current_config()
        return self._get_config_dict(self._get_config_list())

    def _get_config_list(self):
        return self._get_output_list('version')

    # OK, this method was very tricky. Probably endless way to do this better
    # but this works best for the varying output the switch gives you
    def _get_config_dict(self, config_list):
        keywords = ['sysname',
                    'ftp server',
                    'domain default',
                    'telnet server',
                    'ip ttl-expires',
                    'password-recovery',
                    'user-group']
        local_user_keywords = ['password',
                               'authorization-attribute',
                               'service-type']
        interface_keywords = ['edged-port',
                              'link-type',
                              'access',
                              'hybrid',
                              'trunk']
        config_dict = {'sysname': 'HP',
                       'interfaces': {},
                       'vlans': {},
                       'local-user': {}}
        # OK, maybe this has some duplication, but parsing through
        # current-configuration is somewhat tricky.
        # TODO: break into methods and make generic as possible
        i = 0
        for line in config_list:
            for keyword in keywords:
                if keyword in line:
                    m = re.search(keyword + " (.*)$", line, re.DOTALL)
                    if m and len(m.group(1)):
                        value = m.group(1)
                        config_dict[keyword] = value
            m = re.search('^interface ([\w\-\/]+)$', line, re.DOTALL)
            if m and len(m.group(1)):
                interface = m.group(1)
                config_dict['interfaces'][interface] = {}
                for iline in config_list[i:len(config_list)]:
                    vdict = {'tagged': {}, 'untagged': {}}
                    if re.match('^#$', iline):
                        break
                    vdict_flag = False
                    for key in interface_keywords:
                        m1 = re.search('^\s(\w+)\s' + re.escape(key) +
                                       '(\s\w+)?\svlan\s(.*)$', iline)
                        m2 = re.search('^\s(\w+)\s' + re.escape(key) +
                                       '\s(\w+)$', iline)
                        if m1 and len(m1.group(1)):
                            value = None
                            tagged_state = None
                            if m1.group(1) == 'port':
                                if key == 'link-type':
                                    value = m1.group(2)
                                    config_dict['interfaces'][interface][key] \
                                        = value
                                else:
                                    value = m1.group(3).split()
                                    # something was found
                                    vdict_flag = True
                                    if key == 'access':
                                        tagged_state = 'untagged'
                                    elif key == 'trunk':
                                        tagged_state = 'tagged'
                                    else:
                                        tagged_state = value[len(value)-1]
                                        value = value[0:len(value)-1]
                                    vdict[tagged_state][key] = value
                        elif m2 and len(m2.group(1)) and len(m2.group(2)):
                            key = "%s %s" % (m2.group(1), key)
                            value = m2.group(2)
                            config_dict['interfaces'][interface][key] = value

                    # safe to append
                    if vdict_flag:
                        config_dict['interfaces'][interface]['vlan'] = vdict
                        vdict_flag = False

            m = re.search('^vlan ([\w\-\/]+)$', line, re.DOTALL)
            if m and len(m.group(1)):
                vlan_id = m.group(1)
                config_dict['vlans'][vlan_id] = {}
                for iline in config_list[i:len(config_list)]:
                    if re.match('^#$', iline):
                        break
                    m = re.search('^\sname (\w+)$', iline)
                    if m and len(m.group(1)):
                        name = m.group(1)
                        config_dict['vlans'][vlan_id]['name'] = name
            m = re.search('^local-user ([\w\-\/]+)$', line, re.DOTALL)
            if m and len(m.group(1)):
                user_id = m.group(1)
                config_dict['local-user'][user_id] = {}
                # something to collect services that are enabled
                services_enabled = []
                for iline in config_list[i:len(config_list)]:
                    if re.match('^#$', iline):
                        break
                    # possible output following 'local-user'
                    for key in local_user_keywords:
                        m = re.search('^\s?' + key + ' (.*)$', iline)
                        if m and len(m.group(1)):
                            value = m.group(1)
                            # array members - thus far
                            if key == 'service-type':
                                services_enabled += value.split()
                            else:
                                config_dict['local-user'][user_id][key] = value
                # De-dupe
                services_enabled = list(OrderedDict.fromkeys(services_enabled))
                config_dict['local-user'][user_id]['service-type'] =\
                    services_enabled
            i += 1

        self._quit()
        return config_dict

    def _get_prompt(self):
        self._send_command("\n")
        self._send_command("\n")
        prompt_list = self._get_output_list('HP', keep_prompt=True)
        return prompt_list[len(prompt_list) - 1]

    def _get_vlans(self):
        vlan_buf_list = []
        vlan_id = 0
        vlan_dict = {}
        ports_collect = False
        key = ''

        self._set_system_view()
        self._send_command(cmd_display_vlan_all,
                           "ERROR: unable to get switch current config")
        vlan_buf_list = self._get_output_list('VLAN ID:')
        for line in vlan_buf_list:
            # crud, skip it
            if line == ' ' or sys_prompt in line:
                next
            # in case this shows up
            if re.match('^' + re.escape(sys_prompt) + '$', line, re.DOTALL):
                break
            # get the ID
            m = re.search('^\sVLAN ID:\s(\d+)', line, re.DOTALL)
            if m:
                vlan_id = m.group(1)
                vlan_dict[vlan_id] = {}
                next

            # get the rest
            m = re.search('^\s([\w\s]+):\s?(\w[\w\s\.]+)?', line, re.DOTALL)
            if m:
                ports_collect = False
                key = re.sub('\s+', '_', m.group(1))
                if m.group(2):
                    vlan_dict[vlan_id][key] = m.group(2)
                # if 'Ports' and no group(2), that means follow lines
                # will contain the ports for that VPN, start collecting
                elif 'Ports' in key:
                    vlan_dict[vlan_id][key] = []
                    ports_collect = True

            # if collecting ports, just split and append to array
            elif ports_collect:
                ports_list = line.split()
                vlan_dict[vlan_id][key] += ports_list

        return vlan_dict

    def get_facts(self):
        facts = {}
        if not self.module.params.get('gather_facts'):
            return facts
        # developer_mode = self.module.params.get('developer-mode')
        self.dev_setup()
        facts['summary'] = self._get_summary()
        facts['current_config'] = self._get_current_config()
        facts['vlans'] = self._get_vlans()

        return facts

    def dev_setup(self):
        if not self._developer_mode_set:
            self._developer_mode()
        if not self._paging_disabled:
            self._disable_paging()

    def _is_system_view(self):
        if self._system_view:
            return self._system_view
        prompt = self._get_prompt()
        if prompt == sys_prompt:
            self._system_view = True
            return True

    def _set_system_view(self):
        self._send_command("\n")
        while True:
            read_buf = self.channel.recv(1024)
            read_buf = read_buf.replace("\r", "")
            if re.match('.*\n(' + re.escape(sys_prompt) + '|'
                        + top_level_prompt + ')$', read_buf, re.DOTALL):
                break

        if re.match('.*\n' + top_level_prompt + '$', read_buf, re.DOTALL):
            self._send_command(cmd_system_view,
                               "ERROR: unable to enter system-view")
        self._system_view = True

    def reboot(self):
        self.dev_setup()
        self._ensure_top_level_view()
        #prompt = self._get_prompt()

        self._send_command(cmd_reboot, "ERROR: Unable to reboot")
        while True:
            read_buf = self.channel.recv(1024)
            read_buf = read_buf.replace("\r", "")
            if verify_save_current_conf in read_buf:
                if self.module.params.get('save') is True:
                    self._send_command(cmd_yes)
                else:
                    self._send_command(cmd_no)
                    read_buf = self.channel.recv(1024)
                    read_buf = read_buf.replace("\r", "")
            if verify_reboot in read_buf:
                self._send_command(cmd_yes)
                break

        self.append_message("Please wait for the switch to resume... ")
        self.append_message("Rebooting.")
        self._changed = True
