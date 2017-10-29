#!/usr/bin/python
# -*- coding: utf-8 -*-
#
#    StrongSwan server management for Docker installation
#
#    Copyright (C) 2017 Angry Siberian Racoon <angrysiberianracoon@gmail.com>
#
#    https://github.com/angrysiberianracoon/ikev2vpn
#
#    This software is licensed under the MIT
#    License: https://github.com/angrysiberianracoon/ikev2vpn/master/LICENSE

import collections
import json
import os
import sys
import gettext
import subprocess
import signal
import shutil
import re
import zipfile
import random
import string

debug = False


class Config:
    def __init__(self, filename):
        self.filename = filename

        with open(self.filename, 'r') as f:
            self.v = json.load(f, object_pairs_hook=collections.OrderedDict)

    def __getitem__(self, section):
        return self.v[section]

    def has(self, section, key):
        return key in self.v[section].keys()

    def update(self, section, key, value):
        self.v[section][key] = value
        self.save()

    def save(self):
        open(self.filename, 'wb').write(json.dumps(self.v, ensure_ascii=False, indent=4).encode('utf8'))


class OutFormat:
    def __init__(self):
        pass

    CURSOR_UP_ONE = '\x1b[1A'
    ERASE_LINE = '\x1b[2K'
    GREEN = '\033[92m'
    LINK = '\33[33m'
    MENU = '\033[94m'
    BOLD = '\033[1m'
    YELLOW = '\033[93m'
    ENDC = '\033[0m'

    @staticmethod
    def clear_screen():
        print(chr(27) + "[2J")

    @staticmethod
    def clear_line():
        print(OutFormat.CURSOR_UP_ONE + OutFormat.ERASE_LINE + OutFormat.CURSOR_UP_ONE)

    @staticmethod
    def trim(value):
        return re.sub(r'\s+', ' ', value)

    @staticmethod
    def line_dashed():
        print (OutFormat.GREEN + '-----------------------------------------------------' + OutFormat.ENDC)

    @staticmethod
    def line_menu():
        print (OutFormat.MENU + '=============================' + OutFormat.ENDC)

    @staticmethod
    def bold(value):
        return OutFormat.BOLD + value + OutFormat.ENDC

    @staticmethod
    def yellow(value):
        return OutFormat.YELLOW + value + OutFormat.ENDC

    @staticmethod
    def link(value):
        return OutFormat.LINK + value + OutFormat.ENDC

    @staticmethod
    def alert(value):
        print '\n[ ' + OutFormat.BOLD + OutFormat.YELLOW + value + OutFormat.ENDC + ' ]'

    @staticmethod
    def header(value):
        print ('\n\n' + OutFormat.bold(value))
        OutFormat.line()

    @staticmethod
    def logo():
        OutFormat.clear_screen()
        print (OutFormat.BOLD + '    ______ _______   _____')
        print ('   /  _/ //_/ __/ | / /_  |  _  _____  ___')
        print ('  _/ // ,< / _/ | |/ / __/  | |/ / _ \/ _ \\')
        print (' /___/_/|_/___/ |___/____/  |___/ .__/_//_/')
        print ('                               /_/' + OutFormat.ENDC)

    @staticmethod
    def line():
        print (OutFormat.GREEN + '─────────────────────────────────────────────────────' + OutFormat.ENDC)


def lang_init(lang_code):
    path = sys.argv[0]
    path = os.path.join(os.path.dirname(path), 'lang')

    lang = gettext.translation('ikev2vpn', path, [lang_code], fallback="en")
    return lang.gettext


def silent_run(command, show_output=False):
    if show_output:
        subprocess.check_call(command, shell=True)
    else:
        subprocess.check_call(command, shell=True, stdout=open(os.devnull, 'wb'))


def name_validate(value):
    reg = re.compile("^[A-Za-z0-9_.@-]+$")

    if not reg.match(value):
        return _('the name must contain only letters, numbers and symbols [_ - . @]')
    else:
        return None


def ip4_validate(value):
    reg = re.compile(
        "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")

    if not reg.match(value):
        return _('incorrect IP address format')
    else:
        return None


def get_if_name(ip):
    out = subprocess.check_output(['ip', 'r', 'get', ip], cwd=conf['path']['cert_gen_root'])
    reg = re.search(r'dev (\w+)', out)
    return reg.group(1)


def generate_cert_ca(c, o, cn):
    silent_run('ipsec pki --gen --outform pem > ca.pem')

    command = 'ipsec pki \
    --self \
    --lifetime ' + str(conf['cert']['lifetime_server']) + ' \
    --in ca.pem \
    --dn "C=' + c + ', O=' + o + ', CN=' + cn + '" \
    --ca \
    --outform pem > ca.cert.pem'

    silent_run(OutFormat.trim(command))

    shutil.copy(conf['path']['cert_gen_root'] + '/ca.cert.pem', conf['path']['cert_storage'] + '/cacerts/')
    shutil.copy(conf['path']['cert_gen_root'] + '/ca.pem', conf['path']['cert_storage'] + '/private/')


def generate_cert_server(c, o, cn):
    silent_run('ipsec pki --gen --outform pem > server.pem')

    command = 'ipsec pki \
    --issue \
    --lifetime ' + str(conf['cert']['lifetime_server']) + ' \
    --in server.pem \
    --type priv \
    --cacert ca.cert.pem \
    --cakey ca.pem \
    --dn "C=' + c + ', O=' + o + ', CN=' + cn + '" \
    --san="' + cn + '" \
    --flag serverAuth \
    --flag ikeIntermediate \
    --outform pem > server.cert.pem'

    silent_run(OutFormat.trim(command))

    shutil.copy(conf['path']['cert_gen_root'] + '/server.pem',
                conf['path']['cert_storage'] + '/private/')

    shutil.copy(conf['path']['cert_gen_root'] + '/server.cert.pem',
                conf['path']['cert_storage'] + '/certs/')


def generate_cert_client(c, o, cn):
    silent_run('ipsec pki --gen --outform pem > ' + cn + '.pem')

    command = 'ipsec pki \
    --issue \
    --lifetime ' + str(conf['cert']['lifetime_client']) + ' \
    --in ' + cn + '.pem \
    --type priv \
    --cacert ca.cert.pem \
    --cakey ca.pem \
    --dn "C=' + c + ', O=' + o + ', CN=' + cn + '" \
    --san="' + cn + '" \
    --outform pem > ' + cn + '.cert.pem'

    silent_run(OutFormat.trim(command))

    shutil.copy(conf['path']['cert_gen_root'] + '/' + cn + '.pem', conf['path']['cert_storage'] + '/private/')
    shutil.copy(conf['path']['cert_gen_root'] + '/' + cn + '.cert.pem', conf['path']['cert_storage'] + '/certs/')


def generate_cert_client_p12(client_name, server_name):
    export_password = user_input(_(
        'Enter the password for the client certificate\n(it will be displayed on the screen in clear view!)\nyou can leave the field blank:'))

    command = 'openssl pkcs12 \
    -passout pass:' + export_password + '\
    -export \
    -inkey ' + client_name + '.pem \
    -in ' + client_name + '.cert.pem \
    -name "' + client_name + '" \
    -caname "' + server_name + '" \
    -out ' + client_name + '.p12'

    silent_run(OutFormat.trim(command))


def ban_client_cert(client_name):
    os.chdir(conf['path']['cert_storage'])

    command = 'ipsec pki \
        --signcrl \
        --reason key-compromise \
        --cacert cacerts/ca.cert.pem \
        --cakey private/ca.pem \
        --cert certs/' + client_name + '.cert.pem \
        --outform pem > crls/crl.pem'

    if os.path.isfile('crls/crl.pem'):
        command += ' --lastcrl crls/crl.pem.old'
        shutil.copy('crls/crl.pem', 'crls/crl.pem.old')

    silent_run(OutFormat.trim(command))

    if os.path.isfile('crls/crl.pem.old'):
        os.remove("crls/crl.pem.old")


def zip_write_frompath(instance, folder_name, file_names):
    for file_name in file_names:
        save_name = file_name.replace("cert.pem", "cer").replace("pem", "key")

        instance.write(folder_name + '/' + file_name, save_name)


def create_zip_cert_client(client_cn, dest_folder):
    string_hash = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(16)])
    zip_name = client_cn + '_' + string_hash + '.zip'

    cert_zip = zipfile.ZipFile(dest_folder + '/' + zip_name, 'w', zipfile.ZIP_DEFLATED)
    zip_write_frompath(cert_zip, conf['path']['cert_gen_root'],
                       ['ca.cert.pem', client_cn + '.cert.pem', client_cn + '.pem', client_cn + '.p12'])
    cert_zip.close()

    return zip_name


def run_web_server():
    stop_web_server()
    silent_run('httpd -p 0.0.0.0:' + str(conf['network']['web_port']) + ' -h ' + conf['path']['web_root'])


def stop_web_server():
    proc = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    out, err = proc.communicate()

    for line in out.splitlines():
        if 'httpd' in line:
            pid = int(line.split(None, 1)[0])
            os.kill(pid, signal.SIGKILL)


def restart_vpn_server():
    silent_run('supervisorctl restart ipsec', debug)


def create_dir(dir_path):
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)


def remove_dir_content(dir_path):
    if os.path.exists(dir_path):
        for fileName in os.listdir(dir_path):
            os.remove(dir_path + '/' + fileName)


def replace_in_file(file_name, find_text, replace_text):
    f_read = open(file_name, 'r')
    read_data = f_read.read()
    f_read.close()

    content = read_data.replace(find_text, replace_text)

    f_write = open(file_name, 'w')
    f_write.write(content)
    f_write.close()


def menu(options, return_item=False, header=None):
    print '\n'

    if header:
        print OutFormat.bold(header)

    OutFormat.line_menu()
    for key, item in enumerate(options, start=1):
        print ' ' + str(key) + '. ' + item

    if return_item:
        print ' 0. ' + return_item

    OutFormat.line_menu()

    input_items = [str(index) for index in range(1, len(options) + 1)]

    if return_item:
        input_items.append("0")

    return int(confirmation(input_items))


def confirmation(options):
    while 1:
        value = raw_input().lower()
        OutFormat.clear_line()
        if value in options:
            return value


def user_input(promt, validator=None):
    OutFormat.header(promt)
    prev_novalid = False

    while 1:
        value = raw_input()

        if prev_novalid:
            OutFormat.clear_line()
            OutFormat.clear_line()

        prev_novalid = False

        OutFormat.clear_line()
        print _('your input: [{value}]').format(value=OutFormat.yellow(value))

        if validator is not None:
            validator_result = validator(value)

        if validator is None or validator_result is None:
            print _('continue [y] / input again [n] ?')

            if confirmation(['y', 'n']) == 'y':
                OutFormat.clear_line()
                return value

            OutFormat.clear_line()
            OutFormat.clear_line()

        else:
            prev_novalid = True
            print validator_result + _(', try again:')


def add_client_cert(client_name):
    os.chdir(conf['path']['cert_gen_root'])

    generate_cert_client(conf['cert']['country_code'], conf['cert']['service_name'], client_name)

    share_menu = menu([_('download from web (not safe)'), _('copy / paste over screen')], False,
        _('Select the method of obtaining the certificates:'))

    if share_menu == 1:
        share_client_cert_http(client_name)
    elif share_menu == 2:
        share_client_cert_screen(client_name)


def share_client_cert_http(client_name):
    create_dir(conf['path']['web_root'])

    generate_cert_client_p12(client_name, conf['network']['host_ip'])

    client_zip = create_zip_cert_client(client_name, conf['path']['web_root'])

    run_web_server()

    print '\n'
    print OutFormat.bold(_('Download the certificate archive at:'))
    OutFormat.line_dashed()
    print OutFormat.link(
        'http://' + conf['network']['host_ip'] + ':' + str(conf['network']['web_port']) + '/' + client_zip)
    OutFormat.line()
    print _('If you successfully downloaded the certificates, type [y]')
    confirmation(['y'])

    stop_web_server()

    shutil.rmtree(conf['path']['web_root'])


def file_to_screen(file_path, file_name, text_prefix=''):
    print '\n'
    print OutFormat.yellow(text_prefix) + ' ' + OutFormat.bold(_('Copy the text between "---" characters and save it as a text file named "{file_name}"').format(file_name=file_name))

    OutFormat.line_dashed()

    with open(conf['path']['cert_gen_root'] + '/' + file_path, 'r') as cert_file:
        print cert_file.read()

    OutFormat.line_dashed()


def share_client_cert_screen(client_name):
    file_to_screen('ca.cert.pem', 'ca.cer', '[ 1 ]')
    file_to_screen(client_name + '.cert.pem', client_name + '.cer', '[ 2 ]')
    file_to_screen(client_name + '.pem', client_name + '.key', '[ 3 ]')

    print '\n'
    print OutFormat.bold(_('After creating 3 files, you need to generate a certificate PKCS#12 format'))
    print _('If you are using Windows, install OpenSSL {url}').format(url=OutFormat.link('https://wiki.openssl.org/index.php/Binaries'))
    print _('Open the console in the directory with the created files and run the command:')
    OutFormat.line_dashed()
    print OutFormat.yellow('openssl pkcs12 -export \
-inkey ' + client_name + '.key \
-in ' + client_name + '.cer \
-name "' + client_name + '" \
-caname "' + conf['network']['host_ip'] + '" \
-out ' + client_name + '.p12')


def set_network_settings():
    os.chdir(conf['path']['config_gen_root'])

    if_name = get_if_name(conf['network']['host_ip'])

    shutil.copy('ipsec.conf', '/etc')

    replace_in_file('/etc/ipsec.conf', '$LEFTID', conf['network']['host_ip'])
    replace_in_file('/etc/ipsec.conf', '$RIGHTIP', conf['network']['network_for_client'])

    shutil.copy('firewall.updown', '/etc/ipsec.d')

    replace_in_file('/etc/ipsec.d/firewall.updown', '$RIGHTIF', if_name)
    replace_in_file('/etc/ipsec.d/firewall.updown', '$RIGHTIP', conf['network']['network_for_client'])

    silent_run('chmod +x /etc/ipsec.d/firewall.updown')

    silent_run('sysctl -w net.ipv4.ip_forward=1', debug)
    silent_run('sysctl -w net.ipv4.ip_no_pmtu_disc=1', debug)
    silent_run('sysctl -w net.ipv4.conf.all.accept_redirects=0', debug)
    silent_run('sysctl -w net.ipv4.conf.all.send_redirects=0', debug)


def init_setting():
    if os.path.isfile(conf['path']['cert_storage'] + '/cacerts/ca.cert.pem'):
        print _('Re-initialization will invalidate all previously issued certificates. Continue? [y / n]')
        if confirmation(['y', 'n']) == 'n':
            return

    host_ip = user_input(_('Enter the public IP address of the server:'), ip4_validate)
    conf.update('network', 'host_ip', host_ip)

    remove_dir_content(conf['path']['cert_storage'] + '/cacerts')
    remove_dir_content(conf['path']['cert_storage'] + '/certs')
    remove_dir_content(conf['path']['cert_storage'] + '/private')
    remove_dir_content(conf['path']['cert_storage'] + '/crls')

    create_dir(conf['path']['cert_gen_root'])
    os.chdir(conf['path']['cert_gen_root'])

    generate_cert_ca(conf['cert']['country_code'], conf['cert']['service_name'], conf['cert']['ca_name'])
    generate_cert_server(conf['cert']['country_code'], conf['cert']['service_name'], conf['network']['host_ip'])

    set_network_settings()

    restart_vpn_server()

    conf.update('clients', 'active', [])

    add_client()


def add_client():
    if not conf.has('network', 'host_ip'):
        OutFormat.alert(_('First run the initial setup'))
        return

    client_name = user_input(_('Enter the client name:'), name_validate)
    user_list = conf['clients']['active']

    if client_name in user_list:
        print _('Client [{user}] already exist. Re-create the certificate? [y / n]').format(user=OutFormat.yellow(client_name))
        if confirmation(['y', 'n']) == 'n':
            return

    add_client_cert(client_name)

    user_list.append(client_name)
    conf.update('clients', 'active', user_list)


def ban_client():
    user_list = conf['clients']['active']

    if len(user_list) == 0:
        OutFormat.alert(_('No active users'))
        return

    selected_user = menu(user_list, _("[ back ]"), _('Select user for ban:'))

    if selected_user == 0:
        return

    ban_client_cert(user_list[selected_user - 1])

    restart_vpn_server()

    OutFormat.alert(_('Client [{user}] was banned').format(user=user_list[selected_user - 1]))

    user_list.pop(selected_user - 1)
    conf.update('clients', 'active', user_list)


def select_lang():
    locale_list = conf['lang']['list']
    locale_select = menu(locale_list.values())
    locale = locale_list.keys()[locale_select - 1]

    conf.update('lang', 'current', locale)

    return lang_init(locale)


OutFormat.logo()

conf = Config(os.path.dirname(os.path.realpath(__file__)) + '/vpn.json')

if conf.has('lang', 'current'):
    _ = lang_init(conf['lang']['current'])
else:
    _ = select_lang()


operation = None
while operation != 0:
    operation = menu([_('initial setup'), _('add client'), _('ban client'), _('select language')], _('exit'))

    if operation == 1:
        init_setting()
    elif operation == 2:
        add_client()
    elif operation == 3:
        ban_client()
    elif operation == 4:
        _ = select_lang()
