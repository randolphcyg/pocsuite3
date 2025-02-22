import binascii
import json
import re
import socket
from collections import OrderedDict
from dataclasses import asdict

import dacite

from pocsuite3.lib.core.common import urlparse
from pocsuite3.lib.core.datatype import AttribDict
from pocsuite3.lib.json.goby.model import Severity
from pocsuite3.lib.json.goby.protocols.common.expressions import evaluate, Marker
from pocsuite3.lib.json.goby.protocols.common.generators import AttackType
from pocsuite3.lib.json.goby.protocols.http import HTTPMethod, execute_http_request, HttpRequest
from pocsuite3.lib.json.goby.protocols.network import NetworkInputType, execute_network_request
from pocsuite3.lib.json.goby.templates import Template, ScanStep, ExploitStep
from pocsuite3.lib.utils import random_str


def hyphen_to_underscore(dictionary):
    """
    Takes an Array or dictionary and replace all the hyphen('-') in any of its keys with a underscore('_')
    :param dictionary:
    :return: the same object with all hyphens replaced by underscore
    """
    # By default, return the same object
    final_dict = dictionary

    # for Array perform this method on every object
    if isinstance(dictionary, list):
        final_dict = []
        for item in dictionary:
            final_dict.append(hyphen_to_underscore(item))

    # for dictionary traverse all the keys and replace hyphen with underscore
    elif isinstance(dictionary, dict):
        final_dict = {}
        for k, v in dictionary.items():
            # If there is a sub dictionary or an array perform this method of it recursively
            if isinstance(dictionary[k], (dict, list)):
                value = hyphen_to_underscore(v)
                final_dict[k.replace('-', '_')] = value
            else:
                final_dict[k.replace('-', '_')] = v

    return final_dict


def expand_preprocessors(data: str) -> str:
    """
    Certain pre-processors can be specified globally anywhere in the template that run as soon as
    the template is loaded to achieve things like random ids generated for each template run.

    randstr can be suffixed by a number, and new random ids will be created for those names too.
    Ex. {{randstr_1}} which will remain same across the template.
    randstr is also supported within matchers and can be used to match the inputs.
    """
    randstr_to_replace = set(m[0] for m in re.findall(
        fr'({Marker.ParenthesisOpen}randstr(_\w+)?{Marker.ParenthesisClose})', data))
    for s in randstr_to_replace:
        data = data.replace(s, random_str(27))

    return data


# 处理None值 为None则初始化为空列表
def parse_json_with_none(data):
    def dict_ignore_none(ordered_pairs):
        d = {}
        for k, v in ordered_pairs:
            if v is not None:
                if isinstance(v, dict):
                    v = dict_ignore_none(v.items())
                d[k] = v
        return d

    return json.loads(data, object_pairs_hook=dict_ignore_none)


class Goby:
    def __init__(self, template, target=''):
        # [goby tpl]
        self.goby_template = template
        try:
            self.goby_template = binascii.unhexlify(self.goby_template).decode()
        except ValueError:
            pass
        self.goby_template = expand_preprocessors(self.goby_template)

        # [tpl]
        tmp_tpl = parse_json_with_none(self.goby_template)
        data = hyphen_to_underscore(tmp_tpl)
        filtered_data = {k: v for k, v in data.items() if v != ""}
        self.template = dacite.from_dict(data_class=Template, data=filtered_data)
        # 处理 ScanSteps
        if 'ScanSteps' in tmp_tpl:
            if len(tmp_tpl['ScanSteps']) > 0:
                self.template.ScanStepOperation = tmp_tpl['ScanSteps'][0]
            if len(tmp_tpl['ScanSteps']) > 1:
                tmp_scan_step = tmp_tpl['ScanSteps'][1:]
                for item in tmp_scan_step:
                    step = dacite.from_dict(data_class=ScanStep, data=item)
                    self.template.ScanStepsList.append(step)
        # 处理 ExploitSteps
        if 'ExploitSteps' in tmp_tpl:
            if len(tmp_tpl['ExploitSteps']) > 0:
                self.template.ExploitStepOperation = tmp_tpl['ExploitSteps'][0]
            if len(tmp_tpl['ExploitSteps']) > 1:
                tmp_exploit_step = tmp_tpl['ExploitSteps'][1:]
                for item in tmp_exploit_step:
                    step = dacite.from_dict(data_class=ExploitStep, data=item)
                    self.template.ExploitStepList.append(step)

        # [json tpl]
        self.json_template = AttribDict()
        requests = []
        if len(self.template.ScanStepsList) >= 1:
            for item in self.template.ScanStepsList:
                requests.append(item.Request)
        self.json_template['requests'] = requests

        self.target = target
        self.interactsh = None
        self.dynamic_values = OrderedDict()

    def execute_template(self):
        # Dynamic variables can be placed in the path to modify its behavior on runtime.
        # Variables start with {{ and end with }} and are case-sensitive.

        result = False

        u = urlparse(self.target)
        self.dynamic_values['BaseURL'] = self.target
        self.dynamic_values['RootURL'] = f'{u.scheme}://{u.netloc}'
        self.dynamic_values['Hostname'] = u.netloc
        self.dynamic_values['Scheme'] = u.scheme
        self.dynamic_values['Host'] = u.hostname
        self.dynamic_values['Port'] = u.port
        self.dynamic_values['Path'] = '/'.join(u.path.split('/')[0:-1])
        self.dynamic_values['File'] = u.path.split('/')[-1]
        # DSL: Host != ip
        self.dynamic_values['IP'] = ''
        try:
            self.dynamic_values['IP'] = socket.gethostbyname(u.hostname)
        except socket.error:
            pass
        for k, v in self.dynamic_values.copy().items():
            self.dynamic_values[k.lower()] = v

        for k, v in self.template.variables.items():
            self.dynamic_values[k] = evaluate(v)

        if (f'{Marker.ParenthesisOpen}interactsh-url{Marker.ParenthesisClose}' in self.goby_template or
                f'{Marker.General}interactsh-url{Marker.General}' in self.goby_template):
            from pocsuite3.lib.json.goby.protocols.common.interactsh import InteractshClient
            self.interactsh = InteractshClient()
            self.dynamic_values['interactsh-url'] = self.interactsh.client.domain

        res = []
        for item in self.template.ScanStepsList:
            res_item = execute_http_request(item, self.template, self.dynamic_values, self.interactsh)
            res.append(res_item)
        # 对几个测试做汇总
        if self.template.ScanStepOperation == "OR":
            result = any(res)
        elif self.template.ScanStepOperation == "AND":
            result = all(res)
        return result

    def run(self):
        return self.execute_template()

    def __str__(self):
        """
        Convert goby .json template to Pocsuite3 .py
        """
        info = []
        key_convert = {
            'description': 'desc',
            'reference': 'references'
        }
        for k, v in asdict(self.template).items():
            if k in key_convert:
                k = key_convert.get(k)
            if type(v) in [str]:
                v = json.dumps(v.strip(), ensure_ascii=False)

            info.append(f'    {k} = {v}')

        poc_code = [
            'from pocsuite3.api import POCBase, Goby, register_poc\n',
            '\n',
            '\n',
            'class TestPOC(POCBase):\n',
            '\n'.join(info),
            '\n',
            '    def _verify(self):\n',
            '        result = {}\n',
            '        if not self._check(is_http=%s):\n' % (len(self.json_template['requests']) > 0),
            '            return self.parse_output(result)\n',
            "        template = '%s'\n" % binascii.hexlify(self.goby_template.encode()).decode(),
            '        res = Goby(template, self.url).run()\n',
            '        if res:\n',
            '            result["VerifyInfo"] = {}\n',
            '            result["VerifyInfo"]["URL"] = self.url\n',
            '            result["VerifyInfo"]["Info"] = {}\n',
            '            result["VerifyInfo"]["Info"]["Severity"] = "%s"\n' % self.template.Level,
            '            if not isinstance(res, bool):\n'
            '               result["VerifyInfo"]["Info"]["Result"] = res\n',
            '        return self.parse_output(result)\n',
            '\n',
            '\n',
            'register_poc(TestPOC)\n'
        ]
        ret = ''.join(poc_code)
        return ret
