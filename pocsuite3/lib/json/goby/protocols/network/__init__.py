import binascii
import json
import socket
import ssl
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Union

from pocsuite3.lib.core.common import urlparse
from pocsuite3.lib.core.log import LOGGER as logger
from pocsuite3.lib.json.goby.model import CaseInsensitiveEnum
from pocsuite3.lib.json.goby.operators import (ExtractorType,
                                               extract_dsl, extract_kval, extract_regex)
from pocsuite3.lib.json.goby.protocols.common.generators import payload_generator
from pocsuite3.lib.json.goby.protocols.common.interactsh import InteractshClient
from pocsuite3.lib.json.goby.protocols.common.replacer import (
    UNRESOLVED_VARIABLE, marker_replace)


class NetworkInputType(CaseInsensitiveEnum):
    HexType = 'hex'
    TextType = 'text'


@dataclass
class AddressKV:
    address: str = ''
    host: str = ''
    port: int = 0
    tls: bool = False


@dataclass
class Input:
    """Input is the input to send on the network
    """

    # Data is the data to send as the input.
    # It supports DSL Helper Functions as well as normal expressions.
    data: Union[str, int] = ''

    # Type is the type of input specified in `data` field.
    type: NetworkInputType = NetworkInputType.TextType

    # Read is the number of bytes to read from socket.
    read: int = 0

    # Name is the optional name of the data read to provide matching on.
    name: str = ''


@dataclass
class NetworkRequest:
    """NetworkRequest contains a Network protocol request to be made from a template
    """
    # 请求 uri
    uri: str = ''
    # 请求方式，目前支持 GET、POST 、PUT、HEAD、PUSH、DELETE、OPTION、自定义，默认为 GET
    # method: str = HTTPMethod.HTTPGet
    # 请求 header 头，key、value 写入
    header: dict = field(default_factory=dict)
    # 请求参数，内容会作为 post data 发送。
    data: str = ''
    # 参数类型，默认为 text
    data_type: str = ''
    # 是否跟随跳转，true 为跟随跳转否则不跳转，默认为 true
    follow_redirect: bool = True


def network_get_match_part(part: str, resp_data: dict, interactsh=None, return_bytes: bool = False) -> str:
    result = ''
    if part in ['', 'all', 'body']:
        part = 'data'

    if part in resp_data:
        result = resp_data[part]
    elif part.startswith('interactsh'):
        if not isinstance(interactsh, InteractshClient):
            result = ''
        # poll oob data
        else:
            interactsh.poll()
            if part == 'interactsh_protocol':
                result = '\n'.join(interactsh.interactsh_protocol)
            elif part == 'interactsh_request':
                result = '\n'.join(interactsh.interactsh_request)
            elif part == 'interactsh_response':
                result = '\n'.join(interactsh.interactsh_response)

    if return_bytes and not isinstance(result, bytes):
        result = str(result).encode()
    elif not return_bytes and isinstance(result, bytes):
        try:
            result = result.decode()
        except UnicodeDecodeError:
            result = str(result)
    return result


def network_extract(request: NetworkRequest, resp_data: dict):
    extractors = request.extractors
    extractors_result = {'internal': {}, 'external': {}, 'extra_info': []}

    for extractor in extractors:
        item = network_get_match_part(extractor.part, resp_data)

        res = None
        if extractor.type == ExtractorType.RegexExtractor:
            res = extract_regex(extractor, item)
        elif extractor.type == ExtractorType.KValExtractor:
            try:
                item = json.loads(item)
            except json.JSONDecodeError:
                continue
            res = extract_kval(extractor, item)
        elif extractor.type == ExtractorType.DSLExtractor:
            res = extract_dsl(extractor, resp_data)

        logger.debug(f'[+] {extractor} -> {res}')
        extractors_result['internal'].update(res['internal'])
        extractors_result['external'].update(res['external'])
        extractors_result['extra_info'] += res['extra_info']
    return extractors_result


def network_match(request: NetworkRequest, resp_data: dict, interactsh=None):
    matchers = request.matchers
    matchers_result = []

    for i, matcher in enumerate(matchers):
        matcher_res = False
        # item = network_get_match_part(matcher.part, resp_data, interactsh, matcher.type == MatcherType.BinaryMatcher)
        #
        # if matcher.type == MatcherType.SizeMatcher:
        #     matcher_res = match_size(matcher, len(item))
        #
        # elif matcher.type == MatcherType.WordsMatcher:
        #     matcher_res, _ = match_words(matcher, item, resp_data)
        #
        # elif matcher.type == MatcherType.RegexMatcher:
        #     matcher_res, _ = match_regex(matcher, item)
        #
        # elif matcher.type == MatcherType.BinaryMatcher:
        #     matcher_res, _ = match_binary(matcher, item)
        #
        # elif matcher.type == MatcherType.DSLMatcher:
        #     matcher_res = match_dsl(matcher, resp_data)

        # if matcher.negative:
        #     matcher_res = not matcher_res

        logger.debug(f'[+] {matcher} -> {matcher_res}')

        if not matcher_res:
            if request.matchers_condition == 'and':
                return False
            elif request.matchers_condition == 'or':
                continue

        if request.matchers_condition == 'or':
            return True

        matchers_result.append(matcher_res)

        if len(matchers) - 1 == i:
            return True

    return False


def network_request_generator(request: NetworkRequest, dynamic_values: OrderedDict):
    request_count = len(request.addresses)
    for payload_instance in payload_generator(request.payloads, request.attack):
        current_index = 0
        dynamic_values.update(payload_instance)
        for address in request.addresses:
            current_index += 1
            yield address, request.inputs, payload_instance, request_count, current_index


def execute_network_request(request: NetworkRequest, dynamic_values, interactsh) -> Union[bool, list]:
    results = []
    for h in request.host:
        use_tls = False
        if h.startswith('tls://'):
            use_tls = True
            h = h.replace('tls://', '')
        address = marker_replace(h, dynamic_values)
        host, port = urlparse(address).hostname, urlparse(address).port
        address = AddressKV(address=address, host=host, port=port, tls=use_tls)
        request.addresses.append(address)

    for (address, inputs, payload, request_count, current_index) in network_request_generator(request, dynamic_values):
        try:
            req_buf, resp_buf = [], []
            resp_data = {'host': address.address}
            s = socket.socket()
            s.connect((address.host, address.port))
            if address.tls:
                ssl.wrap_socket(s)
            for inp in inputs:
                data = marker_replace(inp.data, dynamic_values)
                if isinstance(data, int):
                    data = str(data)
                if inp.type == NetworkInputType.HexType:
                    data = binascii.unhexlify(data)
                elif not isinstance(data, bytes):
                    data = data.encode('utf-8')

                if inp.read > 0:
                    chunk = s.recv(inp.read)
                    resp_buf.append(chunk)
                    if inp.name:
                        resp_data[inp.name] = chunk

                req_buf.append(data)
                s.send(data)
                time.sleep(0.1)

            last_bytes = []
            if request.read_all:
                while True:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    last_bytes.append(chunk)
            else:
                chunk = s.recv(request.read_size)
                last_bytes.append(chunk)

            # response to DSL Map
            resp_buf += last_bytes
            resp_data['request'] = b''.join(req_buf)
            resp_data['data'] = b''.join(last_bytes)
            resp_data['raw'] = b''.join(resp_buf)
            logger.debug(resp_data)

            extractor_res = network_extract(request, resp_data)

            for k, v in extractor_res['internal'].items():
                if v == UNRESOLVED_VARIABLE and k in dynamic_values:
                    continue
                else:
                    dynamic_values[k] = v

            resp_data.update(dynamic_values)
            match_res = network_match(request, resp_data, interactsh)
            if match_res:
                output = {}
                output.update(extractor_res['external'])
                output.update(payload)
                output['extra_info'] = extractor_res['extra_info']
                results.append(output)
                return results
        except Exception:
            import traceback
            traceback.print_exc()

    return False
