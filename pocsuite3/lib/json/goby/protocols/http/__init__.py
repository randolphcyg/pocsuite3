import re
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Union, List, Optional

from requests_toolbelt.utils import dump

from urllib.parse import urljoin
from pocsuite3.lib.core.data import AttribDict
from pocsuite3.lib.core.log import LOGGER as logger
from pocsuite3.lib.request import requests
from pocsuite3.lib.json.goby.model import CaseInsensitiveEnum
from pocsuite3.lib.json.goby.operators import (Extractor, ExtractorType,
                                               ResponseTest, ResponseTestType,
                                               extract_dsl, extract_json,
                                               extract_kval, extract_regex,
                                               extract_xpath, match_binary,
                                               match_dsl, match_regex,
                                               match_size, match_status_code,
                                               match_words)
from pocsuite3.lib.json.goby.protocols.common.generators import AttackType, payload_generator
from pocsuite3.lib.json.goby.protocols.common.interactsh import InteractshClient
from pocsuite3.lib.json.goby.protocols.common.replacer import (
    UnresolvedVariableException, UNRESOLVED_VARIABLE, marker_replace, Marker)


class HTTPMethod(CaseInsensitiveEnum):
    HTTPGet = "GET"
    HTTPHead = "HEAD"
    HTTPPost = "POST"
    HTTPPut = "PUT"
    HTTPDelete = "DELETE"
    HTTPConnect = "CONNECT"
    HTTPOptions = "OPTIONS"
    HTTPTrace = "TRACE"
    HTTPPatch = "PATCH"
    HTTPPurge = "PURGE"
    HTTPDebug = "DEBUG"


@dataclass
class HttpRequest:
    """HttpRequest contains a http request to be made from a template
    """
    # 请求 uri
    uri: str = ''
    # 请求方式，目前支持 GET、POST 、PUT、HEAD、PUSH、DELETE、OPTION、自定义，默认为 GET
    method: str = HTTPMethod.HTTPGet
    # 请求 header 头，key、value 写入
    header: dict = field(default_factory=dict)
    # 请求参数，内容会作为 post data 发送。
    data: str = ''
    # 参数类型，默认为 text
    data_type: str = ''
    # 是否跟随跳转，true 为跟随跳转否则不跳转，默认为 true
    follow_redirect: bool = True

    # 其他参数
    # RaceCount is the number of times to send a request in Race Condition Attack.
    race_count: int = 0

    # MaxRedirects is the maximum number of redirects that should be followed.
    max_redirects: int = 0

    # PipelineConcurrentConnections is number of connections to create during pipelining.
    pipeline_concurrent_connections: int = 0

    # PipelineRequestsPerConnection is number of requests to send per connection when pipelining.
    pipeline_requests_per_connection: int = 0

    # Threads specifies number of threads to use sending requests. This enables Connection Pooling.
    threads: int = 0

    # MaxSize is the maximum size of http response body to read in bytes.
    max_size: int = 0

    cookie_reuse: bool = False

    read_all: bool = False
    redirects: bool = False
    host_redirects: bool = False
    pipeline: bool = False
    unsafe: bool = False
    race: bool = False

    # Request condition allows checking for condition between multiple requests for writing complex checks and
    # exploits involving multiple HTTP request to complete the exploit chain.
    req_condition: bool = False

    stop_at_first_match: bool = True
    skip_variables_check: bool = False
    iterate_all: bool = False
    digest_username: str = ''
    digest_password: str = ''


def http_response_to_dsl_map(resp: requests.Response):
    """Converts an HTTP response to a map for use in DSL matching
    """
    data = AttribDict()
    if not isinstance(resp, requests.Response):
        return data

    for k, v in resp.cookies.items():
        data[k.lower()] = v
    for k, v in resp.headers.items():
        data[k.lower().replace('-', '_')] = v

    req_headers_raw = '\n'.join(f'{k}: {v}' for k, v in resp.request.headers.items())
    req_body = resp.request.body
    if not req_body:
        req_body = b''
    if not isinstance(req_body, bytes):
        req_body = req_body.encode()
    resp_headers_raw = '\n'.join(f'{k}: {v}' for k, v in resp.headers.items())
    resp_body = resp.content

    data['request'] = req_headers_raw.encode() + b'\n\n' + req_body
    data['response'] = resp_headers_raw.encode() + b'\n\n' + resp_body
    data['status_code'] = resp.status_code
    data['body'] = str(resp_body)
    data['all_headers'] = resp_headers_raw
    data['header'] = resp_headers_raw
    data['kval_extractor_dict'] = {}
    data['kval_extractor_dict'].update(resp.cookies)
    data['kval_extractor_dict'].update(resp.headers)

    return data


def http_get_match_part(part: str, resp_data: dict, interactsh=None, return_bytes: bool = False) -> str:
    result = ''
    if part == '':
        part = 'body'

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


def perform_logical_operation(data, matcher):
    # 获取条件字段的值
    target_value = matcher.value
    operation = matcher.operation

    # 根据操作进行逻辑匹配
    if operation == "==":
        return data == target_value
    elif operation == "!=":
        return data != target_value
    elif operation == ">":
        return data > target_value
    elif operation == "<":
        return data < target_value
    elif operation == ">=":
        return data >= target_value
    elif operation == "<=":
        return data <= target_value
    elif operation == "contains":
        return target_value in data
    elif operation == "not contains":
        return target_value not in data
    elif operation == "start_with":
        return data.startswith(target_value)
    elif operation == "end_with":
        return data.endswith(target_value)
    elif operation == "regex":
        return re.search(target_value, data) is not None
    else:
        raise ValueError(f"Unsupported operation: {operation}")


def http_match(step, resp_data: dict, interactsh=None):
    matchers = step.ResponseTest.checks
    matchers_result = []

    for i, matcher in enumerate(matchers):
        match matcher.variable:
            case "$code":
                matcher_res = perform_logical_operation(str(resp_data['status_code']), matcher)
                matchers_result.append(matcher_res)
            case "$body":
                matcher_res = perform_logical_operation(resp_data['body'], matcher)
                matchers_result.append(matcher_res)

        logger.debug(f'[+] {matcher} -> {matcher_res}')

    if len(matchers_result) > 0:
        if step.ResponseTest.operation == 'AND':
            return all(matchers_result)
        elif step.ResponseTest.operation == 'OR':
            return any(matchers_result)


def http_extract(template, resp_data: dict):
    extractors = template.extractors
    extractors_result = {'internal': {}, 'external': {}, 'extra_info': []}

    for extractor in extractors:
        item = http_get_match_part(extractor.part, resp_data)

        res = None
        if extractor.type == ExtractorType.RegexExtractor:
            res = extract_regex(extractor, item)
        elif extractor.type == ExtractorType.KValExtractor:
            res = extract_kval(extractor, resp_data.get('kval_extractor_dict', {}))
        elif extractor.type == ExtractorType.XPathExtractor:
            res = extract_xpath(extractor, item)
        elif extractor.type == ExtractorType.JSONExtractor:
            res = extract_json(extractor, item)
        elif extractor.type == ExtractorType.DSLExtractor:
            res = extract_dsl(extractor, resp_data)

        logger.debug(f'[+] {extractor} -> {res}')
        extractors_result['internal'].update(res['internal'])
        extractors_result['external'].update(res['external'])
        extractors_result['extra_info'] += res['extra_info']
    return extractors_result


def extract_dict(text, line_sep='\n', kv_sep='='):
    """Split the string into a dictionary according to the split method
    """
    _dict = OrderedDict([i.split(kv_sep, 1) for i in text.split(line_sep)])
    return _dict


def http_request_generator(request: HttpRequest, dynamic_values: OrderedDict):
    method, url, headers, data, kwargs = '', '', '', '', OrderedDict()
    method = request.method
    url = request.uri
    headers = request.header
    data = request.data

    yield method, url, kwargs, data,


def execute_http_request(step, template, dynamic_values, interactsh) -> Union[bool, list]:
    req = step.Request
    results = []
    resp_data_all = {}
    with requests.Session() as session:
        try:
            for (method, url, kwargs, payload) in http_request_generator(req, dynamic_values):
                try:
                    if req.max_redirects:
                        session.max_redirects = req.max_redirects
                    else:
                        session.max_redirects = 10
                    response = session.request(method=method, url=urljoin(dynamic_values['BaseURL'], url), **kwargs)
                    # for debug purpose
                    try:
                        logger.debug(dump.dump_all(response).decode('utf-8'))
                    except UnicodeDecodeError:
                        logger.debug(dump.dump_all(response))

                except Exception:
                    import traceback
                    traceback.print_exc()
                    response = None

                resp_data = http_response_to_dsl_map(response)
                if response:
                    response.close()
                # TODO 提取根据更多情况优化
                extractor_res = http_extract(template, resp_data)
                for k, v in extractor_res['internal'].items():
                    if v == UNRESOLVED_VARIABLE and k in dynamic_values:
                        continue
                    else:
                        dynamic_values[k] = v

                if req.req_condition:
                    resp_data_all.update(resp_data)
                    for k, v in resp_data.items():
                        resp_data_all[f'{k}'] = v

                    resp_data_all.update(dynamic_values)
                    match_res = http_match(step, resp_data_all, interactsh)
                    resp_data_all = {}
                    if match_res:
                        output = {}
                        output.update(extractor_res['external'])
                        output.update(payload)
                        output['extra_info'] = extractor_res['extra_info']
                        results.append(output)
                        if req.stop_at_first_match:
                            return results
                else:
                    resp_data.update(dynamic_values)
                    match_res = http_match(step, resp_data, interactsh)
                    if match_res:
                        output = {}
                        output.update(extractor_res['external'])
                        output.update(payload)
                        output['extra_info'] = extractor_res['extra_info']
                        results.append(output)
                        if req.stop_at_first_match:
                            return results
        except Exception:
            import traceback
            traceback.print_exc()
        if results and any(results):
            return results
        else:
            return False
