import binascii
import re
from dataclasses import dataclass, field
from typing import List

from pocsuite3.lib.json.goby.model import CaseInsensitiveEnum
from pocsuite3.lib.json.goby.protocols.common.expressions import evaluate, Marker


class ResponseTestType(CaseInsensitiveEnum):
    TestGroup = "group"
    TestItem = "item"


@dataclass
class Check:
    # 备注
    bz: str = ''
    # 测试项 operation 逻辑验证方式，主要有 contains、not contains、regex、start_with、end_with、==、!=、>、<、>=、<=
    operation: str = ''
    # 类型，分为测试组（group）、测试项（item）
    type: str = ''
    # 匹配值
    value: str = ''
    # 变量，主要有正文（$body）、Header（$head）、状态码（$code）
    variable: str = ''


@dataclass
class ResponseTest:
    """ResponseTest is used to match a part in the output from a protocol.
    """
    # 类型，主要分为测试组（group）、测试项（item）
    type: str = 'group'
    # 测试组内，测试项之间的验证逻辑关系，通过 AND、OR 表示
    operation: str = 'AND'
    # 测试项/组列表
    checks: List[Check] = field(default_factory=list)


def match_status_code(matcher: ResponseTest, status_code: int):
    """Matches a status code check against a corpus
    """
    return status_code in matcher.status


def match_size(matcher: ResponseTest, length: int):
    """Matches a size check against a corpus
    """
    return length in matcher.size


def match_words(matcher: ResponseTest, corpus: str, data: dict) -> (bool, list):
    """Matches a word check against a corpus
    """
    if matcher.case_insensitive:
        corpus = corpus.lower()

    matched_words = []
    for i, word in enumerate(matcher.words):
        word = evaluate(word, data)
        if matcher.encoding == 'hex':
            try:
                word = binascii.unhexlify(word).decode()
            except (ValueError, UnicodeDecodeError):
                pass
        if matcher.case_insensitive:
            word = word.lower()

        if word not in corpus:
            if matcher.condition == 'and':
                return False, []
            elif matcher.condition == 'or':
                continue

        if matcher.condition == 'or' and not matcher.match_all:
            return True, [word]

        matched_words.append(word)

        if len(matcher.words) - 1 == i and not matcher.match_all:
            return True, matched_words

    if len(matched_words) > 0 and matcher.match_all:
        return True, matched_words

    return False, []


def match_regex(matcher: ResponseTest, corpus: str) -> (bool, list):
    """Matches a regex check against a corpus
    """
    matched_regexes = []
    for i, regex in enumerate(matcher.regex):
        if not re.search(regex, corpus):
            if matcher.condition == 'and':
                return False, []
            elif matcher.condition == 'or':
                continue

        current_matches = re.findall(regex, corpus)
        if matcher.condition == 'or' and not matcher.match_all:
            return True, matched_regexes

        matched_regexes = matched_regexes + current_matches
        if len(matcher.regex) - 1 == i and not matcher.match_all:
            return True, matched_regexes

    if len(matched_regexes) > 0 and matcher.match_all:
        return True, matched_regexes

    return False, []


def match_binary(matcher: ResponseTest, corpus: bytes) -> (bool, list):
    """Matches a binary check against a corpus
    """
    matched_binary = []
    for i, binary in enumerate(matcher.binary):
        binary = binascii.unhexlify(binary)
        if binary not in corpus:
            if matcher.condition == 'and':
                return False, []
            elif matcher.condition == 'or':
                continue

        if matcher.condition == 'or':
            return True, [binary]

        matched_binary.append(binary)
        if len(matcher.binary) - 1 == i:
            return True, matched_binary

    return False, []


def match_dsl(matcher: ResponseTest, data: dict) -> bool:
    """Matches on a generic map result
    """
    for i, expression in enumerate(matcher.dsl):
        result = evaluate(f'{Marker.ParenthesisOpen}{expression}{Marker.ParenthesisClose}', data)
        if not isinstance(result, bool):
            if matcher.condition == 'and':
                return False
            elif matcher.condition == 'or':
                continue

        if result is False:
            if matcher.condition == 'and':
                return False
            elif matcher.condition == 'or':
                continue

        if len(matcher.dsl) - 1 == i:
            return True
    return False
