from dataclasses import dataclass, field
from typing import List

from pocsuite3.lib.json.goby.model import Info, CaseInsensitiveEnum
from pocsuite3.lib.json.goby.protocols.http import HttpRequest
from pocsuite3.lib.json.goby.protocols.network import NetworkRequest
from pocsuite3.lib.json.goby.operators import ResponseTest, Extractor


class ProtocolType(CaseInsensitiveEnum):
    InvalidProtocol = "invalid"
    DNSProtocol = "dns"
    FileProtocol = "file"
    HTTPProtocol = "http"
    HeadlessProtocol = "headless"
    NetworkProtocol = "network"
    WorkflowProtocol = "workflow"
    SSLProtocol = "ssl"
    WebsocketProtocol = "websocket"
    WHOISProtocol = "whois"


@dataclass
class ExpParam:
    # 参数变量名称
    Name: str = ''
    # 变量参数类型，主要分为 input 、select、createSelect
    Type: str = ''
    # 参数默认值，如 type 为 select、createSelect，根据 , 分割
    Value: str = ''
    # 展示条件
    Show: str = ''


@dataclass
class ScanStep:
    Request: HttpRequest
    ResponseTest: ResponseTest

@dataclass
class Template:
    """Template json.
    """
    # 漏洞名称，描述规范参考漏洞规约，默认写中文。
    Name: str = ''
    # 漏洞描述，描述规范参考漏洞规约，默认写中文。
    Description: str = ''
    # 漏洞影响产品，描述规范参考漏洞规约，默认写中文。
    Product: str = ''
    # 漏洞影响产品官方首页。
    Homepage: str = ''
    # 漏洞披露时间，如果找不到写当天时间。
    DisclosureDate: str = ''
    # 作者
    Author: str = ''
    # FOFA 查询规则，必须与 GobyQuery 保持一致。
    FofaQuery: str = ''
    # Goby 查询规则，语法参考 《GobyQuery》章节。
    GobyQuery: str = ''
    # 漏洞等级，0 低危、1 中危、2 高危、3 严重
    Level: str = ''
    # 漏洞影响，描述规范参考漏洞规约，默认写中文。
    Impact: str = ''
    # 漏洞修复建议，描述规范参考漏洞规约。
    Recommendation: str = ''
    # 漏洞参考链接
    References: List[str] = field(default_factory=list)
    # 是否为 0day，true 为是否则为不是
    Is0day: bool = False
    RealReferences: List[str] = field(default_factory=list)
    # 是否包含 EXP
    HasExp: bool = True
    # Exp 需要传入的参数，默认为 []，详情参考 ExpParams 章节
    ExpParams: List[ExpParam] = field(default_factory=list)
    # Exp 提示
    ExpTips: dict = field(default_factory=dict)
    # JSON  格式定义漏洞发包逻辑，详情参考 ScanSteps 章节
    ScanStepsList: List[ScanStep] = field(default_factory=list)
    ScanStepOperation: str = ''
    # JSON 格式定义漏洞利用逻辑，默认为 null，详情参考 ExploitSteps 章节
    ExploitSteps: List[str] = field(default_factory=list)
    # 与 VulType 字段内容保持一致，漏洞类型。
    Tags: List[str] = field(default_factory=list)
    # 漏洞类型，详情见《漏洞类型》章节
    VulType: List[str] = field(default_factory=list)
    # CVE 编号
    CVEIDs: List[str] = field(default_factory=list)
    # CNNVD 编号
    CNNVD: List[str] = field(default_factory=list)
    # CNVD 编号
    CNVD: List[str] = field(default_factory=list)
    # CVSS 漏洞评分
    CVSSScore: str = ''
    # 多语言翻译，key值为国家简写代号，value为翻译字段由Name、Product、Description、Recommendation、Impact、VulType、Tags 组成
    Translation: dict = field(default_factory=dict)
    # 漏洞对应产品的系统层级，如 GitLab 为 Web 应用，填到 Application 层，Struts2 为 Web 开发框架，填到 Support 层
    AttackSurfaces: dict = field(default_factory=dict)

    # 其它参数
    stop_at_first_match: bool = True
    variables: dict = field(default_factory=dict)
    extractors: List[Extractor] = field(default_factory=list)

