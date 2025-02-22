import os
import re
from urllib.parse import urljoin

import pkg_resources
import importlib.machinery
import importlib.util
from importlib.abc import Loader
from pocsuite3.lib.core.data import conf, cmd_line_options


from pocsuite3.lib.core.common import (
    multiple_replace, get_filename, get_md5, get_file_text,
    is_pocsuite3_poc, get_poc_requires, get_poc_name)
from pocsuite3.lib.core.data import kb
from pocsuite3.lib.core.data import logger
from pocsuite3.lib.core.settings import POC_IMPORTDICT


# 生成python模版文件
def gen_py_tpl(filename: str, content: str):
    # 获取项目的根目录
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    # 新文件夹的名称
    folder_name = 'py_templates'
    folder_path = os.path.join(project_root, folder_name)

    # 完整的目标文件路径
    base_name = os.path.basename(filename)
    name_without_extension = os.path.splitext(base_name)[0]
    py_filename = name_without_extension + '.py'
    py_filepath = os.path.join(folder_path, py_filename)

    # 判断文件夹是否存在，不存在则创建
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)

    # 写入文件内容
    with open(py_filepath, "w") as file:
        file.write(content)

    return py_filepath


class PocLoader(Loader):
    def __init__(self, fullname, path):
        self.fullname = fullname
        self.path = path
        self.data = None

    def set_data(self, data):
        self.data = data

    def get_filename(self, fullname):
        return self.path

    def get_data(self, filename):
        if filename.startswith('pocsuite://') and self.data:
            if not is_pocsuite3_poc(self.data):
                data = multiple_replace(self.data, POC_IMPORTDICT)
            else:
                data = self.data
        else:
            code = get_file_text(filename)
            if not is_pocsuite3_poc(code):
                data = multiple_replace(code, POC_IMPORTDICT)
            else:
                data = code
        return data

    @staticmethod
    def check_requires(data):
        requires = get_poc_requires(data)
        requires = [i.strip().strip('"').strip("'") for i in requires.split(',')] if requires else ['']
        if requires is None:
            return
        if requires[0]:
            poc_name = get_poc_name(data)
            info_msg = 'PoC script "{0}" requires "{1}" to be installed'.format(poc_name, ', '.join(requires))
            logger.info(info_msg)
            try:
                for r in requires:
                    r = r.replace(' ', '')
                    install_name, import_name = (r.split(':') + [''])[0:2]
                    t = re.split('>|<|=|~', install_name)
                    if len(t) > 1:
                        install_name = t[0]
                    if not import_name:
                        import_name = install_name
                    __import__(import_name)
                    try:
                        ver = pkg_resources.get_distribution(install_name).version
                    except Exception:
                        ver = 'unknown'
                    logger.info(f'{install_name}=={ver} has been installed')
            except ImportError:
                err_msg = f'{install_name} not found, try install with "python -m pip install {install_name}"'
                logger.error(err_msg)
                raise SystemExit

    def exec_module(self, module):
        filename = self.get_filename(self.fullname)
        poc_code = self.get_data(filename)

        # convert goby json template to pocsuite3 poc script
        if filename.endswith('.json') and re.search(r'ScanSteps', poc_code):
            from pocsuite3.lib.json.goby import Goby
            poc_code = str(Goby(poc_code))
            if conf.convert_goby_to_py:
                # goby json模板生成python模板文件存储
                py_filepath = gen_py_tpl(filename, poc_code)
                logger.info("gen python template: {}".format(py_filepath))

        # convert yaml template to pocsuite3 poc script
        if filename.endswith('.yaml') and re.search(r'matchers:\s+-', poc_code):
            from pocsuite3.lib.yaml.nuclei import Nuclei
            poc_code = str(Nuclei(poc_code))

        self.check_requires(poc_code)
        obj = compile(poc_code, filename, 'exec', dont_inherit=True, optimize=-1)
        try:
            exec(obj, module.__dict__)
        except Exception as err:
            logger.error("Poc: '{}' exec arise error: {} ".format(filename, err))


def load_file_to_module(file_path, module_name=None):
    if '' not in importlib.machinery.SOURCE_SUFFIXES:
        importlib.machinery.SOURCE_SUFFIXES.append('')
    try:
        module_name = 'pocs_{0}'.format(get_filename(file_path, with_ext=False)) if module_name is None else module_name
        spec = importlib.util.spec_from_file_location(module_name, file_path, loader=PocLoader(module_name, file_path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        poc_model = kb.registered_pocs[module_name]
    except KeyError:
        poc_model = None
    except ImportError:
        error_msg = "load module failed! '{}'".format(file_path)
        logger.error(error_msg)
        raise
    return poc_model


def load_string_to_module(code_string, fullname=None):
    try:
        module_name = 'pocs_{0}'.format(get_md5(code_string)) if fullname is None else fullname
        file_path = 'pocsuite://{0}'.format(module_name)
        poc_loader = PocLoader(module_name, file_path)
        poc_loader.set_data(code_string)
        spec = importlib.util.spec_from_file_location(module_name, file_path, loader=poc_loader)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        poc_model = kb.registered_pocs[module_name]
    except KeyError:
        poc_model = None
    except ImportError:
        error_msg = "load module '{0}' failed!".format(fullname)
        logger.error(error_msg)
        raise
    return poc_model


def register_poc(poc_class):
    module = poc_class.__module__.split('.')[0]
    if module in kb.registered_pocs:
        kb.current_poc = kb.registered_pocs[module]
        return

    kb.registered_pocs[module] = poc_class()
    kb.current_poc = kb.registered_pocs[module]
