"""
三语国际化引擎 (Trilingual i18n Engine)
支持: zh-CN (简体中文)、en (English)、zh-HK (粤语/繁体中文)
语言优先级: URL参数 ?lang= > Session > Cookie > Accept-Language 请求头 > 默认 en
"""

import json
import os
from flask import g, request, session, current_app

TRANSLATIONS_DIR = os.path.join(os.path.dirname(__file__), 'translations')
SUPPORTED_LOCALES = ['zh-CN', 'en', 'zh-HK']
DEFAULT_LOCALE = 'en'

LOCALE_NAMES = {
    'zh-CN': '简体中文',
    'en': 'English',
    'zh-HK': '粵語（繁體）',
}

_translations_cache = {}


def load_translations(locale):
    """加载指定语言的翻译字典，带缓存"""
    if locale in _translations_cache:
        return _translations_cache[locale]

    filepath = os.path.join(TRANSLATIONS_DIR, f'{locale}.json')
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
        _translations_cache[locale] = data
        return data
    except (FileNotFoundError, json.JSONDecodeError):
        _translations_cache[locale] = {}
        return {}


def get_locale():
    """
    多级优先级检测当前语言:
    1. URL 查询参数 ?lang=zh-CN
    2. Session 中的 locale
    3. Cookie 中的 locale
    4. Accept-Language 请求头
    5. 默认 en
    """
    # 1. URL 参数
    lang_param = request.args.get('lang')
    if lang_param in SUPPORTED_LOCALES:
        return lang_param

    # 2. Session
    locale = session.get('locale')
    if locale in SUPPORTED_LOCALES:
        return locale

    # 3. Cookie
    locale = request.cookies.get('locale')
    if locale in SUPPORTED_LOCALES:
        return locale

    # 4. Accept-Language 请求头
    if request.accept_languages:
        best = request.accept_languages.best_match(SUPPORTED_LOCALES)
        if best:
            return best

    # 5. 默认
    return DEFAULT_LOCALE


def _(key, **kwargs):
    """
    翻译辅助函数，用于 Jinja2 模板: {{ _('key') }}
    也支持格式化参数: {{ _('welcome_user', name=username) }}
    """
    locale = g.get('locale', DEFAULT_LOCALE)
    translations = load_translations(locale)
    text = translations.get(key, key)
    if kwargs:
        try:
            text = text.format(**kwargs)
        except (KeyError, ValueError):
            pass
    return text


def flash_msg(key, category='message', **kwargs):
    """
    翻译 flash 消息，用法: flash_msg('login_success')
    替代原生的 flask.flash()
    """
    from flask import flash
    msg = _(key, **kwargs)
    flash(msg, category)


def init_i18n(app):
    """
    初始化 i18n，注册 before_request 钩子和模板全局变量

    在 create_app() 或 app 初始化后调用:
        from i18n import init_i18n
        init_i18n(app)
    """

    @app.before_request
    def detect_locale():
        """每次请求前检测并设置当前语言"""
        g.locale = get_locale()
        g.locale_name = LOCALE_NAMES.get(g.locale, g.locale)
        g.supported_locales = SUPPORTED_LOCALES
        g.locale_names = LOCALE_NAMES

    # 注入模板全局变量
    app.add_template_global(_, '_')
    app.add_template_global(LOCALE_NAMES, 'locale_names')
    app.add_template_global(SUPPORTED_LOCALES, 'supported_locales')

    # 语言切换路由
    @app.route('/set-lang', methods=['POST'])
    def set_lang():
        lang = request.form.get('lang', DEFAULT_LOCALE)
        if lang not in SUPPORTED_LOCALES:
            lang = DEFAULT_LOCALE

        session['locale'] = lang
        session.modified = True

        # 302 重定向回来源页
        next_url = request.form.get('next', request.referrer or '/')
        resp = current_app.make_response(
            f'<html><body><script>document.cookie="locale={lang};path=/;max-age=31536000";window.location.href="{next_url}";</script></body></html>'
        )
        resp.set_cookie('locale', lang, max_age=365 * 24 * 3600, path='/')
        return resp
