import json
import logging


class EasyLogger(object):
    STYLE_SIMPLE = 'simple'
    STYLE_INLINE = 'inline'
    STYLE_JSON = 'json'
    STYLE_HYBRID = 'hybrid'

    def __init__(self, impl, style=STYLE_INLINE):
        self.impl = impl
        self.style = style

    def load_from_config(self, config):
        self.style = config['LOG_STYLE']

    def debug(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.DEBUG, msg, style, *args, **kwargs)

    def info(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.INFO, msg, style, *args, **kwargs)

    def warning(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.WARNING, msg, style, *args, **kwargs)

    def warn(self, msg, *args, style=None, **kwargs):
        self.warning(msg, *args, style=style, **kwargs)

    def error(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.ERROR, msg, style, *args, **kwargs)

    def critical(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.CRITICAL, msg, style, *args, **kwargs)

    def exception(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.ERROR, msg, style, exc_info=1, *args, **kwargs)

    def _print_log(self, lvl, msg, style, *args, exc_info=0, **kwargs):
        if self.impl.level > lvl:
            return
        style = style or self.style
        args = [str(e) for e in args]

        if style == self.STYLE_INLINE:
            arg_str = ' '.join(args)
            kwarg_str = ' '.join(['%s=%s' % (str(k), self._check_quote(v))
                                  for k, v in kwargs.items()])
            msg += ' \t' + arg_str + '\t' + kwarg_str
        elif style == self.STYLE_JSON:
            msg = '\n' + json.dumps({
                'msg': msg,
                'args': args,
                'kwargs': kwargs
            }, ensure_ascii=False, indent=2)
        elif style == self.STYLE_HYBRID:
            msg += ' \t' + ' '.join(args)
            if kwargs:
                msg += '\n' + json.dumps(kwargs, indent=2, ensure_ascii=False)
        else:
            if args:
                msg += '\t' + str(args or '')
            if kwargs:
                msg += '\t' + str(kwargs or '')
        self.impl.log(lvl, msg, exc_info=exc_info)

    @staticmethod
    def _check_quote(s):
        s = str(s)
        return '"%s"' % s if ' ' in s else s