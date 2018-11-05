import logging
import json
import traceback


class EasyLogger(object):
    STYLE_SIMPLE = 'simple'
    STYLE_INLINE = 'inline'
    STYLE_JSON = 'json'
    STYLE_HYBRID = 'hybrid'

    def __init__(self, impl, style=STYLE_INLINE):
        self.impl = impl
        self.style = style

    def debug(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.DEBUG, msg, style, *args, **kwargs)

    def info(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.INFO, msg, style, *args, **kwargs)

    def warning(self, msg, *args, style=None, **kwargs):
        self._print_log(logging.WARNING, msg, style, *args, **kwargs)

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
        if style == self.STYLE_INLINE:
            arg_str = ' '.join(args)
            kwarg_str = ' '.join(['%s=%s' % (k, self._check_quote(v)) 
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
                msg += '\n' + json.dumps(kwargs, indent=2)
        else:
            if args:
                msg += '\t' + str(args or '')
            if kwargs:
                msg += '\t' + str(kwargs or '')
        self.impl.log(lvl, '[192.168.9.89] - ' + msg, exc_info=exc_info)

    @staticmethod
    def _check_quote(s):
        s = str(s)
        return '"%s"' % s if ' ' in s else s


# logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
logFormatter = logging.Formatter("[%(asctime)s] [%(levelname)-5.5s] - %(message)s")
rootLogger = logging.getLogger()
rootLogger.setLevel(logging.INFO)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
rootLogger.addHandler(consoleHandler)

log = EasyLogger(impl=rootLogger, style=EasyLogger.STYLE_JSON)
try:
    log.info('test message from new my logger', 'nhatanh', 'tjeubaoit',
             name='abu', nickname='bangbang songoku', age=28)
    log.info('style simple will be overrided', 'abu', 'tjeubaoit', 'nhatanh', 
             name='nhatanh', age=28, style='inline')
    m = dict()
    print(m['ok'])
except Exception as e:
    import sys
    # traceback.print_exc(file=sys.stderr)
    # rootLogger.exception('msg %s %s %s', 'nhatanh', 'abu', 'tjeubaoit', exc_info=1)
    log.exception(repr(e.__dict__), repr(e), style='hybrid')