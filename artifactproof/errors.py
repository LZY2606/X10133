"""整份归档需要进入隔离状态时抛出的错误。"""


class QuarantineError(Exception):
    """扫描过程中发现不可接受的安全问题。

    错误码（``code``）会原样写入清单，供页面明确展示原因；
    已安全扫描到的成员前缀通过 ``prefix`` 传递。
    """

    def __init__(self, code, message, prefix=None, member=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.prefix = prefix or []
        self.member = member
