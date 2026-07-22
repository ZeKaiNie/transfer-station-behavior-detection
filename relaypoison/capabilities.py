"""relaypoison 所需的精简能力枚举。

这里只保留动作模型需要的词表，不依赖 ShadowBlade 的动态引擎或其它模块。
"""

from enum import Enum


class Capability(str, Enum):
    """coding agent 可能声明或执行的七类能力。"""

    NETWORK = "network"
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    SUBPROCESS = "subprocess"
    DYNAMIC_CODE = "dynamic_code"
    CREDENTIAL_ACCESS = "credential_access"
    IDENTITY_WRITE = "identity_write"
