"""兼容旧版 pip（<21.3，无 PEP 660 支持）的可编辑安装垫片。

现代 pip 直接读取 pyproject.toml；此文件让旧环境中的
`pip install -e .` 也可用。两处元数据保持一致。
"""

from setuptools import find_packages, setup

setup(
    name="artifactproof",
    version="1.0.0",
    description="可复现产物核验站：安全扫描 zip/tar 归档并比较真实内容差异与可忽略差异",
    packages=find_packages(include=["artifactproof*"]),
    include_package_data=True,
    package_data={"artifactproof": ["web_assets/*"]},
    python_requires=">=3.9",
    install_requires=[],
    extras_require={"test": ["pytest>=7"]},
    entry_points={
        "console_scripts": ["artifactproof = artifactproof.cli:main"],
    },
)
