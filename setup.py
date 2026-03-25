from setuptools import setup, find_packages

setup(
    name="reposec",
    version="0.1.0",
    author="Nistal Talson",
    description="Free AI-powered security audit for any GitHub repo",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/NISTALTALSON/repoaudit",
    packages=find_packages(),
    install_requires=[
        "click>=8.0",
        "rich>=13.0",
        "requests>=2.28",
        "ollama>=0.1.0",
    ],
    entry_points={
        "console_scripts": [
            "reposec=repoaudit.cli:main",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
    ],
)