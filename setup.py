import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()


def parse_requirements_to_freeze():
    dependencies = []

    def remove_trailing_comment(line):
        return line.split('#')[0].strip()

    with open('requirements-to-freeze.txt') as f:
        for line in (l.strip() for l in f.readlines()):
            if line and not line.startswith('#'):
                dependencies.append(remove_trailing_comment(line))
    print(dependencies)

    return dependencies


setuptools.setup(
    name="trillian",
    version="0.0.1",
    author="Projects by IF Ltd",
    author_email="hello@projectsbyif.com",
    description="Interact with Trillian logs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/projectsbyif/trillian-demo-python-api-client",
    packages=setuptools.find_packages(),
    classifiers=(
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ),
    install_requires=parse_requirements_to_freeze(),
)
