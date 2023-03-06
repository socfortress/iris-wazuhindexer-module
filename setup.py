from setuptools import setup

setup(
    name='iris-wazuhindexer-module',
    python_requires='>=3.9',
    version='0.1.0',
    packages=['iris_wazuhindexer_module', 'iris_wazuhindexer_module.wazuhindexer_handler'],
    url='https://github.com/socfortress/iris-wazuhindexer-module',
    license='MIT',
    author='SOCFortress',
    author_email='info@socfortress.co',
    description='`iris-wazuhindexer-module` is a IRIS pipeline/processor module created with https://github.com/dfir-iris/iris-skeleton-module',
    install_requires=[]
)
