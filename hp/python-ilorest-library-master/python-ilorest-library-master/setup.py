from setuptools import setup, find_packages

extras = {}

setup(name='python-ilorest-library',
      version='3.3.0.0',
      description='iLO Rest Python Library',
	  author = 'Hewlett Packard Enterprise',
	  author_email = 'rajeevalochana.kallur@hpe.com',
      extras_require = extras,
      classifiers=[
          'Development Status :: 3 - Alpha',
          'License :: OSI Approved :: Apache Software License',
          'Programming Language :: Python :: 2.7',
          'Programming Language :: Python :: 3',
          'Topic :: Communications'
      ],
      keywords='Hewlett Packard Enterprise',
      url='https://github.com/HewlettPackard/python-ilorest-library',
      packages=find_packages('src'),
      package_dir={'': 'src'},
      install_requires=[
          'jsonpatch',
          'jsonpath_rw',
          'jsonpointer',
          'urllib3',
          'six'
      ])
