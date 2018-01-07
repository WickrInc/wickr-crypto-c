#!/usr/bin/env python

from distutils.command.build import build
from distutils.core import setup

import os

class my_build(build):
    def run(self):
        build.run(self)
        if not self.dry_run:
            os.spawnlp(os.P_WAIT, 'sh', 'sh', '-c', 'cd .. && gmake lib')
            self.copy_file(os.path.join('..', 'build', 'lib', 'libdecaf.so'), os.path.join(self.build_lib, 'edgold'))

cmdclass = {}
cmdclass['build'] = my_build

setup(name='edgold',
      version='0.1',
      description='The Ed ECC Goldilocks Python wrapper',
      author='John-Mark Gurney',
      author_email='jmg@funkthat.com',
      #url='',
      cmdclass=cmdclass,
      packages=['edgold', ],
     )
