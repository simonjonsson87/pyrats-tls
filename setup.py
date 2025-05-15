# setup.py


from setuptools import setup
setup(
    name="pyrats_tls",
    version="0.1.0",
    packages=["pyrats_tls"],
)


#from setuptools import setup
#from setuptools.command.build_ext import build_ext
#import subprocess
#import os
#
#class CMakeBuild(build_ext):
#    def run(self):
#        build_dir = "build"
#        os.makedirs(build_dir, exist_ok=True)
#        subprocess.check_call(["cmake", "../rats_tls_wrapper"], cwd=build_dir)
#        subprocess.check_call(["cmake", "--build", "."], cwd=build_dir)
#
#        ext = {
#            "linux": "librats_tls_wrapper.so",
#            "darwin": "librats_tls_wrapper.dylib",
#            "win32": "rats_tls_wrapper.dll"
#        }[os.sys.platform]
#
#        # Move built library to Python package dir
#        self.copy_file(os.path.join(build_dir, ext), os.path.join("pyrats_tls", ext))
#
#setup(
#    name="pyrats_tls",
#    version="0.1.0",
#    packages=["pyrats_tls"],
#    cmdclass={"build_ext": CMakeBuild},
#)
