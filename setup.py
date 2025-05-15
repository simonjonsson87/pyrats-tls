# setup.py


from setuptools import setup
import sys

setup(
    name="pyrats_tls",
    version="0.1.0",
    packages=["pyrats_tls"],
    # Ensure platform-specific wheel
    options={
        "bdist_wheel": {
            "plat_name": "macosx_11_0_universal2" if sys.platform == "darwin" else
                         "manylinux_2_17_x86_64" if sys.platform == "linux" else
                         "win_amd64"
        }
    }
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
