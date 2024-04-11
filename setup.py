from setuptools import setup

setup(name="secretsd",
      version="1.0",
      description="A basic FreeDesktop.org Secret Service backend",
      url="https://github.com/grawity/secretsd",
      author="Mantas Mikulėnas",
      author_email="grawity@gmail.com",
      license="MIT",
      packages=["secretsd"],
      install_requires=["dbus", "platformdirs", "pycryptodome"],
      entry_points={"console_scripts": ["secretsd = secretsd.__main__:run"]})
