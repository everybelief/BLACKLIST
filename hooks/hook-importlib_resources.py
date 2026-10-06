# PyInstaller 3.6 自带 hook 会去找不存在的 version.txt，这里覆盖掉。
hiddenimports = ["importlib_resources.abc", "importlib_resources.readers", "importlib_resources.simple"]
datas = []
