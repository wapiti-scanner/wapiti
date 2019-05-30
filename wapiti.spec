# -*- mode: python -*-

block_cipher = None


a = Analysis(
    ['bin/wapiti', 'bin/wapiti-getcookie'],
     pathex=['/data/downloads/wapiti-code'],
     binaries=[],
     datas=[
        ('doc/*', 'doc')
     ],
     hookspath=[],
     runtime_hooks=[],
     excludes=[],
     win_no_prefer_redirects=False,
     win_private_assemblies=False,
     cipher=block_cipher
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name='wapiti',
    debug=False,
    strip=False,
    upx=True,
    console=True
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name='wapiti'
)
