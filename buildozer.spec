[app]
title = Infinite AI Security
package.name = infiniteaisecurity
package.domain = com.infiniteai.security

source.dir = .
source.include_exts = py,png,jpg,kv,atlas,json

version = 1.0
requirements = python3,kivy,requests,asyncio

[buildozer]
log_level = 2

[app]
icon.filename = icon.png
presplash.filename = presplash.png

android.permissions = INTERNET,ACCESS_NETWORK_STATE,WRITE_EXTERNAL_STORAGE

android.api = 30
android.minapi = 21
android.sdk = 30
android.ndk = 23b
android.gradle_dependencies = 

[buildozer]
warn_on_root = 1