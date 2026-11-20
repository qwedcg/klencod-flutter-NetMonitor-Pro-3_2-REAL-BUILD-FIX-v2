from pathlib import Path
import shutil
root = Path.cwd()
files = {
    'settings.gradle':'settings.gradle',
    'build.gradle':'build.gradle',
    'gradle.properties':'gradle.properties',
    'app_build.gradle':'app/build.gradle',
    'AndroidManifest.xml':'app/src/main/AndroidManifest.xml',
    'strings.xml':'app/src/main/res/values/strings.xml',
    'styles.xml':'app/src/main/res/values/styles.xml',
    'activity_main.xml':'app/src/main/res/layout/activity_main.xml',
    'MainActivity.java':'app/src/main/java/com/netmonitor/pro/MainActivity.java',
    'MonitorVpnService.java':'app/src/main/java/com/netmonitor/pro/MonitorVpnService.java',
}
for src_name, dest_name in files.items():
    src = root / src_name
    dst = root / dest_name
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.resolve() != dst.resolve():
        shutil.copy2(src, dst)
print('Project structure created.')
