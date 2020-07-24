module=sktlsf

default:V: $module
    timeout 1 ./$module

$module: $module.nim
	nim c -o:$target $prereq

