module=sktlsf

default:V: $module
    ./$module

$module: $module.nim
	nim c -o:$target $prereq

